-- Unity Mono camera tracker agent. Invokes Unity icalls via Hs.mono.call
-- (privileged C-side resolution + dispatch). Uses native.call on Mono
-- metadata APIs only to obtain the MonoMethod pointer for the scene-
-- discovery disassembly walk; the icall ADDRESS is never exposed to
-- bridge code.

local PTR_SIZE = process.get_pointer_size()
local MONO_HEADER_SIZE = 2 * PTR_SIZE  -- vtable + sync_block

local MONO_MODULE_CANDIDATES = {
    "mono-2.0-bdwgc.dll",
    "mono-2.0-sgen.dll",
    "mono.dll",
}

local UNITY_IMAGE_CANDIDATES = {
    "UnityEngine.CoreModule",
    "UnityEngine.CoreModule.dll",
    "UnityEngine",
    "UnityEngine.dll",
}

local OBSERVE_BATCH_SIZE = 2000

-- m_CachedPtr is the first field on UnityEngine.Object, right after the
-- MonoObject header.
local CACHED_PTR_OFFSET = MONO_HEADER_SIZE

-- localToWorldMatrix offset varies by Unity version; probe these candidates.
local NATIVE_TRANSFORM_MATRIX_OFFSETS = { 0x38, 0x3C, 0x44, 0x48, 0x60, 0x90 }

-- Column-major 4x4: translation = last column, forward = Z basis, up = Y basis.
local MATRIX_POS_X = 12 * 4
local MATRIX_POS_Y = 13 * 4
local MATRIX_POS_Z = 14 * 4

local MATRIX_FWD_X = 8 * 4
local MATRIX_FWD_Y = 9 * 4
local MATRIX_FWD_Z = 10 * 4

local MATRIX_UP_X = 4 * 4
local MATRIX_UP_Y = 5 * 4
local MATRIX_UP_Z = 6 * 4

local mono_dll = nil
local api = {}

local function resolve_mono_module()
    for _, candidate in ipairs(MONO_MODULE_CANDIDATES) do
        local mod = process.find_module(candidate)
        if mod then
            mono_dll = candidate
            return true
        end
    end
    return false, "Mono runtime DLL not found"
end

local function resolve_api()
    local resolve_count = 0
    local fail_count = 0

    local function r(name)
        local fok, faddr = pcall(process.find_export, mono_dll, name)
        if not fok or not faddr or faddr == 0 then
            fail_count = fail_count + 1
            return nil
        end
        local ok, addr, err = pcall(native.lookup, mono_dll, name, faddr)
        if not ok then
            log("Mono:   " .. name .. " -> crashed: " .. tostring(addr))
            fail_count = fail_count + 1
            return nil
        end
        if err then
            log("Mono:   " .. name .. " -> " .. tostring(err))
            fail_count = fail_count + 1
            return nil
        end
        if not addr or addr == 0 then
            fail_count = fail_count + 1
            return nil
        end
        resolve_count = resolve_count + 1
        return addr
    end

    api.get_root_domain            = r("mono_get_root_domain")
    -- mono_thread_attach not whitelisted (would freeze Mono shutdown).
    api.image_loaded               = r("mono_image_loaded")
    api.class_from_name            = r("mono_class_from_name")
    api.class_get_method_from_name = r("mono_class_get_method_from_name")
    api.class_get_property_from_name = r("mono_class_get_property_from_name")
    api.property_get_get_method    = r("mono_property_get_get_method")
    api.class_get_field_from_name  = r("mono_class_get_field_from_name")
    api.field_get_offset           = r("mono_field_get_offset")
    -- mono_string_to_utf8 not whitelisted (leaks without mono_free).
    api.object_unbox               = r("mono_object_unbox")
    -- mono_compile_method no longer on the allowlist. Icall addresses
    -- are resolved by Hs.mono.call in privileged C; bridge code never
    -- sees them. The previous "needed for JIT stub discovery" guard
    -- was vestigial (no code actually called compile_method).

    log("Mono: API -- " .. resolve_count .. " resolved, " .. fail_count .. " failed")

    if not api.get_root_domain then
        return false, mono_dll .. " exports not found"
    end
    return true
end

local function ncall0(addr, ret)
    if not addr then return nil end
    return (native.call(addr, ret, {}, {}))
end

local function ncall1p(addr, ret, a1)
    if not addr then return nil end
    return (native.call(addr, ret, {"pointer"}, {a1}))
end

local mono_methods = {}

local function attach_thread()
    local domain = ncall0(api.get_root_domain, "pointer")
    if not domain or domain == 0 then
        return false, "mono_get_root_domain returned NULL"
    end
    -- Do NOT call mono_thread_attach: it freezes Mono shutdown waiting for
    -- the agent thread. Read-only metadata works without it.
    return true
end

local function load_unity_image()
    for _, name in ipairs(UNITY_IMAGE_CANDIDATES) do
        local ok, image, err = pcall(native.call, api.image_loaded,
            "pointer", {"cstring"}, {name})
        if ok and not err and image and image ~= 0 then
            return image
        end
    end
    return nil
end

local function class_from_name(image, namespace, name)
    local ok, klass, err = pcall(native.call, api.class_from_name,
        "pointer", {"pointer", "cstring", "cstring"}, {image, namespace, name})
    if not ok or err or not klass or klass == 0 then return nil end
    return klass
end

local function method_from_name(klass, name, argc)
    if not klass or klass == 0 then return nil end
    local ok, method, err = pcall(native.call, api.class_get_method_from_name,
        "pointer", {"pointer", "cstring", "int"}, {klass, name, argc})
    if not ok or err or not method or method == 0 then return nil end
    return method
end

local function getter_method(klass, prop_name)
    if not klass or klass == 0 then return nil end
    local ok, prop, err = pcall(native.call, api.class_get_property_from_name,
        "pointer", {"pointer", "cstring"}, {klass, prop_name})
    if not ok or err or not prop or prop == 0 then return nil end
    local ok2, getter, err2 = pcall(native.call, api.property_get_get_method,
        "pointer", {"pointer"}, {prop})
    if not ok2 or err2 or not getter or getter == 0 then return nil end
    return getter
end

local function resolve_metadata()
    log("Mono: Attaching thread...")
    local ok, err = attach_thread()
    if not ok then return false, err end

    log("Mono: Resolving Unity image...")
    local unity_image = load_unity_image()
    if not unity_image then
        return false, "UnityEngine image not found"
    end
    log("Mono: Unity image = 0x" .. string.format("%X", unity_image))

    local cam_class = class_from_name(unity_image, "UnityEngine", "Camera")
    local comp_class = class_from_name(unity_image, "UnityEngine", "Component")
    local xform_class = class_from_name(unity_image, "UnityEngine", "Transform")

    if not cam_class then return false, "Camera class not found" end
    if not comp_class then return false, "Component class not found" end
    if not xform_class then return false, "Transform class not found" end

    -- MonoMethod* pointers; icall address is later read at +0x28.
    mono_methods.camera_get_main = method_from_name(cam_class, "get_main", 0)
    mono_methods.get_transform = getter_method(comp_class, "transform")
    -- _Injected variants are the out-param icalls the property getters wrap;
    -- using them directly lets us whitelist a single icall address.
    mono_methods.get_position_injected = method_from_name(
        xform_class, "get_position_Injected", 1)
    mono_methods.get_rotation_injected = method_from_name(
        xform_class, "get_rotation_Injected", 1)

    if not mono_methods.camera_get_main then
        return false, "Camera.get_main method not found"
    end
    if not mono_methods.get_transform then
        return false, "Component.transform getter not found"
    end

    mono_methods.scene_get_active_injected = nil
    mono_methods.scene_get_count = nil

    -- Scene-name path. GetNameInternal allocates a managed MonoString and
    -- needs a Mono-attached thread, which we can't do (see attach_thread).
    -- Instead we walk Unity's native SceneManager in UnityPlayer.dll: the
    -- icall stubs encode pointers to a static singleton and offsets into a
    -- C++ Scene struct (MSVC std::string SSO layout for the name). All
    -- offsets are discovered at runtime so this works across Unity versions.
    local scene_mgr = class_from_name(
        unity_image, "UnityEngine.SceneManagement", "SceneManager")
    if scene_mgr then
        mono_methods.scene_get_active_injected = method_from_name(
            scene_mgr, "GetActiveScene_Injected", 1)
        mono_methods.scene_get_count = method_from_name(
            scene_mgr, "get_sceneCount", 0)
    end

    log("Mono: Resolved methods:")
    for name, ptr in pairs(mono_methods) do
        if ptr then
            log("  " .. name .. " = 0x" .. string.format("%X", ptr))
        end
    end

    return true
end

-- Sniff localToWorldMatrix by requiring m[15]==1.0 and plausible translation.

local native_matrix_offset = nil

local function probe_matrix_offset(native_ptr)
    for _, off in ipairs(NATIVE_TRANSFORM_MATRIX_OFFSETS) do
        local m33 = memory.read_f32(native_ptr + off + 15 * 4)
        if m33 and math.abs(m33 - 1.0) < 0.001 then
            local px = memory.read_f32(native_ptr + off + MATRIX_POS_X)
            local py = memory.read_f32(native_ptr + off + MATRIX_POS_Y)
            local pz = memory.read_f32(native_ptr + off + MATRIX_POS_Z)
            if px and py and pz
                and px == px and py == py and pz == pz  -- NaN check
                and math.abs(px) < 1e7 and math.abs(py) < 1e7
                and math.abs(pz) < 1e7 then
                log("Mono: Found transform matrix at native+" ..
                    string.format("0x%X", off))
                return off
            end
        end
    end
    return nil
end

local function read_native_position(native_ptr)
    if not native_ptr or native_ptr == 0 then return nil end
    if not native_matrix_offset then return nil end
    local base = native_ptr + native_matrix_offset
    local x = memory.read_f32(base + MATRIX_POS_X)
    local y = memory.read_f32(base + MATRIX_POS_Y)
    local z = memory.read_f32(base + MATRIX_POS_Z)
    if not x or not y or not z then return nil end
    if x ~= x or y ~= y or z ~= z then return nil end
    return { x = x, y = y, z = z }
end

local function read_native_forward(native_ptr)
    if not native_ptr or native_ptr == 0 then return nil end
    if not native_matrix_offset then return nil end
    local base = native_ptr + native_matrix_offset
    local x = memory.read_f32(base + MATRIX_FWD_X)
    local y = memory.read_f32(base + MATRIX_FWD_Y)
    local z = memory.read_f32(base + MATRIX_FWD_Z)
    if not x or not y or not z then return nil end
    if x ~= x or y ~= y or z ~= z then return nil end
    return { x = x, y = y, z = z }
end

local function read_native_up(native_ptr)
    if not native_ptr or native_ptr == 0 then return nil end
    if not native_matrix_offset then return nil end
    local base = native_ptr + native_matrix_offset
    local x = memory.read_f32(base + MATRIX_UP_X)
    local y = memory.read_f32(base + MATRIX_UP_Y)
    local z = memory.read_f32(base + MATRIX_UP_Z)
    if not x or not y or not z then return nil end
    if x ~= x or y ~= y or z ~= z then return nil end
    return { x = x, y = y, z = z }
end

-- ICALL_OFFSET (MonoMethod+0x28) is used ONLY by the scene-discovery
-- disassembly path below; icall INVOCATION goes through Hs.mono.call
-- which resolves the address in privileged C.

local ICALL_OFFSET = 0x28

-- Hs.mono.call signals errors via (nil, err_string), NOT via Lua error().
-- pcall() returns true even when the helper returned (nil, err), which
-- would let void calls silently fail and let callers read stale buffer
-- contents (Codex post-review finding). Wrap in a Lua error() so a single
-- pcall guard covers BOTH thrown errors AND tuple-style errors.
local function hs_mono_call(class_name, method_name, ret, arg_types, args)
    local v, e = Hs.mono.call(class_name, method_name, ret, arg_types, args)
    if e ~= nil then error(e, 2) end
    return v
end

-- Track which optional methods the bridge would invoke. The Hs.mono.call
-- helper resolves and caches each (class, method) pair on first use; this
-- table is a lightweight availability bitmap so the scene path can short-
-- circuit when GetActiveScene_Injected isn't present on this Unity build.
local hs_available = {
    scene_get_active = false,
}

local function resolve_icalls()
    -- Scene-name icall availability mirrors whether the MonoMethod
    -- pointer was located by resolve_metadata above. The pointer
    -- itself is still needed (by the disassembly walk in
    -- attempt_discovery); Hs.mono.call resolves the icall address
    -- separately on first invocation.
    hs_available.scene_get_active = (mono_methods.scene_get_active_injected ~= nil)
    return true
end

-- Native scene-name discovery.
-- All offsets are runtime-discovered so the same code works across Unity
-- versions. Every memory read is bounds-checked against mapped ranges
-- because the sandbox does NOT catch access violations on Windows -- a
-- stray read crashes the target. Failures degrade to "Unknown" without
-- affecting position/rotation tracking.

-- Scratch buffer for GetActiveScene_Injected's out-param.
local scene_buf = nil

local scene_native = {
    discovery_attempted = false,
    discovery_succeeded = false,

    singleton_static_addr   = nil,
    scene_active_offset     = nil,  -- singleton -> Scene*
    scene_handle_offset     = nil,  -- Scene -> int handle
    scene_name_heap_offset  = nil,  -- Scene -> char* heap
    scene_name_inline_offset = nil, -- Scene -> char[16] inline
    scene_name_length_offset = nil, -- Scene -> size_t length
}

-- Sorted [base, end) ranges covering readable memory; built once.
local mapped_ranges = nil

local function build_mapped_ranges()
    local ranges = {}
    local ok, list = pcall(process.enumerate_ranges, "r--")
    if ok and type(list) == "table" then
        for _, r in ipairs(list) do
            if r.base and r.size and r.size > 0 then
                ranges[#ranges + 1] = { r.base, r.base + r.size }
            end
        end
    end
    table.sort(ranges, function(a, b) return a[1] < b[1] end)
    mapped_ranges = ranges
end

-- True if [addr, addr+size) lies entirely inside one mapped range.
local function addr_safe(addr, size)
    if not mapped_ranges then build_mapped_ranges() end
    if not addr or addr == 0 then return false end
    size = size or 1
    local last = addr + size - 1
    for i = 1, #mapped_ranges do
        local r = mapped_ranges[i]
        if addr >= r[1] and last < r[2] then return true end
        if r[1] > addr then return false end  -- sorted; no later range covers
    end
    return false
end

local function safe_read_u8(addr)
    if not addr_safe(addr, 1) then return nil end
    local ok, v = pcall(memory.read_u8, addr)
    return (ok and v) or nil
end
local function safe_read_s32(addr)
    if not addr_safe(addr, 4) then return nil end
    local ok, v = pcall(memory.read_s32, addr)
    return (ok and v) or nil
end
local function safe_read_pointer(addr)
    if not addr_safe(addr, PTR_SIZE) then return nil end
    local ok, v = pcall(memory.read_pointer, addr)
    return (ok and v) or nil
end
local function safe_read_utf8(addr, len)
    if not addr_safe(addr, len) then return nil end
    local ok, v = pcall(memory.read_utf8, addr, len)
    return (ok and v) or nil
end

local function read_s32_imm(addr)
    local b0 = safe_read_u8(addr)
    local b1 = safe_read_u8(addr + 1)
    local b2 = safe_read_u8(addr + 2)
    local b3 = safe_read_u8(addr + 3)
    if not b0 then return nil end
    local v = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
    if v >= 0x80000000 then v = v - 0x100000000 end
    return v
end

-- Decode `mov r32, [reg + disp8]`. Returns disp8 or nil.
local function decode_mov_r32_disp8(addr)
    local op = safe_read_u8(addr)
    local modrm = safe_read_u8(addr + 1)
    if op == 0x8B and modrm and (modrm >> 6) == 0x01 then
        return safe_read_u8(addr + 2)
    end
    return nil
end

-- Decode `mov r64, [reg + disp8]`. Returns disp8 or nil.
local function decode_mov_r64_disp8(addr)
    local rex = safe_read_u8(addr)
    local op  = safe_read_u8(addr + 1)
    local modrm = safe_read_u8(addr + 2)
    if rex == 0x48 and op == 0x8B and modrm and (modrm >> 6) == 0x01 then
        return safe_read_u8(addr + 3)
    end
    return nil
end

-- Decode `mov r64, [rip + disp32]`. Returns the absolute target.
local function decode_mov_r64_rip(addr)
    local rex   = safe_read_u8(addr)
    local op    = safe_read_u8(addr + 1)
    local modrm = safe_read_u8(addr + 2)
    if rex == 0x48 and op == 0x8B and modrm
        and (modrm >> 6) == 0x00 and (modrm & 0x07) == 0x05 then
        local d = read_s32_imm(addr + 3)
        if d then return addr + 7 + d end
    end
    return nil
end

-- Decode `lea r64, [reg + disp8]`. Returns disp8 or nil.
local function decode_lea_r64_disp8(addr)
    local rex = safe_read_u8(addr)
    local op  = safe_read_u8(addr + 1)
    local modrm = safe_read_u8(addr + 2)
    if rex == 0x48 and op == 0x8D and modrm and (modrm >> 6) == 0x01 then
        return safe_read_u8(addr + 3)
    end
    return nil
end

local function decode_call_rel32(addr)
    if safe_read_u8(addr) ~= 0xE8 then return nil end
    local d = read_s32_imm(addr + 1)
    if not d then return nil end
    return addr + 5 + d
end

-- Pass A: find the SceneManager singleton static address by walking
-- GetActiveScene_Injected. We anchor on this icall rather than
-- get_sceneCount because the latter is NULL on some Unity builds.
local function find_first_call_target(addr, span)
    for off = 0, span do
        local target = decode_call_rel32(addr + off)
        if target then return target end
    end
    return nil
end

local function looks_like_singleton_thunk(addr)
    return safe_read_u8(addr    ) == 0x48 and
           safe_read_u8(addr + 1) == 0x8B and
           safe_read_u8(addr + 2) == 0x05 and
           safe_read_u8(addr + 7) == 0xC3
end

local function scan_for_rip_load_to_pointer(addr, span)
    -- Find `mov r64, [rip+disp32]` whose target dereferences to a non-null
    -- mapped pointer -- the singleton static address.
    for off = 0, span do
        local tgt = decode_mov_r64_rip(addr + off)
        if tgt and addr_safe(tgt, PTR_SIZE) then
            local p = safe_read_pointer(tgt)
            if p and p ~= 0 then return tgt end
        end
    end
    return nil
end

local function discover_singleton_static_addr()
    if not hs_available.scene_get_active then return nil, "no GetActiveScene_Injected" end
    local active_icall = safe_read_pointer(
        mono_methods.scene_get_active_injected + ICALL_OFFSET)
    if not active_icall then
        return nil, "GetActiveScene_Injected icall pointer null/unmapped"
    end

    -- Three strategies for whichever depth Unity's optimizer inlined to:
    --   1. icall -> helper_active -> helper_count leaf (`mov rax,[rip+disp32];ret`)
    --   2. helper_count inlined into helper_active; scan for `mov r64,[rip+disp32]`
    --   3. helper_active inlined into the icall stub; same scan
    local helper_active = find_first_call_target(active_icall, 24)

    if helper_active then
        local helper_count = find_first_call_target(helper_active, 16)
        if helper_count and looks_like_singleton_thunk(helper_count) then
            local disp = read_s32_imm(helper_count + 3)
            if disp then return helper_count + 7 + disp end
        end
        local target = scan_for_rip_load_to_pointer(helper_active, 96)
        if target then return target end
    end

    local target = scan_for_rip_load_to_pointer(active_icall, 64)
    if target then return target end

    return nil, string.format(
        "could not locate singleton-static-address (active_icall=0x%X helper_active=%s)",
        active_icall,
        helper_active and string.format("0x%X", helper_active) or "nil")
end

-- Pass B: extract the scene-handle offset by scanning for the
-- `mov eax, [rax+disp8]` that reads it. Defaults to 0x08, which has
-- held stable across Unity history.
local SCENE_HANDLE_DEFAULT = 0x08

local function discover_handle_offset()
    if not mono_methods.scene_get_active_injected then return SCENE_HANDLE_DEFAULT end
    local active_icall = safe_read_pointer(
        mono_methods.scene_get_active_injected + ICALL_OFFSET)
    if not active_icall then return SCENE_HANDLE_DEFAULT end

    -- The `mov eax,[rax+disp8]` may live in helper_active or be inlined
    -- into the icall stub itself. Try the helper first.
    local function scan_for_disp8(addr, span)
        for off = 0, span do
            local disp = decode_mov_r32_disp8(addr + off)
            if disp and disp > 0 and disp < 0x80 then return disp end
        end
    end

    local helper_active = find_first_call_target(active_icall, 24)
    if helper_active then
        local d = scan_for_disp8(helper_active, 56)
        if d then return d end
    end

    -- Skip 9 bytes of prologue (`push rbx; sub rsp,X; mov rbx,rcx`) so
    -- we don't catch a stack-relative load.
    local d = scan_for_disp8(active_icall + 9, 48)
    if d then return d end

    return SCENE_HANDLE_DEFAULT
end

-- Pass C: invert. The active scene pointer in the singleton is whichever
-- one yields the known handle when offset by handle_offset. Self-validating.
local function find_active_offset(singleton, expected_handle, handle_offset)
    for off = 0x10, 0xF0, 8 do
        local cand = safe_read_pointer(singleton + off)
        if cand and cand ~= 0 then
            local h = safe_read_s32(cand + handle_offset)
            if h == expected_handle then return off, cand end
        end
    end
    return nil
end

-- Pass D: extract scene-name field offsets from GetNameInternal's helper,
-- which does `mov rax,[rax+heap_off]; test; jnz; lea rax,[rcx+inline_off]`.
-- Length sits at inline_off + 0x10 in MSVC's std::string SSO layout.
local NAME_LEN_AFTER_INLINE = 0x10

local function disasm_name_offsets(name_helper)
    local heap_off, inline_off
    for off = 0, 56 do
        if not heap_off then
            heap_off = decode_mov_r64_disp8(name_helper + off)
        end
        if heap_off then
            for off2 = off + 4, math.min(off + 32, 60) do
                local d = decode_lea_r64_disp8(name_helper + off2)
                if d and d ~= heap_off then
                    inline_off = d
                    break
                end
            end
            if inline_off then break end
            heap_off = nil  -- false hit
        end
    end
    return heap_off, inline_off
end

-- Confirm a candidate triple by reading the name and verifying it's
-- printable ASCII whose strlen matches the length field.
local function validate_name_layout(scene_ptr, heap_off, inline_off, len_off)
    local len = safe_read_s32(scene_ptr + len_off)
    if not len or len <= 0 or len > 256 then return nil end

    local heap = safe_read_pointer(scene_ptr + heap_off)
    local source
    if heap and heap ~= 0 then
        source = heap
    else
        if len > 15 then return nil end  -- doesn't fit inline
        source = scene_ptr + inline_off
    end

    local text = safe_read_utf8(source, len)
    if not text or text == "" or #text ~= len then return nil end
    for i = 1, #text do
        local c = string.byte(text, i)
        if c < 0x20 or c >= 0x7F then return nil end
    end
    return text
end

-- Fallback: try every offset triple consistent with MSVC std::string SSO,
-- skipping path-shaped strings (we want the bare scene name).
local function scan_name_offsets(scene_ptr)
    local best
    for inline_off = 0x10, 0xB0, 8 do
        local heap_off = inline_off - 8
        local len_off = inline_off + NAME_LEN_AFTER_INLINE
        local text = validate_name_layout(scene_ptr, heap_off, inline_off, len_off)
        if text and not text:find("[/\\]") and not text:find("%.unity$") then
            if not best or #text < #best.text then
                best = { text = text, heap = heap_off,
                         inline = inline_off, len = len_off }
            end
        end
    end
    return best
end

local function attempt_discovery()
    if scene_native.discovery_attempted then return end
    scene_native.discovery_attempted = true

    if not hs_available.scene_get_active then
        log("Mono: scene discovery skipped (GetActiveScene_Injected not available; " ..
            "Unity 5/2017 pre-_Injected build?)")
        return
    end

    build_mapped_ranges()
    log(string.format("Mono: scene discovery: %d mapped memory ranges",
        mapped_ranges and #mapped_ranges or 0))

    local singleton_static, err = discover_singleton_static_addr()
    if not singleton_static then
        log("Mono: scene discovery aborted: " .. tostring(err))
        return
    end
    scene_native.singleton_static_addr = singleton_static
    log(string.format("Mono: scene discovery: singleton_static=0x%X",
        singleton_static))

    scene_native.scene_handle_offset = discover_handle_offset()
    log(string.format("Mono: scene discovery: scene_handle_offset=0x%X (default 0x%X)",
        scene_native.scene_handle_offset, SCENE_HANDLE_DEFAULT))

    -- Need a live handle to drive Pass C and name-offset validation.
    if not scene_buf then scene_buf = memory.alloc(16) end
    pcall(hs_mono_call,
        "UnityEngine.SceneManagement.SceneManager", "GetActiveScene_Injected",
        "void", {"pointer"}, {scene_buf})
    local probe_handle = memory.read_s32(scene_buf)
    if not probe_handle or probe_handle == 0 then
        log("Mono: scene discovery: GetActiveScene_Injected returned handle=0; " ..
            "deferring name-offset discovery until a real scene is loaded")
        return
    end

    local singleton = safe_read_pointer(singleton_static)
    if not singleton then
        log("Mono: scene discovery: singleton pointer @ static address is null/unmapped")
        return
    end

    local active_off, active_scene = find_active_offset(
        singleton, probe_handle, scene_native.scene_handle_offset)
    if not active_off then
        log(string.format("Mono: scene discovery: handle %d not found in singleton " ..
            "(0x10..0xF0 by 8); active-scene offset not discovered",
            probe_handle))
        return
    end
    scene_native.scene_active_offset = active_off
    log(string.format("Mono: scene discovery: scene_active_offset=0x%X (active_scene=0x%X handle=%d)",
        active_off, active_scene, probe_handle))

    -- Pass D: disasm the name helper (or the icall stub if inlined),
    -- then bounded scan as final fallback.
    local function try_disasm_name(addr)
        local h, i = disasm_name_offsets(addr)
        if h and i then
            local l = i + NAME_LEN_AFTER_INLINE
            local text = validate_name_layout(active_scene, h, i, l)
            if text then return h, i, l, text end
        end
    end

    if mono_methods.scene_get_name_internal then
        local name_icall = safe_read_pointer(
            mono_methods.scene_get_name_internal + ICALL_OFFSET)
        if name_icall then
            local heap_off, inline_off, len_off, text

            local helper1 = find_first_call_target(name_icall, 24)
            if helper1 then
                heap_off, inline_off, len_off, text = try_disasm_name(helper1)
            end

            -- Fallback: helper1 was inlined into the icall stub.
            if not heap_off then
                heap_off, inline_off, len_off, text = try_disasm_name(name_icall)
            end

            if heap_off then
                scene_native.scene_name_heap_offset = heap_off
                scene_native.scene_name_inline_offset = inline_off
                scene_native.scene_name_length_offset = len_off
                log(string.format("Mono: scene discovery: name offsets via " ..
                    "disasm: heap=0x%X inline=0x%X len=0x%X (validated name=%q)",
                    heap_off, inline_off, len_off, text))
            end
        end
    end

    if not scene_native.scene_name_heap_offset then
        local found = scan_name_offsets(active_scene)
        if found then
            scene_native.scene_name_heap_offset = found.heap
            scene_native.scene_name_inline_offset = found.inline
            scene_native.scene_name_length_offset = found.len
            log(string.format("Mono: scene discovery: name offsets via scan: " ..
                "heap=0x%X inline=0x%X len=0x%X (validated name=%q)",
                found.heap, found.inline, found.len, found.text))
        else
            log("Mono: scene discovery: name offsets not discoverable on this Unity build; " ..
                "scene tracking unavailable but pos/rot tracking unaffected")
            return
        end
    end

    scene_native.discovery_succeeded = true
end

local captured = {
    camera_ptr = nil,
    transform_ptr = nil,
    native_transform = nil,
}

local scene_cache = {
    -- Sticky last-known-good so transient read failures (e.g. mid-scene-
    -- load) don't flash the GameStore level back to default.
    last_good_name = "Unknown",
    last_good_handle = nil,

    -- Log gate: one success-log and one failure-log per handle transition.
    last_logged_handle = nil,
}

local function read_scene_name()
    if not hs_available.scene_get_active then return scene_cache.last_good_name end

    -- Step 1: live handle. GetActiveScene_Injected writes only an int
    -- (no managed allocation), so it's safe without Mono thread context.
    if not scene_buf then scene_buf = memory.alloc(16) end
    local ok = pcall(hs_mono_call,
        "UnityEngine.SceneManagement.SceneManager", "GetActiveScene_Injected",
        "void", {"pointer"}, {scene_buf})
    if not ok then return scene_cache.last_good_name end
    local icall_handle = memory.read_s32(scene_buf)
    if not icall_handle or icall_handle == 0 then
        return scene_cache.last_good_name
    end

    -- Idempotent; safe every tick.
    attempt_discovery()
    if not scene_native.discovery_succeeded then
        return scene_cache.last_good_name
    end

    -- Step 2: walk singleton -> active Scene*.
    local singleton = safe_read_pointer(scene_native.singleton_static_addr)
    if not singleton then return scene_cache.last_good_name end

    local active_scene = safe_read_pointer(
        singleton + scene_native.scene_active_offset)
    if not active_scene then return scene_cache.last_good_name end

    -- Step 3: cross-check the C++ struct's handle against the icall's.
    -- A mismatch means our discovered layout no longer applies; bail out.
    local struct_handle = safe_read_s32(
        active_scene + scene_native.scene_handle_offset)
    if struct_handle ~= icall_handle then
        if scene_cache.last_logged_handle ~= icall_handle then
            scene_cache.last_logged_handle = icall_handle
            log(string.format("Mono: scene handle mismatch -- icall=%d struct=%s; " ..
                "scene tracking paused for this scene (pos/rot unaffected)",
                icall_handle, tostring(struct_handle)))
        end
        return scene_cache.last_good_name
    end

    local name = validate_name_layout(active_scene,
        scene_native.scene_name_heap_offset,
        scene_native.scene_name_inline_offset,
        scene_native.scene_name_length_offset)

    if name then
        if scene_cache.last_logged_handle ~= icall_handle then
            scene_cache.last_logged_handle = icall_handle
            log(string.format("Mono: scene name read OK -- handle=%d name=%q",
                icall_handle, name))
        end
        scene_cache.last_good_name = name
        scene_cache.last_good_handle = icall_handle
    elseif scene_cache.last_good_handle ~= icall_handle then
        -- Handle changed but new name not yet readable (scene mid-load).
        -- Drop the cached name so we don't keep emitting the old level.
        scene_cache.last_good_name = "Unknown"
        scene_cache.last_good_handle = icall_handle
    end
    return scene_cache.last_good_name
end

local vec3_buf = nil
local quat_buf = nil

local function read_frame()
    local ok, cam_ptr = pcall(hs_mono_call,
        "UnityEngine.Camera", "get_main",
        "pointer", {}, {})
    if not ok or not cam_ptr or cam_ptr == 0 then return nil end

    local tok, tf_ptr = pcall(hs_mono_call,
        "UnityEngine.Component", "get_transform",
        "pointer", {"pointer"}, {cam_ptr})
    if not tok or not tf_ptr or tf_ptr == 0 then return nil end

    local pos = nil
    do
        if not vec3_buf then vec3_buf = memory.alloc(16) end
        local pok = pcall(hs_mono_call,
            "UnityEngine.Transform", "get_position_Injected",
            "void", {"pointer", "pointer"}, {tf_ptr, vec3_buf})
        if pok then
            local x = memory.read_f32(vec3_buf)
            local y = memory.read_f32(vec3_buf + 4)
            local z = memory.read_f32(vec3_buf + 8)
            if x and y and z and x == x then
                pos = { x = x, y = y, z = z }
            end
        end
    end

    if not pos then
        local native_tf = memory.read_pointer(tf_ptr + CACHED_PTR_OFFSET)
        if native_tf and native_tf ~= 0 then
            if not native_matrix_offset then
                native_matrix_offset = probe_matrix_offset(native_tf)
            end
            pos = read_native_position(native_tf)
        end
    end
    if not pos then return nil end

    local fwd, up = nil, nil
    do
        if not quat_buf then quat_buf = memory.alloc(16) end
        local rok = pcall(hs_mono_call,
            "UnityEngine.Transform", "get_rotation_Injected",
            "void", {"pointer", "pointer"}, {tf_ptr, quat_buf})
        if rok then
            local qx = memory.read_f32(quat_buf)
            local qy = memory.read_f32(quat_buf + 4)
            local qz = memory.read_f32(quat_buf + 8)
            local qw = memory.read_f32(quat_buf + 12)
            if qx and qy and qz and qw then
                fwd = {
                    x = 2 * (qx * qz + qw * qy),
                    y = 2 * (qy * qz - qw * qx),
                    z = 1 - 2 * (qx * qx + qy * qy),
                }
                up = {
                    x = 2 * (qx * qy - qw * qz),
                    y = 1 - 2 * (qx * qx + qz * qz),
                    z = 2 * (qy * qz + qw * qx),
                }
            end
        end
    end

    if not fwd or not up then
        local native_tf = memory.read_pointer(tf_ptr + CACHED_PTR_OFFSET)
        if native_tf and native_tf ~= 0 and native_matrix_offset then
            fwd = fwd or read_native_forward(native_tf)
            up = up or read_native_up(native_tf)
        end
    end

    local scene_name = read_scene_name()

    return {
        type = "data",
        protocol = "unity_mono_tracker",
        posX = pos.x,
        posY = pos.y,
        posZ = pos.z,
        fwdX = fwd and fwd.x or 0,
        fwdY = fwd and fwd.y or 0,
        fwdZ = fwd and fwd.z or 0,
        upX = up and up.x or 0,
        upY = up and up.y or 1,
        upZ = up and up.z or 0,
        sceneName = scene_name,
        sceneIndex = -1,
        timestamp = clock() * 1000,
    }
end

local state = {
    initialized = false,
    consecutive_errors = 0,
    warmup_ticks = 0,
    -- Position loss is never fatal; engine detects process exit and the
    -- host script owns the searching-for-player UI.
    WARMUP_TICKS = 5,
}

local function handle_init()
    log("Mono Tracker (Lua): Initializing...")

    send({ type = "progress", message = "Finding Mono runtime...", percent = 5 })
    local ok, err = resolve_mono_module()
    if not ok then
        send({ type = "init-response", success = false, error = tostring(err) })
        return
    end
    log("Mono: Found " .. mono_dll)

    send({ type = "progress", message = "Resolving Mono API...", percent = 15 })
    ok, err = resolve_api()
    if not ok then
        send({ type = "init-response", success = false, error = tostring(err) })
        return
    end

    send({ type = "progress", message = "Resolving Unity metadata...", percent = 30 })
    ok, err = resolve_metadata()
    if not ok then
        send({ type = "init-response", success = false, error = tostring(err) })
        return
    end

    send({ type = "progress", message = "Resolving icalls...", percent = 60 })
    ok = resolve_icalls()
    if not ok then
        send({ type = "init-response", success = false,
            error = "Failed to resolve icall addresses" })
        return
    end

    state.initialized = true
    state.consecutive_errors = 0
    state.warmup_ticks = 0

    send({ type = "progress", message = "Waiting for game data...", percent = 80 })
    send({ type = "init-response", success = true })

    log("==============================================")
    log("  Unity Mono Tracker - Lua (Read-Only)")
    log("  Pointer size:    " .. PTR_SIZE .. " bytes")
    log("  Mono DLL:        " .. mono_dll)
    log("  Camera.get_main: 0x" .. string.format("%X",
        mono_methods.camera_get_main))
    log("  get_transform:   0x" .. string.format("%X",
        mono_methods.get_transform))
    log("  Scene tracking:  " .. (hs_available.scene_get_active
        and "available" or "unavailable"))
    log("==============================================")
end

local function handle_tick()
    if not state.initialized then
        send({ type = "heartbeat", status = "not-initialized" })
        return
    end

    local ok, result = pcall(read_frame)

    if not ok then
        state.consecutive_errors = state.consecutive_errors + 1
        if state.consecutive_errors <= 3 or state.consecutive_errors % 200 == 0 then
            log("Mono: tick error #" .. state.consecutive_errors ..
                ": " .. tostring(result))
        end
    elseif type(result) == "table" then
        send(result)
        state.consecutive_errors = 0
        state.warmup_ticks = state.WARMUP_TICKS
        return
    else
        state.warmup_ticks = state.warmup_ticks + 1
        if state.warmup_ticks <= state.WARMUP_TICKS then
            send({ type = "heartbeat", status = "warming-up",
                ticks = state.warmup_ticks })
            return
        end
        state.consecutive_errors = state.consecutive_errors + 1
    end

    send({ type = "heartbeat", status = "no-position",
        errors = state.consecutive_errors })
end

send({ type = "heartbeat", status = "loading" })

log("==============================================")
log("  Unity Mono Tracker - Lua (Read-Only)")
log("  Pointer size: " .. PTR_SIZE .. " bytes")
log("==============================================")

send({ type = "heartbeat", status = "ready" })

local function parse_message(message)
    if type(message) == "string" then
        if type(json) == "table" and type(json.decode) == "function" then
            local ok, decoded = pcall(json.decode, message)
            if ok and type(decoded) == "table" then
                return decoded
            end
        end
        if message:find('"type"%s*:%s*"init"')     then return { type = "init" } end
        if message:find('"type"%s*:%s*"tick"')     then return { type = "tick" } end
        if message:find('"type"%s*:%s*"shutdown"') then return { type = "shutdown" } end
        return nil
    end
    if type(message) == "table" then return message end
    return nil
end

recv(function(message)
    local msg = parse_message(message)
    if not msg or not msg.type then return end

    local ok, err = pcall(function()
        if msg.type == "init" then
            handle_init()
        elseif msg.type == "tick" then
            handle_tick()
        elseif msg.type == "shutdown" then
            log("Mono Tracker (Lua): Shutdown")
            state.initialized = false
            for _, obs in pairs(observers) do
                pcall(function() obs:detach() end)
            end
            observers = {}
        end
    end)

    if not ok then
        log("Mono handler crash: " .. tostring(err))
        if msg.type == "init" then
            send({ type = "init-response", success = false,
                error = tostring(err) })
        end
    end
end)
