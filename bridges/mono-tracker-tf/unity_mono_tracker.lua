-- unity_mono_tracker.lua -- Unity Mono Camera Tracker for Frida Lua
--
-- Compliant with flat read-only security model. Does NOT call
-- mono_runtime_invoke (excluded from whitelist). Instead:
-- 1. Resolves Mono metadata via whitelisted API exports
-- 2. Uses mono_compile_method to get JIT-compiled native code addresses
-- 3. Observes JIT stubs via native.observe to passively capture
--    Camera* and Transform* instance pointers from game thread calls
-- 4. Reads position/rotation from native C++ Transform via memory.read_*

local PTR_SIZE = process.get_pointer_size()
local MONO_HEADER_SIZE = 2 * PTR_SIZE  -- vtable + sync_block

-- ============================================================================
-- SECTION 1: CONSTANTS
-- ============================================================================

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

-- Observer captures this many mono_runtime_invoke calls per batch.
-- Ring buffer is 64 entries, so we only see the last 64 anyway.
local OBSERVE_BATCH_SIZE = 2000

-- Unity native object layout constants (64-bit):
-- MonoObject header = 16 bytes (vtable + sync). Fields follow.
-- UnityEngine.Object has m_CachedPtr as its first field (at offset 0x10).
-- m_CachedPtr points to the native C++ object.
local CACHED_PTR_OFFSET = MONO_HEADER_SIZE  -- 0x10 on 64-bit

-- Native C++ Transform matrix layout (Unity 2017+, 64-bit):
-- Position can be read from the localToWorldMatrix translation column.
-- The matrix pointer is at a version-dependent offset from the native Transform.
-- We probe multiple candidate offsets.
local NATIVE_TRANSFORM_MATRIX_OFFSETS = { 0x38, 0x3C, 0x44, 0x48, 0x60, 0x90 }

-- localToWorldMatrix is a column-major 4x4 float matrix.
-- Translation = last column: m[12]=x, m[13]=y, m[14]=z
local MATRIX_POS_X = 12 * 4  -- 48
local MATRIX_POS_Y = 13 * 4  -- 52
local MATRIX_POS_Z = 14 * 4  -- 56

-- Forward vector from matrix: third column (Z basis): m[8], m[9], m[10]
local MATRIX_FWD_X = 8 * 4   -- 32
local MATRIX_FWD_Y = 9 * 4   -- 36
local MATRIX_FWD_Z = 10 * 4  -- 40

-- ============================================================================
-- SECTION 2: MONO API RESOLUTION
-- ============================================================================

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
    -- thread_attach removed from whitelist (freezes Mono shutdown)
    api.image_loaded               = r("mono_image_loaded")
    api.class_from_name            = r("mono_class_from_name")
    api.class_get_method_from_name = r("mono_class_get_method_from_name")
    api.class_get_property_from_name = r("mono_class_get_property_from_name")
    api.property_get_get_method    = r("mono_property_get_get_method")
    api.class_get_field_from_name  = r("mono_class_get_field_from_name")
    api.field_get_offset           = r("mono_field_get_offset")
    -- string_to_utf8 removed (leaks without mono_free). Read UTF-16 directly.
    api.object_unbox               = r("mono_object_unbox")
    api.compile_method             = r("mono_compile_method")

    log("Mono: API -- " .. resolve_count .. " resolved, " .. fail_count .. " failed")

    if not api.get_root_domain then
        return false, mono_dll .. " exports not found"
    end
    if not api.compile_method then
        return false, "mono_compile_method not found (needed for JIT stub discovery)"
    end
    return true
end

-- ============================================================================
-- SECTION 3: NATIVE CALL HELPERS
-- ============================================================================

local function ncall0(addr, ret)
    if not addr then return nil end
    return (native.call(addr, ret, {}, {}))
end

local function ncall1p(addr, ret, a1)
    if not addr then return nil end
    return (native.call(addr, ret, {"pointer"}, {a1}))
end

-- ============================================================================
-- SECTION 4: MONO METADATA RESOLUTION
-- ============================================================================

local mono_methods = {}

local function attach_thread()
    local domain = ncall0(api.get_root_domain, "pointer")
    if not domain or domain == 0 then
        return false, "mono_get_root_domain returned NULL"
    end
    -- NOTE: mono_thread_attach deliberately NOT called.
    -- It freezes Mono's shutdown (waits for Frida agent thread forever).
    -- Metadata APIs work without attach for read-only queries.
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

    -- Resolve classes
    local cam_class = class_from_name(unity_image, "UnityEngine", "Camera")
    local comp_class = class_from_name(unity_image, "UnityEngine", "Component")
    local xform_class = class_from_name(unity_image, "UnityEngine", "Transform")

    if not cam_class then return false, "Camera class not found" end
    if not comp_class then return false, "Component class not found" end
    if not xform_class then return false, "Transform class not found" end

    -- Resolve MonoMethod* pointers — needed to read icall addresses at +0x28
    mono_methods.camera_get_main = method_from_name(cam_class, "get_main", 0)
    mono_methods.get_transform = getter_method(comp_class, "transform")
    -- The _Injected methods are separate from the property getters.
    -- Property getter (get_position) wraps the _Injected call internally.
    -- We need the _Injected method directly for its icall address.
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

    -- Scene management (optional)
    mono_methods.scene_get_active = nil
    mono_methods.scene_get_name = nil

    local scene_mgr = class_from_name(
        unity_image, "UnityEngine.SceneManagement", "SceneManager")
    if scene_mgr then
        mono_methods.scene_get_active = method_from_name(
            scene_mgr, "GetActiveScene", 0)
        local scene_class = class_from_name(
            unity_image, "UnityEngine.SceneManagement", "Scene")
        if scene_class then
            mono_methods.scene_get_name = getter_method(scene_class, "name")
        end
    end

    log("Mono: Resolved methods:")
    for name, ptr in pairs(mono_methods) do
        if ptr then
            log("  " .. name .. " = 0x" .. string.format("%X", ptr))
        end
    end

    return true
end

-- ============================================================================
-- SECTION 5: NATIVE TRANSFORM POSITION READING
-- ============================================================================
-- Unity managed Components store a pointer to the native C++ object at
-- m_CachedPtr (offset MONO_HEADER_SIZE from the managed object base).
-- The native C++ Transform stores a localToWorldMatrix (4x4 column-major
-- float matrix). We probe candidate offsets to find the matrix.

local native_matrix_offset = nil  -- discovered offset, cached

local function probe_matrix_offset(native_ptr)
    -- Read each candidate offset and check if it looks like a valid matrix.
    -- A valid transform matrix has [3][3]=1.0 (w component of last row)
    -- and position values are finite.
    for _, off in ipairs(NATIVE_TRANSFORM_MATRIX_OFFSETS) do
        local m33 = memory.read_f32(native_ptr + off + 15 * 4)  -- matrix[15]
        if m33 and math.abs(m33 - 1.0) < 0.001 then
            -- Check that position values are finite and reasonable
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
    if x ~= x or y ~= y or z ~= z then return nil end  -- NaN check
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

-- ============================================================================
-- SECTION 6: ICALL RESOLUTION + WHITELISTING
-- ============================================================================
-- Unity Mono icalls are native C++ implementations in UnityPlayer.dll.
-- The icall address is stored at MonoMethod+0x28. We whitelist them via
-- native.lookup with icall names (same approach as IL2CPP tracker).
-- This lets us CALL the icalls directly — no observer needed.

local ICALL_OFFSET = 0x28  -- MonoMethod -> native icall pointer (Mono 5.x/6.x)

local icalls = {}

local function resolve_icall(display_name, icall_name, mono_method)
    if not mono_method or mono_method == 0 then return nil end
    local addr = memory.read_pointer(mono_method + ICALL_OFFSET)
    if not addr or addr == 0 then
        log("Mono: icall addr nil for " .. display_name)
        return nil
    end
    -- Whitelist via native.lookup (icall path — name contains ::)
    local ok, resolved, err = pcall(native.lookup, mono_dll, icall_name, addr)
    if not ok or err then
        log("Mono: whitelist failed for " .. display_name .. ": " .. tostring(err or resolved))
        return nil
    end
    log("Mono: icall " .. display_name .. " = 0x" .. string.format("%X", resolved))
    return resolved
end

local function resolve_icalls()
    icalls.camera_get_main = resolve_icall(
        "Camera.get_main",
        "UnityEngine.Camera::get_main()",
        mono_methods.camera_get_main)

    icalls.get_transform = resolve_icall(
        "get_transform",
        "UnityEngine.Component::get_transform()",
        mono_methods.get_transform)

    if mono_methods.get_position_injected then
        icalls.get_position = resolve_icall(
            "get_position_Injected",
            "UnityEngine.Transform::get_position_Injected(UnityEngine.Vector3&)",
            mono_methods.get_position_injected)
    end

    if mono_methods.get_rotation_injected then
        icalls.get_rotation = resolve_icall(
            "get_rotation_Injected",
            "UnityEngine.Transform::get_rotation_Injected(UnityEngine.Quaternion&)",
            mono_methods.get_rotation_injected)
    end

    return icalls.camera_get_main ~= nil
end

-- ============================================================================
-- SECTION 7: CAPTURED STATE & DATA READING
-- ============================================================================

local captured = {
    camera_ptr = nil,
    transform_ptr = nil,
    native_transform = nil,
    scene_name_obj = nil,
}

local scene_cache = { name = "Unknown" }

-- No observer processing needed — we call icalls directly now.

local function read_scene_name()
    if not captured.scene_name_obj or captured.scene_name_obj == 0 then
        return scene_cache.name
    end
    -- Read Mono string directly from memory instead of mono_string_to_utf8
    -- (which allocates and leaks without mono_free).
    -- Mono string layout (64-bit): length at +0x10, UTF-16 chars at +0x14
    local ok, len = pcall(memory.read_s32, captured.scene_name_obj + 0x10)
    if not ok or not len or len <= 0 or len > 256 then
        return scene_cache.name
    end
    local ok2, text = pcall(memory.read_utf16, captured.scene_name_obj + 0x14, len)
    if ok2 and text and text ~= "" then
        scene_cache.name = text
    end
    return scene_cache.name
end

-- Convert forward vector to euler angles (degrees, Unity convention)
local function forward_to_euler(fwd)
    if not fwd then return nil end
    local len = math.sqrt(fwd.x * fwd.x + fwd.y * fwd.y + fwd.z * fwd.z)
    if len < 0.001 then return nil end
    local fx = fwd.x / len
    local fy = fwd.y / len
    local fz = fwd.z / len
    -- Unity convention: Y-up, forward = +Z
    -- pitch = asin(fy), yaw = atan2(fx, fz)
    local pitch = math.deg(math.asin(math.max(-1, math.min(1, fy))))
    local yaw = math.deg(math.atan(fx, fz))
    -- Normalize to [0, 360)
    if pitch < 0 then pitch = pitch + 360 end
    if yaw < 0 then yaw = yaw + 360 end
    return { x = pitch, y = yaw, z = 0 }
end

local vec3_buf = nil
local quat_buf = nil

local function read_frame()
    -- Call Camera.get_main() -> Camera*
    if not icalls.camera_get_main then return nil end
    local ok, cam_ptr = pcall(native.call, icalls.camera_get_main, "pointer", {}, {})
    if not ok or not cam_ptr or cam_ptr == 0 then return nil end

    -- Call get_transform(camera) -> Transform*
    if not icalls.get_transform then return nil end
    local tok, tf_ptr = pcall(native.call, icalls.get_transform, "pointer",
        {"pointer"}, {cam_ptr})
    if not tok or not tf_ptr or tf_ptr == 0 then return nil end

    -- Read position via _Injected icall (writes to our buffer) or matrix fallback
    local pos = nil
    if icalls.get_position then
        if not vec3_buf then vec3_buf = memory.alloc(16) end
        local pok = pcall(native.call, icalls.get_position, "void",
            {"pointer", "pointer"}, {tf_ptr, vec3_buf})
        if pok then
            local x = memory.read_f32(vec3_buf)
            local y = memory.read_f32(vec3_buf + 4)
            local z = memory.read_f32(vec3_buf + 8)
            if x and y and z and x == x then
                pos = { x = x, y = y, z = z }
            end
        end
    end

    -- Fallback: read from native transform matrix
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

    -- Read forward from rotation or matrix
    local fwd = nil
    if icalls.get_rotation then
        if not quat_buf then quat_buf = memory.alloc(16) end
        local rok = pcall(native.call, icalls.get_rotation, "void",
            {"pointer", "pointer"}, {tf_ptr, quat_buf})
        if rok then
            local qx = memory.read_f32(quat_buf)
            local qy = memory.read_f32(quat_buf + 4)
            local qz = memory.read_f32(quat_buf + 8)
            local qw = memory.read_f32(quat_buf + 12)
            if qx and qy and qz and qw then
                -- Quaternion to forward vector
                fwd = {
                    x = 2 * (qx * qz + qw * qy),
                    y = 2 * (qy * qz - qw * qx),
                    z = 1 - 2 * (qx * qx + qy * qy),
                }
            end
        end
    end

    -- Fallback: read forward from matrix
    if not fwd then
        local native_tf = memory.read_pointer(tf_ptr + CACHED_PTR_OFFSET)
        if native_tf and native_tf ~= 0 and native_matrix_offset then
            fwd = read_native_forward(native_tf)
        end
    end

    local euler = forward_to_euler(fwd)

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
        eulerX = euler and euler.x or nil,
        eulerY = euler and euler.y or nil,
        eulerZ = euler and euler.z or nil,
        sceneName = scene_name,
        sceneIndex = -1,
        timestamp = clock() * 1000,
    }
end

-- ============================================================================
-- SECTION 8: MESSAGE HANDLER
-- ============================================================================

local state = {
    initialized = false,
    consecutive_errors = 0,
    warmup_ticks = 0,
    -- No fatal-error on position loss. Process exit is detected by the
    -- engine; the bridge host script handles the searching-for-player UI.
    WARMUP_TICKS = 5,  -- brief warmup for icall thread attachment
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
    log("  Scene APIs:      " .. (mono_methods.scene_get_active
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

    -- Send heartbeat so the host knows we're alive but have no position.
    -- No fatal-error: the engine detects process exit; we just keep trying.
    send({ type = "heartbeat", status = "no-position",
        errors = state.consecutive_errors })
end

-- ============================================================================
-- SECTION 9: BOOT & RECV HANDLER
-- ============================================================================

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
