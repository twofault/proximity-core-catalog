-- unity_il2cpp_tracker.lua -- Unity IL2CPP Camera Tracker for GameLink Lua
--
-- Based on the frida-il2cpp-bridge project, but runs via GameLink.
-- Uses IL2CPP C API (whitelisted) for metadata discovery, then
-- il2cpp_resolve_icall + native.lookup() to call Unity internal methods
-- (Camera::get_main, Component::get_transform, Transform::get_position, etc.)
--
-- Preamble auto-injects: json, Pointer, Vec3, Struct, Module, clock(), sendTagged()

-- ============================================================================
-- SECTION 1: CONSTANTS
-- ============================================================================

local PTR_SIZE = process.get_pointer_size()

-- ============================================================================
-- SECTION 2: IL2CPP API RESOLUTION
-- ============================================================================

local api = {}

local function resolve_api()
    local dll = "GameAssembly.dll"
    local resolve_count = 0
    local fail_count = 0

    -- Two-step resolution for pre-whitelisted IL2CPP API functions:
    -- 1. process.find_export resolves the address (fast, doesn't hang)
    -- 2. native.lookup(dll, name, addr) validates against the compiled-in
    --    allowlist and adds to the runtime whitelist (no re-resolution needed)
    --
    -- For runtime-discovered addresses (icalls), use native.lookup with icall name.
    local function r(name)
        -- Step 1: fast address lookup
        local fok, faddr = pcall(process.find_export, dll, name)
        if not fok or not faddr or faddr == 0 then
            fail_count = fail_count + 1
            return nil
        end
        -- Step 2: validate against allowlist + whitelist the address
        local ok, addr, err = pcall(native.lookup, dll, name, faddr)
        if not ok then
            log("IL2CPP:   " .. name .. " -> resolve crashed: " .. tostring(addr))
            fail_count = fail_count + 1
            return nil
        end
        if err then
            log("IL2CPP:   " .. name .. " -> " .. tostring(err))
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

    -- Domain (thread_attach/detach removed — freezes Unity shutdown)
    api.domain_get              = r("il2cpp_domain_get")
    api.domain_get_assemblies   = r("il2cpp_domain_get_assemblies")

    -- Assembly / image
    api.assembly_get_image      = r("il2cpp_assembly_get_image")
    api.image_get_name          = r("il2cpp_image_get_name")
    api.image_get_class_count   = r("il2cpp_image_get_class_count")
    api.image_get_class         = r("il2cpp_image_get_class")

    -- Class metadata
    api.class_from_name         = r("il2cpp_class_from_name")
    api.class_get_name          = r("il2cpp_class_get_name")
    api.class_get_namespace     = r("il2cpp_class_get_namespace")
    api.class_get_parent        = r("il2cpp_class_get_parent")
    api.class_instance_size     = r("il2cpp_class_instance_size")
    api.class_is_valuetype      = r("il2cpp_class_is_valuetype")
    api.class_get_static_field_data = r("il2cpp_class_get_static_field_data")

    -- Field metadata
    api.class_get_fields        = r("il2cpp_class_get_fields")
    api.class_get_field_from_name = r("il2cpp_class_get_field_from_name")
    api.field_get_name          = r("il2cpp_field_get_name")
    api.field_get_offset        = r("il2cpp_field_get_offset")
    api.field_get_flags         = r("il2cpp_field_get_flags")

    -- Method metadata
    api.class_get_method_from_name = r("il2cpp_class_get_method_from_name")
    api.method_get_name         = r("il2cpp_method_get_name")

    -- String read
    api.string_chars            = r("il2cpp_string_chars")
    api.string_length           = r("il2cpp_string_length")

    -- Object read
    api.object_get_class        = r("il2cpp_object_get_class")

    -- Internal call resolution
    api.resolve_icall           = r("il2cpp_resolve_icall")

    log("IL2CPP: resolve_api done — " .. resolve_count .. " resolved, " .. fail_count .. " failed")

    if not api.domain_get then
        return false, "GameAssembly.dll not loaded or il2cpp_domain_get not found"
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

local function ncall2p(addr, ret, a1, a2)
    if not addr then return nil end
    return (native.call(addr, ret, {"pointer", "pointer"}, {a1, a2}))
end

local function ncall3p(addr, ret, a1, a2, a3)
    if not addr then return nil end
    return (native.call(addr, ret, {"pointer", "pointer", "pointer"}, {a1, a2, a3}))
end

-- Allocate a C-string (cached)
local str_cache = {}
local function cstr(s)
    if str_cache[s] then return str_cache[s] end
    local addr = memory.alloc_utf8(s)
    str_cache[s] = addr
    return addr
end

-- Read a C-string pointer to Lua string
local function read_cstr(ptr)
    if not ptr or ptr == 0 then return nil end
    return memory.read_utf8(ptr, 256)
end

-- Read IL2CPP managed String* to Lua string
local function read_il2cpp_string(str_ptr)
    if not str_ptr or str_ptr == 0 then return nil end
    local len = ncall1p(api.string_length, "int32", str_ptr)
    if not len or len <= 0 then return nil end
    local chars = ncall1p(api.string_chars, "pointer", str_ptr)
    if not chars or chars == 0 then return nil end
    return memory.read_utf16(chars, len)
end

-- ============================================================================
-- SECTION 4: IL2CPP READINESS DETECTION
-- ============================================================================
-- Poll until the IL2CPP runtime is fully initialized.
-- Without this, calling IL2CPP API functions can crash the process.

local function wait_for_il2cpp_ready()
    log("IL2CPP:   find_module GameAssembly.dll")
    local ga = process.find_module("GameAssembly.dll")
    if not ga then
        return false, "GameAssembly.dll not loaded"
    end
    log("IL2CPP:   GameAssembly.dll found at 0x" .. string.format("%X", ga.base))

    log("IL2CPP:   calling il2cpp_domain_get")
    local domain = ncall0(api.domain_get, "pointer")
    if not domain or domain == 0 then
        return false, "il2cpp_domain_get returned NULL (IL2CPP not initialized)"
    end
    log("IL2CPP:   domain = 0x" .. string.format("%X", domain))

    -- NOTE: il2cpp_thread_attach is deliberately NOT called here.
    -- It registers the GameLink agent thread with IL2CPP's thread tracker,
    -- causing Unity's shutdown to wait for it forever.
    -- The metadata APIs we use work without thread attach.

    log("IL2CPP:   calling il2cpp_domain_get_assemblies")
    local size_buf = memory.alloc(PTR_SIZE)
    local arr = ncall2p(api.domain_get_assemblies, "pointer", domain, size_buf)
    local count = memory.read_u32(size_buf)
    memory.free(size_buf)

    if not arr or arr == 0 or not count or count == 0 then
        return false, "No assemblies loaded yet"
    end

    log("IL2CPP: Runtime ready — domain=0x" .. string.format("%X", domain) ..
        " assemblies=" .. count)
    return true, domain
end

-- ============================================================================
-- SECTION 5: IL2CPP METADATA HELPERS
-- ============================================================================

local function get_assemblies(domain)
    local size_buf = memory.alloc(PTR_SIZE)
    local arr = ncall2p(api.domain_get_assemblies, "pointer", domain, size_buf)
    if not arr or arr == 0 then return {} end
    local count = memory.read_u32(size_buf)
    memory.free(size_buf)
    if not count or count <= 0 or count > 2000 then return {} end

    local result = {}
    for i = 0, count - 1 do
        local asm = memory.read_pointer(arr + i * PTR_SIZE)
        if asm and asm ~= 0 then result[#result + 1] = asm end
    end
    return result
end

local function get_image_info(assembly)
    local image = ncall1p(api.assembly_get_image, "pointer", assembly)
    if not image or image == 0 then return nil end
    local name_ptr = ncall1p(api.image_get_name, "pointer", image)
    return image, read_cstr(name_ptr)
end

local function find_class(images, namespace, name)
    local ns = cstr(namespace)
    local nm = cstr(name)
    for _, image in ipairs(images) do
        local klass = ncall3p(api.class_from_name, "pointer", image, ns, nm)
        if klass and klass ~= 0 then return klass end
    end
    return nil
end

local function get_field_offset(klass, name)
    local nm = cstr(name)
    local field = ncall2p(api.class_get_field_from_name, "pointer", klass, nm)
    if not field or field == 0 then return nil end
    return ncall1p(api.field_get_offset, "int32", field)
end

-- ============================================================================
-- SECTION 6: ICALL RESOLUTION + WHITELISTING
-- ============================================================================
-- Resolve Unity internal calls via il2cpp_resolve_icall, then whitelist them
-- using native.lookup(dll, icall_name, addr). The icall names are in the
-- compiled-in allowlist as engine-internal read-only getters.

local icalls = {}
local GAME_DLL = "GameAssembly.dll"

local function resolve_icall(name)
    log("IL2CPP:   resolve_icall: " .. name)

    -- Step 1: Resolve the icall address via il2cpp_resolve_icall
    local ok_call, addr, call_err = pcall(function()
        return native.call(api.resolve_icall, "pointer", {"cstring"}, {name})
    end)
    if not ok_call then
        log("IL2CPP:     resolve_icall CRASHED: " .. tostring(addr))
        return nil
    end
    if call_err then
        log("IL2CPP:     resolve_icall error: " .. tostring(call_err))
        return nil
    end
    if not addr or addr == 0 then
        log("IL2CPP:     not found")
        return nil
    end
    log("IL2CPP:     addr = 0x" .. string.format("%X", addr))

    -- Step 2: Whitelist via native.lookup(dll, icall_name, pre_resolved_addr)
    -- This validates the icall name is in the compiled-in allowlist,
    -- then adds the pre-resolved address to the runtime whitelist.
    local ok_wl, wl_addr, wl_err = pcall(native.lookup, GAME_DLL, name, addr)
    if not ok_wl then
        log("IL2CPP:     whitelist CRASHED: " .. tostring(wl_addr))
        return nil
    end
    if wl_err then
        log("IL2CPP:     whitelist FAILED: " .. tostring(wl_err))
        return nil
    end
    log("IL2CPP:     whitelisted OK")

    return addr
end

-- Try multiple icall name variants (format varies across Unity versions)
local function resolve_icall_variants(variants)
    for _, name in ipairs(variants) do
        local addr = resolve_icall(name)
        if addr then return addr end
    end
    return nil
end

local function resolve_all_icalls()
    -- Camera.get_main — static, returns Camera*
    icalls.camera_get_main = resolve_icall_variants({
        "UnityEngine.Camera::get_main()",
        "UnityEngine.Camera::get_main",
    })

    -- Component.get_transform — instance, returns Transform*
    icalls.get_transform = resolve_icall_variants({
        "UnityEngine.Component::get_transform()",
        "UnityEngine.Component::get_transform",
    })

    -- Transform.get_position_Injected — writes Vector3 to output buffer
    icalls.get_position = resolve_icall_variants({
        "UnityEngine.Transform::get_position_Injected(UnityEngine.Vector3&)",
        "UnityEngine.Transform::get_position_Injected",
        "UnityEngine.Transform::INTERNAL_get_position(UnityEngine.Vector3&)",
    })

    -- Transform.get_rotation_Injected — writes Quaternion to output buffer
    icalls.get_rotation = resolve_icall_variants({
        "UnityEngine.Transform::get_rotation_Injected(UnityEngine.Quaternion&)",
        "UnityEngine.Transform::get_rotation_Injected",
        "UnityEngine.Transform::INTERNAL_get_rotation(UnityEngine.Quaternion&)",
    })

    -- Camera.get_enabled — check if camera is enabled
    icalls.camera_get_enabled = resolve_icall_variants({
        "UnityEngine.Behaviour::get_enabled()",
        "UnityEngine.Behaviour::get_enabled",
    })

    if not icalls.camera_get_main then
        return false, "Camera::get_main icall not found"
    end
    if not icalls.get_transform then
        return false, "Component::get_transform icall not found"
    end
    if not icalls.get_position then
        return false, "Transform::get_position_Injected icall not found"
    end

    return true
end

-- ============================================================================
-- SECTION 7: CAMERA + POSITION READING
-- ============================================================================

-- Pre-allocated output buffers for Injected methods
local vec3_buf = nil   -- 12 bytes: 3 floats
local quat_buf = nil   -- 16 bytes: 4 floats

local function ensure_buffers()
    if not vec3_buf then vec3_buf = memory.alloc(16) end  -- 16 for alignment
    if not quat_buf then quat_buf = memory.alloc(16) end
end

-- Get Camera.main via icall
local function get_main_camera()
    local ok, cam, err = pcall(ncall0, icalls.camera_get_main, "pointer")
    if not ok then return nil end  -- access violation caught
    if err or not cam or cam == 0 then return nil end
    return cam
end

-- Get transform from a component via icall
local function get_transform(component)
    if not component or component == 0 then return nil end
    local ok, t, err = pcall(ncall1p, icalls.get_transform, "pointer", component)
    if not ok then return nil end
    if err or not t or t == 0 then return nil end
    return t
end

-- Read position from Transform via _Injected icall
local function get_position(transform)
    if not transform or transform == 0 or not icalls.get_position then return nil end
    ensure_buffers()
    local ok, _, err = pcall(ncall2p, icalls.get_position, "void", transform, vec3_buf)
    if not ok or err then return nil end
    local x = memory.read_f32(vec3_buf)
    local y = memory.read_f32(vec3_buf + 4)
    local z = memory.read_f32(vec3_buf + 8)
    if not x or not y or not z then return nil end
    return { x = x, y = y, z = z }
end

-- Read rotation from Transform via _Injected icall
local function get_rotation(transform)
    if not transform or transform == 0 or not icalls.get_rotation then return nil end
    ensure_buffers()
    local ok, _, err = pcall(ncall2p, icalls.get_rotation, "void", transform, quat_buf)
    if not ok or err then return nil end
    local x = memory.read_f32(quat_buf)
    local y = memory.read_f32(quat_buf + 4)
    local z = memory.read_f32(quat_buf + 8)
    local w = memory.read_f32(quat_buf + 12)
    if not x or not y or not z or not w then return nil end
    return { x = x, y = y, z = z, w = w }
end

-- ============================================================================
-- SECTION 8: ROTATION MATH
-- ============================================================================

-- Quaternion -> euler angles (degrees, Unity ZXY extrinsic convention)
-- X = pitch (up/down, asin ±90°), Y = yaw (left/right, atan2 360°), Z = roll
local function quat_to_euler(q)
    -- Pitch (X): asin(2(wx - yz)) — gimbal-lock axis, ±90°
    local sinp = 2 * (q.w * q.x - q.y * q.z)
    local pitch
    if math.abs(sinp) >= 1 then
        pitch = math.deg((sinp >= 0 and 1 or -1) * math.pi / 2)
    else
        pitch = math.deg(math.asin(sinp))
    end

    -- Yaw (Y): atan2(2(xz + wy), 1 - 2(x² + y²)) — full 360°
    local siny_cosp = 2 * (q.x * q.z + q.w * q.y)
    local cosy_cosp = 1 - 2 * (q.x * q.x + q.y * q.y)
    local yaw = math.deg(math.atan(siny_cosp, cosy_cosp))

    -- Roll (Z): atan2(2(xy + wz), 1 - 2(x² + z²)) — full 360°
    local sinr_cosp = 2 * (q.x * q.y + q.w * q.z)
    local cosr_cosp = 1 - 2 * (q.x * q.x + q.z * q.z)
    local roll = math.deg(math.atan(sinr_cosp, cosr_cosp))

    return pitch, yaw, roll
end

-- Quaternion -> forward vector (Unity: forward = +Z local)
local function quat_to_forward(q)
    return {
        x = 2 * (q.x * q.z + q.w * q.y),
        y = 2 * (q.y * q.z - q.w * q.x),
        z = 1 - 2 * (q.x * q.x + q.y * q.y),
    }
end

-- ============================================================================
-- SECTION 9: SCENE NAME (BEST-EFFORT)
-- ============================================================================

local scene_cache = { name = "Unknown", index = -1 }

local function hash_scene_name(name)
    if not name or name == "" or name == "Unknown" then return -1 end
    local hash = 0
    for i = 1, #name do
        hash = ((hash << 5) - hash + string.byte(name, i)) & 0x7FFFFFFF
    end
    return hash
end

-- Resolve SceneManager icalls for scene name reading
local scene_icalls = {}

local function resolve_scene_icalls()
    scene_icalls.get_active_scene = resolve_icall_variants({
        "UnityEngine.SceneManagement.SceneManager::GetActiveScene_Injected(UnityEngine.SceneManagement.Scene&)",
        "UnityEngine.SceneManagement.SceneManager::GetActiveScene()",
    })
    scene_icalls.get_scene_name = resolve_icall_variants({
        "UnityEngine.SceneManagement.Scene::GetNameInternal(System.Int32)",
        "UnityEngine.SceneManagement.Scene::GetNameInternal",
    })
end

local scene_buf = nil

local function try_read_scene_name()
    if not scene_icalls.get_active_scene then
        return scene_cache.name, scene_cache.index
    end

    if not scene_buf then scene_buf = memory.alloc(16) end

    -- Try _Injected variant (writes Scene struct to buffer)
    ncall1p(scene_icalls.get_active_scene, "void", scene_buf)
    local scene_handle = memory.read_s32(scene_buf)

    if scene_handle and scene_handle ~= 0 and scene_icalls.get_scene_name then
        local name_ptr = native.call(scene_icalls.get_scene_name, "pointer",
            {"int32"}, {scene_handle})
        if name_ptr and name_ptr ~= 0 then
            local name = read_il2cpp_string(name_ptr)
            if name and #name > 0 then
                scene_cache.name = name
                scene_cache.index = hash_scene_name(name)
            end
        end
    end

    return scene_cache.name, scene_cache.index
end

-- ============================================================================
-- SECTION 10: UPDATE LOOP
-- ============================================================================

local function read_frame()
    -- Get Camera.main
    local camera = get_main_camera()
    if not camera then return nil end

    -- Get Camera's Transform
    local transform = get_transform(camera)
    if not transform then return nil end

    -- Read world position
    local pos = get_position(transform)
    if not pos then return nil end

    -- Read rotation (optional)
    local fwd, euler_x, euler_y, euler_z = nil, nil, nil, nil
    local rot = get_rotation(transform)
    if rot then
        fwd = quat_to_forward(rot)
        euler_x, euler_y, euler_z = quat_to_euler(rot)
        if euler_x and euler_x < 0 then euler_x = euler_x + 360 end
        if euler_y and euler_y < 0 then euler_y = euler_y + 360 end
        if euler_z and euler_z < 0 then euler_z = euler_z + 360 end
    end

    -- Scene name (best-effort)
    local scene_name, scene_index = try_read_scene_name()

    return {
        type = "data",
        protocol = "unity_il2cpp_tracker",
        posX = pos.x,
        posY = pos.y,
        posZ = pos.z,
        fwdX = fwd and fwd.x or 0,
        fwdY = fwd and fwd.y or 0,
        fwdZ = fwd and fwd.z or 0,
        eulerX = euler_x,
        eulerY = euler_y,
        eulerZ = euler_z,
        sceneName = scene_name,
        sceneIndex = scene_index,
        timestamp = clock() * 1000,
    }
end

-- ============================================================================
-- SECTION 11: MESSAGE HANDLER
-- ============================================================================

local state = {
    initialized = false,
    consecutive_errors = 0,
    -- No fatal-error on position loss. Process exit is detected by the
    -- engine; the bridge host script handles the searching-for-player UI.
    -- The agent keeps running and retrying each tick.
}

local function handle_init()
    log("IL2CPP Tracker (Lua): Initializing...")

    -- Step 1: Resolve IL2CPP API
    log("IL2CPP: Step 1 - resolve_api()")
    send({ type = "progress", message = "Resolving IL2CPP API...", percent = 5 })
    local ok, err = resolve_api()
    if not ok then
        log("IL2CPP: resolve_api FAILED: " .. tostring(err))
        send({ type = "init-response", success = false, error = tostring(err) })
        return
    end
    log("IL2CPP: resolve_api OK")

    -- Step 2: Wait for IL2CPP to be ready
    log("IL2CPP: Step 2 - wait_for_il2cpp_ready()")
    send({ type = "progress", message = "Waiting for IL2CPP runtime...", percent = 10 })
    local domain
    ok, err = wait_for_il2cpp_ready()
    if not ok then
        log("IL2CPP: wait_for_il2cpp_ready FAILED: " .. tostring(err))
        send({ type = "init-response", success = false, error = tostring(err) })
        return
    end
    log("IL2CPP: wait_for_il2cpp_ready OK")

    -- Step 3: Resolve Unity icalls
    log("IL2CPP: Step 3 - resolve_all_icalls()")
    send({ type = "progress", message = "Resolving Unity methods...", percent = 40 })
    ok, err = resolve_all_icalls()
    if not ok then
        log("IL2CPP: resolve_all_icalls FAILED: " .. tostring(err))
        send({ type = "init-response", success = false, error = tostring(err) })
        return
    end
    log("IL2CPP: resolve_all_icalls OK")

    -- Step 4: Resolve scene icalls (optional)
    log("IL2CPP: Step 4 - resolve_scene_icalls()")
    send({ type = "progress", message = "Resolving scene APIs...", percent = 60 })
    resolve_scene_icalls()
    log("IL2CPP: resolve_scene_icalls OK")

    -- Step 5: Test read
    log("IL2CPP: Step 5 - test read_frame()")
    send({ type = "progress", message = "Testing camera access...", percent = 80 })
    local test = read_frame()
    if test then
        log(string.format("IL2CPP: Test read OK — pos=(%.2f, %.2f, %.2f)",
            test.posX, test.posY, test.posZ))
    else
        log("IL2CPP: Camera.main returned null (may not be spawned yet)")
    end

    state.initialized = true
    state.consecutive_errors = 0

    send({ type = "progress", message = "Tracker ready!", percent = 100 })
    send({ type = "init-response", success = true })

    log("==============================================")
    log("  IL2CPP Tracker (Lua) Initialized")
    log("  camera_get_main: " .. (icalls.camera_get_main and "OK" or "MISSING"))
    log("  get_transform:   " .. (icalls.get_transform and "OK" or "MISSING"))
    log("  get_position:    " .. (icalls.get_position and "OK" or "MISSING"))
    log("  get_rotation:    " .. (icalls.get_rotation and "OK" or "MISSING"))
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
            log("IL2CPP: tick error #" .. state.consecutive_errors ..
                ": " .. tostring(result))
        end
    elseif type(result) == "table" then
        send(result)
        state.consecutive_errors = 0
        return
    else
        -- Camera.main returned null (loading screen, menu, etc.)
        state.consecutive_errors = state.consecutive_errors + 1
    end

    -- Send heartbeat so the host knows we're alive but have no position.
    -- No fatal-error: the engine detects process exit; we just keep trying.
    send({ type = "heartbeat", status = "no-position",
        errors = state.consecutive_errors })
end

-- ============================================================================
-- SECTION 12: BOOT & RECV HANDLER
-- ============================================================================

send({ type = "heartbeat", status = "loading" })

log("==============================================")
log("  Unity IL2CPP Tracker - Lua")
log("  Pointer size: " .. PTR_SIZE .. " bytes")
log("==============================================")

send({ type = "heartbeat", status = "ready" })

-- Message parsing — recv delivers raw JSON strings in Lua backend

local function parse_message(message)
    -- Lua backend: message is a raw JSON string
    if type(message) == "string" then
        if type(json) == "table" and type(json.decode) == "function" then
            local ok, decoded = pcall(json.decode, message)
            if ok and type(decoded) == "table" then
                return decoded
            end
        end
        -- Fallback: regex match
        if message:find('"type"%s*:%s*"init"')     then return { type = "init" } end
        if message:find('"type"%s*:%s*"tick"')     then return { type = "tick" } end
        if message:find('"type"%s*:%s*"shutdown"') then return { type = "shutdown" } end
        return nil
    end
    -- JS backend fallback: already a table
    if type(message) == "table" then return message end
    return nil
end

recv(function(message)
    local msg = parse_message(message)
    if not msg or not msg.type then return end  -- ignore unknown messages

    local ok, err = pcall(function()
        if msg.type == "init" then
            handle_init()
        elseif msg.type == "tick" then
            handle_tick()
        elseif msg.type == "shutdown" then
            log("IL2CPP Tracker (Lua): Shutdown")
            -- Detach from IL2CPP runtime so Unity's shutdown doesn't
            state.initialized = false
        end
    end)

    if not ok then
        log("IL2CPP handler crash: " .. tostring(err))
        if msg.type == "init" then
            send({ type = "init-response", success = false, error = tostring(err) })
        end
    end
end)
