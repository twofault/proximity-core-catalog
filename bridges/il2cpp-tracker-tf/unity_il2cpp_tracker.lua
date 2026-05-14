-- Unity IL2CPP camera tracker.
-- Uses IL2CPP C API for metadata; Unity icalls (Camera::get_main,
-- Transform::get_position, etc.) are invoked via Hs.il2cpp.call which
-- resolves the address in privileged C. The raw icall pointer is never
-- exposed to bridge code.

local PTR_SIZE = process.get_pointer_size()

local api = {}

local function resolve_api()
    local dll = "GameAssembly.dll"
    local resolve_count = 0
    local fail_count = 0

    -- Two-step: find_export resolves the address (doesn't hang), then
    -- native.lookup validates against allowlist and adds to whitelist.
    local function r(name)
        local fok, faddr = pcall(process.find_export, dll, name)
        if not fok or not faddr or faddr == 0 then
            fail_count = fail_count + 1
            return nil
        end
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

    -- thread_attach/detach deliberately omitted -- freezes Unity shutdown.
    api.domain_get              = r("il2cpp_domain_get")
    api.domain_get_assemblies   = r("il2cpp_domain_get_assemblies")

    api.assembly_get_image      = r("il2cpp_assembly_get_image")
    api.image_get_name          = r("il2cpp_image_get_name")
    api.image_get_class_count   = r("il2cpp_image_get_class_count")
    api.image_get_class         = r("il2cpp_image_get_class")

    api.class_from_name         = r("il2cpp_class_from_name")
    api.class_get_name          = r("il2cpp_class_get_name")
    api.class_get_namespace     = r("il2cpp_class_get_namespace")
    api.class_get_parent        = r("il2cpp_class_get_parent")
    api.class_instance_size     = r("il2cpp_class_instance_size")
    api.class_is_valuetype      = r("il2cpp_class_is_valuetype")
    api.class_get_static_field_data = r("il2cpp_class_get_static_field_data")

    api.class_get_fields        = r("il2cpp_class_get_fields")
    api.class_get_field_from_name = r("il2cpp_class_get_field_from_name")
    api.field_get_name          = r("il2cpp_field_get_name")
    api.field_get_offset        = r("il2cpp_field_get_offset")
    api.field_get_flags         = r("il2cpp_field_get_flags")

    api.class_get_method_from_name = r("il2cpp_class_get_method_from_name")
    api.method_get_name         = r("il2cpp_method_get_name")

    api.string_chars            = r("il2cpp_string_chars")
    api.string_length           = r("il2cpp_string_length")

    api.object_get_class        = r("il2cpp_object_get_class")

    -- il2cpp_resolve_icall no longer on the allowlist; the raw resolver
    -- address is held by Hs.il2cpp.call in privileged C. Bridge invokes
    -- Unity icalls by name via Hs.il2cpp.call(name, ret, arg_types, args).

    log("IL2CPP: resolve_api done — " .. resolve_count .. " resolved, " .. fail_count .. " failed")

    if not api.domain_get then
        return false, "GameAssembly.dll not loaded or il2cpp_domain_get not found"
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

local function ncall2p(addr, ret, a1, a2)
    if not addr then return nil end
    return (native.call(addr, ret, {"pointer", "pointer"}, {a1, a2}))
end

local function ncall3p(addr, ret, a1, a2, a3)
    if not addr then return nil end
    return (native.call(addr, ret, {"pointer", "pointer", "pointer"}, {a1, a2, a3}))
end

local str_cache = {}
local function cstr(s)
    if str_cache[s] then return str_cache[s] end
    local addr = memory.alloc_utf8(s)
    str_cache[s] = addr
    return addr
end

local function read_cstr(ptr)
    if not ptr or ptr == 0 then return nil end
    return memory.read_utf8(ptr, 256)
end

local function read_il2cpp_string(str_ptr)
    if not str_ptr or str_ptr == 0 then return nil end
    local len = ncall1p(api.string_length, "int32", str_ptr)
    if not len or len <= 0 then return nil end
    local chars = ncall1p(api.string_chars, "pointer", str_ptr)
    if not chars or chars == 0 then return nil end
    return memory.read_utf16(chars, len)
end

-- Wait for IL2CPP runtime init; calling API before this crashes the process.
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

    -- Never call il2cpp_thread_attach -- registers Frida thread with IL2CPP's
    -- tracker, causing Unity shutdown to wait forever. Metadata APIs work
    -- without it.

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

-- Unity icalls are invoked through Hs.il2cpp.call (privileged C-side
-- resolution + dispatch). The bridge no longer holds raw icall addresses;
-- the helper's internal cache absorbs repeat invocations. Variants
-- (Camera::get_main() vs Camera::get_main; INTERNAL_get_position vs
-- get_position_Injected) are tried in order on each first call.
local IL2CPP_ICALL_VARIANTS = {
    camera_get_main = {
        "UnityEngine.Camera::get_main()",
        "UnityEngine.Camera::get_main",
    },
    get_transform = {
        "UnityEngine.Component::get_transform()",
        "UnityEngine.Component::get_transform",
    },
    get_position = {
        "UnityEngine.Transform::get_position_Injected(UnityEngine.Vector3&)",
        "UnityEngine.Transform::get_position_Injected",
        "UnityEngine.Transform::INTERNAL_get_position(UnityEngine.Vector3&)",
    },
    get_rotation = {
        "UnityEngine.Transform::get_rotation_Injected(UnityEngine.Quaternion&)",
        "UnityEngine.Transform::get_rotation_Injected",
        "UnityEngine.Transform::INTERNAL_get_rotation(UnityEngine.Quaternion&)",
    },
    get_enabled = {
        "UnityEngine.Behaviour::get_enabled()",
        "UnityEngine.Behaviour::get_enabled",
    },
    get_active_scene = {
        "UnityEngine.SceneManagement.SceneManager::GetActiveScene_Injected(UnityEngine.SceneManagement.Scene&)",
        "UnityEngine.SceneManagement.SceneManager::GetActiveScene()",
    },
    get_scene_name = {
        "UnityEngine.SceneManagement.Scene::GetNameInternal(System.Int32)",
        "UnityEngine.SceneManagement.Scene::GetNameInternal",
    },
}

-- Per-key cache of which variant Hs.il2cpp.call accepted, so subsequent
-- invocations skip the variant fallback walk.
local icall_chosen_variant = {}

-- Invoke a Unity icall by logical key. `ret`, `arg_types`, `args` follow
-- native.call's shape. Returns (value, err) like native.call.
local function hs_call_icall(key, ret, arg_types, args)
    local chosen = icall_chosen_variant[key]
    if chosen then
        return Hs.il2cpp.call(chosen, ret, arg_types, args)
    end
    local variants = IL2CPP_ICALL_VARIANTS[key]
    if not variants then return nil, "no IL2CPP_ICALL_VARIANTS for key " .. tostring(key) end
    local last_err = nil
    for _, name in ipairs(variants) do
        local v, e = Hs.il2cpp.call(name, ret, arg_types, args)
        if e == nil then
            icall_chosen_variant[key] = name
            return v, nil
        end
        last_err = e
    end
    return nil, last_err or "all variants failed"
end

-- Pre-allocated out-buffers for _Injected methods (16-byte aligned).
local vec3_buf = nil
local quat_buf = nil

local function ensure_buffers()
    if not vec3_buf then vec3_buf = memory.alloc(16) end
    if not quat_buf then quat_buf = memory.alloc(16) end
end

local function get_main_camera()
    local cam, err = hs_call_icall("camera_get_main", "pointer", {}, {})
    if err or not cam or cam == 0 then return nil end
    return cam
end

local function get_transform(component)
    if not component or component == 0 then return nil end
    local t, err = hs_call_icall("get_transform", "pointer", {"pointer"}, {component})
    if err or not t or t == 0 then return nil end
    return t
end

local function get_position(transform)
    if not transform or transform == 0 then return nil end
    ensure_buffers()
    local _, err = hs_call_icall("get_position", "void", {"pointer", "pointer"},
        {transform, vec3_buf})
    if err then return nil end
    local x = memory.read_f32(vec3_buf)
    local y = memory.read_f32(vec3_buf + 4)
    local z = memory.read_f32(vec3_buf + 8)
    if not x or not y or not z then return nil end
    return { x = x, y = y, z = z }
end

local function get_rotation(transform)
    if not transform or transform == 0 then return nil end
    ensure_buffers()
    local _, err = hs_call_icall("get_rotation", "void", {"pointer", "pointer"},
        {transform, quat_buf})
    if err then return nil end
    local x = memory.read_f32(quat_buf)
    local y = memory.read_f32(quat_buf + 4)
    local z = memory.read_f32(quat_buf + 8)
    local w = memory.read_f32(quat_buf + 12)
    if not x or not y or not z or not w then return nil end
    return { x = x, y = y, z = z, w = w }
end

-- Quaternion -> forward (Unity: forward = +Z local).
local function quat_to_forward(q)
    return {
        x = 2 * (q.x * q.z + q.w * q.y),
        y = 2 * (q.y * q.z - q.w * q.x),
        z = 1 - 2 * (q.x * q.x + q.y * q.y),
    }
end

-- Quaternion -> up (Unity: up = +Y local). Forward+up gives an orthonormal
-- basis so audio never decomposes through euler (degenerate at zenith/nadir).
local function quat_to_up(q)
    return {
        x = 2 * (q.x * q.y - q.w * q.z),
        y = 1 - 2 * (q.x * q.x + q.z * q.z),
        z = 2 * (q.y * q.z + q.w * q.x),
    }
end

local scene_cache = { name = "Unknown", index = -1 }

local function hash_scene_name(name)
    if not name or name == "" or name == "Unknown" then return -1 end
    local hash = 0
    for i = 1, #name do
        hash = ((hash << 5) - hash + string.byte(name, i)) & 0x7FFFFFFF
    end
    return hash
end

local scene_buf = nil

local function try_read_scene_name()
    if not scene_buf then scene_buf = memory.alloc(16) end

    -- _Injected writes the Scene struct to scene_buf.
    local _, e1 = hs_call_icall("get_active_scene", "void", {"pointer"}, {scene_buf})
    if e1 then return scene_cache.name, scene_cache.index end
    local scene_handle = memory.read_s32(scene_buf)

    if scene_handle and scene_handle ~= 0 then
        local name_ptr, _ = hs_call_icall("get_scene_name", "pointer",
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

local function read_frame()
    local camera = get_main_camera()
    if not camera then return nil end

    local transform = get_transform(camera)
    if not transform then return nil end

    local pos = get_position(transform)
    if not pos then return nil end

    -- Emit forward+up; main.lua drives orientation through setCameraBasis,
    -- skipping gimbal-locked euler conversion.
    local fwd, up = nil, nil
    local rot = get_rotation(transform)
    if rot then
        fwd = quat_to_forward(rot)
        up = quat_to_up(rot)
    end

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
        upX = up and up.x or 0,
        upY = up and up.y or 1,
        upZ = up and up.z or 0,
        sceneName = scene_name,
        sceneIndex = scene_index,
        timestamp = clock() * 1000,
    }
end

local state = {
    initialized = false,
    consecutive_errors = 0,
    -- No fatal on position loss; engine detects exit, host shows searching UI.
}

local function handle_init()
    log("IL2CPP Tracker (Lua): Initializing...")

    log("IL2CPP: Step 1 - resolve_api()")
    send({ type = "progress", message = "Resolving IL2CPP API...", percent = 5 })
    local ok, err = resolve_api()
    if not ok then
        log("IL2CPP: resolve_api FAILED: " .. tostring(err))
        send({ type = "init-response", success = false, error = tostring(err) })
        return
    end
    log("IL2CPP: resolve_api OK")

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

    -- Icall resolution is now deferred to first call inside Hs.il2cpp.call;
    -- the helper caches the (name)->addr mapping. A first read_frame()
    -- below will populate the cache and surface any incompatibility.

    log("IL2CPP: Step 3 - test read_frame()")
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
    for key, chosen in pairs(icall_chosen_variant) do
        log("  " .. key .. ": " .. chosen)
    end
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
        -- Camera.main null (loading, menu, etc.).
        state.consecutive_errors = state.consecutive_errors + 1
    end

    -- Heartbeat keeps host aware; retry next tick rather than fatal.
    send({ type = "heartbeat", status = "no-position",
        errors = state.consecutive_errors })
end

send({ type = "heartbeat", status = "loading" })

log("==============================================")
log("  Unity IL2CPP Tracker - Lua")
log("  Pointer size: " .. PTR_SIZE .. " bytes")
log("==============================================")

send({ type = "heartbeat", status = "ready" })

local function parse_message(message)
    -- Lua backend delivers raw JSON strings; JS delivers tables.
    if type(message) == "string" then
        if type(json) == "table" and type(json.decode) == "function" then
            local ok, decoded = pcall(json.decode, message)
            if ok and type(decoded) == "table" then
                return decoded
            end
        end
        -- Regex fallback when json decode is unavailable.
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
            log("IL2CPP Tracker (Lua): Shutdown")
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
