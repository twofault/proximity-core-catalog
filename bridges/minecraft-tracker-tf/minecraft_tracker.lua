-- ProximityCore GameLink Lua Script: Minecraft Java Edition Tracker
--
-- Reads player position/rotation via JNI. Read-only security model:
--   - JNI_GetCreatedJavaVMs pre-whitelisted (jvm.dll export)
--   - JNI vtable functions whitelisted via native.lookup("jvm.dll", "jni::Name", addr)
--   - JIT accessor stubs accepted in executable heap memory (not just loaded modules)
--   - Field getters ONLY (GetDoubleField etc.) — no Call*Method (arbitrary code exec)
--   - No NewGlobalRef (JVM mutation) — player re-read each tick
--   - Tick-driven by main.lua (no setInterval in Lua backend)

local PTR = 8 -- pointer size (64-bit JVM only)

-- JNINativeInterface_ vtable slot indices
local JNI = {
    ExceptionOccurred = 15, ExceptionClear = 17,
    FindClass = 6, GetFieldID = 94, GetObjectField = 95,
    GetIntField = 100, GetFloatField = 102, GetDoubleField = 103,
    GetStaticFieldID = 144, GetStaticObjectField = 145,
}

-- JNIInvokeInterface_ vtable slot indices
local JVM = { AttachCurrentThread = 4, GetEnv = 6 }

-- Runtime state
local env    = nil   -- JNIEnv* (integer)
local vtable = nil   -- function table pointer (integer)
local funcs  = {}    -- name -> verified native address

local mc = {}        -- resolved Minecraft JNI references
local jvm_ready = false
local initialized = false
local consecutive_errors = 0
local error_time = 0

-- ── JNI vtable helpers ──────────────────────────────────────────

local function verify_fn(name, index)
    local addr = memory.read_pointer(vtable + index * PTR)
    if addr == nil or addr == 0 then return nil end
    -- Whitelist via icall path (jni:: prefix with :: triggers any-module check).
    -- JVM JIT accessor stubs live in executable heap, not in jvm.dll.
    local ok, _, err = pcall(native.lookup, "jvm.dll", "jni::" .. name, addr)
    if not ok or err then return nil end
    funcs[name] = addr
    return addr
end

local function jcall(name, ret, types, args)
    local addr = funcs[name]
    if not addr then return nil, name .. " not resolved" end
    return native.call(addr, ret, types, args)
end

-- ── JNI wrappers ────────────────────────────────────────────────

local function check_ex()
    if not funcs["ExceptionOccurred"] then return false end
    local ex = jcall("ExceptionOccurred", "pointer", {"pointer"}, {env})
    if ex and ex ~= 0 then
        if funcs["ExceptionClear"] then
            jcall("ExceptionClear", "void", {"pointer"}, {env})
        end
        return true
    end
    return false
end

local function find_class(jni_name)
    local buf = memory.alloc_utf8(jni_name)
    if not buf then return nil end
    local cls = jcall("FindClass", "pointer", {"pointer", "pointer"}, {env, buf})
    memory.free(buf)
    if not cls or cls == 0 or check_ex() then return nil end
    return cls
end

--- Resolve a field or static field ID, allocating temp strings for name+sig.
local function get_fid(fn_name, clazz, name, sig)
    local n, s = memory.alloc_utf8(name), memory.alloc_utf8(sig)
    if not n or not s then
        if n then memory.free(n) end
        if s then memory.free(s) end
        return nil
    end
    local fid = jcall(fn_name, "pointer",
        {"pointer", "pointer", "pointer", "pointer"}, {env, clazz, n, s})
    memory.free(n)
    memory.free(s)
    if not fid or fid == 0 or check_ex() then return nil end
    return fid
end

local function get_field_id(clazz, name, sig)
    return get_fid("GetFieldID", clazz, name, sig)
end

local function get_static_field_id(clazz, name, sig)
    return get_fid("GetStaticFieldID", clazz, name, sig)
end

local function get_static_obj(clazz, fid)
    return jcall("GetStaticObjectField", "pointer",
        {"pointer", "pointer", "pointer"}, {env, clazz, fid})
end

local function get_obj(obj, fid)
    return jcall("GetObjectField", "pointer",
        {"pointer", "pointer", "pointer"}, {env, obj, fid})
end

local function get_double(obj, fid)
    return jcall("GetDoubleField", "double",
        {"pointer", "pointer", "pointer"}, {env, obj, fid})
end

--- Read float field. Try GetFloatField (XMM0 dispatch), fall back to
--- GetIntField with bit reinterpretation via string.pack/unpack.
local function get_float(obj, fid)
    if funcs["GetFloatField"] then
        local v = jcall("GetFloatField", "float",
            {"pointer", "pointer", "pointer"}, {env, obj, fid})
        if v then return v end
    end
    local raw = jcall("GetIntField", "int",
        {"pointer", "pointer", "pointer"}, {env, obj, fid})
    if not raw then return nil end
    return string.unpack("f", string.pack("i4", raw))
end

-- ── JVM initialization ──────────────────────────────────────────

local vm_ptr = nil  -- cached for re-attachment

local function init_jvm()
    log("Initializing JVM access...")

    local get_vms_raw = process.find_export("jvm.dll", "JNI_GetCreatedJavaVMs")
    if not get_vms_raw or get_vms_raw == 0 then return false, "jvm.dll not loaded" end
    local get_vms = native.lookup("jvm.dll", "JNI_GetCreatedJavaVMs", get_vms_raw)

    local vm_buf, cnt_buf = memory.alloc(PTR), memory.alloc(4)
    if not vm_buf or not cnt_buf then return false, "alloc failed" end

    native.call(get_vms, "int",
        {"pointer", "int", "pointer"}, {vm_buf, 1, cnt_buf})
    vm_ptr = memory.read_pointer(vm_buf)
    local vm_n = memory.read_s32(cnt_buf)
    memory.free(vm_buf)
    memory.free(cnt_buf)

    if not vm_ptr or vm_ptr == 0 or vm_n == 0 then
        return false, "no JVM found"
    end
    log("  JavaVM* = " .. string.format("0x%X", vm_ptr))

    -- Read JavaVM vtable and whitelist AttachCurrentThread via icall path
    local jvm_vt = memory.read_pointer(vm_ptr)
    if not jvm_vt or jvm_vt == 0 then return false, "no JavaVM vtable" end

    local at_addr = memory.read_pointer(jvm_vt + JVM.AttachCurrentThread * PTR)
    if not at_addr or at_addr == 0 then return false, "no AttachCurrentThread" end
    native.lookup("jvm.dll", "jni::AttachCurrentThread", at_addr)

    -- Attach current thread to JVM (required before any JNI calls)
    local env_buf = memory.alloc(PTR)
    if not env_buf then return false, "alloc failed" end

    local ok, rc = pcall(native.call, at_addr, "int",
        {"pointer", "pointer", "pointer"}, {vm_ptr, env_buf, 0})
    env = memory.read_pointer(env_buf)
    memory.free(env_buf)

    if not ok or not env or env == 0 then
        return false, "AttachCurrentThread failed"
    end
    log("  JNIEnv* = " .. string.format("0x%X", env))

    vtable = memory.read_pointer(env)
    if not vtable or vtable == 0 then return false, "no JNI vtable" end
    return true
end

-- ── Verify JNI functions ────────────────────────────────────────

local function verify_jni_functions()
    log("Verifying JNI vtable...")
    local required = {
        {"FindClass", JNI.FindClass}, {"GetStaticFieldID", JNI.GetStaticFieldID},
        {"GetStaticObjectField", JNI.GetStaticObjectField},
        {"GetFieldID", JNI.GetFieldID}, {"GetObjectField", JNI.GetObjectField},
        {"GetDoubleField", JNI.GetDoubleField}, {"GetIntField", JNI.GetIntField},
    }
    local failed = {}
    for _, e in ipairs(required) do
        if verify_fn(e[1], e[2]) then
            log("  [ok] " .. e[1])
        else
            log("  [FAIL] " .. e[1])
            failed[#failed + 1] = e[1]
        end
    end
    if #failed > 0 then
        return false, "failed: " .. table.concat(failed, ", ")
    end
    -- Optional (don't block init)
    for _, e in ipairs({
        {"ExceptionOccurred", JNI.ExceptionOccurred},
        {"ExceptionClear", JNI.ExceptionClear},
        {"GetFloatField", JNI.GetFloatField},
    }) do
        if verify_fn(e[1], e[2]) then
            log("  [ok] " .. e[1] .. " (opt)")
        else
            log("  [skip] " .. e[1] .. " (opt)")
        end
    end
    return true
end

-- ── Minecraft class/field resolution ────────────────────────────

local function apply_mappings(data)
    log("Resolving Minecraft " .. (data.version or "?") .. "...")
    local c, f = data.classes, data.fields
    local mj = (c.Minecraft or ""):gsub("%.", "/")

    mc.mc_cls = find_class(mj)
    if not mc.mc_cls then return false, "Minecraft class not found" end

    mc.inst_fid = get_static_field_id(mc.mc_cls, f["Minecraft.instance"], "L"..mj..";")
    if not mc.inst_fid then return false, "Minecraft.instance not found" end

    local lp = (c.LocalPlayer or ""):gsub("%.", "/")
    mc.player_fid = get_field_id(mc.mc_cls, f["Minecraft.player"], "L"..lp..";")
    if not mc.player_fid then return false, "Minecraft.player not found" end

    local ej = (c.Entity or ""):gsub("%.", "/")
    mc.ent_cls = find_class(ej)
    if not mc.ent_cls then return false, "Entity class not found" end

    local vj = (c.Vec3 or ""):gsub("%.", "/")
    mc.v3_cls = find_class(vj)
    if not mc.v3_cls then return false, "Vec3 class not found" end

    mc.pos_fid = get_field_id(mc.ent_cls, f["Entity.position"], "L"..vj..";")
    if not mc.pos_fid then return false, "Entity.position not found" end

    mc.xrot_fid = get_field_id(mc.ent_cls, f["Entity.xRot"], "F")
    mc.yrot_fid = get_field_id(mc.ent_cls, f["Entity.yRot"], "F")
    if not mc.xrot_fid or not mc.yrot_fid then
        return false, "rotation fields not found"
    end

    mc.vx_fid = get_field_id(mc.v3_cls, f["Vec3.x"], "D")
    mc.vy_fid = get_field_id(mc.v3_cls, f["Vec3.y"], "D")
    mc.vz_fid = get_field_id(mc.v3_cls, f["Vec3.z"], "D")
    if not mc.vx_fid or not mc.vy_fid or not mc.vz_fid then
        return false, "Vec3 fields not found"
    end

    log("  All resolved")
    return true
end

-- ── Player data reading ─────────────────────────────────────────

local function get_player_data()
    local inst = get_static_obj(mc.mc_cls, mc.inst_fid)
    if not inst or inst == 0 then return nil end

    local player = get_obj(inst, mc.player_fid)
    if not player or player == 0 then return nil end

    local pos = get_obj(player, mc.pos_fid)
    if not pos or pos == 0 then return nil end

    local x = get_double(pos, mc.vx_fid)
    local y = get_double(pos, mc.vy_fid)
    local z = get_double(pos, mc.vz_fid)
    if not x or not y or not z then return nil end

    return {
        type = "data", protocol = "minecraft_tracker",
        posX = x, posY = y, posZ = z,
        fwdX = 0, fwdY = 0, fwdZ = 0,
        yaw = get_float(player, mc.yrot_fid),
        pitch = get_float(player, mc.xrot_fid),
        sceneName = "Minecraft", sceneIndex = 0,
        timestamp = clock(),
    }
end

-- ── Tick + message handling ─────────────────────────────────────

local function do_tick()
    if not initialized then return end
    local ok, result = pcall(get_player_data)
    if ok and result then
        sendTagged(result)
        consecutive_errors = 0
        return
    end
    consecutive_errors = consecutive_errors + 1
    local now = clock()
    if now - error_time > 1000 then
        if not ok then log("Read error: " .. tostring(result):sub(1, 200)) end
        error_time = now
    end
    -- Send heartbeat so the host knows we're alive but have no position.
    -- No fatal-error: the engine detects process exit; we just keep trying.
    sendTagged({ type = "heartbeat", status = "no-position",
        errors = consecutive_errors })
end

local function handle_message(message)
    if type(message) == "string" then
        local ok, p = pcall(json.decode, message)
        if ok and p then message = p else recv(handle_message); return end
    end
    if type(message) ~= "table" then recv(handle_message); return end

    if message.type == "tick" then
        do_tick()
    elseif message.type == "init" and message.data then
        local ok, err = apply_mappings(message.data)
        if ok then
            initialized = true
            consecutive_errors = 0
            sendTagged({type = "init-response", success = true})
        else
            sendTagged({type = "init-response", success = false, error = err})
        end
    elseif message.type == "rpc" and message.method == "applyInitialization" then
        local ok, err = apply_mappings(message.args or {})
        if ok then initialized = true; consecutive_errors = 0 end
        sendTagged({type = "rpc-response", id = message.id, success = ok, error = err})
    elseif message.type == "shutdown" then
        initialized = false
    end
    recv(handle_message)
end

-- ── Entry point ─────────────────────────────────────────────────

log("ProximityCore: Minecraft Tracker (Lua)")

local ok, err = init_jvm()
if not ok then
    log("JVM init failed: " .. (err or "?"))
    sendTagged({type = "fatal-error", error = "JVM: " .. (err or "?")})
else
    local vok, verr = verify_jni_functions()
    if not vok then
        log("JNI verify failed: " .. (verr or "?"))
        sendTagged({type = "fatal-error", error = "JNI: " .. (verr or "?")})
    else
        jvm_ready = true
        log("JNI ready, waiting for mappings...")
    end
end

recv(handle_message)
