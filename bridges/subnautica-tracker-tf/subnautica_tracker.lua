-- GameLink agent for Subnautica. Camera uses the generic Unity Mono icall
-- path; Player state (vehicle / sub / underwater) reads fields off the
-- Player singleton, located by scanning writable memory for its MonoVTable.
-- First attach ~60s; subsequent attaches reuse the cached pointer.

local PTR_SIZE = process.get_pointer_size()
local MONO_HEADER_SIZE = 2 * PTR_SIZE  -- vtable + sync_block = 0x10 on 64-bit
local CACHED_PTR_OFFSET = MONO_HEADER_SIZE
local SCAN_PROGRESS_INTERVAL_MS = 500

local NATIVE_TRANSFORM_MATRIX_OFFSETS = { 0x38, 0x3C, 0x44, 0x48, 0x60, 0x90 }
local MATRIX_POS_X = 12 * 4
local MATRIX_POS_Y = 13 * 4
local MATRIX_POS_Z = 14 * 4
local MATRIX_FWD_X = 8 * 4
local MATRIX_FWD_Y = 9 * 4
local MATRIX_FWD_Z = 10 * 4
local MATRIX_UP_X = 4 * 4
local MATRIX_UP_Y = 5 * 4
local MATRIX_UP_Z = 6 * 4

local MONO_MODULE_CANDIDATES = {
    "mono-2.0-bdwgc.dll", "mono-2.0-sgen.dll", "mono.dll",
}

local UNITY_IMAGE_CANDIDATES = {
    "UnityEngine.CoreModule", "UnityEngine.CoreModule.dll",
    "UnityEngine", "UnityEngine.dll",
}

local ICALL_OFFSET = 0x28  -- MonoMethod+0x28 for icall methods

local state = {
    initialized = false,
    consecutive_errors = 0,
    warmup_ticks = 0,
    player_ptr = nil,
    player_vtable = nil,
}

local mono_dll = nil
local api = {}
local mono_methods = {}
local icalls = {}
local image_assembly_csharp = nil
local image_unity = nil
local classes = {}
local off = {}

local vec3_buf = nil
local quat_buf = nil
local scene_buf = nil

local native_matrix_offset = nil

-- ── Mono runtime resolution ──

local function r(name)
    local fok, faddr = pcall(process.find_export, mono_dll, name)
    if not fok or not faddr or faddr == 0 then return nil end
    local ok, addr = pcall(native.lookup, mono_dll, name, faddr)
    if not ok or not addr or addr == 0 then return nil end
    return addr
end

local function resolve_mono_module()
    for _, candidate in ipairs(MONO_MODULE_CANDIDATES) do
        if process.find_module(candidate) then
            mono_dll = candidate
            return true
        end
    end
    return false, "Mono runtime DLL not found"
end

local function resolve_api()
    api.get_root_domain              = r("mono_get_root_domain")
    api.image_loaded                 = r("mono_image_loaded")
    api.class_from_name              = r("mono_class_from_name")
    api.class_get_method_from_name   = r("mono_class_get_method_from_name")
    api.class_get_property_from_name = r("mono_class_get_property_from_name")
    api.property_get_get_method      = r("mono_property_get_get_method")
    api.class_get_field_from_name    = r("mono_class_get_field_from_name")
    api.field_get_offset             = r("mono_field_get_offset")

    if not api.get_root_domain or not api.image_loaded or not api.class_from_name then
        return false, "Required Mono API exports missing"
    end
    return true
end

local function image_loaded(name)
    local ok, img, err = pcall(native.call, api.image_loaded,
        "pointer", {"cstring"}, {name})
    if ok and not err and img and img ~= 0 then return img end
    return nil
end

local function class_from_name(image, ns, name)
    if not image then return nil end
    local ok, k, err = pcall(native.call, api.class_from_name, "pointer",
        {"pointer", "cstring", "cstring"}, {image, ns, name})
    if ok and not err and k and k ~= 0 then return k end
    return nil
end

local function method_from_name(klass, name, argc)
    if not klass or klass == 0 then return nil end
    local ok, m, err = pcall(native.call, api.class_get_method_from_name,
        "pointer", {"pointer", "cstring", "int"}, {klass, name, argc})
    if ok and not err and m and m ~= 0 then return m end
    return nil
end

local function getter_method(klass, prop)
    if not klass or klass == 0 then return nil end
    local ok, p, err = pcall(native.call, api.class_get_property_from_name,
        "pointer", {"pointer", "cstring"}, {klass, prop})
    if not ok or err or not p or p == 0 then return nil end
    local ok2, g, err2 = pcall(native.call, api.property_get_get_method,
        "pointer", {"pointer"}, {p})
    if ok2 and not err2 and g and g ~= 0 then return g end
    return nil
end

local function field_offset(klass, name)
    if not klass or klass == 0 then return nil end
    local ok, f, err = pcall(native.call, api.class_get_field_from_name,
        "pointer", {"pointer", "cstring"}, {klass, name})
    if not ok or err or not f or f == 0 then return nil end
    local ok2, o, err2 = pcall(native.call, api.field_get_offset, "int",
        {"pointer"}, {f})
    if not ok2 or err2 then return nil end
    return o
end

local function resolve_icall_variants(name, mono_method, variants)
    if not mono_method or mono_method == 0 then return nil end
    local addr = memory.read_pointer(mono_method + ICALL_OFFSET)
    if not addr or addr == 0 then return nil end
    for _, v in ipairs(variants) do
        local ok, resolved, err = pcall(native.lookup, mono_dll, v, addr)
        if ok and not err and resolved and resolved ~= 0 then return resolved end
    end
    return nil
end

local function resolve_metadata()
    image_unity = nil
    for _, name in ipairs(UNITY_IMAGE_CANDIDATES) do
        image_unity = image_loaded(name)
        if image_unity then break end
    end
    if not image_unity then return false, "UnityEngine image not found" end

    image_assembly_csharp = image_loaded("Assembly-CSharp") or image_loaded("Assembly-CSharp.dll")
    if not image_assembly_csharp then
        return false, "Assembly-CSharp image not found"
    end

    -- Unity classes (for camera tracking)
    local cam_class   = class_from_name(image_unity, "UnityEngine", "Camera")
    local comp_class  = class_from_name(image_unity, "UnityEngine", "Component")
    local xform_class = class_from_name(image_unity, "UnityEngine", "Transform")
    local sm_class    = class_from_name(image_unity,
        "UnityEngine.SceneManagement", "SceneManager")

    mono_methods.camera_get_main     = method_from_name(cam_class, "get_main", 0)
    mono_methods.get_transform       = getter_method(comp_class, "transform")
    mono_methods.get_position_inj    = method_from_name(xform_class,
        "get_position_Injected", 1)
    mono_methods.get_rotation_inj    = method_from_name(xform_class,
        "get_rotation_Injected", 1)
    if sm_class then
        mono_methods.scene_get_active_inj = method_from_name(sm_class,
            "GetActiveScene_Injected", 1)
    end

    if not mono_methods.camera_get_main or not mono_methods.get_transform then
        return false, "Unity icall metadata incomplete"
    end

    -- Subnautica classes
    classes.Player  = class_from_name(image_assembly_csharp, "", "Player")
    classes.SubRoot = class_from_name(image_assembly_csharp, "", "SubRoot")
    classes.SeaMoth = class_from_name(image_assembly_csharp, "", "SeaMoth")
    classes.Exosuit = class_from_name(image_assembly_csharp, "", "Exosuit")
    classes.Vehicle = class_from_name(image_assembly_csharp, "", "Vehicle")

    if not classes.Player then
        return false, "Subnautica Player class not found"
    end

    -- Player field offsets
    off.isUnderwater          = field_offset(classes.Player, "isUnderwater")
    off.isUnderwaterForSwim   = field_offset(classes.Player, "isUnderwaterForSwimming")
    off.currentMountedVehicle = field_offset(classes.Player, "currentMountedVehicle")
    off.currentSub            = field_offset(classes.Player, "_currentSub")
    off.motorMode             = field_offset(classes.Player, "motorMode")
    off.precursorOutOfWater   = field_offset(classes.Player, "precursorOutOfWater")
    off.camRoot               = field_offset(classes.Player, "camRoot")

    -- SubRoot offsets
    if classes.SubRoot then
        off.isBase    = field_offset(classes.SubRoot, "isBase")
        off.isCyclops = field_offset(classes.SubRoot, "isCyclops")
    end

    if not off.currentMountedVehicle or not off.currentSub or not off.camRoot then
        return false, "Required Player field offsets missing"
    end

    return true
end

local function resolve_icalls()
    icalls.camera_get_main = resolve_icall_variants("Camera.get_main",
        mono_methods.camera_get_main,
        { "UnityEngine.Camera::get_main()", "UnityEngine.Camera::get_main" })
    icalls.get_transform = resolve_icall_variants("Component.get_transform",
        mono_methods.get_transform,
        { "UnityEngine.Component::get_transform()",
          "UnityEngine.Component::get_transform" })
    icalls.get_position = resolve_icall_variants("Transform.get_position",
        mono_methods.get_position_inj,
        { "UnityEngine.Transform::get_position_Injected(UnityEngine.Vector3&)",
          "UnityEngine.Transform::get_position_Injected" })
    icalls.get_rotation = resolve_icall_variants("Transform.get_rotation",
        mono_methods.get_rotation_inj,
        { "UnityEngine.Transform::get_rotation_Injected(UnityEngine.Quaternion&)",
          "UnityEngine.Transform::get_rotation_Injected" })
    if mono_methods.scene_get_active_inj then
        icalls.scene_get_active = resolve_icall_variants("Scene.GetActive",
            mono_methods.scene_get_active_inj,
            { "UnityEngine.SceneManagement.SceneManager::GetActiveScene_Injected(UnityEngine.SceneManagement.Scene&)",
              "UnityEngine.SceneManagement.SceneManager::GetActiveScene_Injected" })
    end
    return icalls.camera_get_main ~= nil and icalls.get_transform ~= nil
end

-- ── Player singleton discovery via memory scan ──

local mapped_ranges = nil

local function build_mapped_ranges()
    local ranges = {}
    local ok, list = pcall(process.enumerate_ranges, "r--")
    if ok and type(list) == "table" then
        for _, rg in ipairs(list) do
            if rg.base and rg.size and rg.size > 0 then
                ranges[#ranges + 1] = { rg.base, rg.base + rg.size }
            end
        end
    end
    table.sort(ranges, function(a, b) return a[1] < b[1] end)
    mapped_ranges = ranges
end

local function addr_mapped(addr, size)
    if not mapped_ranges then build_mapped_ranges() end
    if not addr or addr == 0 then return false end
    size = size or 1
    local last = addr + size - 1
    for i = 1, #mapped_ranges do
        local rr = mapped_ranges[i]
        if addr >= rr[1] and last < rr[2] then return true end
        if rr[1] > addr then return false end
    end
    return false
end

local function safe_pointer(addr)
    if not addr_mapped(addr, PTR_SIZE) then return nil end
    local ok, v = pcall(memory.read_pointer, addr)
    return (ok and v) or nil
end

local function safe_u8(addr)
    if not addr_mapped(addr, 1) then return nil end
    local ok, v = pcall(memory.read_u8, addr); return ok and v or nil
end

local function safe_u32(addr)
    if not addr_mapped(addr, 4) then return nil end
    local ok, v = pcall(memory.read_u32, addr); return ok and v or nil
end

local function addr_to_pattern(addr)
    local b, v = {}, addr
    for i = 1, 8 do b[i] = string.format("%02X", v & 0xFF); v = v >> 8 end
    return table.concat(b, " ")
end

local function field_is_valid_obj_or_null(addr)
    if not addr then return false end
    if addr == 0 then return true end
    if not addr_mapped(addr, 16) then return false end
    local vt = safe_pointer(addr)
    if not vt or vt == 0 or not addr_mapped(vt, 8) then return false end
    local klass = safe_pointer(vt)
    return klass and addr_mapped(klass, 8) and true or false
end

-- Validate a cached (vtable, player_ptr) pair against the current process.
-- Returns true if the addresses are still valid Player references.
local function validate_cached(vtable, player_ptr)
    if not vtable or not player_ptr or vtable == 0 or player_ptr == 0 then
        return false
    end
    build_mapped_ranges()
    if not addr_mapped(vtable, 0x40) or not addr_mapped(player_ptr, 0x300) then
        return false
    end
    -- Vtable's first 8 bytes must point to the current session's Player class.
    if safe_pointer(vtable) ~= classes.Player then return false end
    -- Player instance's first 8 bytes must be the vtable.
    if safe_pointer(player_ptr) ~= vtable then return false end
    -- Sanity check on a value field.
    local mm = safe_u32(player_ptr + off.motorMode)
    if not mm or mm > 50 then return false end
    return true
end

-- Two-stage scan: find MonoVTable for Player, then find the instance.
-- Returns (player_ptr, vtable) or (nil, errmsg).
local function find_player()
    build_mapped_ranges()

    local pattern = addr_to_pattern(classes.Player)
    local ranges_ok, ranges = pcall(process.enumerate_ranges, "rw-")
    if not ranges_ok or not ranges then
        return nil, "enumerate_ranges failed"
    end

    -- Stage 1: locate the Player MonoVTable.
    local root_domain = native.call(api.get_root_domain, "pointer", {}, {})
    local last_progress_log = 0
    local total_size = 0
    for _, range in ipairs(ranges) do total_size = total_size + range.size end
    local total_mb = math.floor(total_size / (1024 * 1024))

    local vtable = nil
    local scanned = 0
    local range_idx = 0
    local total_ranges = #ranges
    for _, range in ipairs(ranges) do
        range_idx = range_idx + 1
        local ok, hits = pcall(memory.scan, range.base, range.size, pattern)
        if ok and hits then
            for _, h in ipairs(hits) do
                if safe_pointer(h + 0x10) == root_domain then
                    vtable = h
                    break
                end
            end
        end
        if vtable then break end

        scanned = scanned + range.size
        if clock() - last_progress_log > SCAN_PROGRESS_INTERVAL_MS then
            local pct = math.min(50, math.floor(scanned * 50 / total_size))
            local scanned_mb = math.floor(scanned / (1024 * 1024))
            send({ type = "progress", percent = pct,
                message = string.format(
                    "Stage 1/2 (vtable): range %d/%d -- %d MB / %d MB",
                    range_idx, total_ranges, scanned_mb, total_mb) })
            last_progress_log = clock()
        end
    end

    if not vtable then return nil, "Player MonoVTable not found" end

    send({ type = "progress", percent = 50,
        message = string.format("Stage 1/2 complete: vtable = 0x%X", vtable) })

    -- Stage 2: scan for instances starting with the vtable pointer.
    local vt_pattern = addr_to_pattern(vtable)
    local insts = {}
    scanned = 0
    range_idx = 0
    last_progress_log = 0
    for _, range in ipairs(ranges) do
        range_idx = range_idx + 1
        local ok, hits = pcall(memory.scan, range.base, range.size, vt_pattern)
        if ok and hits then
            for _, h in ipairs(hits) do insts[#insts+1] = h end
        end
        scanned = scanned + range.size
        if clock() - last_progress_log > SCAN_PROGRESS_INTERVAL_MS then
            local pct = 50 + math.min(45, math.floor(scanned * 45 / total_size))
            local scanned_mb = math.floor(scanned / (1024 * 1024))
            send({ type = "progress", percent = pct,
                message = string.format(
                    "Stage 2/2 (instance): range %d/%d -- %d MB / %d MB -- %d hits",
                    range_idx, total_ranges, scanned_mb, total_mb, #insts) })
            last_progress_log = clock()
        end
    end

    -- Score by structural validity (sync_block=0, valid ref fields, sane enums).
    local best = nil
    for _, ic in ipairs(insts) do
        local sync = safe_pointer(ic + 0x08)
        local cam  = safe_pointer(ic + off.camRoot)
        local iuw  = safe_pointer(ic + off.isUnderwater)
        local iuw2 = safe_pointer(ic + off.isUnderwaterForSwim)
        local veh  = safe_pointer(ic + off.currentMountedVehicle)
        local sub  = safe_pointer(ic + off.currentSub)
        local mm   = safe_u32(ic + off.motorMode)
        local poow = safe_u8(ic + off.precursorOutOfWater)

        local score = 0
        if sync == 0 then score = score + 2 end
        if mm and mm <= 20 then score = score + 1 end
        if poow and poow <= 1 then score = score + 1 end
        if field_is_valid_obj_or_null(cam) and cam ~= 0 then score = score + 2 end
        if field_is_valid_obj_or_null(iuw) and iuw ~= 0 then score = score + 2 end
        if field_is_valid_obj_or_null(iuw2) and iuw2 ~= 0 then score = score + 2 end
        if field_is_valid_obj_or_null(veh) then score = score + 1 end
        if field_is_valid_obj_or_null(sub) then score = score + 1 end

        if not best or score > best.score then
            best = { ic = ic, score = score }
        end
    end

    if not best or best.score < 8 then
        return nil, string.format(
            "No valid Player instance (best score %d among %d candidates)",
            best and best.score or -1, #insts)
    end

    return best.ic, vtable
end

-- ── Frame reading ──

local function probe_matrix_offset(native_ptr)
    for _, o in ipairs(NATIVE_TRANSFORM_MATRIX_OFFSETS) do
        local m33 = memory.read_f32(native_ptr + o + 15 * 4)
        if m33 and math.abs(m33 - 1.0) < 0.001 then
            local px = memory.read_f32(native_ptr + o + MATRIX_POS_X)
            local py = memory.read_f32(native_ptr + o + MATRIX_POS_Y)
            local pz = memory.read_f32(native_ptr + o + MATRIX_POS_Z)
            if px and py and pz and px == px and py == py and pz == pz
                and math.abs(px) < 1e7 and math.abs(py) < 1e7 and math.abs(pz) < 1e7 then
                return o
            end
        end
    end
    return nil
end

local function read_native_pos(native_ptr)
    if not native_matrix_offset then return nil end
    local b = native_ptr + native_matrix_offset
    local x = memory.read_f32(b + MATRIX_POS_X)
    local y = memory.read_f32(b + MATRIX_POS_Y)
    local z = memory.read_f32(b + MATRIX_POS_Z)
    if not x or x ~= x then return nil end
    return { x = x, y = y, z = z }
end

local function read_native_forward(native_ptr)
    if not native_matrix_offset then return nil end
    local b = native_ptr + native_matrix_offset
    local x = memory.read_f32(b + MATRIX_FWD_X)
    local y = memory.read_f32(b + MATRIX_FWD_Y)
    local z = memory.read_f32(b + MATRIX_FWD_Z)
    if not x or x ~= x then return nil end
    return { x = x, y = y, z = z }
end

local function read_native_up(native_ptr)
    if not native_matrix_offset then return nil end
    local b = native_ptr + native_matrix_offset
    local x = memory.read_f32(b + MATRIX_UP_X)
    local y = memory.read_f32(b + MATRIX_UP_Y)
    local z = memory.read_f32(b + MATRIX_UP_Z)
    if not x or x ~= x then return nil end
    return { x = x, y = y, z = z }
end

local function read_camera()
    if not icalls.camera_get_main then return nil end
    local ok, cam = pcall(native.call, icalls.camera_get_main, "pointer", {}, {})
    if not ok or not cam or cam == 0 then return nil end

    local tok, tf = pcall(native.call, icalls.get_transform, "pointer",
        {"pointer"}, {cam})
    if not tok or not tf or tf == 0 then return nil end

    local pos, fwd, up
    if icalls.get_position then
        if not vec3_buf then vec3_buf = memory.alloc(16) end
        local pok = pcall(native.call, icalls.get_position, "void",
            {"pointer", "pointer"}, {tf, vec3_buf})
        if pok then
            local x = memory.read_f32(vec3_buf)
            local y = memory.read_f32(vec3_buf + 4)
            local z = memory.read_f32(vec3_buf + 8)
            if x and y and z and x == x then pos = { x = x, y = y, z = z } end
        end
    end
    if not pos then
        local native_tf = memory.read_pointer(tf + CACHED_PTR_OFFSET)
        if native_tf and native_tf ~= 0 then
            if not native_matrix_offset then
                native_matrix_offset = probe_matrix_offset(native_tf)
            end
            pos = read_native_pos(native_tf)
        end
    end
    if not pos then return nil end

    if icalls.get_rotation then
        if not quat_buf then quat_buf = memory.alloc(16) end
        local rok = pcall(native.call, icalls.get_rotation, "void",
            {"pointer", "pointer"}, {tf, quat_buf})
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
        local native_tf = memory.read_pointer(tf + CACHED_PTR_OFFSET)
        if native_tf and native_tf ~= 0 and native_matrix_offset then
            fwd = fwd or read_native_forward(native_tf)
            up = up or read_native_up(native_tf)
        end
    end

    return pos, fwd, up
end

-- Subnautica's scene name isn't used for level-change audio routing, so
-- we don't bother with the mono-tracker's SceneManager disasm path.
local function read_scene_name() return "" end

-- ── Player state classification ──

local function classify_player_state()
    if not state.player_ptr then return {} end
    local p = state.player_ptr

    -- Defensive vtable check (Boehm GC is non-moving so this rarely fires).
    local vt = safe_pointer(p)
    if vt ~= state.player_vtable then
        return { vtable_invalidated = true }
    end

    local veh  = safe_pointer(p + off.currentMountedVehicle)
    local sub  = safe_pointer(p + off.currentSub)
    local poow = safe_u8(p + off.precursorOutOfWater)
    local mm   = safe_u32(p + off.motorMode)

    -- Player.isUnderwater is a Utils.MonitoredValue<bool>; the bool sits
    -- at +0x18 (after vtable, sync_block, observers list).
    local is_underwater_game = nil
    if off.isUnderwater then
        local iuw_obj = safe_pointer(p + off.isUnderwater)
        if iuw_obj and iuw_obj ~= 0 and addr_mapped(iuw_obj, 32) then
            local v = safe_u8(iuw_obj + 0x18)
            if v ~= nil then is_underwater_game = (v ~= 0) end
        end
    end

    local veh_class = nil
    if veh and veh ~= 0 then
        local vvt = safe_pointer(veh)
        if vvt then veh_class = safe_pointer(vvt) end
    end
    local in_seamoth     = veh_class == classes.SeaMoth
    local in_exosuit     = veh_class == classes.Exosuit
    local in_any_vehicle = veh ~= nil and veh ~= 0

    local in_base, in_cyclops = false, false
    if sub and sub ~= 0 then
        if off.isBase    then in_base    = (safe_u8(sub + off.isBase)    or 0) ~= 0 end
        if off.isCyclops then in_cyclops = (safe_u8(sub + off.isCyclops) or 0) ~= 0 end
    end
    local in_any_sub = sub ~= nil and sub ~= 0

    -- "In an air pocket" — any sub, vehicle, or Precursor dry zone.
    local in_air = in_any_sub or in_any_vehicle or (poow == 1)
    local radio_access = in_seamoth or in_exosuit or in_cyclops

    -- Room size (meters) drives the listener-room muffle: sounds beyond
    -- this radius from the listener get muffled. 0 disables the effect.
    local room_size = 0
    if in_seamoth or in_exosuit then room_size = 1
    elseif in_cyclops             then room_size = 10
    end

    -- Reverb strength on the listener bus.
    local reverb = 0
    if in_seamoth or in_exosuit then reverb = 0.15
    elseif in_cyclops             then reverb = 0.4
    elseif in_base                then reverb = 0.25
    end

    return {
        vtable_invalidated = false,
        in_seamoth = in_seamoth,
        in_exosuit = in_exosuit,
        in_any_vehicle = in_any_vehicle,
        in_base = in_base,
        in_cyclops = in_cyclops,
        in_any_sub = in_any_sub,
        in_air = in_air,
        radio_access = radio_access,
        room_size = room_size,
        reverb = reverb,
        motor_mode = mm or -1,
        precursor_out_of_water = poow == 1,
        is_underwater_game = is_underwater_game,
    }
end

-- ── Lifecycle ──

local function do_init(init_data)
    send({ type = "progress", percent = 5, message = "Finding Mono runtime..." })
    local ok, err = resolve_mono_module()
    if not ok then
        send({ type = "init-response", success = false, error = err })
        return
    end

    send({ type = "progress", percent = 10, message = "Resolving Mono API..." })
    ok, err = resolve_api()
    if not ok then
        send({ type = "init-response", success = false, error = err })
        return
    end

    send({ type = "progress", percent = 15, message = "Resolving Subnautica classes..." })
    ok, err = resolve_metadata()
    if not ok then
        send({ type = "init-response", success = false, error = err })
        return
    end

    send({ type = "progress", percent = 25, message = "Resolving Unity icalls..." })
    if not resolve_icalls() then
        send({ type = "init-response", success = false,
            error = "Failed to resolve Unity icalls" })
        return
    end

    -- Fast path: try cached addresses from a prior attach to the same process.
    local player_ptr, vtable
    if init_data and init_data.cached_player_ptr and init_data.cached_vtable then
        send({ type = "progress", percent = 28, message = "Validating cached addresses..." })
        if validate_cached(init_data.cached_vtable, init_data.cached_player_ptr) then
            player_ptr = init_data.cached_player_ptr
            vtable    = init_data.cached_vtable
            log(string.format("[Subnautica] Cache HIT -- Player @ 0x%X vtable=0x%X",
                player_ptr, vtable))
            send({ type = "progress", percent = 95, message = "Cache hit -- skipping scan" })
        else
            log("[Subnautica] Cache MISS -- cached addresses no longer valid")
        end
    end

    if not player_ptr then
        send({ type = "progress", percent = 30,
            message = "Scanning for Player (first attach -- may take ~60s)..." })
        local p, vt_or_err = find_player()
        if not p then
            send({ type = "init-response", success = false, error = vt_or_err })
            return
        end
        player_ptr = p
        vtable = vt_or_err
        -- Notify host so it can persist the result for the next attach.
        send({ type = "discovery-complete",
            player_ptr = player_ptr, player_vtable = vtable })
    end

    state.player_ptr = player_ptr
    state.player_vtable = vtable

    state.initialized = true
    state.consecutive_errors = 0
    state.warmup_ticks = 0

    send({ type = "progress", percent = 100, message = "Connected!" })
    send({ type = "init-response", success = true })

    log(string.format("[Subnautica] Player @ 0x%X vtable=0x%X",
        state.player_ptr, state.player_vtable))
end

local function read_frame()
    local pos, fwd, up = read_camera()
    if not pos then return nil end

    local pstate = classify_player_state()

    return {
        type = "data",
        protocol = "subnautica_tracker",
        posX = pos.x, posY = pos.y, posZ = pos.z,
        fwdX = fwd and fwd.x or 0,
        fwdY = fwd and fwd.y or 0,
        fwdZ = fwd and fwd.z or 0,
        upX = up and up.x or 0,
        upY = up and up.y or 1,
        upZ = up and up.z or 0,
        sceneName = "",
        sceneIndex = -1,
        timestamp = clock() * 1000,
        -- Subnautica-specific state
        roomSize       = pstate.room_size,
        reverb         = pstate.reverb,
        inSeamoth      = pstate.in_seamoth,
        inExosuit      = pstate.in_exosuit,
        inAnyVehicle   = pstate.in_any_vehicle,
        inBase         = pstate.in_base,
        inCyclops      = pstate.in_cyclops,
        inAnySub       = pstate.in_any_sub,
        inAir          = pstate.in_air,
        radioAccess    = pstate.radio_access,
        motorMode      = pstate.motor_mode,
        precursorOOW   = pstate.precursor_out_of_water,
        -- Game's own underwater determination (Player.isUnderwater._value).
        -- nil if read failed; consumer should fall back to (posY < 0).
        isUnderwaterGame = pstate.is_underwater_game,
    }
end

local function do_tick()
    if not state.initialized then
        send({ type = "heartbeat", status = "not-initialized" })
        return
    end

    local ok, result = pcall(read_frame)
    if not ok then
        state.consecutive_errors = state.consecutive_errors + 1
        if state.consecutive_errors <= 3 or state.consecutive_errors % 200 == 0 then
            log("[Subnautica] tick err #" .. state.consecutive_errors ..
                ": " .. tostring(result))
        end
    elseif type(result) == "table" then
        send(result)
        state.consecutive_errors = 0
        state.warmup_ticks = 5
        return
    else
        state.warmup_ticks = state.warmup_ticks + 1
        if state.warmup_ticks <= 5 then
            send({ type = "heartbeat", status = "warming-up" })
            return
        end
        state.consecutive_errors = state.consecutive_errors + 1
    end

    send({ type = "heartbeat", status = "no-position",
        errors = state.consecutive_errors })
end

-- ── Message loop ──

send({ type = "heartbeat", status = "loading" })

local function parse_message(msg)
    if type(msg) == "string" then
        if type(json) == "table" and type(json.decode) == "function" then
            local ok, dec = pcall(json.decode, msg)
            if ok and type(dec) == "table" then return dec end
        end
        if msg:find('"type"%s*:%s*"init"')     then return { type = "init" } end
        if msg:find('"type"%s*:%s*"tick"')     then return { type = "tick" } end
        if msg:find('"type"%s*:%s*"shutdown"') then return { type = "shutdown" } end
        return nil
    end
    if type(msg) == "table" then return msg end
    return nil
end

recv(function(message)
    local msg = parse_message(message)
    if not msg or not msg.type then return end
    local ok, err = pcall(function()
        if msg.type == "init" then do_init(msg.data)
        elseif msg.type == "tick" then do_tick()
        elseif msg.type == "shutdown" then
            log("[Subnautica] shutdown")
            state.initialized = false
        end
    end)
    if not ok then
        log("[Subnautica] handler crash: " .. tostring(err))
        if msg.type == "init" then
            send({ type = "init-response", success = false, error = tostring(err) })
        end
    end
end)
