-- DST agent: find lua_pcall → observe to capture lua_State* → walk Lua 5.1
-- internals for ThePlayer.entity (position) and TheCamera (heading/distance).
-- Read-only: memory.read_* + native.observe only.

local PTR = process.get_pointer_size()
local IS_X64 = (PTR == 8)

local LUA_TNIL = 0
local LUA_TBOOLEAN = 1
local LUA_TLIGHTUSERDATA = 2
local LUA_TNUMBER = 3
local LUA_TSTRING = 4
local LUA_TTABLE = 5
local LUA_TFUNCTION = 6
local LUA_TUSERDATA = 7

local TYPE_NAMES = {
    [0] = "nil", [1] = "boolean", [2] = "lightuserdata", [3] = "number",
    [4] = "string", [5] = "table", [6] = "function", [7] = "userdata",
}

local TVALUE_SIZE = 16  -- sizeof(TValue) on MSVC Lua 5.1 (32 and 64-bit)

-- Lua 5.1 MSVC struct offsets (verified empirically).
local OFF = {}
if IS_X64 then
    OFF.L_TOP  = 16;  OFF.L_BASE = 24;  OFF.L_G = 32;  OFF.L_GT = 120
    OFF.TBL_FLAGS = 10;  OFF.TBL_LSIZENODE = 11
    OFF.TBL_META = 16;  OFF.TBL_ARRAY = 24;  OFF.TBL_NODE = 32
    OFF.TBL_SIZEARRAY = 56
    OFF.NODE_SIZE = 40
    OFF.NODE_KEY_VAL = 16;  OFF.NODE_KEY_TT = 24;  OFF.NODE_KEY_NEXT = 32
    OFF.TSTR_LEN = 16;  OFF.TSTR_DATA = 24
    OFF.UDATA_DATA = 40
else
    OFF.L_TOP  = 8;   OFF.L_BASE = 12;  OFF.L_G = 16;  OFF.L_GT = 72
    OFF.TBL_FLAGS = 6;   OFF.TBL_LSIZENODE = 7
    OFF.TBL_META = 8;   OFF.TBL_ARRAY = 12;  OFF.TBL_NODE = 16
    OFF.TBL_SIZEARRAY = 28
    OFF.NODE_SIZE = 32
    OFF.NODE_KEY_VAL = 16;  OFF.NODE_KEY_TT = 24;  OFF.NODE_KEY_NEXT = 28
    OFF.TSTR_LEN = 12;  OFF.TSTR_DATA = 16
    OFF.UDATA_DATA = 20
end

local MAX_SCAN_CHUNK = 0x1000
local MAX_SCAN_MATCHES = 64
local CALL_SCAN_BYTES = 512

local PHASE_IDLE = 0
local PHASE_FINDING_PCALL = 1
local PHASE_OBSERVING = 2
local PHASE_PROBING_STATES = 3
local PHASE_DISCOVERING = 4
local PHASE_READY = 5

local function rptr(addr)
    if not addr or addr == 0 then return nil end
    local ok, v = pcall(memory.read_pointer, addr)
    if not ok or not v or v == 0 then return nil end
    return v
end

local function ru8(addr)
    if not addr or addr == 0 then return nil end
    local ok, v = pcall(memory.read_u8, addr)
    return ok and v or nil
end

local function rs32(addr)
    if not addr or addr == 0 then return nil end
    local ok, v = pcall(memory.read_s32, addr)
    return ok and v or nil
end

local function rf32(addr)
    if not addr or addr == 0 then return nil end
    local ok, v = pcall(memory.read_f32, addr)
    return ok and v or nil
end

local function rf64(addr)
    if not addr or addr == 0 then return nil end
    local ok, v = pcall(memory.read_f64, addr)
    return ok and v or nil
end

local function rutf8(addr, maxlen)
    if not addr or addr == 0 then return nil end
    local ok, v = pcall(memory.read_utf8, addr, maxlen or 256)
    return ok and v or nil
end

local function rbytes(addr, len)
    if not addr or addr == 0 then return nil end
    local ok, v = pcall(memory.read_bytes, addr, len)
    return ok and v or nil
end

-- Returns (type_tag, raw_value): double for numbers, pointer for gc/ptr types.
local function read_tv(addr)
    if not addr or addr == 0 then return nil, nil end
    local tt = rs32(addr + 8)  -- TValue.tt at +8 (after Value union)
    if not tt then return nil, nil end
    if tt == LUA_TNUMBER then
        return tt, rf64(addr)
    elseif tt == LUA_TBOOLEAN then
        return tt, rs32(addr)
    elseif tt == LUA_TNIL then
        return tt, nil
    else
        return tt, rptr(addr)
    end
end

local function read_tstring(ts)
    if not ts then return nil end
    return rutf8(ts + OFF.TSTR_DATA, 256)
end

local function get_globals(L)
    if not L then return nil end
    local tt = rs32(L + OFF.L_GT + 8)
    if tt ~= LUA_TTABLE then return nil end
    return rptr(L + OFF.L_GT)
end

local function validate_table(tbl)
    if not tbl then return false end
    local lsn = ru8(tbl + OFF.TBL_LSIZENODE)
    if not lsn or lsn > 30 then return false end  -- 2^30 nodes = junk pointer
    local node = rptr(tbl + OFF.TBL_NODE)
    if not node then return false end
    local sa = rs32(tbl + OFF.TBL_SIZEARRAY)
    if not sa or sa < 0 or sa > 100000 then return false end
    return true
end

local function tbl_get(tbl, key)
    if not validate_table(tbl) then return nil, nil end
    local lsn = ru8(tbl + OFF.TBL_LSIZENODE)
    local node_base = rptr(tbl + OFF.TBL_NODE)
    local num_nodes = 1
    for _ = 1, lsn do num_nodes = num_nodes * 2 end

    for i = 0, num_nodes - 1 do
        local n = node_base + i * OFF.NODE_SIZE
        local ktt = rs32(n + OFF.NODE_KEY_TT)
        if ktt == LUA_TSTRING then
            local kptr = rptr(n + OFF.NODE_KEY_VAL)
            if kptr then
                local s = read_tstring(kptr)
                if s == key then
                    return read_tv(n)
                end
            end
        end
    end
    return nil, nil
end

-- Diagnostic dump of all non-nil string keys in a table.
local function tbl_keys(tbl, max_keys)
    local out = {}
    if not validate_table(tbl) then return out end
    local lsn = ru8(tbl + OFF.TBL_LSIZENODE)
    local node_base = rptr(tbl + OFF.TBL_NODE)
    local num_nodes = 1
    for _ = 1, lsn do num_nodes = num_nodes * 2 end
    local cap = max_keys or 80

    for i = 0, num_nodes - 1 do
        local n = node_base + i * OFF.NODE_SIZE
        local ktt = rs32(n + OFF.NODE_KEY_TT)
        if ktt and ktt ~= LUA_TNIL then
            local entry = {}
            if ktt == LUA_TSTRING then
                entry.name = read_tstring(rptr(n + OFF.NODE_KEY_VAL)) or "?"
            else
                entry.name = "(" .. (TYPE_NAMES[ktt] or "?") .. ")"
            end
            local vtt, vval = read_tv(n)
            entry.vtt = vtt
            entry.vtt_name = TYPE_NAMES[vtt] or "?"
            if vtt == LUA_TNUMBER then entry.vnum = vval end
            if vtt == LUA_TSTRING then entry.vstr = read_tstring(vval) end
            out[#out + 1] = entry
            if #out >= cap then break end
        end
    end
    return out
end

-- Read a number from a table's array part (1-based).
local function tbl_array_num(tbl, index)
    if not tbl or index < 1 then return nil end
    local sa = rs32(tbl + OFF.TBL_SIZEARRAY)
    if not sa or index > sa then return nil end
    local arr = rptr(tbl + OFF.TBL_ARRAY)
    if not arr then return nil end
    local tt, val = read_tv(arr + (index - 1) * TVALUE_SIZE)
    if tt == LUA_TNUMBER then return val end
    return nil
end

local function find_main_module()
    local names = {
        "dontstarve_steam_x64.exe", "dontstarve_steam.exe",
        "dontstarve_x64.exe", "dontstarve.exe",
    }
    for _, name in ipairs(names) do
        local ok, m = pcall(process.find_module, name)
        if ok and m then return m end
    end
    local ok, mods = pcall(process.enumerate_modules)
    if ok and type(mods) == "table" and #mods > 0 then return mods[1] end
    return nil
end

local function module_contains(m, addr)
    if type(m) ~= "table" then return false end
    return addr >= m.base and addr < (m.base + m.size)
end

local function scan_exports_for(target_name)
    local dll_names = {
        "lua51.dll", "lua5.1.dll", "lua52.dll", "lua53.dll", "lua54.dll", "lua.dll",
    }
    local main = find_main_module()
    if main then dll_names[#dll_names + 1] = main.name end

    for _, mod_name in ipairs(dll_names) do
        local ok, addr = pcall(process.find_export, mod_name, target_name)
        if ok and addr and addr ~= 0 then
            return addr, mod_name
        end
    end
    return nil
end

local function scan_module(m, pattern, max_matches)
    local results = {}
    if not m then return results end
    local cap = max_matches or MAX_SCAN_MATCHES
    local overlap = #pattern - 1
    local offset = 0
    while offset < m.size do
        local chunk = math.min(MAX_SCAN_CHUNK, m.size - offset)
        local addr = m.base + offset
        local ok, bytes = pcall(memory.read_bytes, addr, chunk)
        if ok and bytes then
            local pos = 1
            while true do
                local idx = string.find(bytes, pattern, pos, true)
                if not idx then break end
                results[#results + 1] = addr + (idx - 1)
                if #results >= cap then return results end
                pos = idx + 1
            end
        end
        if (offset + chunk) >= m.size then break end
        offset = offset + chunk - math.max(overlap, 0)
    end
    return results
end

-- Find null-terminated string in module.
local function find_string_in_module(m, str)
    local pattern = string.char(0) .. str .. string.char(0)
    local hits = scan_module(m, pattern, MAX_SCAN_MATCHES)
    local out = {}
    for _, a in ipairs(hits) do out[#out + 1] = a + 1 end  -- skip leading NUL
    if #out == 0 then
        -- Fallback: strings at section start have no leading NUL.
        hits = scan_module(m, str .. string.char(0), MAX_SCAN_MATCHES)
        for _, a in ipairs(hits) do out[#out + 1] = a end
    end
    return out
end

local function ptr_bytes(value)
    local t = {}
    local x = value
    for _ = 1, PTR do
        t[#t + 1] = string.char(x % 256)
        x = (x - (x % 256)) / 256
    end
    return table.concat(t)
end

local function find_ptr_refs(m, ptr_val)
    return scan_module(m, ptr_bytes(ptr_val), MAX_SCAN_MATCHES)
end

-- Find the C function registered via luaL_Reg for a given name.
local function find_reg_func(m, str_addrs)
    for _, sa in ipairs(str_addrs) do
        local refs = find_ptr_refs(m, sa)
        for _, ref in ipairs(refs) do
            local fptr = rptr(ref + PTR)
            if fptr and module_contains(m, fptr) then
                return fptr
            end
        end
    end
    return nil
end

-- Extract E8 near-call targets from the first max_bytes of a function.
local function get_call_targets(m, faddr, max_bytes)
    local out = {}
    local bytes = rbytes(faddr, max_bytes or CALL_SCAN_BYTES)
    if not bytes then return out end
    for i = 1, #bytes - 4 do
        if string.byte(bytes, i) == 0xE8 then
            local b1, b2, b3, b4 = string.byte(bytes, i+1, i+4)
            local rel = b1 + b2*0x100 + b3*0x10000 + b4*0x1000000
            if rel >= 0x80000000 then rel = rel - 0x100000000 end
            local target = faddr + (i-1) + 5 + rel
            if module_contains(m, target) then
                out[#out + 1] = target
            end
        end
    end
    return out
end

local function find_lua_pcall()
    -- Try direct export first.
    local addr, from = scan_exports_for("lua_pcall")
    if addr then
        log("[+] lua_pcall via export: " .. tostring(addr) .. " (" .. from .. ")")
        return addr
    end
    addr, from = scan_exports_for("lua_pcallk")
    if addr then
        log("[+] lua_pcallk via export: " .. tostring(addr) .. " (" .. from .. ")")
        return addr
    end

    -- Fallback: locate luaB_pcall via luaL_Reg and disassemble its call targets.
    local m = find_main_module()
    if not m then return nil end
    log("[*] Scanning " .. m.name .. " for lua_pcall via luaL_Reg...")

    local pcall_strs = find_string_in_module(m, "pcall")
    if #pcall_strs == 0 then
        log("[-] String 'pcall' not found in module")
        return nil
    end
    log("[+] Found 'pcall' at " .. #pcall_strs .. " location(s)")

    local luaB_pcall = find_reg_func(m, pcall_strs)
    if not luaB_pcall then
        log("[-] luaB_pcall not found via luaL_Reg")
        return nil
    end
    log("[+] luaB_pcall @ " .. tostring(luaB_pcall))

    -- luaB_pcall's 3rd call (after luaL_checkany, lua_gettop) is lua_pcall.
    local targets = get_call_targets(m, luaB_pcall, CALL_SCAN_BYTES)
    if #targets >= 3 then
        log("[+] lua_pcall (3rd call target) @ " .. tostring(targets[3]))
        return targets[3]
    elseif #targets >= 2 then
        log("[+] lua_pcall (2nd call target) @ " .. tostring(targets[2]))
        return targets[2]
    end

    log("[-] Could not resolve lua_pcall from luaB_pcall calls")
    return nil
end

-- Camera ref position (set during init if camera found). Player must be
-- within ~100 units of camera, which rejects bogus probe hits.
local cam_ref_x, cam_ref_z = nil, nil

-- DST is isometric: x,z in [-600, 600], y near 0.
local function is_coord_triple(v1, v2, v3)
    if not v1 or not v2 or not v3 then return false end
    if v1 ~= v1 or v2 ~= v2 or v3 ~= v3 then return false end
    if math.abs(v1) > 0 and math.abs(v1) < 1e-30 then return false end
    if math.abs(v2) > 0 and math.abs(v2) < 1e-30 then return false end
    if math.abs(v3) > 0 and math.abs(v3) < 1e-30 then return false end
    if math.abs(v1) > 800 or math.abs(v3) > 800 then return false end
    if math.abs(v2) > 50 then return false end
    if math.abs(v1) < 1.0 and math.abs(v3) < 1.0 then return false end
    if cam_ref_x and cam_ref_z then
        local dx = math.abs(v1 - cam_ref_x)
        local dz = math.abs(v3 - cam_ref_z)
        if dx > 100 or dz > 100 then return false end
    end
    return true
end

-- Probe object for 3 consecutive coord-shaped floats/doubles. Tries direct
-- offsets, then one level of pointer indirection. Returns probe table or nil.
local function probe_position(base, scan_size)
    if not base then return nil end
    scan_size = scan_size or 1500

    -- Doubles first — Lua 5.1 uses doubles, engine sometimes matches.
    for off = 0, scan_size - 24, 8 do
        local a, b, c = rf64(base + off), rf64(base + off + 8), rf64(base + off + 16)
        if is_coord_triple(a, b, c) then
            return { ptr = base, offset = off, elem = 8 }
        end
    end

    for off = 0, scan_size - 12, 4 do
        local a, b, c = rf32(base + off), rf32(base + off + 4), rf32(base + off + 8)
        if is_coord_triple(a, b, c) then
            return { ptr = base, offset = off, elem = 4 }
        end
    end

    -- One level of pointer indirection.
    for off = 0, math.min(scan_size, 400) - PTR, PTR do
        local p = rptr(base + off)
        if p then
            for io = 0, 200 - 24, 8 do
                local a, b, c = rf64(p + io), rf64(p + io + 8), rf64(p + io + 16)
                if is_coord_triple(a, b, c) then
                    return { ptr = base, ptr_off = off, offset = io, elem = 8, indirect = true }
                end
            end
            for io = 0, 200 - 12, 4 do
                local a, b, c = rf32(p + io), rf32(p + io + 4), rf32(p + io + 8)
                if is_coord_triple(a, b, c) then
                    return { ptr = base, ptr_off = off, offset = io, elem = 4, indirect = true }
                end
            end
        end
    end

    return nil
end

local function read_position(probe)
    if not probe then return nil end
    local base = probe.ptr
    if probe.indirect then
        base = rptr(base + probe.ptr_off)
        if not base then return nil end
    end
    local rd = probe.elem == 4 and rf32 or rf64
    local x = rd(base + probe.offset)
    local y = rd(base + probe.offset + probe.elem)
    local z = rd(base + probe.offset + probe.elem * 2)
    if x and y and z and x == x and y == y and z == z then
        return x, y, z
    end
    return nil
end

local state = {
    phase = PHASE_IDLE,
    lua_pcall_addr = nil,
    observer = nil,
    captured_states = {},
    main_state = nil,
    globals_tbl = nil,
    player_tbl = nil,
    camera_tbl = nil,
    entity_ptr = nil,
    pos_probe = nil,
    has_camera_position = false,
    consecutive_errors = 0,
    ticks = 0,
    init_start = 0,
    init_timeout = 45000,
    last_diag = 0,
}

local function send_progress(msg, pct)
    send({ type = "progress", message = msg, percent = pct })
end

local function fail_init(err)
    log("[FAIL] " .. tostring(err))
    if state.observer then
        pcall(function() state.observer:detach() end)
        state.observer = nil
    end
    send({ type = "init-response", success = false, error = tostring(err) })
    state.phase = PHASE_IDLE
end

local function complete_init()
    if state.observer then
        pcall(function() state.observer:detach() end)
        state.observer = nil
    end
    state.phase = PHASE_READY
    state.consecutive_errors = 0
    local has_pos = state.pos_probe ~= nil
    send({
        type = "init-response",
        success = true,
        hasCameraPosition = state.has_camera_position,
        hasPosition = has_pos,
    })
    log("========================================")
    log("  DST Tracker Initialized (Compliant)")
    log("  Position: " .. (has_pos and "yes" or "NO (camera-only)"))
    log("  Camera 3D: " .. (state.has_camera_position and "yes" or "no"))
    log("  Camera table: " .. (state.camera_tbl and "yes" or "no"))
    log("========================================")
end

local function do_find_pcall()
    send_progress("Finding Lua runtime...", 10)
    local addr = find_lua_pcall()
    if not addr then
        fail_init("Could not find lua_pcall in process")
        return
    end
    state.lua_pcall_addr = addr
    state.phase = PHASE_OBSERVING
end

local function do_start_observe()
    send_progress("Observing Lua calls...", 20)
    local obs, err = native.observe(state.lua_pcall_addr, { count = 5000, max_args = 1 })
    if not obs then
        fail_init("native.observe failed: " .. tostring(err))
        return
    end
    state.observer = obs
    state.phase = PHASE_PROBING_STATES
    log("[+] Observing lua_pcall — waiting for states...")
end

local function do_probe_states()
    if not state.observer or not state.observer:is_active() then
        local count = 0
        for _ in pairs(state.captured_states) do count = count + 1 end
        if count == 0 then
            fail_init("Observer exhausted without capturing any states")
            return
        end
        state.phase = PHASE_DISCOVERING
        return
    end

    local results = state.observer:results()
    if results then
        for _, cap in ipairs(results) do
            local L = cap.args and cap.args[0]
            if L and L ~= 0 then
                local key = tostring(L)
                if not state.captured_states[key] then
                    state.captured_states[key] = { ptr = L, count = 1 }
                    log("[+] Captured lua_State: " .. key)
                else
                    state.captured_states[key].count = state.captured_states[key].count + 1
                end
            end
        end
    end

    -- Require enough samples that the busiest state is unambiguous.
    local best_key, best_count = nil, 0
    for k, v in pairs(state.captured_states) do
        if v.count > best_count then
            best_key = k
            best_count = v.count
        end
    end

    if best_count >= 10 then
        send_progress("Probing Lua states...", 35)
        state.phase = PHASE_DISCOVERING
    end
end

local discover_camera
local discover_position

local function do_discover()
    send_progress("Searching for ThePlayer...", 40)

    -- Busiest state first.
    local sorted = {}
    for _, v in pairs(state.captured_states) do
        sorted[#sorted + 1] = v
    end
    table.sort(sorted, function(a, b) return a.count > b.count end)

    for _, entry in ipairs(sorted) do
        local L = entry.ptr
        local globals = get_globals(L)
        if globals and validate_table(globals) then
            log("[*] State " .. tostring(L) .. " — globals table @ " .. tostring(globals))

            local ptt, pval = tbl_get(globals, "ThePlayer")
            if ptt == LUA_TTABLE and pval then
                log("[+] ThePlayer found (table @ " .. tostring(pval) .. ")")
                state.main_state = L
                state.globals_tbl = globals
                state.player_tbl = pval

                local keys = tbl_keys(pval, 40)
                log("[*] ThePlayer has " .. #keys .. " hash entries:")
                for _, k in ipairs(keys) do
                    local info = "  " .. (k.name or "?") .. " : " .. (k.vtt_name or "?")
                    if k.vnum then info = info .. " = " .. tostring(k.vnum) end
                    if k.vstr then info = info .. " = \"" .. k.vstr .. "\"" end
                    log(info)
                end

                local ctt, cval = tbl_get(globals, "TheCamera")
                if ctt == LUA_TTABLE and cval then
                    log("[+] TheCamera found (table @ " .. tostring(cval) .. ")")
                    state.camera_tbl = cval
                elseif ctt == LUA_TUSERDATA and cval then
                    log("[+] TheCamera found (userdata @ " .. tostring(cval) .. ")")
                    -- Userdata-backed camera class; can't walk its hash.
                    state.camera_tbl = nil
                else
                    log("[!] TheCamera not found or nil (tt=" .. tostring(ctt) .. ")")
                end

                if state.camera_tbl then
                    send_progress("Reading camera data...", 55)
                    discover_camera(state.camera_tbl)
                end

                send_progress("Locating player position...", 65)
                discover_position(state.player_tbl, state.globals_tbl)

                complete_init()
                return

            elseif ptt == LUA_TNIL or not ptt then
                log("[*] State " .. tostring(L) .. " — ThePlayer is nil (menu/loading?)")
            else
                log("[*] State " .. tostring(L) .. " — ThePlayer type=" ..
                    tostring(TYPE_NAMES[ptt] or ptt))
            end
        else
            log("[*] State " .. tostring(L) .. " — no valid globals table")
        end
    end

    -- ThePlayer not in any state yet (menu/loading) — keep polling.
    state.phase = PHASE_PROBING_STATES
end

discover_camera = function(cam_tbl)
    local keys = tbl_keys(cam_tbl, 40)
    log("[*] TheCamera has " .. #keys .. " hash entries:")
    for _, k in ipairs(keys) do
        local info = "  " .. (k.name or "?") .. " : " .. (k.vtt_name or "?")
        if k.vnum then info = info .. " = " .. string.format("%.4f", k.vnum) end
        log(info)
    end

    local htt, hval = tbl_get(cam_tbl, "heading")
    if htt == LUA_TNUMBER then
        log("[+] Camera heading = " .. string.format("%.2f", hval))
    else
        htt, hval = tbl_get(cam_tbl, "headingtarget")
        if htt == LUA_TNUMBER then
            log("[+] Camera headingtarget = " .. string.format("%.2f", hval))
        end
    end

    local dtt, dval = tbl_get(cam_tbl, "distance")
    if dtt == LUA_TNUMBER then
        log("[+] Camera distance = " .. string.format("%.2f", dval))
    else
        dtt, dval = tbl_get(cam_tbl, "distancetarget")
        if dtt == LUA_TNUMBER then
            log("[+] Camera distancetarget = " .. string.format("%.2f", dval))
        end
    end

    local xtt, xval = tbl_get(cam_tbl, "currentpos")
    if xtt == LUA_TTABLE then
        -- currentpos: {x,y,z} table on some camera implementations.
        local cx_tt, cx = tbl_get(xval, "x")
        local cy_tt, cy = tbl_get(xval, "y")
        local cz_tt, cz = tbl_get(xval, "z")
        if cx_tt == LUA_TNUMBER and cy_tt == LUA_TNUMBER and cz_tt == LUA_TNUMBER then
            state.has_camera_position = true
            cam_ref_x = cx
            cam_ref_z = cz
            log("[+] Camera 3D position: " .. string.format("%.2f, %.2f, %.2f", cx, cy, cz))
        end
    end
end

discover_position = function(player_tbl, globals_tbl)
    log("[*] Position probing with cam_ref: " ..
        (cam_ref_x and string.format("(%.1f, %.1f)", cam_ref_x, cam_ref_z) or "none"))

    -- ThePlayer.entity (lightuserdata) → C++ Entity. Heap position on some
    -- Entity shapes is stale; probe scans for a live-looking triple.
    local ett, eval = tbl_get(player_tbl, "entity")
    if ett == LUA_TLIGHTUSERDATA and eval then
        log("[+] ThePlayer.entity (lightuserdata) @ " .. tostring(eval))
        state.entity_ptr = eval
        local probe = probe_position(eval, 2000)
        if probe then
            local x, y, z = read_position(probe)
            log("[+] Position in entity: off=" .. probe.offset ..
                " elem=" .. probe.elem .. (probe.indirect and " indirect" or "") ..
                " val=(" .. tostring(x) .. ", " .. tostring(y) .. ", " .. tostring(z) .. ")")
            state.pos_probe = probe
            return
        else
            log("[!] No coordinate-like data in entity memory")
        end
    elseif ett == LUA_TUSERDATA and eval then
        log("[+] ThePlayer.entity (userdata) @ " .. tostring(eval))
        -- Payload offset varies with exact Lua build — try several.
        for _, data_off in ipairs({OFF.UDATA_DATA, OFF.UDATA_DATA - 8, OFF.UDATA_DATA + 8, 16, 24, 32}) do
            local cpp_ptr = rptr(eval + data_off)
            if cpp_ptr then
                local probe = probe_position(cpp_ptr, 2000)
                if probe then
                    local x, y, z = read_position(probe)
                    log("[+] Position via entity userdata+" .. data_off ..
                        " → " .. tostring(cpp_ptr) .. ": off=" .. probe.offset ..
                        " elem=" .. probe.elem ..
                        " val=(" .. string.format("%.2f, %.2f, %.2f", x or 0, y or 0, z or 0) .. ")")
                    state.entity_ptr = cpp_ptr
                    state.pos_probe = probe
                    return
                end
            end
        end
        -- Read the userdata body as a direct C++ object.
        local probe = probe_position(eval, 2000)
        if probe then
            local x, y, z = read_position(probe)
            log("[+] Position in entity userdata directly: off=" .. probe.offset ..
                " val=(" .. string.format("%.2f, %.2f, %.2f", x or 0, y or 0, z or 0) .. ")")
            state.entity_ptr = eval
            state.pos_probe = probe
            return
        end
        log("[!] No position in entity userdata at any payload offset")
    else
        log("[!] ThePlayer.entity not found (tt=" .. tostring(ett) .. ")")
    end

    -- Fallback: ThePlayer.Transform (some builds cache it here).
    local ttt, tval = tbl_get(player_tbl, "Transform")
    if ttt == LUA_TUSERDATA and tval then
        log("[+] ThePlayer.Transform (userdata) @ " .. tostring(tval))
        local cpp = rptr(tval + OFF.UDATA_DATA)
        if cpp then
            local probe = probe_position(cpp, 1500)
            if probe then
                log("[+] Position found in Transform: offset=" .. probe.offset)
                state.pos_probe = probe
                return
            end
        end
    elseif ttt == LUA_TLIGHTUSERDATA and tval then
        log("[+] ThePlayer.Transform (lightuserdata) @ " .. tostring(tval))
        local probe = probe_position(tval, 1500)
        if probe then
            log("[+] Position found in Transform lightuserdata: offset=" .. probe.offset)
            state.pos_probe = probe
            return
        end
    end

    -- Fallback: scan every lightuserdata/userdata field on ThePlayer.
    log("[*] Scanning all lightuserdata/userdata fields in ThePlayer...")
    local lsn = ru8(player_tbl + OFF.TBL_LSIZENODE) or 0
    local node_base = rptr(player_tbl + OFF.TBL_NODE)
    if node_base then
        local num_nodes = 1
        for _ = 1, lsn do num_nodes = num_nodes * 2 end
        local tried = 0
        for i = 0, num_nodes - 1 do
            local n = node_base + i * OFF.NODE_SIZE
            local vtt, vval = read_tv(n)
            if (vtt == LUA_TLIGHTUSERDATA or vtt == LUA_TUSERDATA) and vval then
                tried = tried + 1
                local target = vval
                if vtt == LUA_TUSERDATA then
                    target = rptr(vval + OFF.UDATA_DATA) or vval
                end
                local probe = probe_position(target, 1000)
                if probe then
                    local ktt = rs32(n + OFF.NODE_KEY_TT)
                    local kname = "?"
                    if ktt == LUA_TSTRING then
                        kname = read_tstring(rptr(n + OFF.NODE_KEY_VAL)) or "?"
                    end
                    log("[+] Position found via field '" .. kname .. "' @ " .. tostring(target))
                    state.entity_ptr = target
                    state.pos_probe = probe
                    return
                end
            end
            if tried >= 30 then break end
        end
        log("[!] Scanned " .. tried .. " ptr fields, no position found")
    end

    -- Fallback: Physics component also carries position in DST.
    local phtt, phval = tbl_get(player_tbl, "Physics")
    if (phtt == LUA_TUSERDATA or phtt == LUA_TLIGHTUSERDATA) and phval then
        local target = phval
        if phtt == LUA_TUSERDATA then
            target = rptr(phval + OFF.UDATA_DATA) or phval
        end
        local probe = probe_position(target, 1000)
        if probe then
            log("[+] Position found via Physics component")
            state.pos_probe = probe
            return
        end
    end

    log("[!] Position discovery FAILED — running in camera-only mode")
end

local function do_tick()
    if state.phase ~= PHASE_READY then return end

    -- ThePlayer can go nil on death/reload — re-validate periodically.
    if state.ticks % 100 == 0 then
        local ptt = tbl_get(state.globals_tbl, "ThePlayer")
        if ptt == LUA_TNIL or not ptt then
            log("[!] ThePlayer became nil — waiting for respawn")
            send({ type = "heartbeat", status = "no-player" })
            return
        end
    end

    local heading, distance, pitch = nil, nil, nil
    if state.camera_tbl then
        local htt, hval = tbl_get(state.camera_tbl, "heading")
        if htt == LUA_TNUMBER then heading = hval end
        if not heading then
            htt, hval = tbl_get(state.camera_tbl, "headingtarget")
            if htt == LUA_TNUMBER then heading = hval end
        end

        local dtt, dval = tbl_get(state.camera_tbl, "distance")
        if dtt == LUA_TNUMBER then distance = dval end
        if not distance then
            dtt, dval = tbl_get(state.camera_tbl, "distancetarget")
            if dtt == LUA_TNUMBER then distance = dval end
        end

        local ptt, pval = tbl_get(state.camera_tbl, "pitch")
        if ptt == LUA_TNUMBER then pitch = pval end
    end

    local camX, camY, camZ = nil, nil, nil
    if state.has_camera_position and state.camera_tbl then
        local cptt, cpval = tbl_get(state.camera_tbl, "currentpos")
        if cptt == LUA_TTABLE then
            local _, cx = tbl_get(cpval, "x")
            local _, cy = tbl_get(cpval, "y")
            local _, cz = tbl_get(cpval, "z")
            if cx and cy and cz then
                camX, camY, camZ = cx, cy, cz
            end
        end
    end

    local posX, posY, posZ = nil, nil, nil
    if state.pos_probe then
        posX, posY, posZ = read_position(state.pos_probe)
    end

    if posX or heading then
        local payload = { type = "data" }
        if posX then
            payload.posX = posX
            payload.posY = posY
            payload.posZ = posZ
        end
        if heading then payload.camHeading = heading end
        if distance then payload.camDistance = distance end
        if pitch then payload.camPitch = pitch end
        if camX then
            payload.camX = camX
            payload.camY = camY
            payload.camZ = camZ
        end
        payload.timestamp = clock()

        send(payload)
        state.consecutive_errors = 0
    else
        state.consecutive_errors = state.consecutive_errors + 1
        if state.consecutive_errors <= 3 or state.consecutive_errors % 200 == 0 then
            log("[!] No data (err count: " .. state.consecutive_errors .. ")")
        end
        -- Heartbeat = alive but no position; engine handles process exit.
        send({ type = "heartbeat", status = "no-position",
            errors = state.consecutive_errors })
    end
end

local function handle_init()
    log("====================================")
    log("  DST Tracker (Compliant Lua)")
    log("  PTR=" .. PTR .. " " .. (IS_X64 and "x64" or "x86"))
    log("====================================")

    state.phase = PHASE_FINDING_PCALL
    state.captured_states = {}
    state.main_state = nil
    state.globals_tbl = nil
    state.player_tbl = nil
    state.camera_tbl = nil
    state.entity_ptr = nil
    state.pos_probe = nil
    state.has_camera_position = false
    state.consecutive_errors = 0
    state.ticks = 0
    state.init_start = clock()

    do_find_pcall()
    if state.phase ~= PHASE_OBSERVING then return end

    do_start_observe()
    if state.phase ~= PHASE_PROBING_STATES then return end

    -- Busy-poll up to 5s while the game thread feeds the observer ring.
    log("[*] Busy-polling observer for lua_State* captures...")
    local poll_deadline = clock() + 5000
    while clock() < poll_deadline do
        do_probe_states()
        if state.phase == PHASE_DISCOVERING then
            break
        end
    end

    if state.phase == PHASE_DISCOVERING then
        do_discover()
    else
        log("[*] No states found yet in busy-wait, switching to tick-driven polling")
    end
end

local function handle_tick()
    state.ticks = state.ticks + 1

    if state.phase == PHASE_PROBING_STATES then
        if (clock() - state.init_start) > state.init_timeout then
            fail_init("Timeout: could not find ThePlayer after " ..
                      state.init_timeout / 1000 .. "s")
            return
        end
        do_probe_states()
        if state.phase == PHASE_DISCOVERING then
            do_discover()
        end

    elseif state.phase == PHASE_DISCOVERING then
        do_discover()

    elseif state.phase == PHASE_READY then
        do_tick()
    end
end

local function handle_shutdown()
    log("[!] Shutdown requested")
    if state.observer then
        pcall(function() state.observer:detach() end)
        state.observer = nil
    end
    state.phase = PHASE_IDLE
end

send({ type = "heartbeat", status = "loading" })
log("[*] DST Tracker (Compliant Lua) loaded, waiting for init...")

recv(function(message)
    local ok, err = pcall(function()
        local msg = message
        if type(msg) == "string" then
            if type(json) == "table" and json.decode then
                local dok, decoded = pcall(json.decode, msg)
                if dok then msg = decoded end
            end
        end

        if type(msg) ~= "table" then return end

        if msg.type == "init" then
            handle_init()
        elseif msg.type == "tick" then
            handle_tick()
        elseif msg.type == "shutdown" then
            handle_shutdown()
        end
    end)

    if not ok then
        log("[!] Handler error: " .. tostring(err))
        state.consecutive_errors = (state.consecutive_errors or 0) + 1
        if state.consecutive_errors >= 20 and state.phase ~= PHASE_IDLE then
            send({ type = "fatal-error", error = "Agent crashed: " .. tostring(err) })
            state.phase = PHASE_IDLE
        end
    end
end)
