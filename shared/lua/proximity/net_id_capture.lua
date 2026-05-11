-- SHARED / VENDORED SOURCE.
-- This file is the single source of truth for the net_id_capture
-- subscript. At build time, .github/scripts/build_zip.sh copies this
-- file into each bridge zip as `net_id_capture.lua` according to that
-- bridge's `.catalog-vendor.json`. Do not edit per-bridge copies; they
-- do not exist in the source tree.

-- Generic networking-session-ID detector loaded alongside the main
-- tracker. Probes loaded SDKs (Steam currently; EOS/Photon planned)
-- and emits source-prefixed IDs (steam_lobby:..., steam_server:...)
-- only for CONFIRMED active sessions — rejecting unvalidated
-- candidates avoids leaking master-server IDs shared across thousands
-- of unrelated players.
--
-- Cadence: scan once on first tick, revalidate cached ID every ~3s,
-- full re-scan every ~30s.

local PTR_SIZE = process.get_pointer_size()

local POLL_VALIDATE_MS = 3000
local POLL_RESCAN_MS   = 30000

local last_emitted_id = nil

local function tagged_send(tbl)
    if type(sendTagged) == "function" then sendTagged(tbl) else send(tbl) end
end

local function emit_session(id, source, extra)
    if id == last_emitted_id then return end
    last_emitted_id = id
    local payload = {
        type = "session-id",
        id = id,
        source = source,
    }
    if type(extra) == "table" then
        for k, v in pairs(extra) do payload[k] = v end
    end
    tagged_send(payload)
    log("net_id_capture: session " .. tostring(source) .. " -> " .. tostring(id))
end

local function emit_clear(reason)
    if last_emitted_id == nil then return end
    last_emitted_id = nil
    tagged_send({ type = "session-id", id = nil, reason = reason })
    log("net_id_capture: session cleared (" .. tostring(reason) .. ")")
end

-- Steamworks helpers

local STEAM_DLL_CANDIDATES = { "steam_api64.dll", "steam_api.dll" }
local steam_dll = nil
for _, n in ipairs(STEAM_DLL_CANDIDATES) do
    if process.find_module(n) then steam_dll = n; break end
end

-- Returns nil silently if the export isn't present (SDK version varies).
local function resolve_steam(name)
    if not steam_dll then return nil end
    local ok, addr = pcall(process.find_export, steam_dll, name)
    if not ok or not addr or addr == 0 then return nil end
    local lk_ok, resolved, err = pcall(native.lookup, steam_dll, name, addr)
    if not lk_ok or err or not resolved or resolved == 0 then return nil end
    return resolved
end

-- Each Steamworks update bumps the version suffix; fall through the list.
local function resolve_steam_first(names)
    for _, n in ipairs(names) do
        local a = resolve_steam(n)
        if a then return a, n end
    end
    return nil
end

local steam = {}

if steam_dll then
    log("net_id_capture: steam dll found = " .. steam_dll)

    steam.user_accessor = resolve_steam_first({
        "SteamAPI_SteamUser_v023",
        "SteamAPI_SteamUser_v022",
        "SteamAPI_SteamUser_v021",
        "SteamAPI_SteamUser_v020",
        "SteamAPI_SteamUser_v019",
    })
    steam.get_user_steam_id = resolve_steam("SteamAPI_ISteamUser_GetSteamID")

    steam.mm_accessor = resolve_steam("SteamAPI_SteamMatchmaking_v009")
    steam.mm_num_members = resolve_steam("SteamAPI_ISteamMatchmaking_GetNumLobbyMembers")
    steam.mm_owner = resolve_steam("SteamAPI_ISteamMatchmaking_GetLobbyOwner")
    steam.mm_data = resolve_steam("SteamAPI_ISteamMatchmaking_GetLobbyData")

    -- Dedicated-server hosts only.
    steam.gs_accessor = resolve_steam_first({
        "SteamAPI_SteamGameServer_v015",
        "SteamAPI_SteamGameServer_v014",
        "SteamAPI_SteamGameServer_v013",
    })
    steam.gs_get_id = resolve_steam("SteamAPI_ISteamGameServer_GetSteamID")
    steam.gs_logged_on = resolve_steam("SteamAPI_ISteamGameServer_BLoggedOn")
end

-- Cached once the game has loaded the accessor's underlying singletons.
local steam_iface = {
    user = nil,
    matchmaking = nil,
    game_server = nil,
}

local function fetch_steam_user()
    if steam_iface.user then return steam_iface.user end
    if not steam.user_accessor then return nil end
    local ok, p = pcall(native.call, steam.user_accessor, "pointer", {}, {})
    if ok and p and p ~= 0 then steam_iface.user = p; return p end
    return nil
end

local function fetch_steam_matchmaking()
    if steam_iface.matchmaking then return steam_iface.matchmaking end
    if not steam.mm_accessor then return nil end
    local ok, p = pcall(native.call, steam.mm_accessor, "pointer", {}, {})
    if ok and p and p ~= 0 then steam_iface.matchmaking = p; return p end
    return nil
end

local function fetch_steam_gameserver()
    if steam_iface.game_server then return steam_iface.game_server end
    if not steam.gs_accessor then return nil end
    local ok, p = pcall(native.call, steam.gs_accessor, "pointer", {}, {})
    if ok and p and p ~= 0 then steam_iface.game_server = p; return p end
    return nil
end

-- Returns (id_string, num_members, owner_id_string) on success, else nil.
local function validate_steam_lobby(candidate_u64)
    if not steam.mm_num_members or not steam.mm_owner then return nil end
    local mm = fetch_steam_matchmaking()
    if not mm then return nil end

    local ok_n, num = pcall(native.call, steam.mm_num_members, "int",
        {"pointer", "uint64"}, {mm, candidate_u64})
    if not ok_n or not num or num <= 0 then return nil end

    local ok_o, owner = pcall(native.call, steam.mm_owner, "uint64",
        {"pointer", "uint64"}, {mm, candidate_u64})
    if not ok_o or not owner or owner == 0 then return nil end

    return tostring(candidate_u64), num, tostring(owner)
end

-- A Steam lobby ID is a 64-bit CSteamID; upper 32 bits encode
-- (EUniverse << 24) | EAccountType. Lobbies settle to one of these
-- 4-byte upper-half patterns. Scan for the pattern, then read the
-- low 4 bytes preceding it as the account ID.
local LOBBY_HIGH_BYTE_PATTERNS = {
    "00 00 86 01",  -- EUniverse=Public(1), EAccountType=Chat(8) | inst flags
    "00 00 80 01",  -- alternate lobby flag combination
}

local function scan_steam_lobby_candidates(max_candidates)
    max_candidates = max_candidates or 32
    local found = {}
    local seen = {}

    local ok, ranges = pcall(process.enumerate_ranges, "rw-")
    if not ok or type(ranges) ~= "table" then return found end

    for pi = 1, #LOBBY_HIGH_BYTE_PATTERNS do
        local pattern = LOBBY_HIGH_BYTE_PATTERNS[pi]
        for ri = 1, #ranges do
            if #found >= max_candidates then break end
            local r = ranges[ri]
            if r.size and r.size > 1024 and r.size < 50 * 1024 * 1024 then
                local r_base = r.base
                local r_end = r.base + r.size
                local ok_scan, hits = pcall(memory.scan, r.base, r.size, pattern)
                if ok_scan and type(hits) == "table" then
                    for hi = 1, #hits do
                        if #found >= max_candidates then break end
                        local high_addr = hits[hi]
                        local low_addr = high_addr - 4
                        -- Bounds check the 8-byte read window — Frida's
                        -- GUM exceptor does NOT catch SEH violations in
                        -- the Windows agent context, so an unmapped read
                        -- crashes the target game.
                        if low_addr >= r_base and high_addr + 4 <= r_end then
                            local ok_low, low = pcall(memory.read_u32, low_addr)
                            local ok_high, high = pcall(memory.read_u32, high_addr)
                            if ok_low and ok_high and low and high then
                                -- Lua 5.4 native int64 in Frida Lua backend.
                                local id64 = (high << 32) | low
                                if not seen[id64] and id64 ~= 0 then
                                    seen[id64] = true
                                    found[#found + 1] = id64
                                end
                            end
                        end
                    end
                end
            end
        end
        if #found >= max_candidates then break end
    end

    return found
end

local function check_steam_lobby()
    if not steam.mm_accessor then return false end

    local candidates = scan_steam_lobby_candidates(64)
    if #candidates == 0 then return false end

    for _, cand in ipairs(candidates) do
        local id_str, members, owner = validate_steam_lobby(cand)
        if id_str then
            -- Best-effort lobby name for context.
            local extra = {
                memberCount = members,
                ownerSteamId = owner,
            }
            if steam.mm_data then
                local mm = fetch_steam_matchmaking()
                local key_buf = memory.alloc_utf8("name")
                local ok_d, ptr = pcall(native.call, steam.mm_data, "pointer",
                    {"pointer", "uint64", "pointer"}, {mm, cand, key_buf})
                if ok_d and ptr and ptr ~= 0 then
                    local ok_s, s = pcall(memory.read_utf8, ptr, 256)
                    if ok_s and s and #s > 0 then extra.lobbyName = s end
                end
            end
            emit_session("steam_lobby:" .. id_str, "steam_lobby", extra)
            return true
        end
    end
    return false
end

local function check_steam_game_server()
    if not steam.gs_accessor or not steam.gs_get_id then return false end
    local gs = fetch_steam_gameserver()
    if not gs then return false end

    -- BLoggedOn distinguishes a real server from a freshly-allocated
    -- but inactive interface; both calls must succeed.
    if steam.gs_logged_on then
        local ok, logged = pcall(native.call, steam.gs_logged_on, "bool",
            {"pointer"}, {gs})
        if not ok or not logged then return false end
    end

    local ok_id, id = pcall(native.call, steam.gs_get_id, "uint64",
        {"pointer"}, {gs})
    if not ok_id or not id or id == 0 then return false end

    emit_session("steam_server:" .. tostring(id), "steam_server", {
        isHosting = true,
    })
    return true
end

-- Probe loop. Precedence: Steam lobby > Steam game-server > EOS > Photon.
-- EOS and Photon not yet implemented.

local last_validate_ms = 0
local last_rescan_ms = 0

local function probe()
    local now = clock()  -- milliseconds in Frida-Lua's clock()
    local lobby_cached = last_emitted_id ~= nil
        and last_emitted_id:sub(1, 12) == "steam_lobby:"
    local validate_ok = false

    -- Cheap re-call of num-members on the cached lobby ID.
    if lobby_cached then
        if (now - last_validate_ms) >= POLL_VALIDATE_MS then
            last_validate_ms = now
            local id_str = last_emitted_id:sub(13)
            local id_u64 = tonumber(id_str)
            if id_u64 then
                local _, members = validate_steam_lobby(id_u64)
                if members and members > 0 then
                    validate_ok = true
                else
                    emit_clear("steam_lobby_left")
                end
            end
        else
            validate_ok = true
        end
    end

    -- Full memory scan only when we don't already have a working ID —
    -- avoids blocking the worker 1-3s every 30s.
    if validate_ok then
        return
    end

    if (now - last_rescan_ms) >= POLL_RESCAN_MS then
        last_rescan_ms = now
        if steam_dll then
            if check_steam_lobby() then return end
            if check_steam_game_server() then return end
        end
        if last_emitted_id then emit_clear("rescan_no_match") end
    end
end

-- Init

send({
    type = "log",
    payload = string.format(
        "net_id_capture: init (steam=%s, user_accessor=%s, mm_accessor=%s, gs_accessor=%s)",
        tostring(steam_dll),
        steam.user_accessor and "yes" or "no",
        steam.mm_accessor and "yes" or "no",
        steam.gs_accessor and "yes" or "no")
})

-- DO NOT run probe() at top level: script.load() blocks until top-level
-- finishes, and a multi-second memory scan there stalls all session
-- work including the main engine ticks. Defer to the first tick — at
-- 60Hz that's ~16ms after script load.
local first_probe_done = false

-- Host pulls us with the same `tick` protocol as the main agent.
recv(function(message)
    local msg = message
    if type(message) == "string" then
        if type(json) == "table" and type(json.decode) == "function" then
            local ok_d, decoded = pcall(json.decode, message)
            if ok_d and type(decoded) == "table" then msg = decoded end
        end
    end
    if type(msg) ~= "table" then return end

    if msg.type == "tick" then
        if not first_probe_done then
            first_probe_done = true
            local ok, err = pcall(probe)
            if not ok then
                log("net_id_capture: initial probe error: " .. tostring(err))
            end
            return
        end
        local ok2, err2 = pcall(probe)
        if not ok2 then
            log("net_id_capture: probe error: " .. tostring(err2))
        end
    elseif msg.type == "shutdown" then
        emit_clear("script_shutdown")
    end
end)
