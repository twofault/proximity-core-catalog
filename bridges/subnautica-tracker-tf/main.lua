-- Subnautica bridge. Drives camera + surroundings (underwater, radio_access,
-- room_size, reverb) from the Player singleton and Camera.main.

local TICK_STALL_RESET_SECONDS = 0.2
local ATTACH_TIMEOUT_MS = 25000
local ATTACH_MAX_ATTEMPTS = 3
local ATTACH_RETRY_DELAY_MS = 4000
local SEARCHING_LOG_INTERVAL = 600  -- 10s at 60Hz

local CACHE_KEY = "subnautica_player_addresses"

local script_handle = nil
local tick_in_flight = false
local tick_wait_seconds = 0
local no_data_count = 0
local is_searching = false
local current_pid = nil

-- Latched surroundings — only push to GameStore on actual change.
local last_underwater = nil
local last_radio_access = nil
local last_room_size = nil
local last_reverb = nil

-- Mono heap addresses change per process launch, so the cache is PID-keyed:
-- a hit means the agent can skip the ~60s scan, a miss falls back to it.
local function load_player_cache()
    if not Cache or type(Cache.load) ~= "function" then return nil end
    local cached = Cache.load(CACHE_KEY)
    if not cached then return nil end
    if cached.pid ~= current_pid then
        Core.log("Cache miss: stored PID " .. tostring(cached.pid) ..
            " != current " .. tostring(current_pid) .. " (game restarted)")
        return nil
    end
    return cached
end

local function save_player_cache(player_ptr, player_vtable)
    if not Cache or type(Cache.save) ~= "function" then return end
    Cache.save(CACHE_KEY, {
        pid = current_pid,
        player_ptr = player_ptr,
        player_vtable = player_vtable,
        saved_at_ms = Core.getTimeMillis(),
    })
    Core.log(string.format("Cached: pid=%d player=0x%X vtable=0x%X",
        current_pid, player_ptr, player_vtable))
end

local function yield_for_ms(ms)
    local start = Core.getTimeMillis()
    while (Core.getTimeMillis() - start) < ms do
        if Bridge.isCancelled() then return false end
        coroutine.yield()
    end
    return true
end

local function attach_with_retries()
    local last_error = "unknown"

    local lingering_wait_start = Core.getTimeMillis()
    while not Gamelink.isLingeringClear() do
        if Bridge.isCancelled() then return false, "Cancelled" end
        if Core.getTimeMillis() - lingering_wait_start > 15000 then
            Core.warn("Previous Frida worker did not finish unwinding within 15s")
            break
        end
        Bridge.setProgress("Waiting for previous session to close...", 30, 1)
        coroutine.yield()
    end

    for attempt = 1, ATTACH_MAX_ATTEMPTS do
        Bridge.setProgress("Attaching to Subnautica...", 30, 3)
        local res, err = Gamelink.attach({ timeout_ms = ATTACH_TIMEOUT_MS })
        if err then
            last_error = err
        else
            if not res.pending then return true, nil end
            while true do
                if Bridge.isCancelled() then return false, "Cancelled" end
                local status, status_err = Gamelink.pollAttach()
                if status_err then last_error = status_err; break end
                if status.done then
                    if not status_err then return true, nil end
                    last_error = status_err; break
                end
                Bridge.setProgress(status.message or "Attaching...", 30, 3)
                coroutine.yield()
            end
        end

        if attempt < ATTACH_MAX_ATTEMPTS then
            Core.warn("Attach attempt " .. attempt .. " failed: " ..
                tostring(last_error) .. " (retrying)")
            Bridge.setProgress("Retrying attach...", 25, 2)
            if not yield_for_ms(ATTACH_RETRY_DELAY_MS) then
                return false, "Cancelled"
            end
        end
    end
    return false, last_error
end

function init()
    local pid = Bridge.getPid()
    if not pid then
        Core.error("No target PID set!")
        Bridge.shutdown("No target PID")
        return
    end
    current_pid = pid

    Core.log("Subnautica Tracker: Initializing for PID " .. tostring(pid))
    Bridge.setProgress("Initializing...", 5, 2)

    -- Cache lookup happens BEFORE attach so we can decide whether to show
    -- the long-scan message in the UI.
    local cached = load_player_cache()
    if cached then
        Core.log(string.format(
            "Cache hit for PID %d: player=0x%X vtable=0x%X",
            pid, cached.player_ptr, cached.player_vtable))
    end

    local ok, err = attach_with_retries()
    if not ok then
        if err == "Cancelled" then Bridge.shutdown("Cancelled")
        else
            Core.error("GameLink attach failed: " .. tostring(err))
            Bridge.shutdown("GameLink attach failed")
        end
        return
    end
    Core.log("GameLink attached")

    if Bridge.isCancelled() then Bridge.shutdown("Cancelled"); return end

    Bridge.setProgress("Loading tracker agent...", 50, 1)
    local loaded = Gamelink.getLoadedScripts()
    if loaded and #loaded > 0 then
        script_handle = loaded[1]
        for i = 2, #loaded do
            if loaded[i] > script_handle then script_handle = loaded[i] end
        end
        Core.log("Reusing parked tracker agent (handle " .. tostring(script_handle) .. ")")
    else
        local h, lerr = Gamelink.loadScript("subnautica_tracker.lua",
            { runtime = "lua" })
        if lerr then
            Core.error("Failed to load tracker: " .. tostring(lerr))
            Bridge.shutdown("Tracker load failed")
            return
        end
        script_handle = h
    end

    tick_in_flight = false
    tick_wait_seconds = 0
    no_data_count = 0

    if Bridge.isCancelled() then Bridge.shutdown("Cancelled"); return end

    if cached then
        Bridge.setProgress("Verifying cached addresses...", 60, 1)
        Bridge.setProgressFooter("Reusing addresses from previous attach to this game session")
    else
        Bridge.setProgress("Initializing engine (first attach scans memory, ~60s)...",
            60, 5)
        Bridge.setProgressFooter("Future attaches in this game session will be instant")
    end

    local init_msg = { type = "init" }
    if cached then
        init_msg.data = {
            cached_player_ptr = cached.player_ptr,
            cached_vtable = cached.player_vtable,
        }
    end

    local _, send_err = Gamelink.send(script_handle, init_msg)
    if send_err then
        Core.error("Failed to send init: " .. tostring(send_err))
        Bridge.shutdown("Init send failed")
        return
    end

    local init_ok = false
    local init_done = false
    while true do
        if Bridge.isCancelled() then Bridge.shutdown("Cancelled"); return end
        local messages = Gamelink.poll(script_handle)
        if messages then
            for _, msg in ipairs(messages) do
                if msg.type == "log" and msg.payload then
                    Core.log("[agent] " .. tostring(msg.payload))
                end
                if msg.type == "data" and msg.payload then
                    local d = msg.payload
                    if d.type == "progress" then
                        Bridge.setProgress(d.message or "Discovering...",
                            60 + (d.percent or 0) * 0.39, 0.5)
                    elseif d.type == "discovery-complete" then
                        if d.player_ptr and d.player_vtable then
                            save_player_cache(d.player_ptr, d.player_vtable)
                        end
                    elseif d.type == "init-response" then
                        init_done = true
                        if d.success then
                            Core.log("Agent initialized")
                            init_ok = true
                        else
                            Core.error("Agent init failed: " .. (d.error or "unknown"))
                        end
                        break
                    elseif d.type == "fatal-error" then
                        init_done = true
                        Core.error("Agent fatal: " .. (d.error or "unknown"))
                        break
                    end
                end
            end
        end
        if init_ok or init_done then break end
        coroutine.yield()
    end

    if not init_ok then
        Gamelink.unloadScript(script_handle)
        script_handle = nil
        Bridge.shutdown("Tracker init failed")
        return
    end

    local _, tick_err = Gamelink.send(script_handle, {
        type = "tick", now_ms = Core.getTimeMillis(),
    })
    if tick_err then
        Core.error("Failed to prime tick: " .. tostring(tick_err))
        Gamelink.unloadScript(script_handle)
        script_handle = nil
        Bridge.shutdown("Failed to prime tracker")
        return
    end
    tick_in_flight = true
    tick_wait_seconds = 0

    Bridge.setProgressSnap("Connected!", 100)
    Core.log("Subnautica Tracker initialized")
end

-- Underwater strength ramps from UNDERWATER_FLOOR at depth=0 (just submerged)
-- to 1.0 at UNDERWATER_FULL_DEPTH meters. EPSILON suppresses tiny wire churn.
local UNDERWATER_FLOOR = 0.5
local UNDERWATER_FULL_DEPTH = 20.0
local UNDERWATER_EPSILON = 0.05

local function apply_surroundings(d)
    -- Continuous underwater strength gated by inAir (a sub/vehicle/Precursor
    -- pocket reports 0 regardless of camera depth).
    local raw_underwater
    if d.isUnderwaterGame ~= nil then
        raw_underwater = d.isUnderwaterGame
    else
        raw_underwater = (d.posY ~= nil and d.posY < 0)
    end

    local underwater = 0
    if raw_underwater and not d.inAir then
        local depth = math.max(0, -(d.posY or 0))
        local extra = math.min(1.0 - UNDERWATER_FLOOR, depth / UNDERWATER_FULL_DEPTH)
        underwater = UNDERWATER_FLOOR + extra
    end

    if last_underwater == nil
        or math.abs(underwater - last_underwater) > UNDERWATER_EPSILON
        or (underwater == 0) ~= (last_underwater == 0) then
        GameStore.setSurrounding("underwater", underwater)
        if (underwater > 0) ~= ((last_underwater or 0) > 0) then
            Core.log(string.format(
                "[surroundings] underwater = %s (depth=%.1f m)",
                underwater > 0 and "ON" or "OFF",
                math.max(0, -(d.posY or 0))))
        end
        last_underwater = underwater
    end

    local radio = d.radioAccess and 1 or 0
    if radio ~= last_radio_access then
        GameStore.setSurrounding("radio_access", radio)
        last_radio_access = radio
        Core.log("[surroundings] radio_access = " ..
            (radio == 1 and "ON" or "OFF"))
    end

    local rs = d.roomSize or 0
    if rs ~= last_room_size then
        GameStore.setSurrounding("room_size", rs)
        last_room_size = rs
        Core.log(string.format("[surroundings] room_size = %g m", rs))
    end

    local rv = d.reverb or 0
    if rv ~= last_reverb then
        GameStore.setSurrounding("reverb", rv)
        last_reverb = rv
        Core.log(string.format("[surroundings] reverb = %.2f", rv))
    end
end

function update(dt)
    if not script_handle then return end

    if Gamelink.isError() then
        local err = Gamelink.getError() or "Unknown error"
        Core.error("GameLink error: " .. err)
        Bridge.shutdown("GameLink error: " .. err)
        return
    end

    local messages = Gamelink.poll()
    local had_data = false
    if messages then
        for _, msg in ipairs(messages) do
            tick_in_flight = false
            tick_wait_seconds = 0

            if msg.type == "log" and msg.payload then
                Core.log("[agent] " .. tostring(msg.payload))
            end

            if msg.type == "data" and msg.payload then
                had_data = true
                no_data_count = 0
                local d = msg.payload

                if d.type == "fatal-error" then
                    Core.error("Agent error: " .. (d.error or "unknown"))
                end

                if d.posX then
                    -- Unity is +Z forward, Proximity is -Z forward → negate Z
                    GameStore.setCameraPosition(d.posX, d.posY, -(d.posZ or 0))
                    if is_searching then
                        is_searching = false
                        Bridge.push("searching_for_player", false, 30000)
                        Core.log("Player position recovered")
                    end
                end

                if d.upX ~= nil then
                    local fx = d.fwdX or 0
                    local fy = d.fwdY or 0
                    local fz = -(d.fwdZ or 0)
                    local ux = d.upX or 0
                    local uy = d.upY or 1
                    local uz = -(d.upZ or 0)
                    GameStore.setCameraBasis(fx, fy, fz, ux, uy, uz)
                end

                apply_surroundings(d)
            end
        end
    end

    if not had_data then
        no_data_count = no_data_count + 1
        if no_data_count == 20 then
            Core.warn("No data for 1s (loading screen?)")
            is_searching = true
            Bridge.push("searching_for_player", true, 30000)
        elseif no_data_count % SEARCHING_LOG_INTERVAL == 0 then
            Core.warn("Still searching... (" ..
                math.floor(no_data_count / 20) .. "s)")
        end
    end

    local dt_s = dt
    if not dt_s or dt_s <= 0 then dt_s = 1 / 60 end

    if tick_in_flight then
        tick_wait_seconds = tick_wait_seconds + dt_s
        if tick_wait_seconds >= TICK_STALL_RESET_SECONDS then
            tick_in_flight = false
            tick_wait_seconds = 0
        end
    end

    if not tick_in_flight then
        local _, terr = Gamelink.send(script_handle, {
            type = "tick", now_ms = Core.getTimeMillis(),
        })
        if terr then
            Core.error("Tick send failed: " .. tostring(terr))
            Bridge.shutdown("Tracker communication failed")
            return
        end
        tick_in_flight = true
        tick_wait_seconds = 0
    end
end

function dispose()
    Core.log("Subnautica Tracker: Disposing...")
    script_handle = nil
    tick_in_flight = false
    tick_wait_seconds = 0
    last_underwater = nil
    last_radio_access = nil
    last_room_size = nil
    last_reverb = nil
end
