-- Terraria bridge: host script. Pure memory-scan, no injection.

local INIT_TIMEOUT_MS = 60000
local TICK_STALL_SECONDS = 1.5
local ATTACH_TIMEOUT_MS = 8000
local SEARCHING_LOG_INTERVAL = 600  -- 10s at 60Hz

local handle = nil
local no_data = 0
local is_searching = false
local tick_in_flight = false
local tick_wait = 0

local function cancelled()
    if Bridge.isCancelled() then
        Bridge.shutdown("Cancelled")
        return true
    end
    return false
end

function init()
    local pid = Bridge.getPid()
    if not pid then
        Bridge.shutdown("No target PID")
        return
    end

    Bridge.setProgress("Attaching...", 40, 3)
    if cancelled() then return end

    local attach, attach_err = Gamelink.attach({ timeout_ms = ATTACH_TIMEOUT_MS })
    if attach_err then
        Bridge.shutdown("Attach failed: " .. tostring(attach_err))
        return
    end
    if attach.pending then
        while true do
            if cancelled() then return end
            local status, status_err = Gamelink.pollAttach()
            if status_err then
                last_error = status_err
                break
            end
            if status.done then
                if status_err then
                    Bridge.shutdown("Attach failed: " .. tostring(status_err))
                    return
                end
                break
            end
            Bridge.setProgress(status.message or "Attaching...", 40, 3)
            coroutine.yield()
        end
    end

    if cancelled() then return end

    Bridge.setProgress("Loading tracker...", 60, 1)
    local load_handle, load_err = Gamelink.loadScript("terraria_tracker.lua", {
        runtime = "lua",
    })
    if load_err then
        Gamelink.detach()
        Bridge.shutdown("Load failed: " .. tostring(load_err))
        return
    end
    handle = load_handle

    if cancelled() then return end

    Bridge.setProgress("Scanning game memory...", 80, 5)
    local ok_ok, ok_err = Gamelink.send(handle, { type = "init" })
    if ok_err then
        Gamelink.unloadScript(handle)
        handle = nil
        Gamelink.detach()
        Bridge.shutdown("Send failed")
        return
    end

    local start = Core.getTimeMillis()
    while Core.getTimeMillis() - start < INIT_TIMEOUT_MS do
        if cancelled() then return end

        local messages = Gamelink.poll(handle)
        if messages then
            for _, msg in ipairs(messages) do
                if msg.type == "data" and msg.payload then
                    local p = msg.payload
                    if p.type == "init-response" then
                        if p.success then
                            Gamelink.send(handle, {
                                type = "tick",
                                now_ms = Core.getTimeMillis(),
                            })
                            tick_in_flight = true
                            tick_wait = 0
                            Bridge.setProgressSnap("Connected!", 100)
                            return
                        end
                        Bridge.shutdown("Init failed: " .. tostring(p.error))
                        return
                    elseif p.type == "progress" then
                        Bridge.setProgress(
                            p.message or "Working...",
                            80 + (p.percent or 0) * 0.19, 0.5
                        )
                    elseif p.type == "fatal-error" then
                        Bridge.shutdown("Fatal: " .. tostring(p.error))
                        return
                    end
                end
            end
        end
        coroutine.yield()
    end

    Bridge.shutdown("Init timeout")
end

function update(dt)
    if not handle then return end

    if Gamelink.is_error() then
        Bridge.shutdown("GameLink error: " .. (Gamelink.last_error() or "unknown"))
        return
    end

    local messages = Gamelink.poll(handle)
    local had_data = false

    if messages then
        for _, msg in ipairs(messages) do
            tick_in_flight = false
            tick_wait = 0

            if msg.type == "data" and msg.payload then
                local d = msg.payload
                -- Agent fatal errors log only — engine detects process exit,
                -- Gamelink.is_error handles Frida errors above.
                if d.type == "fatal-error" then
                    Core.error("Agent error: " .. tostring(d.error))
                elseif d.posX ~= nil then
                    had_data = true
                    no_data = 0
                    GameStore.setCameraPosition(d.posX, d.posY, d.posZ)
                    if is_searching then
                        is_searching = false
                        Bridge.push("searching_for_player", false, 30000)
                        Core.log("Player position recovered")
                    end
                end
            end
        end
    end

    if not had_data then
        no_data = no_data + 1
        if no_data == 20 then
            Core.warn("No position data for 1 second (loading screen?)")
            is_searching = true
            Bridge.push("searching_for_player", true, 30000)
        elseif no_data % SEARCHING_LOG_INTERVAL == 0 then
            Core.warn("Still searching for player... ("
                .. math.floor(no_data / 20) .. "s)")
        end
    end

    local dt_s = tonumber(dt) or 0
    if tick_in_flight then
        tick_wait = tick_wait + dt_s
        if tick_wait >= TICK_STALL_SECONDS then
            tick_in_flight = false
            tick_wait = 0
        end
    end

    if not tick_in_flight then
        local ok_ok, ok_err = Gamelink.send(handle, {
            type = "tick",
            now_ms = Core.getTimeMillis(),
        })
        if ok_err then
            Bridge.shutdown("Tick failed")
            return
        end
        tick_in_flight = true
        tick_wait = 0
    end
end

function dispose()
    -- Runtime auto-cleans Gamelink (unload + detach) after dispose returns.
    handle = nil
    tick_in_flight = false
    tick_wait = 0
end
