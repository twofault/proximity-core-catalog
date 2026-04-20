-- Terraria Game Bridge (Compliant)
-- Host-side script — no file injection, pure memory-scan approach.

local INIT_TIMEOUT_MS = 60000
local TICK_STALL_SECONDS = 1.5
local ATTACH_TIMEOUT_MS = 8000
local SEARCHING_LOG_INTERVAL = 200  -- Log "searching" every 10 seconds at 20Hz

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

    local attach = Frida.attach({ timeout_ms = ATTACH_TIMEOUT_MS })
    if not attach.success then
        Bridge.shutdown("Attach failed: " .. tostring(attach.error))
        return
    end
    -- Poll until attach completes (yields back to engine each tick)
    if attach.pending then
        while true do
            if cancelled() then return end
            local status = Frida.pollAttach()
            if status.done then
                if not status.success then
                    Bridge.shutdown("Attach failed: " .. tostring(status.error))
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
    local load = Frida.load("terraria_tracker.lua", {
        runtime = "lua",
        capability = "invoke",
    })
    if not load.success then
        Frida.detach()
        Bridge.shutdown("Load failed: " .. tostring(load.error))
        return
    end
    handle = load.handle

    if cancelled() then return end

    Bridge.setProgress("Scanning game memory...", 80, 5)
    local ok = Frida.send(handle, { type = "init" })
    if not ok.success then
        Frida.unload(handle)
        handle = nil
        Frida.detach()
        Bridge.shutdown("Send failed")
        return
    end

    local start = Core.getTimeMillis()
    while Core.getTimeMillis() - start < INIT_TIMEOUT_MS do
        if cancelled() then return end

        local messages = Frida.poll(handle)
        if messages then
            for _, msg in ipairs(messages) do
                if msg.type == "data" and msg.payload then
                    local p = msg.payload
                    if p.type == "init-response" then
                        if p.success then
                            Frida.send(handle, {
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

    if Frida.is_error() then
        Bridge.shutdown("Frida error: " .. (Frida.last_error() or "unknown"))
        return
    end

    local messages = Frida.poll(handle)
    local had_data = false

    if messages then
        for _, msg in ipairs(messages) do
            tick_in_flight = false
            tick_wait = 0

            if msg.type == "data" and msg.payload then
                local d = msg.payload
                -- Fatal errors from agent are logged but do NOT disconnect.
                -- Process exit is detected by the engine; Frida errors are
                -- caught by Frida.is_error() above.
                if d.type == "fatal-error" then
                    Core.error("Agent error: " .. tostring(d.error))
                elseif d.posX ~= nil then
                    had_data = true
                    no_data = 0
                    LocalPlayer.setCameraPosition(d.posX, d.posY, d.posZ)
                    -- Clear searching state when position data resumes
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
        local ok = Frida.send(handle, {
            type = "tick",
            now_ms = Core.getTimeMillis(),
        })
        if not ok.success then
            Bridge.shutdown("Tick failed")
            return
        end
        tick_in_flight = true
        tick_wait = 0
    end
end

function dispose()
    pcall(function()
        if handle then
            Frida.send(handle, { type = "dispose" })
            Frida.unload(handle)
            handle = nil
        end
        if Frida.is_attached() then
            Frida.detach()
        end
    end)
    tick_in_flight = false
    tick_wait = 0
end
