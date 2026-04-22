-- Unity Mono camera tracker. Pull-tick mode: host ticks, agent responds.
-- Flat read-only sandbox — mono_runtime_invoke not whitelisted.

local TICK_STALL_RESET_SECONDS = 0.2
local ATTACH_TIMEOUT_MS = 25000
local ATTACH_MAX_ATTEMPTS = 3
local ATTACH_RETRY_DELAY_MS = 4000
local SEARCHING_LOG_INTERVAL = 600  -- Log "searching" every 10 seconds at 60Hz

local script_handle = nil
local tick_in_flight = false
local tick_wait_seconds = 0
local no_data_count = 0
local is_searching = false

local function yield_for_ms(ms)
    local start = Core.getTimeMillis()
    while (Core.getTimeMillis() - start) < ms do
        if Bridge.isCancelled() then
            return false
        end
        coroutine.yield()
    end
    return true
end

local function attach_with_retries()
    local last_error = "unknown"

    for attempt = 1, ATTACH_MAX_ATTEMPTS do
        Bridge.setProgress("Attaching to process...", 40, 3)
        local attach_result = Gamelink.attach({ timeout_ms = ATTACH_TIMEOUT_MS })
        if not attach_result.success then
            last_error = attach_result.error or "unknown"
        else
            if not attach_result.pending then
                return true, nil
            end

            while true do
                if Bridge.isCancelled() then
                    return false, "Cancelled"
                end

                local status = Gamelink.pollAttach()
                if status.done then
                    if status.success then
                        return true, nil
                    end
                    last_error = status.error or "unknown"
                    break
                end

                Bridge.setProgress(status.message or "Attaching...", 40, 3)
                coroutine.yield()
            end
        end

        if attempt < ATTACH_MAX_ATTEMPTS then
            Core.warn("Attach attempt " .. tostring(attempt) .. " failed: "
                .. tostring(last_error) .. " (retrying)")
            Bridge.setProgress("Retrying attach...", 35, 2)
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

    Core.log("Mono Tracker: Initializing for PID " .. tostring(pid))
    Bridge.setProgress("Initializing...", 5, 2)

    local attached, attach_error = attach_with_retries()
    if not attached then
        if attach_error == "Cancelled" then
            Bridge.shutdown("Cancelled")
        else
            Core.error("GameLink attach failed: " .. tostring(attach_error))
            Bridge.shutdown("GameLink attach failed")
        end
        return
    end
    Core.log("GameLink attached successfully")

    if Bridge.isCancelled() then
        Bridge.shutdown("Cancelled")
        return
    end

    Bridge.setProgress("Loading tracker agent...", 60, 1)
    local loaded = Gamelink.getLoadedScripts()
    if loaded and #loaded > 0 then
        script_handle = loaded[1]
        for i = 2, #loaded do
            if loaded[i] > script_handle then
                script_handle = loaded[i]
            end
        end
        Core.log("Reusing parked tracker agent (handle: "
            .. tostring(script_handle) .. ")")
    else
        local load_result = Gamelink.load("unity_mono_tracker.lua", {
            runtime = "lua",
            capability = "invoke",
        })
        if not load_result.success then
            Core.error("Failed to load tracker: " .. (load_result.error or "unknown"))
            Bridge.shutdown("Tracker load failed")
            return
        end
        script_handle = load_result.handle
    end

    tick_in_flight = false
    tick_wait_seconds = 0
    no_data_count = 0
    Core.log("Tracker agent loaded (handle: " .. tostring(script_handle) .. ")")

    if Bridge.isCancelled() then
        Bridge.shutdown("Cancelled")
        return
    end

    Bridge.setProgress("Initializing engine...", 80, 5)
    local send_result = Gamelink.send(script_handle, { type = "init" })
    if not send_result.success then
        Core.error("Failed to send init: " .. (send_result.error or "unknown"))
        Bridge.shutdown("Init send failed")
        return
    end

    local init_ok = false
    while true do
        if Bridge.isCancelled() then
            Bridge.shutdown("Cancelled")
            return
        end

        local messages = Gamelink.poll(script_handle)
        if messages then
            for _, msg in ipairs(messages) do
                if msg.type == "log" and msg.payload then
                    Core.log("[agent] " .. tostring(msg.payload))
                end
                if msg.type == "data" and msg.payload then
                    local d = msg.payload
                    if d.type == "progress" then
                        Bridge.setProgress(d.message or "Discovering...", 80 + (d.percent or 0) * 0.19, 0.5)
                    elseif d.type == "init-response" then
                        if d.success then
                            Core.log("Tracker agent initialized successfully")
                            init_ok = true
                        else
                            Core.error("Agent init failed: " ..
                                (d.error or "unknown"))
                        end
                        break
                    elseif d.type == "fatal-error" then
                        Core.error("Agent fatal: " .. (d.error or "unknown"))
                        break
                    end
                end
            end
        end

        if init_ok then break end
        coroutine.yield()
    end

    if not init_ok then
        Core.error("Tracker initialization failed")
        Gamelink.unload(script_handle)
        script_handle = nil
        Bridge.shutdown("Tracker init failed")
        return
    end

    local tick_result = Gamelink.post(script_handle, {
        type = "tick",
        now_ms = Core.getTimeMillis(),
    })
    if not tick_result.success then
        Core.error("Failed to prime tick: " .. (tick_result.error or "unknown"))
        Gamelink.unload(script_handle)
        script_handle = nil
        Bridge.shutdown("Failed to prime tracker")
        return
    end
    tick_in_flight = true
    tick_wait_seconds = 0

    Bridge.setProgressSnap("Connected!", 100)
    Core.log("Mono Tracker initialized (pull-tick mode, read-only)")
end

function update(dt)
    if not script_handle then return end

    if Gamelink.isError() then
        local err = Gamelink.getError() or "Unknown error"
        Core.error("GameLink error: " .. err)
        Bridge.shutdown("GameLink error: " .. err)
        return
    end

    local messages = Gamelink.poll(script_handle)

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

                -- Fatal errors logged but do not disconnect — process exit is
                -- detected by the engine; Frida errors caught above.
                if d.type == "fatal-error" then
                    Core.error("Agent error: " .. (d.error or "unknown"))
                end

                if d.posX then
                    LocalPlayer.setCameraPosition(
                        d.posX, d.posY, -(d.posZ or 0))
                    if is_searching then
                        is_searching = false
                        Bridge.push("searching_for_player", false, 30000)
                        Core.log("Player position recovered")
                    end
                end

                if d.eulerX then
                    local function toSigned(deg)
                        if deg > 180 then return deg - 360 end
                        return deg
                    end
                    -- Unity X+ = looking down, ours = looking up.
                    local pitch = math.rad(toSigned(d.eulerX))
                    -- Unity Y: 0=+Z CW, ours: 0=-Z CCW — negate for Z flip.
                    local yaw = -math.rad(toSigned(d.eulerY))
                    local roll = math.rad(toSigned(d.eulerZ))
                    LocalPlayer.setCameraOrientation(pitch, yaw, roll)
                elseif d.fwdX then
                    local fx = d.fwdX or 0
                    local fy = d.fwdY or 0
                    local fz = -(d.fwdZ or 0)
                    local pitch = math.asin(
                        math.max(-1, math.min(1, fy)))
                    local yaw = math.atan(-fx, -fz)
                    LocalPlayer.setCameraOrientation(pitch, yaw, 0)
                end
            end
        end
    end

    if not had_data then
        no_data_count = no_data_count + 1
        if no_data_count == 20 then
            Core.warn("No position data for 1 second (loading screen?)")
            is_searching = true
            Bridge.push("searching_for_player", true, 30000)
        elseif no_data_count % SEARCHING_LOG_INTERVAL == 0 then
            Core.warn("Still searching for player... ("
                .. math.floor(no_data_count / 20) .. "s)")
        end
    end

    local dt_seconds = dt
    if not dt_seconds or dt_seconds <= 0 then dt_seconds = 1 / 60 end

    if tick_in_flight then
        tick_wait_seconds = tick_wait_seconds + dt_seconds
        if tick_wait_seconds >= TICK_STALL_RESET_SECONDS then
            tick_in_flight = false
            tick_wait_seconds = 0
        end
    end

    if not tick_in_flight then
        local tick_result = Gamelink.post(script_handle, {
            type = "tick",
            now_ms = Core.getTimeMillis(),
        })
        if not tick_result.success then
            Core.error("Tick send failed: " .. (tick_result.error or "unknown"))
            Bridge.shutdown("Tracker communication failed")
            return
        end
        tick_in_flight = true
        tick_wait_seconds = 0
    end
end

function dispose()
    Core.log("Mono Tracker: Disposing...")

    pcall(function()
        if script_handle then
            pcall(function()
                Gamelink.post(script_handle, { type = "shutdown" })
            end)
            script_handle = nil
        end
    end)

    tick_in_flight = false
    tick_wait_seconds = 0
end
