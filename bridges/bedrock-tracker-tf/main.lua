-- Minecraft Bedrock Edition GameBridge.
-- Camera is a global Vec3 + forward unit vector in the exe's static data;
-- offset is auto-discovered and cached per exe hash.

local TICK_STALL_RESET_SECONDS = 0.2
local ATTACH_TIMEOUT_MS = 10000
local SEARCHING_LOG_INTERVAL = 600  -- every 10s at 60Hz

local DIMENSION_NAMES = {
    [0] = "overworld",
    [1] = "nether",
    [2] = "the_end",
}

local script_handle = nil
local tick_in_flight = false
local tick_wait_seconds = 0
local no_data_count = 0
local is_searching = false
local last_dimension = nil

local function check_cancel()
    if Bridge.isCancelled() then
        Core.log("Initialization cancelled")
        Bridge.shutdown("Cancelled")
        return true
    end
    return false
end

function init()
    local pid = Bridge.getPid()
    if not pid then
        Core.error("No target PID")
        Bridge.shutdown("No target PID")
        return
    end

    Bridge.setProgress("Detecting Minecraft Bedrock...", 5, 2)
    Core.log("Bedrock Bridge: Initializing for PID " .. tostring(pid))

    local cache_key = nil
    if Bridge.hashFileMetadata then
        local profile = Bridge.getGameProfile()
        local exe_path = profile and profile.exe
        if exe_path and exe_path ~= "unknown.exe" then
            local meta = Bridge.hashFileMetadata(exe_path)
            if meta then
                cache_key = "bedrock_cam_" .. meta.hash
                Core.log("Exe hash: " .. meta.hash)
            end
        end
    end
    if not cache_key then
        cache_key = "bedrock_cam_default"
    end

    local cached_offset = nil
    if cache_key then
        Bridge.setProgress("Checking cache...", 10, 1)
        local cached = Cache.load(cache_key)
        if cached and cached.offset then
            cached_offset = cached
            Core.log("Cache hit: offset 0x" .. string.format("%X", cached.offset))
            Bridge.setProgress("Using cached offsets...", 30, 0.5)
        else
            Core.log("No cache, will scan for camera data")
        end
    end

    if check_cancel() then return end

    Bridge.setProgress("Attaching to process...", 40, 3)
    local attach_result = Gamelink.attach({ timeout_ms = ATTACH_TIMEOUT_MS })
    if not attach_result.success then
        Core.error("GameLink attach failed: " .. (attach_result.error or "unknown"))
        Bridge.shutdown("GameLink attach failed")
        return
    end
    if attach_result.pending then
        while true do
            if check_cancel() then return end
            local status = Gamelink.pollAttach()
            if status.done then
                if not status.success then
                    Core.error("GameLink attach failed: " .. (status.error or "unknown"))
                    Bridge.shutdown("GameLink attach failed")
                    return
                end
                break
            end
            Bridge.setProgress(status.message or "Attaching...", 40, 3)
            coroutine.yield()
        end
    end
    Core.log("GameLink attached")

    if check_cancel() then return end

    Bridge.setProgress("Loading tracker agent...", 60, 1)
    local load_result = Gamelink.load("bedrock_tracker.lua", {
        runtime = "lua",
        capability = "observe",
    })
    if not load_result.success then
        Core.error("Failed to load tracker: " .. tostring(load_result.error))
        Gamelink.detach()
        Bridge.shutdown("Tracker load failed")
        return
    end
    script_handle = load_result.handle
    Core.log("Agent loaded (handle: " .. tostring(script_handle) .. ")")

    if check_cancel() then return end

    if cached_offset then
        Bridge.setProgress("Verifying cached offset...", 70, 1)
        Bridge.setProgressFooter("Using cached camera offset from previous session")
    else
        Bridge.setProgress("Scanning for camera data...", 70, 3)
        Bridge.setProgressFooter("First connection scans the executable. Future connections will be instant. Move your character and look around during this scan.")
    end

    local init_msg = { type = "init" }
    if cached_offset then
        init_msg.data = cached_offset
    end

    local send_result = Gamelink.send(script_handle, init_msg)
    if not send_result.success then
        Core.error("Failed to send init: " .. tostring(send_result.error))
        Gamelink.unload(script_handle)
        script_handle = nil
        Gamelink.detach()
        Bridge.shutdown("Init send failed")
        return
    end

    local init_ok = false
    local init_done = false

    while true do
        if check_cancel() then return end

        local messages = Gamelink.poll(script_handle)
        if messages then
            for _, msg in ipairs(messages) do
                if msg.type == "log" and msg.payload then
                    Core.log("[agent] " .. tostring(msg.payload))
                end
                if msg.type == "data" and msg.payload then
                    local d = msg.payload
                    if d.type == "progress" then
                        -- Agent sends 0-100%, map to our 70-99% range
                        local ui_pct = 70 + (d.percent or 0) * 0.29
                        Bridge.setProgress(d.message or "Scanning...", ui_pct, 0.3)
                    elseif d.type == "discovery-complete" then
                        if cache_key and d.offset then
                            if Cache.save(cache_key, { offset = d.offset }) then
                                Core.log("Cached offset 0x" .. string.format("%X", d.offset))
                            end
                        end
                    elseif d.type == "init-response" then
                        init_done = true
                        if d.success then
                            Core.log("Agent initialized")
                            init_ok = true
                        else
                            Core.error("Agent init failed: " .. tostring(d.error))
                        end
                        break
                    elseif d.type == "fatal-error" then
                        init_done = true
                        Core.error("Agent fatal: " .. tostring(d.error))
                        break
                    end
                end
            end
        end

        if init_ok or init_done then break end
        coroutine.yield()
    end

    if not init_ok then
        Core.error("Initialization failed")
        Gamelink.unload(script_handle)
        script_handle = nil
        Gamelink.detach()
        Bridge.shutdown("Could not find camera data. Tips: be in a world (not the main menu), look around and walk during connection, and stay away from coordinates 0,0. If the position seems wrong, use Edit Game > Clear Cache and reconnect.")
        return
    end

    local tick_result = Gamelink.post(script_handle, {
        type = "tick",
        now_ms = Core.getTimeMillis(),
    })
    if not tick_result.success then
        Core.error("Failed to prime tick")
        Gamelink.unload(script_handle)
        script_handle = nil
        Gamelink.detach()
        Bridge.shutdown("Tracker communication failed")
        return
    end
    tick_in_flight = true
    tick_wait_seconds = 0

    Bridge.setProgressFooter("")
    Bridge.setProgressSnap("Connected!", 100)
    Core.log("Bedrock Bridge initialized")
end

function update(dt)
    if not script_handle then return end

    if Gamelink.isError() then
        local err = Gamelink.getError() or "Unknown"
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
                local d = msg.payload

                if d.type == "fatal-error" then
                    Core.error("Agent error: " .. (d.error or "unknown"))
                end

                if d.posX then
                    had_data = true
                    no_data_count = 0

                    -- Bedrock uses same coordinate system as Java Edition
                    -- (X=East, Y=Up, Z=South) — pass through directly.
                    -- Camera Y is at eye level; speaker defaults to camera.
                    LocalPlayer.setCameraPosition(d.posX, d.posY, d.posZ)

                    -- Negate fwdX/fwdZ to flip 180° on the XZ plane
                    if d.fwdX and d.fwdY and d.fwdZ then
                        local yaw = math.atan2(-d.fwdX, -d.fwdZ)
                        local horiz = math.sqrt(d.fwdX * d.fwdX + d.fwdZ * d.fwdZ)
                        local pitch = math.atan2(d.fwdY, horiz)
                        LocalPlayer.setCameraOrientation(pitch, yaw, 0)
                    end

                    if d.dimension ~= nil then
                        local dim_name = DIMENSION_NAMES[d.dimension] or "overworld"
                        if dim_name ~= last_dimension then
                            last_dimension = dim_name
                            Bridge.push("level_name", dim_name, 30000)
                            Core.log("Dimension: " .. dim_name)
                        end
                    end

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
        no_data_count = no_data_count + 1
        if no_data_count == 20 then
            Core.warn("No position data for 1 second")
            is_searching = true
            Bridge.push("searching_for_player", true, 30000)
        elseif no_data_count % SEARCHING_LOG_INTERVAL == 0 then
            Core.warn("Still searching... (" .. math.floor(no_data_count / 20) .. "s)")
        end
    end

    local dt_seconds = dt
    if not dt_seconds or dt_seconds <= 0 then
        dt_seconds = 1 / 60
    end

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
            Core.error("Tick failed")
            Bridge.shutdown("Tracker communication failed")
            return
        end
        tick_in_flight = true
        tick_wait_seconds = 0
    end
end

function dispose()
    Core.log("Bedrock Bridge: Disposing")
    pcall(function()
        if script_handle then
            pcall(function()
                Gamelink.post(script_handle, { type = "shutdown" })
            end)
            Gamelink.unload(script_handle)
            script_handle = nil
        end
        if Gamelink.isAttached() then
            Gamelink.detach()
        end
    end)
    tick_in_flight = false
    tick_wait_seconds = 0
end
