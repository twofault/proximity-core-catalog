-- Unreal Engine GameBridge
-- Extracts player data from UE4/UE5 games using Frida Lua runtime introspection.
-- ue_engine.lua discovers struct offsets at runtime — no hardcoded pointer path.

-- No timeout for discovery — scanning large games can take several minutes
local TICK_STALL_RESET_SECONDS = 0.2
local ATTACH_TIMEOUT_MS = 10000
local SEARCHING_LOG_INTERVAL = 600  -- Log "searching" every 10 seconds at 60Hz

-- Unreal: X=Forward, Y=Right, Z=Up (left-handed, Z-up, centimeters)
-- Standard: X=Right, Y=Up, Z=Forward (right-handed, Y-up, meters)
local UNREAL_TO_METERS = 0.01

local script_handle = nil
local use_pull_ticks = false
local tick_in_flight = false
local tick_wait_seconds = 0
local no_data_count = 0
local is_searching = false
local resolved_offsets = nil
local vector_precision = "vtFloat"
local vector_size = 4
local game_name = nil

local function unreal_to_standard_position(ux, uy, uz)
    local scale = UNREAL_TO_METERS
    return uy * scale,   -- Standard X = Unreal Y (right)
           uz * scale,   -- Standard Y = Unreal Z (up)
           -ux * scale   -- Standard Z = -Unreal X (forward, negated for handedness)
end

-- UE yaw is CW from above; our yaw is CCW → negate.
-- After coordinate conversion: UE +X forward → standard -Z, UE +Y right → standard +X.
local function unreal_rotation_to_orientation(pitch_deg, yaw_deg)
    local pitch_rad = math.rad(pitch_deg or 0)
    local yaw_rad = -math.rad(yaw_deg or 0)
    return pitch_rad, yaw_rad, 0
end

local function check_cancel()
    if Bridge.isCancelled() then
        Core.log("Initialization cancelled by user")
        Bridge.shutdown("Cancelled")
        return true
    end
    return false
end

local function extract_game_name(window_title)
    if not window_title then return nil end
    local name = window_title:gsub("%s*%-%s*Unreal Engine.*", "")
    name = name:gsub("%s*%(64%-bit%).*", "")
    name = name:gsub("%s*%(32%-bit%).*", "")
    name = name:gsub("[^%w%-_]", "_")
    return name
end

local function validate_cache(cached)
    if not cached then return false end
    if not cached.offsets or not cached.vectorPrecision then return false end
    if not cached.offsets.GWorld then return false end
    if not cached.offsets.X then return false end
    return true
end

function init()
    local pid = Bridge.getPid()
    if not pid then
        Core.error("No target PID set!")
        Bridge.shutdown("No target PID")
        return
    end

    Bridge.setProgress("Detecting game...", 5, 2)
    Core.log("Unreal Bridge: Initializing for PID " .. tostring(pid))

    local cache_key = nil

    local window_title = Bridge.getWindowTitle()
    if window_title then
        game_name = extract_game_name(window_title)
        Core.log("Window title: " .. window_title)
    end

    if Bridge.hashFileMetadata then
        local profile = Bridge.getGameProfile()
        local exe_path = profile and profile.exe
        if exe_path and exe_path ~= "unknown.exe" then
            local meta = Bridge.hashFileMetadata(exe_path)
            if meta then
                cache_key = "ue_offsets_" .. meta.hash
                Core.log("Exe hash: " .. meta.hash .. " (size=" .. tostring(meta.size) .. ")")
            end
        end
        if not cache_key and game_name then
            cache_key = "ue_offsets_name_" .. game_name
            Core.log("Using window title as cache key (no exe path available)")
        end
    elseif game_name then
        cache_key = "ue_offsets_" .. game_name
    end

    local cached_offsets = nil
    if cache_key then
        Bridge.setProgress("Checking cache...", 10, 1)
        local cached = Cache.load(cache_key)
        if validate_cache(cached) then
            cached_offsets = cached
            Core.log("Cache hit! Using cached offsets")
            Bridge.setProgress("Using cached offsets...", 30, 0.5)
        else
            Core.log("No valid cache, will discover offsets at runtime")
        end
    end

    if check_cancel() then return end

    Bridge.setProgress("Attaching to process...", 45, 3)
    Core.log("Attaching Frida to PID " .. tostring(pid) .. "...")

    local attach_result, attach_result_err = Gamelink.attach({ timeout_ms = ATTACH_TIMEOUT_MS })
    if attach_result_err then
        Core.error("Failed to attach Frida: " .. (attach_result_err or "unknown"))
        Bridge.shutdown("GameLink attach failed")
        return
    end
    if attach_result.pending then
        while true do
            if check_cancel() then return end
            local status, status_err = Gamelink.pollAttach()
            if status.done then
                if status_err then
                    Core.error("GameLink attach failed: " .. (status_err or "unknown"))
                    Bridge.shutdown("GameLink attach failed")
                    return
                end
                break
            end
            Bridge.setProgress(status.message or "Attaching...", 45, 3)
            coroutine.yield()
        end
    end
    Core.log("GameLink attached successfully")

    if check_cancel() then return end

    Bridge.setProgress("Loading engine agent...", 60, 1)
    local load_result_handle, load_result_err = Gamelink.loadScript("ue_engine.lua", {
        runtime = "lua",
    })
    if load_result_err then
        Core.warn("Lua engine load failed: " .. tostring(load_result_err))

        -- Fallback: legacy JS tracker with Dumper-7 flow
        Core.log("Falling back to legacy JS tracker...")
        load_result = Gamelink.loadScript("unreal_tracker.js", {
            runtime = "default",
        })
        if load_result_err then
            Core.error("Failed to load any tracker: " .. tostring(load_result_err))
            Gamelink.detach()
            Bridge.shutdown("Tracker load failed")
            return
        end
        script_handle = load_result_handle
        use_pull_ticks = false
        Core.log("Legacy JS tracker loaded")
        Bridge.setProgressSnap("Connected (legacy mode)!", 100)
        return
    end

    script_handle = load_result_handle
    use_pull_ticks = true
    tick_in_flight = false
    tick_wait_seconds = 0
    no_data_count = 0
    Core.log("ue_engine.lua loaded (handle: " .. tostring(script_handle) .. ")")

    if check_cancel() then return end

    local init_message
    if cached_offsets then
        Bridge.setProgress("Initializing engine...", 85, 1)
        -- cached_offsets shape: {offsets={GWorld=..., X=...}, vectorPrecision=..., vectorSize=...}
        init_message = { type = "init", data = cached_offsets }
        Core.log("Sending cached offsets to agent (skipping discovery)")
        Core.log("  Cache has " .. tostring(cached_offsets.vectorPrecision) .. " precision")
        Bridge.setProgressFooter("Using cached offsets from previous session")
    else
        Bridge.setProgress("Initializing engine...", 85, 5)
        init_message = { type = "init" }
        Core.log("Sending init to agent (full discovery)")
        Bridge.setProgressFooter("First connection (or after game update) requires scanning. Future connections will be almost instant.")
    end

    local send_result_ok, send_result_err = Gamelink.send(script_handle, init_message)
    if send_result_err then
        Core.error("Failed to send init: " .. tostring(send_result_err or "unknown"))
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
                        -- Agent sends 0-100%, scale into 85-99% range
                        local ui_pct = 85 + (d.percent or 0) * 0.14
                        Bridge.setProgress(d.message or "Discovering...", ui_pct, 0.5)

                    elseif d.type == "discovery-complete" then
                        if cache_key and d.offsets then
                            local cache_data = {
                                offsets = d.offsets,
                                vectorPrecision = d.vectorPrecision or "vtFloat",
                                vectorSize = d.vectorSize or 4,
                            }
                            if Cache.save(cache_key, cache_data) then
                                Core.log("Cached discovered offsets for next launch")
                            end
                        end

                    elseif d.type == "init-response" then
                        init_done = true
                        if d.success then
                            Core.log("Engine agent initialized successfully")
                            init_ok = true
                        else
                            Core.error("Engine init failed: " .. tostring(d.error or "unknown"))
                        end
                        break

                    elseif d.type == "fatal-error" then
                        init_done = true
                        Core.error("Engine fatal error: " .. tostring(d.error or "unknown"))
                        break
                    end
                end
            end
        end

        if init_ok or init_done then break end
        coroutine.yield()
    end

    if not init_ok then
        Core.error("Engine initialization failed or timed out")
        Gamelink.unloadScript(script_handle)
        script_handle = nil
        Gamelink.detach()
        Bridge.shutdown("Could not find player data. If you are in a menu, try joining a game first and reconnecting.")
        return
    end

    -- Prime the first tick
    local tick_result_ok, tick_result_err = Gamelink.send(script_handle, {
        type = "tick",
        now_ms = Core.getTimeMillis(),
    })
    if tick_result_err then
        Core.error("Failed to prime tick: " .. (tick_result_err or "unknown"))
        Gamelink.unloadScript(script_handle)
        script_handle = nil
        Gamelink.detach()
        Bridge.shutdown("Failed to prime tracker")
        return
    end
    tick_in_flight = true
    tick_wait_seconds = 0

    Bridge.setProgressFooter("")
    Bridge.setProgressSnap("Connected!", 100)
    Core.log("Unreal Bridge initialized successfully (Lua engine)")
end

function update(dt)
    if not script_handle then return end

    if Gamelink.isError() then
        local err = Gamelink.getError() or "Unknown error"
        Core.error("GameLink error detected: " .. err)
        Bridge.shutdown("GameLink error: " .. err)
        return
    end

    local messages = Gamelink.poll(script_handle)

    local had_data = false
    if messages then
        for _, msg in ipairs(messages) do
            if use_pull_ticks then
                tick_in_flight = false
                tick_wait_seconds = 0
            end

            if msg.type == "log" and msg.payload then
                Core.log("[agent] " .. tostring(msg.payload))
            end

            if msg.type == "data" and msg.payload then
                had_data = true
                no_data_count = 0
                local d = msg.payload

                -- Fatal errors from agent are logged but do NOT disconnect.
                -- Process exit is detected by the engine; Frida errors are
                -- caught by Gamelink.isError() above.
                if d.type == "fatal-error" then
                    Core.error("Agent error: " .. (d.error or "unknown"))
                end

                if d.posX then
                    local std_x, std_y, std_z = unreal_to_standard_position(d.posX, d.posY, d.posZ)
                    LocalPlayer.setCameraPosition(std_x, std_y, std_z)
                    if is_searching then
                        is_searching = false
                        Bridge.push("searching_for_player", false, 30000)
                        Core.log("Player position recovered")
                    end
                end

                -- Prefer ControlRotation (camera) when available; fall back to body rotation.
                -- In Unreal's FRotator: rotX=Roll, rotY=Pitch, rotZ=Yaw — but RelativeRotation
                -- exposes rotY as Yaw, which is what we want for the fallback.
                if d.pitch then
                    local pitch, yaw, roll = unreal_rotation_to_orientation(d.pitch, d.yaw)
                    LocalPlayer.setCameraOrientation(pitch, yaw, roll)
                elseif d.rotY ~= nil then
                    local pitch, yaw, roll = unreal_rotation_to_orientation(d.rotX or 0, d.rotY)
                    LocalPlayer.setCameraOrientation(pitch, yaw, roll)
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

    if use_pull_ticks then
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
            local tick_result_ok, tick_result_err = Gamelink.send(script_handle, {
                type = "tick",
                now_ms = Core.getTimeMillis(),
            })
            if tick_result_err then
                Core.error("Failed to request tracker tick: " .. (tick_result_err or "unknown"))
                Bridge.shutdown("Tracker communication failed")
                return
            end
            tick_in_flight = true
            tick_wait_seconds = 0
        end
    end
end

function dispose()
    Core.log("Unreal Bridge: Disposing...")

    pcall(function()
        if script_handle then
            pcall(function()
                Gamelink.send(script_handle, { type = "shutdown" })
            end)
            Gamelink.unloadScript(script_handle)
            script_handle = nil
        end

        if Gamelink.is_attached() then
            Gamelink.detach()
        end
    end)

    use_pull_ticks = false
    tick_in_flight = false
    tick_wait_seconds = 0
    resolved_offsets = nil
end
