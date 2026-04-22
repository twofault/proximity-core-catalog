-- Unreal Engine GameBridge
-- Extracts player data from UE4/UE5 games using GameLink Lua runtime introspection
-- No DLL injection required — ue_engine.lua discovers struct offsets at runtime
-- Uses coroutines for clean async flow

-- ============================================================================
-- CONSTANTS
-- ============================================================================

-- No timeout for discovery — scanning large games can take several minutes
local TICK_STALL_RESET_SECONDS = 0.2
local ATTACH_TIMEOUT_MS = 10000
local SEARCHING_LOG_INTERVAL = 200  -- Log "searching" every 10 seconds at 20Hz

-- Coordinate system conversion constants
-- Unreal: X=Forward, Y=Right, Z=Up (left-handed, Z-up, centimeters)
-- Standard: X=Right, Y=Up, Z=Forward (right-handed, Y-up, meters)
local UNREAL_TO_METERS = 0.01  -- Unreal uses centimeters, convert to meters

-- Note: pointer path is now discovered at runtime by ue_engine.lua
-- No hardcoded POINTER_PATH needed — the agent resolves offsets via UE reflection

-- ============================================================================
-- STATE
-- ============================================================================

local script_handle = nil  -- Handle from Gamelink.load for multi-script support
local use_pull_ticks = false
local tick_in_flight = false
local tick_wait_seconds = 0
local no_data_count = 0
local is_searching = false
local resolved_offsets = nil
local vector_precision = "vtFloat"
local vector_size = 4
local game_name = nil  -- Used as cache key

-- ============================================================================
-- COORDINATE CONVERSION FUNCTIONS
-- ============================================================================

--- Convert Unreal position to standard coordinate system
-- Unreal: X=Forward, Y=Right, Z=Up (centimeters)
-- Standard: X=Right, Y=Up, Z=Forward (meters)
-- @param ux Unreal X (forward)
-- @param uy Unreal Y (right)
-- @param uz Unreal Z (up)
-- @return standard_x, standard_y, standard_z
local function unreal_to_standard_position(ux, uy, uz)
    local scale = UNREAL_TO_METERS
    return uy * scale,   -- Standard X = Unreal Y (right)
           uz * scale,   -- Standard Y = Unreal Z (up)
           -ux * scale   -- Standard Z = -Unreal X (forward, negated for handedness)
end

--- Convert Unreal rotation (pitch/yaw in degrees) to standard euler orientation
-- Unreal: Yaw 0 = +X (forward), Yaw 90 = +Y (right), Pitch up = positive
-- Standard: pitch (up/down), yaw (left/right), roll
-- Convention: yaw 0 = -Z forward, positive yaw = leftward rotation
-- After coordinate conversion: UE +X forward → standard -Z, UE +Y right → standard +X
-- UE rotates rightward (CW from above), our yaw rotates leftward → negate
-- @param pitch_deg Unreal pitch in degrees
-- @param yaw_deg Unreal yaw in degrees
-- @return pitch_rad, yaw_rad, roll_rad (in radians, standard coordinate system)
local function unreal_rotation_to_orientation(pitch_deg, yaw_deg)
    local pitch_rad = math.rad(pitch_deg or 0)
    local yaw_rad = -math.rad(yaw_deg or 0)
    return pitch_rad, yaw_rad, 0
end

-- ============================================================================
-- UTILITY FUNCTIONS
-- ============================================================================

--- Helper to check cancellation
local function check_cancel()
    if Bridge.isCancelled() then
        Core.log("Initialization cancelled by user")
        Bridge.shutdown("Cancelled")
        return true
    end
    return false
end

-- Note: load_tracker_script and update_path_for_precision removed
-- ue_engine.lua handles both discovery and tracking as a single agent

--- Extract game name from window title for cache key
local function extract_game_name(window_title)
    if not window_title then return nil end
    -- Remove common suffixes like " - Unreal Engine", "(64-bit)", etc.
    local name = window_title:gsub("%s*%-%s*Unreal Engine.*", "")
    name = name:gsub("%s*%(64%-bit%).*", "")
    name = name:gsub("%s*%(32%-bit%).*", "")
    -- Sanitize for use as cache key
    name = name:gsub("[^%w%-_]", "_")
    return name
end

--- Validate cached offsets have required entries
local function validate_cache(cached)
    if not cached then return false end
    if not cached.offsets or not cached.vectorPrecision then return false end
    -- Check we have the essential offsets
    if not cached.offsets.GWorld then return false end
    if not cached.offsets.X then return false end
    return true
end

-- Note: build_cache_data removed — agent sends cache-ready offsets directly

-- ============================================================================
-- INITIALIZATION (runs as coroutine)
-- ============================================================================

function init()
    local pid = Bridge.getPid()
    if not pid then
        Core.error("No target PID set!")
        Bridge.shutdown("No target PID")
        return
    end

    Bridge.setProgress("Detecting game...", 5, 2)
    Core.log("Unreal Bridge: Initializing for PID " .. tostring(pid))

    -- Step 1: Build version hash for cache key using exe metadata
    local cache_key = nil

    -- Get window title for logging
    local window_title = Bridge.getWindowTitle()
    if window_title then
        game_name = extract_game_name(window_title)
        Core.log("Window title: " .. window_title)
    end

    -- Hash exe metadata for a stable, version-aware cache key
    if Bridge.hashFileMetadata then
        -- Try to get exe path from game profile or first module
        local profile = Bridge.getGameProfile()
        local exe_path = profile and profile.exe
        if exe_path and exe_path ~= "unknown.exe" then
            local meta = Bridge.hashFileMetadata(exe_path)
            if meta then
                cache_key = "ue_offsets_" .. meta.hash
                Core.log("Exe hash: " .. meta.hash .. " (size=" .. tostring(meta.size) .. ")")
            end
        end
        -- Fallback: use game name from window title
        if not cache_key and game_name then
            cache_key = "ue_offsets_name_" .. game_name
            Core.log("Using window title as cache key (no exe path available)")
        end
    elseif game_name then
        -- Legacy fallback if hashFileMetadata not available
        cache_key = "ue_offsets_" .. game_name
    end

    -- Step 2: Check cache for this game version
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

    -- Step 3: Attach GameLink (non-blocking — yields while attaching)
    Bridge.setProgress("Attaching to process...", 45, 3)
    Core.log("Attaching to PID " .. tostring(pid) .. "...")

    local attach_result = Gamelink.attach({ timeout_ms = ATTACH_TIMEOUT_MS })
    if not attach_result.success then
        Core.error("Failed to attach: " .. (attach_result.error or "unknown"))
        Bridge.shutdown("GameLink attach failed")
        return
    end
    -- Poll until attach completes (yields back to engine each tick)
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
            Bridge.setProgress(status.message or "Attaching...", 45, 3)
            coroutine.yield()
        end
    end
    Core.log("GameLink attached successfully")

    if check_cancel() then return end

    -- Step 4: Load ue_engine.lua (all-in-one discovery + tracking agent)
    Bridge.setProgress("Loading engine agent...", 60, 1)
    local load_result = Gamelink.load("ue_engine.lua", {
        runtime = "lua",
        capability = "observe",
    })
    if not load_result.success then
        Core.warn("Lua engine load failed: " .. tostring(load_result.error))

        -- Fallback: try legacy JS tracker with Dumper-7 flow
        Core.log("Falling back to legacy JS tracker...")
        load_result = Gamelink.load("unreal_tracker.js", {
            runtime = "default",
            capability = "observe",
        })
        if not load_result.success then
            Core.error("Failed to load any tracker: " .. tostring(load_result.error))
            Gamelink.detach()
            Bridge.shutdown("Tracker load failed")
            return
        end
        -- Legacy JS mode uses old init flow
        script_handle = load_result.handle
        use_pull_ticks = false
        Core.log("Legacy JS tracker loaded")
        Bridge.setProgressSnap("Connected (legacy mode)!", 100)
        return
    end

    script_handle = load_result.handle
    use_pull_ticks = true  -- ue_engine.lua uses pull-tick mode
    tick_in_flight = false
    tick_wait_seconds = 0
    no_data_count = 0
    Core.log("ue_engine.lua loaded (handle: " .. tostring(script_handle) .. ")")

    if check_cancel() then return end

    -- Step 5: Send init message — with cached offsets or empty (triggers discovery)
    local init_message
    if cached_offsets then
        Bridge.setProgress("Initializing engine...", 85, 1)
        -- cached_offsets already has shape: {offsets={GWorld=..., X=...}, vectorPrecision=..., vectorSize=...}
        -- Send it directly as 'data' field so the agent gets it as-is
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

    local send_result = Gamelink.send(script_handle, init_message)
    if not send_result.success then
        Core.error("Failed to send init: " .. tostring(send_result.error or "unknown"))
        Gamelink.detach()
        Bridge.shutdown("Init send failed")
        return
    end

    -- Step 6: Wait for init-response (agent discovers or uses cache, then confirms ready)
    local init_ok = false
    local init_done = false  -- true when init-response or fatal-error received

    while true do
        if check_cancel() then return end

        local messages = Gamelink.poll(script_handle)
        if messages then
            for _, msg in ipairs(messages) do
                -- Forward agent log messages
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
                        -- Agent discovered offsets — cache the full envelope
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
        Gamelink.unload(script_handle)
        script_handle = nil
        Gamelink.detach()
        Bridge.shutdown("Could not find player data. If you are in a menu, try joining a game first and reconnecting.")
        return
    end

    -- Step 7: Prime the first tick
    local tick_result = Gamelink.post(script_handle, {
        type = "tick",
        now_ms = Core.getTimeMillis(),
    })
    if not tick_result.success then
        Core.error("Failed to prime tick: " .. (tick_result.error or "unknown"))
        Gamelink.unload(script_handle)
        script_handle = nil
        Gamelink.detach()
        Bridge.shutdown("Failed to prime tracker")
        return
    end
    tick_in_flight = true
    tick_wait_seconds = 0

    -- Clear footer and mark as ready
    Bridge.setProgressFooter("")
    Bridge.setProgressSnap("Connected!", 100)
    Core.log("Unreal Bridge initialized successfully (Lua engine)")
end

-- ============================================================================
-- UPDATE LOOP
-- ============================================================================

function update(dt)
    if not script_handle then return end

    -- Check for GameLink errors
    if Gamelink.isError() then
        local err = Gamelink.getError() or "Unknown error"
        Core.error("GameLink error detected: " .. err)
        Bridge.shutdown("GameLink error: " .. err)
        return
    end

    -- Poll for messages from our script (filtered by handle at Rust level)
    local messages = Gamelink.poll(script_handle)

    local had_data = false
    if messages then
        for _, msg in ipairs(messages) do
            if use_pull_ticks then
                tick_in_flight = false
                tick_wait_seconds = 0
            end

            -- Forward agent log messages to bridge log
            if msg.type == "log" and msg.payload then
                Core.log("[agent] " .. tostring(msg.payload))
            end

            if msg.type == "data" and msg.payload then
                had_data = true
                no_data_count = 0
                local d = msg.payload

                -- Fatal errors from agent are logged but do NOT disconnect.
                -- Process exit is detected by the engine; GameLink errors are
                -- caught by Gamelink.isError() above.
                if d.type == "fatal-error" then
                    Core.error("Agent error: " .. (d.error or "unknown"))
                end

                -- Convert and set camera position (Unreal -> Standard coordinates)
                if d.posX then
                    local std_x, std_y, std_z = unreal_to_standard_position(d.posX, d.posY, d.posZ)
                    LocalPlayer.setCameraPosition(std_x, std_y, std_z)
                    -- Clear searching state when position data resumes
                    if is_searching then
                        is_searching = false
                        Bridge.push("searching_for_player", false, 30000)
                        Core.log("Player position recovered")
                    end
                end

                -- Convert camera pitch/yaw to euler orientation in standard coordinates
                -- Prefer ControlRotation (camera) if available, fallback to body rotation
                if d.pitch then
                    -- Camera rotation available (ControlRotation offset resolved)
                    local pitch, yaw, roll = unreal_rotation_to_orientation(d.pitch, d.yaw)
                    LocalPlayer.setCameraOrientation(pitch, yaw, roll)
                elseif d.rotY ~= nil then
                    -- Fallback: use body rotation when camera rotation unavailable
                    -- In Unreal's FRotator: rotX=Roll, rotY=Pitch, rotZ=Yaw (but varies by game)
                    -- For RelativeRotation, rotY is typically Yaw
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
            local tick_result = Gamelink.post(script_handle, {
                type = "tick",
                now_ms = Core.getTimeMillis(),
            })
            if not tick_result.success then
                Core.error("Failed to request tracker tick: " .. (tick_result.error or "unknown"))
                Bridge.shutdown("Tracker communication failed")
                return
            end
            tick_in_flight = true
            tick_wait_seconds = 0
        end
    end
end

-- ============================================================================
-- DISPOSAL
-- ============================================================================

function dispose()
    Core.log("Unreal Bridge: Disposing...")

    pcall(function()
        -- Unload our script first
        if script_handle then
            pcall(function()
                Gamelink.post(script_handle, { type = "shutdown" })
            end)
            Gamelink.unload(script_handle)
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
