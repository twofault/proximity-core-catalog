-- Don't Starve Together Game Bridge
-- Extracts player position and camera position/orientation from DST
--
-- Architecture:
--   Lua (this file) -> Frida Lua agent (compliant, memory-read only)
--     -> native.observe(lua_pcall) for state discovery
--     -> memory.read_* to walk Lua 5.1 internals for position/camera
--   Fallback: JS agent (full Frida API) for non-Lua-runtime builds

-- ============================================================================
-- CONSTANTS
-- ============================================================================

local ATTACH_TIMEOUT_MS = 10000
local SEARCHING_LOG_INTERVAL = 200  -- Log "searching" every 10 seconds at 20Hz

-- ============================================================================
-- STATE
-- ============================================================================

local script_handle = nil
local script_mode = nil -- "lua" or "js"
local no_data_count = 0
local is_searching = false
local has_camera_position = false  -- set from init-response
local has_position = true          -- false = camera-only mode (no player pos found)
local init_complete = false

-- Player position tracking via camera deltas
local player_x = nil                   -- tracked player X (stable during orbit/zoom)
local player_z = nil                   -- tracked player Z
local prev_cam_x = nil                 -- camera position from previous frame
local prev_cam_z = nil
local prev_heading = nil               -- heading from previous frame
local prev_distance = nil              -- distance from previous frame

-- Smoothed zoom distance
local cur_cam_dist = nil
local ZOOM_SMOOTH = 4.0


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

    Bridge.setProgress("Initializing...", 5, 2)
    Core.log("DST Bridge: Initializing for PID " .. tostring(pid))

    local function check_cancel()
        if Bridge.isCancelled() then
            Core.log("Initialization cancelled by user")
            Bridge.shutdown("Cancelled")
            return true
        end
        return false
    end

    -- Step 1: Attach Frida (non-blocking — yields while attaching)
    Bridge.setProgress("Attaching to process...", 40, 3)

    local attach_result = Gamelink.attach({ timeout_ms = ATTACH_TIMEOUT_MS })
    if not attach_result.success then
        Core.error("Failed to attach Frida: " .. (attach_result.error or "unknown"))
        Bridge.shutdown("Frida attach failed")
        return
    end
    -- Poll until attach completes (yields back to engine each tick)
    if attach_result.pending then
        while true do
            if check_cancel() then return end
            local status = Gamelink.pollAttach()
            if status.done then
                if not status.success then
                    Core.error("Frida attach failed: " .. (status.error or "unknown"))
                    Bridge.shutdown("Frida attach failed")
                    return
                end
                break
            end
            Bridge.setProgress(status.message or "Attaching...", 40, 3)
            coroutine.yield()
        end
    end
    Core.log("Frida attached successfully")

    if check_cancel() then return end

    -- Step 2: Load the Frida script
    Bridge.setProgress("Loading tracker script...", 55, 1)
    local load_result = Gamelink.loadScript("dst_tracker.lua")
    if load_result.success then
        script_mode = "lua"
    else
        Core.warn("Lua agent load failed, falling back to JS: " .. tostring(load_result.error))
        load_result = Gamelink.loadScript("dst_tracker.js", {
            runtime = "default",
            capability = "observe"
        })
        if load_result.success then
            script_mode = "js"
        end
    end

    if not load_result.success then
        Core.error("Failed to load Frida script: " .. (load_result.error or "unknown"))
        Gamelink.detach()
        Bridge.shutdown("Script load failed")
        return
    end
    script_handle = load_result.handle
    Core.log("Frida script loaded (mode: " .. script_mode .. ", handle: " .. tostring(script_handle) .. ")")

    if check_cancel() then return end

    -- Step 3: Send init message to trigger agent initialization
    Bridge.setProgress("Starting runtime discovery...", 80, 5)

    local init_message = {
        type = "init",
        now_ms = Core.getTimeMillis()
    }
    local send_result = Gamelink.send(script_handle, init_message)
    if not send_result.success then
        Core.error("Failed to send init message: " .. (send_result.error or "unknown"))
        Gamelink.detach()
        Bridge.shutdown("Failed to send init message")
        return
    end

    -- Step 4: Wait for init response, processing progress updates
    local response_timeout = 60000
    local start_time = Core.getTimeMillis()
    local got_response = false
    local attempted_js_fallback = (script_mode == "js")

    local function try_js_fallback(reason)
        if attempted_js_fallback then
            return false
        end
        attempted_js_fallback = true

        Core.warn("Lua agent init failed, falling back to JS: " .. tostring(reason))

        pcall(function()
            if script_handle then
                Gamelink.unloadScript(script_handle)
            end
        end)
        script_handle = nil

        local js_load = Gamelink.loadScript("dst_tracker.js", {
            runtime = "default",
            capability = "observe"
        })
        if not js_load.success then
            Core.error("Failed to load JS fallback script: " .. tostring(js_load.error))
            return false
        end

        script_handle = js_load.handle
        script_mode = "js"

        local js_init_send = Gamelink.send(script_handle, init_message)
        if not js_init_send.success then
            Core.error("Failed to send init to JS fallback: " .. tostring(js_init_send.error))
            return false
        end

        start_time = Core.getTimeMillis()
        return true
    end

    while Core.getTimeMillis() - start_time < response_timeout do
        if check_cancel() then return end

        -- Send tick messages during init (the compliant Lua agent does synchronous
        -- init in its recv handler, but ticks also drive the fallback state machine)
        local _ = Gamelink.send(script_handle, {
            type = "tick",
            now_ms = Core.getTimeMillis()
        })

        local messages = Gamelink.poll(script_handle)
        if messages then
            for _, msg in ipairs(messages) do
                if msg.type == "data" and msg.payload then
                    local payload = msg.payload

                    if payload.type == "init-response" then
                        if payload.success then
                            Core.log("Frida script initialized successfully")
                            has_camera_position = payload.hasCameraPosition or false
                            has_position = (payload.hasPosition ~= false)
                            Core.log("Camera 3D: " .. (has_camera_position and "yes" or "no") ..
                                     ", Position: " .. (has_position and "yes" or "camera-only"))
                            got_response = true
                            init_complete = true
                        else
                            local init_err = payload.error or "unknown"
                            if script_mode == "lua" and try_js_fallback(init_err) then
                                break
                            end
                            Core.error("Init failed: " .. init_err)
                            Gamelink.detach()
                            Bridge.shutdown("Init failed: " .. init_err)
                            return
                        end
                        break

                    elseif payload.type == "progress" then
                        Bridge.setProgress(payload.message or "Working...", 80 + (payload.percent or 0) * 0.19, 0.5)

                    elseif payload.type == "fatal-error" then
                        local fatal_err = payload.error or "unknown"
                        if script_mode == "lua" and try_js_fallback(fatal_err) then
                            break
                        end
                        Core.error("Fatal error: " .. fatal_err)
                        Gamelink.detach()
                        Bridge.shutdown("Fatal error during init")
                        return
                    end

                end
            end
        end

        if got_response then break end
        coroutine.yield()
    end

    if not got_response then
        if script_mode == "lua" and try_js_fallback("Init timeout") then
            while Core.getTimeMillis() - start_time < response_timeout do
                if check_cancel() then return end

                local messages = Gamelink.poll(script_handle)
                if messages then
                    for _, msg in ipairs(messages) do
                        if msg.type == "data" and msg.payload and msg.payload.type == "init-response" then
                            if msg.payload.success then
                                has_camera_position = msg.payload.hasCameraPosition or false
                                has_position = (msg.payload.hasPosition ~= false)
                                got_response = true
                                init_complete = true
                                break
                            end
                        end
                    end
                end

                if got_response then break end
                coroutine.yield()
            end
        end
    end

    if not got_response then
        Core.error("Timeout waiting for init response (60s)")
        Gamelink.detach()
        Bridge.shutdown("Init timeout")
        return
    end

    -- Step 5: Ready!
    Bridge.setProgressSnap("Connected!", 100)
    Core.log("DST Bridge initialized")
end

-- ============================================================================
-- UPDATE LOOP
-- ============================================================================

function update(dt)
    if not script_handle then return end

    -- Check for Frida errors (process exited, session lost, etc.)
    if Gamelink.isError() then
        local err = Gamelink.getError() or "Unknown error"
        Core.error("Frida error: " .. err)
        Bridge.shutdown("Frida error: " .. err)
        return
    end

    -- Send tick messages continuously. The compliant Lua agent uses tick-driven
    -- polling (no interceptor self-polling), so ticks are needed both during
    -- init and after. The JS fallback handles ticks gracefully when not needed.
    local _ = Gamelink.send(script_handle, {
        type = "tick",
        now_ms = Core.getTimeMillis()
    })

    local messages = Gamelink.poll(script_handle)
    local had_data = false

    if messages then
        for _, msg in ipairs(messages) do
            if msg.type == "data" and msg.payload then
                local d = msg.payload

                -- Fatal errors from agent are logged but do NOT disconnect.
                -- Process exit is detected by the engine; Frida errors are
                -- caught by Gamelink.isError() above.
                if d.type == "fatal-error" then
                    Core.error("Agent error: " .. (d.error or "unknown"))
                end

                -- Heartbeat = agent is alive but no position data (menu, death, loading)
                if d.type == "heartbeat" then
                    had_data = true
                    no_data_count = 0
                end

                if d.type == "data" and (d.posX or d.camX or d.camHeading) then
                    had_data = true
                    no_data_count = 0
                    -- Clear searching state when position data resumes
                    if is_searching then
                        is_searching = false
                        Bridge.push("searching_for_player", false, 30000)
                        Core.log("Player position recovered")
                    end

                    local headingDeg = d.camHeading or 0
                    local headingRad = math.rad(headingDeg)
                    local pitchDeg = d.camPitch or 42
                    local pitchRad = math.rad(pitchDeg)
                    local camDist = d.camDistance or 30

                    -- Smooth zoom distance (exponential ease-out)
                    if cur_cam_dist == nil then
                        cur_cam_dist = camDist
                    else
                        local t = 1.0 - math.exp(-ZOOM_SMOOTH * dt)
                        cur_cam_dist = cur_cam_dist + (camDist - cur_cam_dist) * t
                    end

                    -- ── Player position: delta-tracked from camera movement ──
                    -- The entity C++ memory position (d.posX) is stale (written once,
                    -- not updated per-tick). Instead, we track the player by observing
                    -- camera movement: when heading/distance don't change but camera
                    -- moves → player walked. When heading/distance change → orbit/zoom,
                    -- player stays put. This matches the old architecture exactly.
                    if player_x == nil then
                        -- First frame: seed from entity stale position (close enough)
                        -- or approximate from camera inverse
                        if d.posX then
                            player_x = d.posX
                            player_z = d.posZ
                        elseif d.camX then
                            local hd = camDist * math.cos(pitchRad)
                            player_x = d.camX - hd * math.cos(headingRad)
                            player_z = d.camZ - hd * math.sin(headingRad)
                        else
                            had_data = true
                            return
                        end
                        prev_cam_x = d.camX
                        prev_cam_z = d.camZ
                        prev_heading = headingDeg
                        prev_distance = camDist
                    elseif d.camX and prev_cam_x then
                        -- Detect what changed since last frame
                        local heading_changed = math.abs(headingDeg - prev_heading) > 0.3
                        local distance_changed = math.abs(camDist - prev_distance) > 0.05

                        if not heading_changed and not distance_changed then
                            -- No orbit/zoom → camera delta = player movement
                            local dx = d.camX - prev_cam_x
                            local dz = d.camZ - prev_cam_z
                            -- Cap to prevent teleport on respawn/scene load
                            local cap = 5
                            dx = math.max(-cap, math.min(cap, dx))
                            dz = math.max(-cap, math.min(cap, dz))
                            player_x = player_x + dx
                            player_z = player_z + dz
                        end
                        -- If orbit/zoom changed: player stays put, only camera moves

                        prev_cam_x = d.camX
                        prev_cam_z = d.camZ
                        prev_heading = headingDeg
                        prev_distance = camDist
                    end

                    local posX = player_x
                    local posY = 0
                    local posZ = player_z

                    -- ── Camera = player + orbit offset (old architecture) ──
                    -- Reconstruct camera from player position + heading + smoothed
                    -- distance. Only the camera moves during orbit/zoom.
                    local hDist = cur_cam_dist * math.cos(pitchRad)
                    local vDist = cur_cam_dist * math.sin(pitchRad)
                    local camX = posX + hDist * math.cos(headingRad)
                    local camY = posY + vDist
                    local camZ = posZ + hDist * math.sin(headingRad)

                    -- Yaw from heading (same convention as old code)
                    local yaw = headingRad + math.pi / 2
                    local pitch = -pitchRad

                    -- Negate Z for right-handed coordinate system
                    LocalPlayer.setCameraPosition(camX, camY, -camZ)
                    LocalPlayer.setCameraOrientation(pitch, yaw, 0)
                    LocalPlayer.setSpeakerPosition(posX, posY, -posZ)
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
end

-- ============================================================================
-- DISPOSAL
-- ============================================================================

function dispose()
    Core.log("DST Bridge: Disposing...")
    pcall(function()
        if script_handle then
            -- Tell the Frida agent to clean up (detach observers / hooks)
            pcall(function()
                Gamelink.send(script_handle, { type = "shutdown" })
            end)

            Gamelink.unloadScript(script_handle)
            script_handle = nil
            script_mode = nil
        end
        if Gamelink.isAttached() then
            Gamelink.detach()
        end
    end)
end
