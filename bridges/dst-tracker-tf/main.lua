-- DST bridge: walks Lua 5.1 internals (via native.observe(lua_pcall)) for
-- position/camera. Falls back to JS agent when the Lua runtime isn't available.

local ATTACH_TIMEOUT_MS = 10000
local SEARCHING_LOG_INTERVAL = 600  -- 10s at 60Hz

local script_handle = nil
local script_mode = nil
local no_data_count = 0
local is_searching = false
local has_camera_position = false
local has_position = true
local init_complete = false

-- Player position is delta-tracked from camera moves; the entity's heap
-- position is stale (written once, not per-tick).
local player_x = nil
local player_z = nil
local prev_cam_x = nil
local prev_cam_z = nil
local prev_heading = nil
local prev_distance = nil

local cur_cam_dist = nil
local ZOOM_SMOOTH = 4.0

-- Gimbal guard: near pitch ±90° float noise spins the audio "up" vector.
-- DST's orbit camera rarely hits this in normal play, but mods/debug can.
local PITCH_CLAMP_RAD = math.rad(89)
local YAW_HOLD_PITCH_RAD = math.rad(85)
local YAW_JUMP_REJECT_RAD = math.rad(30)
local last_stable_yaw = 0

local function wrap_pi(angle)
    while angle > math.pi do angle = angle - 2 * math.pi end
    while angle < -math.pi do angle = angle + 2 * math.pi end
    return angle
end

local function set_camera_orientation_stable(pitch, yaw, roll)
    if pitch > PITCH_CLAMP_RAD then pitch = PITCH_CLAMP_RAD
    elseif pitch < -PITCH_CLAMP_RAD then pitch = -PITCH_CLAMP_RAD end

    if math.abs(pitch) > YAW_HOLD_PITCH_RAD then
        local dy = wrap_pi(yaw - last_stable_yaw)
        if math.abs(dy) > YAW_JUMP_REJECT_RAD then
            yaw = last_stable_yaw
        else
            last_stable_yaw = yaw
        end
    else
        last_stable_yaw = yaw
    end

    GameStore.setCameraOrientation(pitch, yaw, roll or 0)
end


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

    Bridge.setProgress("Attaching to process...", 40, 3)

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
            if status_err then
                last_error = status_err
                break
            end
            if status.done then
                if status_err then
                    Core.error("GameLink attach failed: " .. (status_err or "unknown"))
                    Bridge.shutdown("GameLink attach failed")
                    return
                end
                break
            end
            Bridge.setProgress(status.message or "Attaching...", 40, 3)
            coroutine.yield()
        end
    end
    Core.log("GameLink attached successfully")

    if check_cancel() then return end

    Bridge.setProgress("Loading tracker script...", 55, 1)
    local load_result_handle, load_result_err = Gamelink.loadScript("dst_tracker.lua")
    if not load_result_err then
        script_mode = "lua"
    else
        Core.warn("Lua agent load failed, falling back to JS: " .. tostring(load_result_err))
        load_result_handle, load_result_err = Gamelink.loadScript("dst_tracker.js", {
            runtime = "default",
        })
        if not load_result_err then
            script_mode = "js"
        end
    end

    if load_result_err then
        Core.error("Failed to load Frida script: " .. (load_result_err or "unknown"))
        Gamelink.detach()
        Bridge.shutdown("Script load failed")
        return
    end
    script_handle = load_result_handle
    Core.log("GameLink script loaded (mode: " .. script_mode .. ", handle: " .. tostring(script_handle) .. ")")

    if check_cancel() then return end

    Bridge.setProgress("Starting runtime discovery...", 80, 5)

    local init_message = {
        type = "init",
        now_ms = Core.getTimeMillis()
    }
    local send_result_ok, send_result_err = Gamelink.send(script_handle, init_message)
    if send_result_err then
        Core.error("Failed to send init message: " .. (send_result_err or "unknown"))
        Gamelink.detach()
        Bridge.shutdown("Failed to send init message")
        return
    end

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

        local js_load_handle, js_load_err = Gamelink.loadScript("dst_tracker.js", {
            runtime = "default",
        })
        if js_load_err then
            Core.error("Failed to load JS fallback script: " .. tostring(js_load_err))
            return false
        end

        script_handle = js_load_handle
        script_mode = "js"

        local js_init_send_ok, js_init_send_err = Gamelink.send(script_handle, init_message)
        if js_init_send_err then
            Core.error("Failed to send init to JS fallback: " .. tostring(js_init_send_err))
            return false
        end

        start_time = Core.getTimeMillis()
        return true
    end

    while Core.getTimeMillis() - start_time < response_timeout do
        if check_cancel() then return end

        -- Ticks drive the JS fallback state machine during init.
        local __ok, __err = Gamelink.send(script_handle, {
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
                            Core.log("GameLink script initialized successfully")
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

    Bridge.setProgressSnap("Connected!", 100)
    Core.log("DST Bridge initialized")
end

function update(dt)
    if not script_handle then return end

    if Gamelink.isError() then
        local err = Gamelink.getError() or "Unknown error"
        Core.error("GameLink error: " .. err)
        Bridge.shutdown("GameLink error: " .. err)
        return
    end

    -- Lua agent polls tick-driven (no self-polling); ticks needed every frame.
    local __ok, __err = Gamelink.send(script_handle, {
        type = "tick",
        now_ms = Core.getTimeMillis()
    })

    local messages = Gamelink.poll(script_handle)
    local had_data = false

    if messages then
        for _, msg in ipairs(messages) do
            if msg.type == "data" and msg.payload then
                local d = msg.payload

                -- Agent fatal errors are logged but don't disconnect — engine
                -- detects process exit, Gamelink.isError handles Frida errors.
                if d.type == "fatal-error" then
                    Core.error("Agent error: " .. (d.error or "unknown"))
                end

                -- Heartbeat = agent alive, no position (menu/death/loading).
                if d.type == "heartbeat" then
                    had_data = true
                    no_data_count = 0
                end

                if d.type == "data" and (d.posX or d.camX or d.camHeading) then
                    had_data = true
                    no_data_count = 0
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

                    if cur_cam_dist == nil then
                        cur_cam_dist = camDist
                    else
                        local t = 1.0 - math.exp(-ZOOM_SMOOTH * dt)
                        cur_cam_dist = cur_cam_dist + (camDist - cur_cam_dist) * t
                    end

                    -- Camera-move-without-orbit/zoom = player walked.
                    -- Orbit/zoom = player still, camera moved.
                    if player_x == nil then
                        -- Seed from stale entity pos, or camera-inverse.
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
                        local heading_changed = math.abs(headingDeg - prev_heading) > 0.3
                        local distance_changed = math.abs(camDist - prev_distance) > 0.05

                        if not heading_changed and not distance_changed then
                            local dx = d.camX - prev_cam_x
                            local dz = d.camZ - prev_cam_z
                            -- Cap to absorb respawn/scene-load teleports.
                            local cap = 5
                            dx = math.max(-cap, math.min(cap, dx))
                            dz = math.max(-cap, math.min(cap, dz))
                            player_x = player_x + dx
                            player_z = player_z + dz
                        end

                        prev_cam_x = d.camX
                        prev_cam_z = d.camZ
                        prev_heading = headingDeg
                        prev_distance = camDist
                    end

                    local posX = player_x
                    local posY = 0
                    local posZ = player_z

                    -- Reconstruct camera from player + heading + smoothed dist.
                    local hDist = cur_cam_dist * math.cos(pitchRad)
                    local vDist = cur_cam_dist * math.sin(pitchRad)
                    local camX = posX + hDist * math.cos(headingRad)
                    local camY = posY + vDist
                    local camZ = posZ + hDist * math.sin(headingRad)

                    local yaw = headingRad + math.pi / 2
                    local pitch = -pitchRad

                    -- Negate Z: right-handed coordinate system.
                    GameStore.setCameraPosition(camX, camY, -camZ)
                    set_camera_orientation_stable(pitch, yaw, 0)
                    GameStore.setSpeakerPosition(posX, posY, -posZ)
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

function dispose()
    Core.log("DST Bridge: Disposing...")
    -- Runtime auto-cleans Gamelink (unload + detach) after dispose returns.
    script_handle = nil
    script_mode = nil
end
