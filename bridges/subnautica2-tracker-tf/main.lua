-- Subnautica 2 GameBridge. Extends the generic UE position tracker with
-- SN2-specific surroundings: underwater, in-base, in-vehicle, room_size,
-- reverb. The agent (sn2_tracker.lua) emits pawn class + a handful of
-- reflection-discovered fields; this host classifies them and pushes the
-- appropriate surroundings to GameStore.

-- 5s effectively disables tick re-send. Lower values (we tried 0.2s) pile
-- up ticks in the agent queue during IPC stalls and produce a burst-then-
-- silence pattern when the queue drains. Agent death is caught separately
-- via Gamelink.isError().
local TICK_STALL_RESET_SECONDS = 5.0
-- Re-attach to the same PID is slow because the previous agent leaked
-- (we never unload to avoid crashing the target's loader). 25s leaves
-- headroom over the measured 9-10s hot-reattach cost.
local ATTACH_TIMEOUT_MS = 25000
local SEARCHING_LOG_INTERVAL = 600  -- 10s at 60Hz

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
local last_scene_name = nil

-- Captured at init so auto-recovery can invalidate / re-save without
-- re-deriving the key.
local current_cache_key = nil

-- Optional second script that probes loaded networking SDKs for an active
-- session ID. Failure to load is non-fatal — position tracking continues.
local NET_ID_TICK_INTERVAL_S = 1.0
local net_id_handle = nil
local last_session_id = nil
local last_net_id_tick = 0

local function unreal_to_standard_position(ux, uy, uz)
    local scale = UNREAL_TO_METERS
    return uy * scale,   -- Standard X = Unreal Y (right)
           uz * scale,   -- Standard Y = Unreal Z (up)
           -ux * scale   -- Standard Z = -Unreal X (forward, negated for handedness)
end

-- FRotator components store unsigned degrees [0, 360); normalize to
-- (-180, 180] before clamping or the pitch clamp treats 350° (looking
-- down 10°) as past +89° and snaps the listener straight up.
local function normalize_axis_deg(deg)
    if not deg then return 0 end
    deg = deg % 360
    if deg > 180 then deg = deg - 360 end
    return deg
end

-- UE yaw is CW from above; ours is CCW → negate.
local function unreal_rotation_to_orientation(pitch_deg, yaw_deg)
    local pitch_rad = math.rad(normalize_axis_deg(pitch_deg))
    local yaw_rad = -math.rad(normalize_axis_deg(yaw_deg))
    return pitch_rad, yaw_rad, 0
end

-- Gimbal-lock-safe: clamp pitch below ±90° and hold last stable yaw
-- when pitch is near zenith/nadir and yaw jumps wildly (float noise in
-- the source FRotator spins the audio "up" vector otherwise).
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

-- ── Subnautica 2 surroundings mapping ──
--
-- The agent emits raw pawn state; this host turns it into the registered
-- surroundings (underwater, radio_access, room_size, reverb). Latching is
-- per-key so we don't spam GameStore each tick.

local last_underwater = nil
local last_radio_access = nil
local last_room_size = nil
local last_reverb = nil
local last_pawn_class = nil

-- Vehicle class-name → { room_size_meters, reverb } overrides. Anything we
-- don't recognise still gets the "is a vehicle" defaults (small cockpit).
-- Tuned to match the SN1 bridge feel. Names are checked lowercase against
-- both the current pawn class name AND the `pilotingVehicleClassName`
-- field (set when the character keeps its class but references a vehicle).
local SN2_VEHICLE_TUNING = {
    -- Pattern (lowercase substring on the pawn or piloting class name).
    { match = "tadpole",   room = 1,  reverb = 0.18 },  -- small one-seater
    { match = "seatruck",  room = 4,  reverb = 0.25 },  -- bigger cabin
    { match = "hoverbike", room = 1,  reverb = 0.15 },
    { match = "prawn",     room = 1,  reverb = 0.15 },
    { match = "submarine", room = 10, reverb = 0.4  },  -- big metal hull
}
local DEFAULT_VEHICLE_ROOM = 1.5
local DEFAULT_VEHICLE_REVERB = 0.2

-- Two contexts:
--   "vehicle:<name>" — pawn is a vehicle OR character references one
--   "open"           — anything else (open world or inside a habitat)
--
-- "Base" detection was removed: no reliable property on `BP_Character_01_C`
-- distinguishes habitat-air-pocket from open ocean. `InBaseGracePeriod`
-- reads its Class Default Object value (0.15) even outside any base, so
-- gating on it falsely tagged the player as always-in-air, which silently
-- disabled underwater muffling everywhere. When SN2 surfaces a stable
-- in-base signal (live timer or air-pocket volume hit) we can add a third
-- context here.
local function classify_room_and_reverb(d)
    if d.pawnIsVehicle or (d.pilotingVehicleClassName and d.pilotingVehicleClassName ~= "") then
        local candidates = {
            (d.pilotingVehicleClassName or ""):lower(),
            (d.pawnClassName or ""):lower(),
        }
        for _, lc in ipairs(candidates) do
            if lc ~= "" then
                for _, t in ipairs(SN2_VEHICLE_TUNING) do
                    if lc:find(t.match, 1, true) then
                        return t.room, t.reverb, "vehicle:" .. t.match
                    end
                end
            end
        end
        return DEFAULT_VEHICLE_ROOM, DEFAULT_VEHICLE_REVERB, "vehicle"
    end
    return 0, 0, "open"
end

local function apply_surroundings(d, posY_meters)
    -- Two contexts today: "vehicle:<name>" or "open".
    local room_size, reverb_strength, context = classify_room_and_reverb(d)
    local in_vehicle = (context ~= "open")

    -- Underwater = CMC.MovementMode == MOVE_Swimming (the only reliable
    -- signal on SN2 right now), suppressed while piloting a vehicle so the
    -- Tadpole/Seatruck cabin sounds dry. When the player is in a habitat,
    -- the CMC drops out of MOVE_Swimming naturally (back to MOVE_Walking),
    -- so we get habitat air "for free" without explicit base detection.
    -- If `isSwimming` is unknown (no CMC resolved), default to dry — the
    -- agent will have logged a probe warning so the regression is visible.
    local underwater = 0
    if d.isSwimming and not in_vehicle then
        underwater = 0.8
    end

    local radio_access = d.pawnIsVehicle and 1 or 0

    if underwater ~= last_underwater
        and (last_underwater == nil or math.abs(underwater - (last_underwater or 0)) > 0.05
             or (underwater == 0) ~= ((last_underwater or 0) == 0)) then
        GameStore.setSurrounding("underwater", underwater)
        last_underwater = underwater
    end
    if radio_access ~= last_radio_access then
        GameStore.setSurrounding("radio_access", radio_access)
        last_radio_access = radio_access
    end
    if room_size ~= last_room_size then
        GameStore.setSurrounding("room_size", room_size)
        last_room_size = room_size
    end
    if reverb_strength ~= last_reverb then
        GameStore.setSurrounding("reverb", reverb_strength)
        last_reverb = reverb_strength
    end

    -- One log line per meaningful state change. No per-tick spam.
    local sig = table.concat({
        d.pawnClassName or "?",
        d.pilotingVehicleClassName or "-",
        tostring(d.movementMode),
        tostring(d.isSwimming),
        context,
        string.format("%.2f", underwater),
        tostring(radio_access),
    }, "|")
    if sig ~= last_pawn_class then
        Core.log(string.format(
            "[surroundings] pawn='%s' piloting='%s' mm=%s isSwim=%s context=%s underwater=%.2f radio=%d room=%g reverb=%.2f",
            d.pawnClassName or "?", d.pilotingVehicleClassName or "none",
            tostring(d.movementMode), tostring(d.isSwimming),
            context, underwater, radio_access, room_size, reverb_strength))
        last_pawn_class = sig
    end
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

-- Bump when cached payload shape changes — older caches are invalidated
-- so users get new behavior without manual wiping. v4 added full-chain
-- GWorld validation; v3 added structural OGI checks; v2 added alternates.
-- v5 required the cache to carry a `reflection` block so the SN2 probe
-- could read per-property fields. v6 drops the unreliable habitat signals
-- (RecentlySubmerged / InBaseGracePeriod / CurrentOxygenator /
-- bInBaseReplication) from the agent payload — bumping forces a refresh
-- so v5 caches don't keep producing the dead fields the host no longer
-- reads.
local CACHE_SCHEMA_VERSION = 6

local function validate_cache(cached)
    if not cached then return false end
    if not cached.offsets or not cached.vectorPrecision then return false end
    if not cached.offsets.GWorld then return false end
    if not cached.offsets.X then return false end
    if (cached.schemaVersion or 1) < CACHE_SCHEMA_VERSION then
        Core.log("Cache schema is older than v" .. CACHE_SCHEMA_VERSION
            .. " — invalidating to pick up improved discovery")
        return false
    end
    if type(cached.reflection) ~= "table" then
        Core.log("Cache is missing the `reflection` block — invalidating so "
            .. "the SN2 probe can read per-property fields after next attach")
        return false
    end
    return true
end

function init()
    local pid = Bridge.getPid()
    if not pid then
        Core.error("No target PID set!")
        Bridge.shutdown("No target PID")
        return
    end

    Bridge.setProgress("Detecting game...", 2, 1)
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
        current_cache_key = cache_key
        Bridge.setProgress("Checking cache...", 5, 1)
        local cached = Cache.load(cache_key)
        if validate_cache(cached) then
            cached_offsets = cached
            Core.log("Cache hit! Using cached offsets")
            Bridge.setProgress("Using cached offsets...", 12, 0.5)
        else
            Core.log("No valid cache, will discover offsets at runtime")
        end
    end

    if check_cancel() then return end

    Bridge.setProgress("Attaching to process...", 15, 3)
    Core.log("Attaching Frida to PID " .. tostring(pid) .. "...")

    -- Wait for any lingering worker from a prior detach. Polling yields
    -- the coroutine so the engine keeps ticking during the wait.
    local lingering_wait_start = Core.getTimeMillis()
    while not Gamelink.isLingeringClear() do
        if Bridge.isCancelled() then
            Bridge.shutdown("Cancelled")
            return
        end
        if Core.getTimeMillis() - lingering_wait_start > 15000 then
            Core.warn("Previous Frida worker did not finish unwinding within 15s; " ..
                "attempting attach anyway")
            break
        end
        Bridge.setProgress("Waiting for previous session to close...", 15, 1)
        coroutine.yield()
    end

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
            Bridge.setProgress(status.message or "Attaching...", 15, 3)
            coroutine.yield()
        end
    end
    Core.log("GameLink attached successfully")

    if check_cancel() then return end

    Bridge.setProgress("Loading engine agent...", 22, 1)
    local load_result_handle, load_result_err = Gamelink.loadScript("sn2_tracker.lua", {
        runtime = "lua",
    })
    if load_result_err then
        Core.warn("Lua engine load failed: " .. tostring(load_result_err))

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
        Bridge.setProgress("Initializing engine...", 28, 1)
        init_message = { type = "init", data = cached_offsets }
        Core.log("Sending cached offsets to agent (skipping discovery)")
        Core.log("  Cache has " .. tostring(cached_offsets.vectorPrecision) .. " precision")
        Bridge.setProgressFooter("Using cached offsets from previous session")
    else
        Bridge.setProgress("Initializing engine...", 28, 2)
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
                        -- Map agent 0-100% to UI 30-99%.
                        local ui_pct = 30 + (d.percent or 0) * 0.69
                        Bridge.setProgress(d.message or "Discovering...", ui_pct, 0.5)

                    elseif d.type == "discovery-complete" then
                        if cache_key and d.offsets then
                            local cache_data = {
                                offsets = d.offsets,
                                vectorPrecision = d.vectorPrecision or "vtFloat",
                                vectorSize = d.vectorSize or 4,
                                schemaVersion = CACHE_SCHEMA_VERSION,
                                -- Lets the agent rehydrate UObjectLayout +
                                -- GNames on cache hit and resolve map names
                                -- without re-running the GObjects/GNames scan.
                                discoveryState = d.discoveryState,
                                -- Promote reflection to the top so the SN2
                                -- probe (and validate_cache) can find it
                                -- without spelunking the discoveryState.
                                reflection = d.discoveryState
                                    and d.discoveryState.reflection,
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

    -- Optional net-id-capture helper. Non-fatal — bridge keeps working
    -- without session detection if this fails to load.
    local net_handle, net_err = Gamelink.loadScript("net_id_capture.lua", { runtime = "lua" })
    if net_err or not net_handle then
        Core.log("net_id_capture: not loaded ("
            .. tostring(net_err or "nil handle")
            .. ") -- session-id detection disabled")
    else
        net_id_handle = net_handle
        Core.log("net_id_capture: loaded (handle " .. tostring(net_id_handle) .. ")")
    end
end

-- Polling is done in update() so engine + helper share one queue drain.
local function tick_net_id_capture(dt)
    if not net_id_handle then return end
    last_net_id_tick = last_net_id_tick + (dt or 1 / 60)
    if last_net_id_tick >= NET_ID_TICK_INTERVAL_S then
        last_net_id_tick = 0
        pcall(Gamelink.send, net_id_handle, {
            type = "tick", now_ms = Core.getTimeMillis(),
        })
    end
end

local function handle_net_id_message(msg)
    if msg.type == "log" and msg.payload then
        Core.log("[net_id] " .. tostring(msg.payload))
    elseif msg.type == "data" and msg.payload then
        local d = msg.payload
        if d.type == "session-id" then
            if d.id and d.id ~= last_session_id then
                last_session_id = d.id
                pcall(Session.suggestPublicSession, d.id)
                Core.log("Session ID set: " .. tostring(d.id) ..
                    " (source=" .. tostring(d.source) .. ")")
            elseif not d.id and last_session_id then
                last_session_id = nil
                pcall(Session.clearSuggestedSession)
                Core.log("Session ID cleared (reason="
                    .. tostring(d.reason or "?") .. ")")
            end
        end
    end
end

function update(dt)
    if not script_handle then return end

    if Gamelink.isError() then
        local err = Gamelink.getError() or "Unknown error"
        Core.error("GameLink error detected: " .. err)
        Bridge.shutdown("GameLink error: " .. err)
        return
    end

    tick_net_id_capture(dt)

    -- Pull unfiltered and route by msg.handle — Gamelink.poll(handle)
    -- discards non-matching messages, so two filtered polls in one tick
    -- race over the same queue and the loser sees nothing.
    local messages = Gamelink.poll()

    -- Burst detection: > 5 messages in one poll means the IPC pipe was
    -- stalled and we're draining a backlog. Only the LAST position
    -- survives the per-frame coalesce, so the user sees freeze-then-jump.
    if messages and #messages > 5 then
        Core.warn(string.format(
            "Bridge poll drained %d messages in one frame (IPC backlog — sound stage will jump)",
            #messages
        ))
    end

    local had_data = false
    if messages then
        for _, msg in ipairs(messages) do
            if net_id_handle and msg.handle == net_id_handle then
                handle_net_id_message(msg)
                goto continue_msg
            end

            -- Engine agent: untagged or engine-handle-tagged messages.
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

                -- Logged but does NOT disconnect — process exit is detected
                -- by the engine, Frida errors by Gamelink.isError() above.
                if d.type == "fatal-error" then
                    Core.error("Agent error: " .. (d.error or "unknown"))
                end

                -- Invalidate cache on START so a kill mid-recovery leaves
                -- a clean slate; re-save on the discovery-complete that
                -- follows.
                if d.type == "auto-recovery-started" then
                    Core.warn("Auto-recovery: agent reports cached offsets are stale; "
                        .. "invalidating cache and re-running discovery")
                    if current_cache_key then
                        local removed = Cache.remove(current_cache_key)
                        Core.log("Cache invalidated (key=" .. tostring(current_cache_key)
                            .. ", removed=" .. tostring(removed) .. ")")
                    end
                    is_searching = true
                    Bridge.push("searching_for_player", true, 60000)
                elseif d.type == "auto-recovery-failed" then
                    Core.error("Auto-recovery FAILED: " .. tostring(d.error or "unknown")
                        .. " — bridge will keep trying with cached offsets but will "
                        .. "likely stay broken until the user reconnects")
                elseif d.type == "discovery-complete" then
                    -- Fires on init AND auto-recovery; save offsets so
                    -- the next attach skips discovery.
                    if current_cache_key and d.offsets then
                        local cache_data = {
                            offsets = d.offsets,
                            vectorPrecision = d.vectorPrecision or "vtFloat",
                            vectorSize = d.vectorSize or 4,
                            schemaVersion = CACHE_SCHEMA_VERSION,
                            discoveryState = d.discoveryState,
                            reflection = d.discoveryState
                                and d.discoveryState.reflection,
                        }
                        if Cache.save(current_cache_key, cache_data) then
                            Core.log("Auto-recovery: cached fresh offsets")
                        end
                    end
                elseif d.type == "init-response" and d.auto_recovered then
                    Core.log("Auto-recovery COMPLETE — resuming normal operation")
                    -- Trust the recovery message instead of waiting for
                    -- the first post-recovery read (which may still be
                    -- a transient null).
                    if is_searching then
                        is_searching = false
                        Bridge.push("searching_for_player", false, 30000)
                    end
                end

                local std_y_meters = nil
                if d.posX then
                    local std_x, std_y, std_z = unreal_to_standard_position(d.posX, d.posY, d.posZ)
                    std_y_meters = std_y
                    GameStore.setCameraPosition(std_x, std_y, std_z)
                    if is_searching then
                        is_searching = false
                        Bridge.push("searching_for_player", false, 30000)
                        Core.log("Player position recovered")
                    end
                end

                -- Surroundings — depend on pawn class + state fields the SN2
                -- agent attaches. No-op when the agent hasn't sent its first
                -- enriched frame yet.
                if d.pawnClassName ~= nil then
                    apply_surroundings(d, std_y_meters)
                end

                -- Prefer camera ControlRotation; fall back to body rotation.
                -- RelativeRotation exposes rotY as Yaw (not the FRotator
                -- pitch — Unreal's accessor naming is inconsistent here).
                if d.pitch then
                    local pitch, yaw, roll = unreal_rotation_to_orientation(d.pitch, d.yaw)
                    set_camera_orientation_stable(pitch, yaw, roll)
                elseif d.rotY ~= nil then
                    local pitch, yaw, roll = unreal_rotation_to_orientation(d.rotX or 0, d.rotY)
                    set_camera_orientation_stable(pitch, yaw, roll)
                end

                -- Map name → GameStore level, only on real changed names.
                -- Placeholder names mean GWorld isn't reachable yet — leave
                -- the level on canonical "default".
                if type(d.sceneName) == "string"
                    and d.sceneName ~= ""
                    and d.sceneName ~= "Unknown"
                    and d.sceneName ~= "Unreal"
                    and d.sceneName ~= last_scene_name
                then
                    GameStore.setLevel(d.sceneName)
                    last_scene_name = d.sceneName
                    Core.log("Map changed: " .. d.sceneName)
                end
            end

            ::continue_msg::
        end
    end

    if not had_data then
        no_data_count = no_data_count + 1

        -- 60 frames = 1s at 60Hz. Lower thresholds fire spuriously on
        -- transient heartbeats from GWorld chain misreads.
        local NO_DATA_WARN_FRAMES = 60
        if no_data_count == NO_DATA_WARN_FRAMES then
            -- Buffer size disambiguates "agent hung" from "IPC stalled".
            local diag = Gamelink.getDiagnostics and Gamelink.getDiagnostics() or nil
            local buf = diag and diag.messageBufferSize or -1
            local since = diag and diag.secondsSinceLastData or -1
            Core.warn(string.format(
                "No position data for 1 second (loading screen?) — buf=%d since_data=%.2fs",
                buf, since
            ))
            is_searching = true
            Bridge.push("searching_for_player", true, 30000)
        elseif no_data_count % SEARCHING_LOG_INTERVAL == 0 then
            Core.warn("Still searching for player... ("
                .. math.floor(no_data_count / NO_DATA_WARN_FRAMES) .. "s)")
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

    -- Runtime handles Gamelink unload + Frida detach. Do NOT call
    -- Gamelink.unloadScript here — the synchronous unload-sync used to
    -- block 10-30s waiting on agent ack during discovery.
    use_pull_ticks = false
    tick_in_flight = false
    tick_wait_seconds = 0
    resolved_offsets = nil
    script_handle = nil
    net_id_handle = nil
    last_session_id = nil
end
