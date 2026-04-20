-- Minecraft Java Edition GameBridge
-- Extracts player data from Minecraft using Frida with automatic deobfuscation
-- Uses coroutines for clean async flow - no manual state machine needed!

-- ============================================================================
-- CONSTANTS
-- ============================================================================

local HTTP_TIMEOUT_MS = 30000   -- 30 second timeout
local ATTACH_TIMEOUT_MS = 10000
local SEARCHING_LOG_INTERVAL = 200  -- Log "searching" every 10 seconds at 20Hz

-- Required mappings for player tracking
local REQUIRED_CLASSES = {
    {"Minecraft", "net.minecraft.client.Minecraft"},
    {"LocalPlayer", "net.minecraft.client.player.LocalPlayer"},
    {"Entity", "net.minecraft.world.entity.Entity"},
    {"Vec3", "net.minecraft.world.phys.Vec3"},
}

local REQUIRED_FIELDS = {
    {"Minecraft.instance", "net.minecraft.client.Minecraft", "instance"},
    {"Minecraft.player", "net.minecraft.client.Minecraft", "player"},
    {"Entity.position", "net.minecraft.world.entity.Entity", "position"},
    {"Entity.xRot", "net.minecraft.world.entity.Entity", "xRot"},
    {"Entity.yRot", "net.minecraft.world.entity.Entity", "yRot"},
    {"Vec3.x", "net.minecraft.world.phys.Vec3", "x"},
    {"Vec3.y", "net.minecraft.world.phys.Vec3", "y"},
    {"Vec3.z", "net.minecraft.world.phys.Vec3", "z"},
}

-- ============================================================================
-- STATE
-- ============================================================================

local script_handle = nil  -- Handle from loadScript for multi-script support
local no_data_count = 0
local is_searching = false
local minecraft_version = nil
local mappings = { classes = {}, fields = {}, methods = {} }

-- ============================================================================
-- UTILITY FUNCTIONS
-- ============================================================================

--- Wait for an HTTP request to complete, yielding each frame.
--- Checks for cancellation each frame and optionally shows progress.
--- @param handle userdata The HTTP handle from Http.get()
--- @param timeout_ms number Timeout in milliseconds
--- @param progress_msg string|nil Optional progress message to display
--- @param progress_target number|nil Target progress percentage (bar animates toward it)
--- @param half_life number|nil Animation half-life in seconds (default 3.0 for HTTP waits)
--- @return boolean success
--- @return string|nil data Response body on success
--- @return string|nil error Error message on failure
local function await_http(handle, timeout_ms, progress_msg, progress_target, half_life)
    local start = Core.getTimeMillis()
    local show_progress = progress_msg and progress_target

    -- Set animated progress target once — the frontend animates toward it
    if show_progress then
        Bridge.setProgress(progress_msg, progress_target, half_life or 3.0)
    end

    while not handle:isComplete() do
        -- Check for user cancellation
        if Bridge.isCancelled() then
            handle:cancel()
            return false, nil, "Cancelled by user"
        end

        local elapsed = Core.getTimeMillis() - start
        if elapsed > timeout_ms then
            handle:cancel()
            return false, nil, "Request timed out after " .. (timeout_ms / 1000) .. " seconds"
        end

        coroutine.yield()  -- Let UI update
    end

    -- Snap to target on completion
    if show_progress then
        Bridge.setProgressSnap(progress_msg, progress_target)
    end

    return handle:result()
end

--- Extract version string from text (e.g., "Minecraft 1.21.3" -> "1.21.3")
local function extract_version(text)
    -- Try x.xx.x pattern first
    local version = text:match("(%d+%.%d+%.%d+)")
    if version then return version end

    -- Try x.xx pattern
    return text:match("(%d+%.%d+)")
end

--- Compare two version strings. Returns true if a >= b.
--- Handles versions like "1.26.1", "1.21", "25.1" etc.
local function version_gte(a, b)
    local function parse(v)
        local parts = {}
        for n in v:gmatch("(%d+)") do
            table.insert(parts, tonumber(n))
        end
        return parts
    end
    local pa, pb = parse(a), parse(b)
    for i = 1, math.max(#pa, #pb) do
        local va = pa[i] or 0
        local vb = pb[i] or 0
        if va > vb then return true end
        if va < vb then return false end
    end
    return true -- equal
end

--- Check if a version is unobfuscated (1.26.1+, Mojang stopped obfuscating).
local function is_unobfuscated(version)
    return version_gte(version, "1.26.1")
end

-- ============================================================================
-- MAPPINGS PARSING
-- ============================================================================

--- Parse ProGuard mappings text into structured tables.
--- Yields periodically to keep UI responsive and reports progress.
--- @param mappings_text string The raw ProGuard mappings content
--- @param progress_start number Starting progress percentage (e.g., 50)
--- @param progress_end number Ending progress percentage (e.g., 85)
local function parse_mappings(mappings_text, progress_start, progress_end)
    local lines = {}
    for line in mappings_text:gmatch("[^\r\n]+") do
        table.insert(lines, line)
    end

    local total_lines = #lines
    local current_class = nil
    local class_count = 0
    local yield_counter = 0
    local progress_range = progress_end - progress_start

    for i, line in ipairs(lines) do
        -- Yield every 1000 lines to keep UI responsive and update progress
        yield_counter = yield_counter + 1
        if yield_counter >= 1000 then
            yield_counter = 0
            -- Calculate target within the parsing range, animate with short half-life
            local pct = math.floor(i / total_lines * 100)
            local target = math.floor(progress_start + (i / total_lines) * progress_range)
            Bridge.setProgress("Parsing mappings... (" .. pct .. "%)", target, 0.5)
        end

        -- Skip comments and empty lines
        if line:match("^#") or line:match("^%s*$") then
            goto continue
        end

        -- Class mapping: "net.minecraft.client.Minecraft -> abc:"
        local deobf_class, obf_class = line:match("^([%w%.]+)%s*%->%s*([%w]+):")
        if deobf_class and obf_class then
            current_class = deobf_class
            mappings.classes[deobf_class] = obf_class
            class_count = class_count + 1
            goto continue
        end

        -- Field/method mapping (indented lines)
        if current_class and line:match("^%s+") then
            line = line:gsub("^%s+", "")
            line = line:gsub("^%d+:%d+:", "")

            local left, obf_name = line:match("^(.-)%s*%->%s*([%w]+)%s*$")
            if left and obf_name then
                local method_name = left:match("([%w]+)%s*%(")
                if method_name then
                    -- Method
                    mappings.methods[current_class .. "." .. method_name] = obf_name
                else
                    -- Field
                    local field_name = left:match("([%w]+)%s*$")
                    if field_name then
                        mappings.fields[current_class .. "." .. field_name] = obf_name
                    end
                end
            end
        end

        ::continue::
    end

    Core.log(string.format("Parsed %d classes", class_count))
end

--- Resolve a class or field name to its (possibly obfuscated) form.
--- For unobfuscated versions (1.26.1+), returns the original name unchanged.
local unobfuscated_mode = false

local function resolve_name(class_name, field_name)
    if unobfuscated_mode then
        -- No obfuscation — return the original name directly
        if field_name then
            return field_name
        else
            return class_name
        end
    end
    if field_name then
        local key = class_name .. "." .. field_name
        return mappings.fields[key] or mappings.methods[key]
    else
        return mappings.classes[class_name]
    end
end

--- Gather initialization data for Frida script.
--- Returns (data, error) - data is nil if any required mapping is missing.
local function gather_init_data()
    local data = {
        version = minecraft_version,
        classes = {},
        fields = {}
    }

    -- Resolve class mappings
    for _, pair in ipairs(REQUIRED_CLASSES) do
        local short_name, full_name = pair[1], pair[2]
        local obf_name = resolve_name(full_name, nil)
        if not obf_name then
            return nil, "Missing class mapping for " .. full_name
        end
        data.classes[short_name] = obf_name
        Core.log("  Class: " .. short_name .. " -> " .. obf_name)
    end

    -- Resolve field mappings
    for _, triple in ipairs(REQUIRED_FIELDS) do
        local field_key, class_name, field_name = triple[1], triple[2], triple[3]
        local obf_name = resolve_name(class_name, field_name)
        if not obf_name then
            return nil, "Missing field mapping for " .. class_name .. "." .. field_name
        end
        data.fields[field_key] = obf_name
        Core.log("  Field: " .. field_key .. " -> " .. obf_name)
    end

    return data, nil
end

--- Validate cached mappings have all required entries.
local function validate_cache(cached)
    if not cached or not cached.classes or not cached.fields then
        return false
    end

    for _, pair in ipairs(REQUIRED_CLASSES) do
        if not cached.classes[pair[2]] then return false end
    end

    for _, triple in ipairs(REQUIRED_FIELDS) do
        local key = triple[2] .. "." .. triple[3]
        if not cached.fields[key] then return false end
    end

    return true
end

--- Extract only required mappings for caching.
local function extract_for_cache()
    local cache = { classes = {}, fields = {} }

    for _, pair in ipairs(REQUIRED_CLASSES) do
        local full_name = pair[2]
        if mappings.classes[full_name] then
            cache.classes[full_name] = mappings.classes[full_name]
        end
    end

    for _, triple in ipairs(REQUIRED_FIELDS) do
        local key = triple[2] .. "." .. triple[3]
        if mappings.fields[key] then
            cache.fields[key] = mappings.fields[key]
        end
    end

    return cache
end

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
    Core.log("Minecraft Bridge: Initializing for PID " .. tostring(pid))

    -- Helper to check cancellation
    local function check_cancel()
        if Bridge.isCancelled() then
            Core.log("Initialization cancelled by user")
            Bridge.shutdown("Cancelled")
            return true
        end
        return false
    end

    -- Step 1: Detect Minecraft version from window title
    Bridge.setProgress("Detecting version...", 10, 1)
    local window_title = Bridge.getWindowTitle()
    local detected_version = nil

    if window_title then
        Core.log("Window title: " .. window_title)
        detected_version = extract_version(window_title)
        if detected_version then
            Core.log("Detected version from window: " .. detected_version)
        end
    else
        Core.log("Could not get window title for PID " .. tostring(pid))
    end

    -- Step 2: Check if this version is unobfuscated (1.26.1+)
    -- From 1.26.1 onward, Mojang no longer obfuscates — use real class/field names.
    if detected_version and is_unobfuscated(detected_version) then
        Core.log("Version " .. detected_version .. " is unobfuscated — skipping mapping download")
        minecraft_version = detected_version
        unobfuscated_mode = true
        goto mappings_ready
    end

    -- Step 3: Check cache for DETECTED version ONLY (if we detected one)
    Bridge.setProgress("Checking cache...", 15, 1)

    if detected_version then
        local cache_key = "minecraft_mappings_" .. detected_version
        local cached = Cache.load(cache_key)

        if validate_cache(cached) then
            Core.log("Cache hit for detected version " .. detected_version)
            minecraft_version = detected_version
            mappings.classes = cached.classes
            mappings.fields = cached.fields
            goto mappings_ready
        else
            Core.log("No cache for detected version " .. detected_version .. ", will download")
        end
    end

    -- Step 4: Download mappings for the target version (obfuscated versions only)
    Core.log("Downloading version manifest...")
    do
        local handle = Http.get("https://launchermeta.mojang.com/mc/game/version_manifest.json")
        local success, manifest_json, err = await_http(
            handle, HTTP_TIMEOUT_MS,
            "Downloading version manifest...", 25, 3.0
        )

        if check_cancel() then return end

        if not success then
            Core.error("Failed to download manifest: " .. (err or "unknown"))
            Bridge.shutdown("Failed to download manifest")
            return
        end

        local manifest = Json.decode(manifest_json)
        if not manifest or not manifest.versions then
            Core.error("Invalid manifest format")
            Bridge.shutdown("Invalid manifest")
            return
        end

        -- Build version list: detected version first, then fallbacks
        local versions_to_try = {}
        if detected_version then
            table.insert(versions_to_try, detected_version)
        end
        -- Only add fallbacks if we didn't detect a version
        if not detected_version then
            local common_versions = {"1.21.4", "1.21.3", "1.21.1", "1.21", "1.20.6", "1.20.4", "1.20.1"}
            for _, v in ipairs(common_versions) do
                table.insert(versions_to_try, v)
            end
        end

        -- Step 5: Find version with mappings
        Bridge.setProgress("Finding mappings...", 30, 3.0)

        for _, version in ipairs(versions_to_try) do
            if check_cancel() then return end

            for _, v in ipairs(manifest.versions) do
                if v.id == version then
                    Core.log("Checking version " .. version .. "...")

                    local vh = Http.get(v.url)
                    local vs, vdata, verr = await_http(
                        vh, HTTP_TIMEOUT_MS,
                        "Checking " .. version .. "...", 32, 3.0
                    )

                    if check_cancel() then return end

                    if vs then
                        local vinfo = Json.decode(vdata)
                        if vinfo and vinfo.downloads and vinfo.downloads.client_mappings then
                            minecraft_version = version

                            Core.log("Downloading mappings for " .. version .. "...")

                            local mh = Http.get(vinfo.downloads.client_mappings.url)
                            local ms, mdata, merr = await_http(
                                mh, HTTP_TIMEOUT_MS,
                                "Downloading mappings for " .. version .. "...", 35, 3.0
                            )

                            if check_cancel() then return end

                            if ms then
                                Bridge.setProgress("Parsing mappings...", 50, 0.5)
                                Core.log("Parsing mappings (" .. #mdata .. " bytes)...")
                                parse_mappings(mdata, 50, 85)

                                local cache_data = extract_for_cache()
                                local cache_key = "minecraft_mappings_" .. version
                                if Cache.save(cache_key, cache_data) then
                                    Core.log("Cached mappings for " .. version)
                                end

                                goto mappings_ready
                            else
                                Core.warn("Failed to download mappings: " .. (merr or "unknown"))
                            end
                        end
                    end
                end
            end
        end

        -- If we detected a version but couldn't find mappings, it might be unobfuscated
        -- (version detection might have slightly different format than our threshold check)
        if detected_version then
            Core.warn("No mappings for " .. detected_version .. " — trying unobfuscated mode")
            minecraft_version = detected_version
            unobfuscated_mode = true
            goto mappings_ready
        end

        Core.error("Could not find mappings for any supported version")
        Bridge.shutdown("No mappings available")
        return
    end

    ::mappings_ready::
    if check_cancel() then return end

    Bridge.setProgressSnap("Mappings ready", 90)
    Core.log("Mappings ready for Minecraft " .. minecraft_version)

    -- Step 6: Attach Frida (non-blocking — yields while attaching)
    Bridge.setProgress("Attaching to process...", 93, 2)
    Core.log("Attaching Frida to PID " .. tostring(pid) .. "...")

    local attach_result = Frida.attach({ timeout_ms = ATTACH_TIMEOUT_MS })
    if not attach_result.success then
        Core.error("Failed to attach Frida: " .. (attach_result.error or "unknown"))
        Bridge.shutdown("Frida attach failed")
        return
    end
    -- Poll until attach completes (yields back to engine each tick)
    if attach_result.pending then
        while true do
            if check_cancel() then return end
            local status = Frida.pollAttach()
            if status.done then
                if not status.success then
                    Core.error("Frida attach failed: " .. (status.error or "unknown"))
                    Bridge.shutdown("Frida attach failed")
                    return
                end
                break
            end
            -- Just update the message — animated progress crawls toward 93
            Bridge.setProgressFooter(status.message or "")
            coroutine.yield()
        end
    end
    Core.log("Frida attached successfully")

    if check_cancel() then return end

    -- Step 7: Load the Frida Lua script (pre-trusted via manifest.json frida_script field)
    Bridge.setProgress("Loading tracker script...", 95, 1)
    local load_result = Frida.loadScript("minecraft_tracker.lua")
    if not load_result.success then
        Core.error("Failed to load Frida script: " .. (load_result.error or "unknown"))
        Frida.detach()
        Bridge.shutdown("Script load failed")
        return
    end
    script_handle = load_result.handle
    Core.log("Frida script loaded (handle: " .. tostring(script_handle) .. ")")

    if check_cancel() then return end

    -- Step 8: Prepare and send init data to Frida script via message passing
    Bridge.setProgress("Sending mappings...", 97, 1)
    Core.log("Resolving mappings for Frida script...")
    local init_data, gather_err = gather_init_data()
    if not init_data then
        Core.error("Failed to gather init data: " .. (gather_err or "unknown"))
        Frida.detach()
        Bridge.shutdown("Failed to resolve mappings")
        return
    end
    Core.log("Resolved " .. #REQUIRED_CLASSES .. " classes and " .. #REQUIRED_FIELDS .. " fields")

    -- Send init data to the Frida script via message passing
    -- The Frida script expects: { type: "init", data: {...} }
    local init_message = {
        type = "init",
        data = init_data
    }
    Core.log("Sending init message to Frida script...")
    local send_result = Frida.send(script_handle, init_message)
    if not send_result.success then
        Core.error("Failed to send init data: " .. (send_result.error or "unknown"))
        Frida.detach()
        Bridge.shutdown("Failed to send mappings")
        return
    end

    -- Wait for init response from Frida script
    local response_timeout = 10000  -- 10 seconds
    local start_time = Core.getTimeMillis()
    local got_response = false

    while Core.getTimeMillis() - start_time < response_timeout do
        if check_cancel() then return end

        -- Poll for messages from our script (filtered by handle at Rust level)
        local messages = Frida.poll(script_handle)
        if messages then
            for _, msg in ipairs(messages) do
                if msg.type == "data" and msg.payload then
                    local payload = msg.payload
                    if payload.type == "init-response" then
                        if payload.success then
                            Core.log("Frida script initialized successfully")
                            got_response = true
                        else
                            Core.error("Frida init failed: " .. (payload.error or "unknown"))
                            Frida.detach()
                            Bridge.shutdown("Frida init failed")
                            return
                        end
                        break
                    end
                end
            end
        end

        if got_response then break end
        coroutine.yield()  -- Let other things run
    end

    if not got_response then
        Core.error("Timeout waiting for Frida init response")
        Frida.detach()
        Bridge.shutdown("Frida init timeout")
        return
    end

    -- Step 9: Mark as ready
    Bridge.setProgressSnap("Connected!", 100)
    Core.log("Minecraft Bridge initialized for version " .. minecraft_version)
end

-- ============================================================================
-- UPDATE LOOP
-- ============================================================================

function update(dt)
    if not script_handle then return end

    -- Check if Frida has encountered an error (process exited, session lost, etc.)
    if Frida.isError() then
        local err = Frida.getError() or "Unknown error"
        Core.error("Frida error detected: " .. err)
        Bridge.shutdown("Frida error: " .. err)
        return
    end

    -- Send a tick message to drive the Lua Frida script's update loop.
    -- The Lua backend has no setInterval, so main.lua drives updates at 20Hz.
    Frida.send(script_handle, {type = "tick"})

    -- Poll for response messages from our script
    local messages = Frida.poll(script_handle)

    local had_data = false
    if messages then
        for _, msg in ipairs(messages) do
            if msg.type == "data" and msg.payload then
                had_data = true
                no_data_count = 0
                local d = msg.payload

                -- Fatal errors from agent are logged but do NOT disconnect.
                -- Process exit is detected by the engine; Frida errors are
                -- caught by Frida.isError() above.
                if d.type == "fatal-error" then
                    Core.error("Agent error: " .. (d.error or "unknown"))
                end

                -- Set camera position
                if d.posX then
                    LocalPlayer.setCameraPosition(d.posX, d.posY, d.posZ)
                    -- Clear searching state when position data resumes
                    if is_searching then
                        is_searching = false
                        Bridge.push("searching_for_player", false, 30000)
                        Core.log("Player position recovered")
                    end
                end

                -- Set orientation from yaw/pitch (euler angles in radians)
                if d.yaw then
                    -- Minecraft pitch: positive = looking down, negative = looking up
                    -- Our pitch: positive = looking up -> negate Minecraft pitch
                    local pitch_rad = -math.rad(d.pitch or 0)

                    -- Minecraft yaw: 0 = south (+Z), increases clockwise (90 = west/-X)
                    -- Our yaw: 0 = -Z forward, increases counterclockwise (pi/2 = -X)
                    -- Mapping: our_yaw = pi - mc_yaw_rad
                    local yaw_rad = math.pi - math.rad(d.yaw)

                    LocalPlayer.setCameraOrientation(pitch_rad, yaw_rad, 0)
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
    Core.log("Minecraft Bridge: Disposing...")

    -- Always try to detach/cleanup, even if in error state
    -- Frida.isAttached() returns false when in error state, but we still need cleanup
    pcall(function()
        -- Unload our script first
        if script_handle then
            pcall(function()
                Frida.send(script_handle, { type = "shutdown" })
            end)
            Frida.unloadScript(script_handle)
            script_handle = nil
        end

        if Frida.isAttached() then
            Frida.detach()
        end
    end)
end
