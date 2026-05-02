-- CS2 Vision Tracker - Map-based position tracking via computer vision
-- Port of test2map.py algorithm to Proximity Core Lua API

local PROCESSING_SCALE = 0.85
local MIN_MATCH_COUNT = 10
local MAX_FEATURES = 2000
local POS_SMOOTHING = 4.0
local ROT_SMOOTHING = 12.0
local CALIBRATION_SCREENSHOT_SCALE = 1.0
local PRE_CAPTURE_COUNTDOWN_SECONDS = 10
local USE_SCREEN_CAPTURE = true
local MIN_INLIER_COUNT = 6
local MIN_HOMOGRAPHY_CONFIDENCE = 0.08
local TRACK_RECOVER_FRAMES = 6
local TRACK_LOST_FRAMES = 20
local MAP_BOUNDS_MARGIN = 32
local CUE_TTL_MS = 5000
local REGION_CACHE_KEY = USE_SCREEN_CAPTURE and "image_region_screen" or "image_region_window"
local WINDOW_SIGNATURE_CACHE_KEY = REGION_CACHE_KEY .. "_window_signature"

local TRACK_REGION = nil

local refFeatures = nil
local refKeypoints = nil
local smoothedPosX = 0
local smoothedPosY = 0
local smoothedRot = 0
local lastPosX = nil
local lastPosY = nil
local velocityX = 0
local velocityY = 0
local confidence = 0
local mapWidth = 0
local mapHeight = 0
local debugFrameCounter = 0
local trackingVisible = false
local visibleFrameCount = 0
local missingFrameCount = 0
local lastLostReason = nil

local function makeCaptureOpts(extra)
    local opts = extra or {}
    if USE_SCREEN_CAPTURE then
        opts.screen = true
    end
    return opts
end

local function smoothValue(current, target, speed, dt)
    return current + (target - current) * (1.0 - math.exp(-speed * dt))
end

local function smoothAngle(current, target, speed, dt)
    local diff = target - current
    if diff > math.pi then diff = diff - 2 * math.pi end
    if diff < -math.pi then diff = diff + 2 * math.pi end
    return current + diff * (1.0 - math.exp(-speed * dt))
end

local function isFiniteNumber(v)
    return v == v and v > -math.huge and v < math.huge
end

local function emitCue(kind, detail)
    if Bridge.emitCue then
        Bridge.emitCue(kind, detail, CUE_TTL_MS)
        return
    end

    local payload = Json.encode({
        nonce = tostring(Core.getTimeMillis()),
        kind = kind,
        detail = detail
    })
    Bridge.push("bridge_ui_cue", payload, CUE_TTL_MS)
end

local function markTrackingVisible()
    missingFrameCount = 0
    visibleFrameCount = visibleFrameCount + 1

    if not trackingVisible and visibleFrameCount >= TRACK_RECOVER_FRAMES then
        trackingVisible = true
        lastLostReason = nil
        emitCue("region_visible", "Tracked image region detected")
    end
end

local function markTrackingMissing(reason)
    visibleFrameCount = 0
    missingFrameCount = missingFrameCount + 1

    if trackingVisible and missingFrameCount >= TRACK_LOST_FRAMES then
        trackingVisible = false
        if reason then
            lastLostReason = reason
        end
        emitCue("region_lost", lastLostReason or "Lost tracked image region")
    end
end

local function clearCalibrationUiState()
    Bridge.push("calibration_mode", "", 1)
    Bridge.push("calibration_screenshot", "", 1)
    Bridge.push("calibration_scale", "", 1)
    Bridge.push("calibration_title", "", 1)
    Bridge.push("calibration_instructions", "", 1)
end

local function getCurrentWindowSignature()
    if not Bridge.getWindowBounds then
        return nil
    end

    local bounds = Bridge.getWindowBounds()
    if not bounds or not bounds.width or not bounds.height then
        return nil
    end

    return {
        x = bounds.x or 0,
        y = bounds.y or 0,
        width = bounds.width,
        height = bounds.height
    }
end

local function isSameWindowSignature(a, b)
    if not a or not b then
        return false
    end
    return a.x == b.x and a.y == b.y and a.width == b.width and a.height == b.height
end

local function publishInfoActions()
    if not Bridge.setInfoActions then
        return
    end

    Bridge.setInfoActions({
        title = "Bridge Actions",
        description = "Advanced controls exposed by this bridge package.",
        actions = {
            {
                id = "restart_setup",
                label = "Restart setup",
                variant = "danger",
                confirm = "Clear cached calibration and reinitialize this bridge?"
            }
        }
    }, 86400000)
end

local function clearSetupCache()
    Cache.remove(REGION_CACHE_KEY)
    Cache.remove(WINDOW_SIGNATURE_CACHE_KEY)
end

local function handleBridgeInfoActions()
    if not Bridge.pollInfoAction then
        return false
    end

    local action = Bridge.pollInfoAction()
    if not action or not action.id then
        return false
    end

    if action.id == "restart_setup" then
        clearSetupCache()
        clearCalibrationUiState()
        emitCue("setup_reset", "Setup cache cleared, restarting bridge")
        if Bridge.reinitialize then
            Bridge.reinitialize("Restarting setup...")
        else
            Bridge.shutdown("Restarting setup...")
        end
        return true
    end

    return false
end

local function loadOrCalibrateTrackedRegion()
    local currentWindowSignature = getCurrentWindowSignature()

    local cached = Cache.load(REGION_CACHE_KEY)
    if cached and cached.x and cached.y and cached.w and cached.h then
        local cachedWindowSignature = Cache.load(WINDOW_SIGNATURE_CACHE_KEY)
        if currentWindowSignature and not cachedWindowSignature then
            Core.log("Cached image region has no window signature; forcing one-time re-setup")
            clearSetupCache()
            emitCue("region_invalidated", "Setup format updated, please crop again")
        elseif currentWindowSignature and cachedWindowSignature and
           not isSameWindowSignature(currentWindowSignature, cachedWindowSignature) then
            Core.log("Window bounds changed since last setup; clearing cached image region")
            clearSetupCache()
            emitCue("region_invalidated", "Window changed, setup required again")
        else
            Core.log("Using cached image region: " ..
                cached.x .. "," .. cached.y .. " " .. cached.w .. "x" .. cached.h)
            return cached
        end
    end

    if PRE_CAPTURE_COUNTDOWN_SECONDS > 0 then
        local endTime = Core.getTimeMillis() + (PRE_CAPTURE_COUNTDOWN_SECONDS * 1000)
        local lastRemaining = nil
        while Core.getTimeMillis() < endTime do
            local remaining = math.ceil((endTime - Core.getTimeMillis()) / 1000)
            if remaining ~= lastRemaining then
                emitCue("countdown_tick", "Capture starts in " .. remaining .. "s")
                lastRemaining = remaining
            end
            Bridge.setProgress("Switch to your game window now (" .. remaining .. "s)", 5, 2)
        end
    end

    Bridge.setProgress("Capturing target window for region selection...", 8, 1)
    emitCue("capture_ready", "Prepare to crop the minimap region")

    Bridge.push("calibration_result", "", 1)

    local screenshot = Capture.take(makeCaptureOpts())
    if not screenshot then
        error("Failed to capture game window for calibration")
    end

    local calibrationScale = CALIBRATION_SCREENSHOT_SCALE
    local screenshotForUi = screenshot
    if calibrationScale and calibrationScale > 0 and calibrationScale < 1 then
        screenshotForUi = screenshot:scale(calibrationScale)
    else
        calibrationScale = 1.0
    end
    local dataUrl = screenshotForUi:toDataUrl()
    emitCue("capture_taken", "Screenshot ready for region selection")

    Bridge.push("calibration_screenshot", dataUrl, 120000)
    Bridge.push("calibration_scale", tostring(calibrationScale), 120000)
    if Bridge.setCalibrationUi then
        Bridge.setCalibrationUi(
            "Select Capture Region",
            "Crop the minimap region so the minimap is completely centered and fully covered.",
            120000
        )
    else
        Bridge.push("calibration_title", "Select Capture Region", 120000)
        Bridge.push("calibration_instructions", "Crop the minimap region so the minimap is completely centered and fully covered.", 120000)
    end
    Bridge.push("calibration_mode", "region_select", 120000)

    Core.log("Waiting for user to select capture region...")

    local maxAttempts = 3600 -- ~3 minutes at 60Hz
    for _ = 1, maxAttempts do
        Bridge.setProgress("Select capture region on the screenshot", 10, 2)

        local resultJson = Bridge.getString("calibration_result")
        if resultJson and resultJson ~= "" then
            local ok, result = pcall(Json.decode, resultJson)
            if ok and result and result.x and result.y and result.w and result.h then
                Cache.save(REGION_CACHE_KEY, {
                    x = result.x,
                    y = result.y,
                    w = result.w,
                    h = result.h
                })
                if currentWindowSignature then
                    Cache.save(WINDOW_SIGNATURE_CACHE_KEY, currentWindowSignature)
                end
                Core.log("Image region selected and cached: " ..
                    result.x .. "," .. result.y .. " " .. result.w .. "x" .. result.h)

                clearCalibrationUiState()

                emitCue("selection_confirmed", "Capture region confirmed")
                return result
            end
        end
    end

    clearCalibrationUiState()
    error("Image region selection timed out")
end

function init()
    publishInfoActions()

    TRACK_REGION = loadOrCalibrateTrackedRegion()

    Bridge.setProgress("Loading reference map...", 30, 1)

    local refMap = Resource.loadImage("map.png")
    if not refMap then
        error("Failed to load reference map (map.png)")
    end

    local size = refMap:getSize()
    mapWidth = size.width
    mapHeight = size.height

    smoothedPosX = mapWidth / 2
    smoothedPosY = mapHeight / 2
    GameStore.setCameraPosition(smoothedPosX, 0, smoothedPosY)

    Bridge.setProgress("Processing reference map...", 50, 1)

    local refGray = refMap:grayscale()
    local refScaled = refGray:scale(PROCESSING_SCALE)

    Bridge.setProgress("Detecting features on reference map...", 70, 1)

    refFeatures = CV.detectFeatures(refScaled, {
        maxFeatures = MAX_FEATURES,
        threshold = 20
    })

    refKeypoints = refFeatures:getKeypoints()

    Bridge.setProgressSnap("Bridge initialized - vision tracking active", 100)
    Core.log("CS2 Vision Tracker initialized with " .. refFeatures.count .. " reference features")
    emitCue("bridge_initialized", "Vision tracker initialized")
end

function update(dt)
    if handleBridgeInfoActions() then
        return
    end

    local live = Capture.take(makeCaptureOpts({
        region = TRACK_REGION,
        scale = PROCESSING_SCALE,
        grayscale = true
    }))

    if not live then
        markTrackingMissing("No capture frame")
        return
    end

    local liveSize = live:getSize()
    if liveSize.width < 10 or liveSize.height < 10 then
        markTrackingMissing("Capture region too small")
        return
    end

    local liveFeatures = CV.detectFeatures(live, {
        maxFeatures = MAX_FEATURES,
        threshold = 20
    })

    if liveFeatures.count < MIN_MATCH_COUNT then
        markTrackingMissing("Too few live features")
        debugFrameCounter = debugFrameCounter + 1
        if debugFrameCounter % 120 == 0 then
            Core.warn("CS2 vision: too few live features (" .. liveFeatures.count .. "), need >= " .. MIN_MATCH_COUNT)
        end
        return
    end

    local matches = CV.matchFeatures(liveFeatures, refFeatures, {
        ratioTest = 0.75,
        maxResults = 100
    })

    confidence = math.min(1.0, #matches / 50.0)

    if #matches < MIN_MATCH_COUNT then
        markTrackingMissing("Too few feature matches")
        debugFrameCounter = debugFrameCounter + 1
        if debugFrameCounter % 120 == 0 then
            Core.warn("CS2 vision: too few matches (" .. #matches .. "), need >= " .. MIN_MATCH_COUNT)
        end
        return
    end

    local liveKeypoints = liveFeatures:getKeypoints()
    local srcPoints = {}
    local dstPoints = {}

    for _, m in ipairs(matches) do
        local liveKp = liveKeypoints[m.queryIdx]  -- already 1-based from Lua API
        local refKp = refKeypoints[m.trainIdx]    -- already 1-based from Lua API

        if liveKp and refKp then
            table.insert(srcPoints, {x = liveKp.x, y = liveKp.y})
            table.insert(dstPoints, {x = refKp.x, y = refKp.y})
        end
    end

    if #srcPoints < 4 then
        markTrackingMissing("Insufficient correspondence points")
        debugFrameCounter = debugFrameCounter + 1
        if debugFrameCounter % 120 == 0 then
            Core.warn("CS2 vision: insufficient correspondence points (" .. #srcPoints .. ")")
        end
        return
    end

    local H = CV.findHomography(srcPoints, dstPoints, {
        threshold = 5.0,
        method = "ransac",
        maxIterations = 2000
    })

    if not H then
        markTrackingMissing("Homography failed")
        debugFrameCounter = debugFrameCounter + 1
        if debugFrameCounter % 120 == 0 then
            Core.warn("CS2 vision: homography failed")
        end
        return
    end

    if H.inlierCount < MIN_INLIER_COUNT then
        markTrackingMissing("Homography inlier count too low")
        return
    end

    if H.confidence and H.confidence < MIN_HOMOGRAPHY_CONFIDENCE then
        markTrackingMissing("Homography confidence too low")
        return
    end

    -- Use the actual captured frame size (already in scaled processing space).
    local liveCenterX = liveSize.width / 2
    local liveCenterY = liveSize.height / 2

    local posResult = H:transformPoint(liveCenterX, liveCenterY)
    -- Result is in reference map scaled space, convert back
    local visionPosX = posResult.x / PROCESSING_SCALE
    local visionPosY = posResult.y / PROCESSING_SCALE

    if not isFiniteNumber(visionPosX) or not isFiniteNumber(visionPosY) then
        markTrackingMissing("Invalid position transform")
        return
    end

    if visionPosX < -MAP_BOUNDS_MARGIN or visionPosX > mapWidth + MAP_BOUNDS_MARGIN or
       visionPosY < -MAP_BOUNDS_MARGIN or visionPosY > mapHeight + MAP_BOUNDS_MARGIN then
        markTrackingMissing("Position outside reference map bounds")
        return
    end

    local fwdOffsetY = 15
    local fwdResult = H:transformPoint(liveCenterX, liveCenterY - fwdOffsetY)
    local fwdRefX = fwdResult.x / PROCESSING_SCALE
    local fwdRefY = fwdResult.y / PROCESSING_SCALE
    local dirX = fwdRefX - visionPosX
    local dirY = fwdRefY - visionPosY

    if not isFiniteNumber(dirX) or not isFiniteNumber(dirY) or ((dirX * dirX + dirY * dirY) < 0.0001) then
        markTrackingMissing("Invalid orientation transform")
        return
    end

    local visionRot = math.atan2(dirY, dirX)
    if not isFiniteNumber(visionRot) then
        markTrackingMissing("Invalid rotation value")
        return
    end

    markTrackingVisible()

    local safeDt = math.max(dt or 0, 1.0 / 240.0)

    if lastPosX then
        velocityX = 0.9 * velocityX + 0.1 * ((visionPosX - lastPosX) / safeDt)
        velocityY = 0.9 * velocityY + 0.1 * ((visionPosY - lastPosY) / safeDt)
    end
    lastPosX = visionPosX
    lastPosY = visionPosY

    local predictedX = smoothedPosX + velocityX * safeDt
    local predictedY = smoothedPosY + velocityY * safeDt
    local conf2 = confidence * confidence
    local targetX = (1 - conf2) * predictedX + conf2 * visionPosX
    local targetY = (1 - conf2) * predictedY + conf2 * visionPosY

    smoothedPosX = smoothValue(smoothedPosX, targetX, POS_SMOOTHING, safeDt)
    smoothedPosY = smoothValue(smoothedPosY, targetY, POS_SMOOTHING, safeDt)
    smoothedRot = smoothAngle(smoothedRot, visionRot, ROT_SMOOTHING, safeDt)

    -- map 2D -> 3D: x=map_x, y=0, z=map_y
    GameStore.setCameraPosition(smoothedPosX, 0, smoothedPosY)
    GameStore.setCameraOrientation(0, smoothedRot, 0)
end

function dispose()
    refFeatures = nil
    refKeypoints = nil
    trackingVisible = false
    visibleFrameCount = 0
    missingFrameCount = 0
    if Bridge.setInfoActions then
        Bridge.setInfoActions({ actions = {} }, 1)
    end
    Bridge.push("bridge_info_action_request", "", 1)
    emitCue("bridge_disposed", "Vision tracker disposed")
    Core.log("CS2 Vision Tracker disposed")
end
