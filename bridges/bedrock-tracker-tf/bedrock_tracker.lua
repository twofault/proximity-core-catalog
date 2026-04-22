-- bedrock_tracker.lua — GameLink agent for Minecraft Bedrock Edition
-- Discovers camera position in the executable's .data section.
-- Compliant with flat read-only security model (memory reads only).
--
-- Discovery pipeline:
--   1. Structural scan: find Vec3 + unit forward vector with zero padding
--   2. Liveness check: re-read candidates after delay — real camera updates each frame
--   3. Tiebreak by position magnitude
--
-- Once cached, works at any position/orientation (only validates unit vector).

local mc = process.find_module("Minecraft.Windows.exe")
local BASE = mc.base
local SIZE = mc.size

local pos_addr = nil

-- Dimension ID is stored 20 bytes before the camera position (same struct).
-- 0=Overworld, 1=Nether, 2=The End
local DIM_OFFSET = -20

local function safe_f32(addr)
    local ok, v = pcall(memory.read_f32, addr)
    return (ok and v and v == v) and v or nil
end

local function is_unit_vector(fx, fy, fz)
    local mag = math.sqrt(fx*fx + fy*fy + fz*fz)
    return mag > 0.95 and mag < 1.05
end

local function is_fractional(v)
    return math.abs(v) > 0.001 and math.abs(math.abs(v) - 1.0) > 0.001
end

local function read_camera(addr)
    local x  = safe_f32(addr)
    local y  = safe_f32(addr + 4)
    local z  = safe_f32(addr + 8)
    local fx = safe_f32(addr + 12)
    local fy = safe_f32(addr + 16)
    local fz = safe_f32(addr + 20)
    if x and y and z and fx and fy and fz then
        return x, y, z, fx, fy, fz
    end
    return nil
end

local function fwd_changed(c, fx, fy, fz)
    return math.abs(fx - c.fx) > 0.0001
        or math.abs(fy - c.fy) > 0.0001
        or math.abs(fz - c.fz) > 0.0001
end

local function discover_position(cached_offset)
    if cached_offset then
        local x, y, z, fx, fy, fz = read_camera(BASE + cached_offset)
        if fx and is_unit_vector(fx, fy, fz) then
            log("Cache hit: offset 0x" .. string.format("%X", cached_offset))
            pos_addr = BASE + cached_offset
            return cached_offset
        end
        log("Cache miss: rescanning")
    end

    local ranges = process.enumerate_ranges("rw-")
    local data_ranges = {}
    local total_bytes = 0
    for _, r in ipairs(ranges) do
        if r.base >= BASE and r.base < BASE + SIZE then
            data_ranges[#data_ranges + 1] = r
            total_bytes = total_bytes + r.size
        end
    end
    -- Scan larger sections first (camera tends to be in the main .data section)
    table.sort(data_ranges, function(a, b) return a.size > b.size end)

    local total_kb = total_bytes // 1024
    log(string.format("Scanning %d .data sections (%d KB)", #data_ranges, total_kb))
    send({ type = "progress", message = string.format("Scanning %d KB of static data...", total_kb), percent = 10 })

    -- Phase 1: Structural scan — find all candidates
    local candidates = {}
    local scanned_bytes = 0

    for ri, r in ipairs(data_ranges) do
        local limit = r.size - 24
        for off = 4, limit, 4 do
            local addr = r.base + off

            local prev = safe_f32(addr - 4)
            if not prev or math.abs(prev) > 0.01 then goto continue end

            local x = safe_f32(addr)
            if not x then goto continue end
            local y = safe_f32(addr + 4)
            if not y then goto continue end
            local z = safe_f32(addr + 8)
            if not z then goto continue end

            if math.abs(x) > 100000 or math.abs(z) > 100000 then goto continue end
            if y < -100 or y > 400 then goto continue end

            local fx = safe_f32(addr + 12)
            local fy = safe_f32(addr + 16)
            local fz = safe_f32(addr + 20)
            if not fx or not fy or not fz then goto continue end

            if not is_unit_vector(fx, fy, fz) then goto continue end

            local frac_count = 0
            if is_fractional(fx) then frac_count = frac_count + 1 end
            if is_fractional(fy) then frac_count = frac_count + 1 end
            if is_fractional(fz) then frac_count = frac_count + 1 end
            if frac_count < 2 then goto continue end

            candidates[#candidates + 1] = {
                addr = addr, offset = addr - BASE,
                x = x, y = y, z = z,
                fx = fx, fy = fy, fz = fz,
            }
            ::continue::
        end

        scanned_bytes = scanned_bytes + r.size
        local pct = math.floor(scanned_bytes * 70 / total_bytes) + 10  -- 10-80%
        send({ type = "progress",
            message = string.format("Scanned %d/%d sections, %d candidates...", ri, #data_ranges, #candidates),
            percent = pct })
    end

    log(string.format("Structural scan: %d candidates", #candidates))

    if #candidates == 0 then
        return nil, "No camera found. Ensure you are in a game world, and try moving your mouse slightly."
    end

    -- Phase 2: Liveness check — the real camera updates every frame.
    -- Wait at least 300ms then re-read. Static data won't change.
    send({ type = "progress", message = string.format("Verifying %d candidates...", #candidates), percent = 82 })

    local wait_start = clock()
    while clock() - wait_start < 400 do end  -- 400ms

    local live = {}
    for _, c in ipairs(candidates) do
        local x, y, z, fx, fy, fz = read_camera(c.addr)
        if fx and is_unit_vector(fx, fy, fz) and fwd_changed(c, fx, fy, fz) then
            live[#live + 1] = {
                addr = c.addr, offset = c.offset,
                x = x, y = y, z = z,
                fx = fx, fy = fy, fz = fz,
            }
        end
    end

    log(string.format("Liveness check: %d/%d candidates are live", #live, #candidates))
    send({ type = "progress",
        message = string.format("%d live candidates found", #live), percent = 90 })

    -- Use live candidates if any, otherwise fall back to all candidates
    -- (player might be perfectly still — live check can't distinguish)
    local pool = #live > 0 and live or candidates
    if #live == 0 then
        log("No live candidates (player still?), using magnitude tiebreaker on all candidates")
    end

    -- Tiebreak: largest position magnitude
    local best = pool[1]
    for _, c in ipairs(pool) do
        if (math.abs(c.x) + math.abs(c.z)) > (math.abs(best.x) + math.abs(best.z)) then
            best = c
        end
    end

    log(string.format("Selected: +0x%X pos=(%.2f,%.2f,%.2f) fwd=(%.3f,%.3f,%.3f)",
        best.offset, best.x, best.y, best.z, best.fx, best.fy, best.fz))
    pos_addr = best.addr
    return best.offset
end

local state = { initialized = false }

local function handle_init(msg)
    send({ type = "progress", message = "Initializing...", percent = 5 })
    local cached = msg.data and msg.data.offset or nil
    local offset, err = discover_position(cached)
    if not offset then
        send({ type = "init-response", success = false, error = err or "Discovery failed" })
        return
    end
    state.initialized = true
    send({ type = "progress", message = "Connected!", percent = 100 })
    send({ type = "discovery-complete", offset = offset })
    send({ type = "init-response", success = true })
end

local function handle_tick()
    if not state.initialized or not pos_addr then
        send({ type = "heartbeat", status = "not-initialized" })
        return
    end
    local x, y, z, fx, fy, fz = read_camera(pos_addr)
    if fx then
        local fmag = math.sqrt(fx*fx + fy*fy + fz*fz)
        if math.abs(x) < 100000 and math.abs(z) < 100000 and fmag > 0.5 then
            -- Read dimension ID from fixed offset before camera
            local ok, dim = pcall(memory.read_s32, pos_addr + DIM_OFFSET)
            local dimension = (ok and dim >= 0 and dim <= 2) and dim or 0
            send({ type = "data", posX = x, posY = y, posZ = z,
                fwdX = fx, fwdY = fy, fwdZ = fz,
                dimension = dimension, timestamp = clock() })
            return
        end
    end
    send({ type = "heartbeat", status = "no-position" })
end

send({ type = "heartbeat", status = "loading" })
recv(function(message)
    local msg = type(message) == "string" and json.decode(message) or message
    if not msg or not msg.type then return end
    local ok, err = pcall(function()
        if msg.type == "init" then handle_init(msg)
        elseif msg.type == "tick" then handle_tick() end
    end)
    if not ok then
        log("Handler error: " .. tostring(err))
        if msg.type == "init" then
            send({ type = "init-response", success = false, error = tostring(err) })
        end
    end
end)
