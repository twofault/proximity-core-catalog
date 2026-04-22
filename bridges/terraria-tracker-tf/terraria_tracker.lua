-- terraria_tracker.lua
-- Finds Terraria player position via pure memory scanning + reads.
-- No CLR hosting, no code execution, no disk I/O, no native.call.

local PTR = process.get_pointer_size()
local IS_64 = (PTR == 8)
local SCALE = 50.0
local SCAN_CHUNK = 2 * 1024 * 1024
local MAX_COORD = 150000
local MIN_COORD = 10

local state = {
    initialized = false,
    errors = 0,
    -- No fatal-error on position loss. Process exit is detected by the
    -- engine; the bridge host script handles the searching-for-player UI.
    elems_base = nil,
    player_mt = nil,
    pos_off = nil,
    player_idx = 0,
    rediscover_at = 50,
}

local function rptr(a)
    if not a or a == 0 then return nil end
    local v, e = memory.read_pointer(a)
    return (not e and v and v ~= 0) and v or nil
end

local function rf32(a)
    if not a or a == 0 then return nil end
    local v, e = memory.read_f32(a)
    return (not e) and v or nil
end

local function valid_f(v)
    return v and v == v and v > -1e30 and v < 1e30
end

local function is_terraria_pos(x, y)
    if not valid_f(x) or not valid_f(y) then return false end
    -- Terraria pixel coords: X typically 1000-134000, Y typically 500-38000
    if x < -1000 or x > MAX_COORD then return false end
    if y < -1000 or y > MAX_COORD then return false end
    -- Reject only when BOTH coords are near zero (uninitialized player)
    if math.abs(x) < MIN_COORD and math.abs(y) < MIN_COORD then return false end
    return true
end

local function probe_pos(obj)
    for off = PTR, 512 - 8, 4 do
        local x, y = rf32(obj + off), rf32(obj + off + 4)
        if is_terraria_pos(x, y) then return off end
    end
    return nil
end

local function validate_candidate(hit)
    local arr_mt = rptr(hit - PTR)
    if not arr_mt then return nil end

    -- Elements start after the length field (+ padding on 64-bit)
    local base = hit + (IS_64 and 8 or 4)

    -- Sample first 20 elements for MT consistency
    local ref_mt = nil
    local same, non_null = 0, 0
    for i = 0, math.min(19, 255) do
        local elem = rptr(base + i * PTR)
        if elem then
            non_null = non_null + 1
            local mt = rptr(elem)
            if mt then
                if not ref_mt then ref_mt = mt end
                if mt == ref_mt then same = same + 1 end
            end
        end
    end

    if same < 3 or non_null < 3 then return nil end
    if ref_mt == arr_mt then return nil end

    for i = 0, math.min(19, 255) do
        local elem = rptr(base + i * PTR)
        if elem then
            local off = probe_pos(elem)
            if off then
                -- Deep validation: check many more elements share the MT
                local deep_same = 0
                for j = 20, 255, 10 do
                    local e = rptr(base + j * PTR)
                    if e and rptr(e) == ref_mt then
                        deep_same = deep_same + 1
                    end
                end
                if deep_same >= 10 then
                    return { base = base, mt = ref_mt, pos_off = off, idx = i }
                end
            end
        end
    end
    return nil
end

local function discover()
    local ranges = process.enumerate_ranges("rw")
    if not ranges then return nil end

    table.sort(ranges, function(a, b) return a.size > b.size end)

    local scanned = 0
    for _, r in ipairs(ranges) do
        if r.size < 4096 then break end

        local off = 0
        while off < r.size do
            local chunk = math.min(SCAN_CHUNK, r.size - off)
            if chunk < 16 then break end

            local ok, hits = pcall(memory.scan, r.base + off, chunk, "00 01 00 00")
            if ok and hits then
                for _, h in ipairs(hits) do
                    local result = validate_candidate(h)
                    if result then return result end
                end
            end

            off = off + chunk
            scanned = scanned + chunk
        end
    end

    log("Scanned " .. math.floor(scanned / 1048576) .. " MB, Player[] not found")
    return nil
end

local function read_position()
    local elem = rptr(state.elems_base + state.player_idx * PTR)
    if not elem then return nil, nil end
    if rptr(elem) ~= state.player_mt then return nil, nil end
    local x = rf32(elem + state.pos_off)
    local y = rf32(elem + state.pos_off + 4)
    if not valid_f(x) or not valid_f(y) then return nil, nil end
    return x, y
end

local function handle_init()
    send({ type = "progress", message = "Scanning game memory...", percent = 10 })

    local result = discover()
    if not result then
        send({
            type = "init-response",
            success = false,
            error = "Player[] not found. Is a character loaded in a world?",
        })
        return
    end

    state.elems_base = result.base
    state.player_mt = result.mt
    state.pos_off = result.pos_off
    state.player_idx = result.idx or 0
    state.initialized = true
    state.errors = 0

    local x, y = read_position()
    local init_pos = nil
    if x then
        init_pos = { x = x / SCALE, y = -y / SCALE }
        log(string.format("Position: %.0f, %.0f (offset %d)", x, y, state.pos_off))
    end

    send({ type = "init-response", success = true, initialPosition = init_pos })
end

local function handle_tick(msg)
    if not state.initialized then
        send({ type = "heartbeat", status = "not-initialized" })
        return
    end

    local now = 0
    if type(msg) == "table" and type(msg.now_ms) == "number" then
        now = msg.now_ms
    end

    local ok, x, y = pcall(read_position)
    if ok and x then
        send({
            type = "data",
            protocol = "terraria_tracker",
            posX = x / SCALE,
            posY = -y / SCALE,
            posZ = 0,
            yaw = 0,
            pitch = 0,
            timestamp = now,
        })
        state.errors = 0
        return
    end

    state.errors = state.errors + 1

    if state.errors == state.rediscover_at then
        log("Re-discovering after " .. state.errors .. " errors...")
        local result = discover()
        if result then
            state.elems_base = result.base
            state.player_mt = result.mt
            state.pos_off = result.pos_off
            state.player_idx = result.idx or 0
            state.errors = 0
            log("Re-discovery succeeded")
            return
        end
    end

    if state.errors <= 3 or state.errors % 200 == 0 then
        log("Tick error #" .. state.errors)
    end
    -- Send heartbeat so the host knows we're alive but have no position.
    -- No fatal-error: the engine detects process exit; we just keep trying.
    send({ type = "heartbeat", status = "no-position" })
end

send({ type = "heartbeat", status = "loading" })
log("Terraria Tracker (read-only) loading...")

recv(function(message)
    local msg = message
    if type(msg) == "string" then
        local ok, d = pcall(json.decode, msg)
        if ok and type(d) == "table" then msg = d end
    end
    if type(msg) == "table" and type(msg.payload) == "table" then
        msg = msg.payload
    end
    if type(msg) ~= "table" or not msg.type then return end

    local ok, err = pcall(function()
        if msg.type == "init" then
            handle_init()
        elseif msg.type == "tick" then
            handle_tick(msg)
        elseif msg.type == "dispose" then
            state.initialized = false
        end
    end)
    if not ok then
        log("Handler crash: " .. tostring(err))
        if msg.type == "init" then
            send({ type = "init-response", success = false, error = tostring(err) })
        end
    end
end)
