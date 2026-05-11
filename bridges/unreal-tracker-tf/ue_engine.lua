-- Unreal Engine runtime introspection for Frida Lua. Supports UE 4.11
-- through current UE5.
--
-- Layout variants this code handles:
--   GObjects:   FFixedUObjectArray (UE 4.11-4.20), FChunkedFixedUObjectArray (UE 4.21+)
--   GNames:     TNameEntryArray (UE < 4.23), FNamePool (UE 4.23+)
--   Properties: UProperty/UField (UE < 4.25), FProperty/FField (UE 4.25+)
--   Vectors:    float (UE4, early UE5), double/LWC (UE 5.0+)
--   FName:      4-byte (UE 5.6+), 8-byte (standard), 12-byte (case-preserving)
--
-- Protocol: host sends {type="init"} (fresh) or {type="init", offsets={...}}
-- (cached); agent replies discovery-complete + init-response, then streams
-- position on each {type="tick"}.

local PTR_SIZE = process.get_pointer_size()

-- FUObjectItem stride candidates (bytes per slot).
local ITEM_SIZES_TO_TRY = { 0x18, 0x20, 0x10 }

-- FChunkedFixedUObjectArray (UE 4.21+).
local CHUNKED_GOBJECTS_LAYOUTS = {
    { objects = 0x00, maxEl = 0x10, numEl = 0x14, maxCh = 0x18, numCh = 0x1C, name = "Default" },
    { objects = 0x10, maxEl = 0x00, numEl = 0x04, maxCh = 0x08, numCh = 0x0C, name = "AltA" },
    { objects = 0x10, maxEl = 0x20, numEl = 0x24, maxCh = 0x28, numCh = 0x2C, name = "AltB" },
    { objects = 0x18, maxEl = 0x10, numEl = 0x00, maxCh = 0x14, numCh = 0x20, name = "AltC" },
    { objects = 0x18, maxEl = 0x00, numEl = 0x14, maxCh = 0x10, numCh = 0x04, name = "AltD" },
}

-- FFixedUObjectArray (UE 4.11-4.20) — flat, no chunking.
local FIXED_GOBJECTS_LAYOUTS = {
    { objectsOff = 0x00, maxOff = PTR_SIZE, numOff = PTR_SIZE + 4, name = "FixedDefault" },
}

local FNAME_HEADER_FORMATS = {
    { shift = 6, lenMask = 0x3FF, name = "Modern" },
    { shift = 1, lenMask = 0x7FFF, name = "Legacy" },
}

local PROPERTY_CATEGORIES = {
    NUMERIC   = { "ByteProperty", "Int8Property", "Int16Property", "IntProperty",
                  "Int64Property", "UInt16Property", "UInt32Property", "UInt64Property",
                  "FloatProperty", "DoubleProperty" },
    BOOLEAN   = { "BoolProperty" },
    STRING    = { "NameProperty", "StrProperty", "TextProperty" },
    OBJECT    = { "ObjectProperty", "WeakObjectProperty", "LazyObjectProperty",
                  "SoftObjectProperty", "ClassProperty", "SoftClassProperty",
                  "InterfaceProperty" },
    STRUCT    = { "StructProperty" },
    CONTAINER = { "ArrayProperty", "MapProperty", "SetProperty" },
    DELEGATE  = { "DelegateProperty", "MulticastDelegateProperty",
                  "MulticastInlineDelegateProperty", "MulticastSparseDelegateProperty" },
    ENUM      = { "EnumProperty" },
    OTHER     = { "FieldPathProperty", "ObjectPtrProperty" },
}

local function is_null(p)
    return p == nil or p == 0
end

local MemUtil = {}

function MemUtil.readPtr(addr)
    if is_null(addr) then return nil end
    return memory.read_pointer(addr)
end

function MemUtil.readU8(addr)
    if is_null(addr) then return nil end
    return memory.read_u8(addr)
end

function MemUtil.readU16(addr)
    if is_null(addr) then return nil end
    return memory.read_u16(addr)
end

function MemUtil.readS32(addr)
    if is_null(addr) then return nil end
    return memory.read_s32(addr)
end

function MemUtil.readU32(addr)
    if is_null(addr) then return nil end
    return memory.read_u32(addr)
end

function MemUtil.readS64(addr)
    if is_null(addr) then return nil end
    return memory.read_s64(addr)
end

function MemUtil.readF32(addr)
    if is_null(addr) then return nil end
    return memory.read_f32(addr)
end

function MemUtil.readF64(addr)
    if is_null(addr) then return nil end
    return memory.read_f64(addr)
end

function MemUtil.readCStr(addr, maxLen)
    if is_null(addr) then return nil end
    return memory.read_utf8(addr, maxLen or 256)
end

function MemUtil.readUtf16(addr, len)
    if is_null(addr) then return nil end
    return memory.read_utf16(addr, len)
end

function MemUtil.readBytes(addr, len)
    if is_null(addr) then return nil end
    return memory.read_bytes(addr, len)
end

-- Non-null + canonical x64 address (high bits all-0 or all-1).
function MemUtil.isValidPtr(p)
    if is_null(p) then return false end
    if PTR_SIZE == 8 then
        local hi = (p >> 47) & 0x1FFFF
        return hi == 0 or hi == 0x1FFFF
    end
    return true
end

function MemUtil.isReadable(addr)
    if is_null(addr) then return false end
    local val = memory.read_u8(addr)
    return val ~= nil
end

function MemUtil.findDataSections(mod)
    local modBase = mod.base
    local modEnd = modBase + mod.size
    local allRanges = process.enumerate_ranges("rw-")
    local result = {}
    for i = 1, #allRanges do
        local r = allRanges[i]
        if r.base >= modBase and r.base < modEnd then
            result[#result + 1] = r
        end
    end
    return result
end

function MemUtil.isInModule(addr, mod)
    return addr >= mod.base and addr < (mod.base + mod.size)
end

-- TArray<T> header: {data, count, max}.
function MemUtil.readTArray(addr)
    if is_null(addr) then return nil end
    local data = MemUtil.readPtr(addr)
    local count = MemUtil.readS32(addr + PTR_SIZE)
    local maxVal = MemUtil.readS32(addr + PTR_SIZE + 4)
    if not data or count == nil or maxVal == nil then return nil end
    if count < 0 or count > 0x1000000 then return nil end
    if maxVal < count then return nil end
    return { data = data, count = count, max = maxVal }
end

-- FString is TArray<TCHAR>; count includes the trailing null.
function MemUtil.readFString(addr)
    local arr = MemUtil.readTArray(addr)
    if not arr or arr.count <= 0 then return "" end
    return MemUtil.readUtf16(arr.data, arr.count - 1) or ""
end

function MemUtil.sleep(ms)
    local until_time = clock() + (ms / 1000.0)
    while clock() < until_time do end
end

local GObjectsScanner = {
    result = nil,
}

-- Tries FChunkedFixedUObjectArray (4.21+) then FFixedUObjectArray.
function GObjectsScanner.discover(self, mod)
    local dataSections = MemUtil.findDataSections(mod)
    if #dataSections == 0 then
        self:_log("error", "No data sections found in module")
        return false
    end
    self:_log("scanning", "Scanning " .. #dataSections .. " data sections for GObjects")
    log("GObjects: " .. #dataSections .. " data sections, module=" .. tostring(mod.name)
        .. " base=0x" .. string.format("%X", mod.base) .. " size=0x" .. string.format("%X", mod.size))

    -- Manager times out without periodic data — heartbeat every N iters.
    local heartbeat_interval = 2000
    local scan_count = 0

    -- Chunked first: more validation points, fewer false positives.
    for si = 1, #dataSections do
        local section = dataSections[si]
        if section.size < 0x30 then goto next_chunked_section end
        local scanSize = math.min(section.size, 0x2000000)
        local endAddr = section.base + scanSize - 0x30
        local totalAddrs = math.floor((endAddr - section.base) / PTR_SIZE)

        if si == 1 or si == #dataSections or si % 10 == 0 then
            log("GObjects: Scanning section " .. si .. "/" .. #dataSections
                .. " base=0x" .. string.format("%X", section.base)
                .. " size=0x" .. string.format("%X", section.size)
                .. " (" .. totalAddrs .. " candidates)")
        end

        local addr = section.base
        while addr < endAddr do
            for li = 1, #CHUNKED_GOBJECTS_LAYOUTS do
                local result = self:_validateChunked(addr, CHUNKED_GOBJECTS_LAYOUTS[li])
                if result then
                    self.result = result
                    self:_log("found", result.layout .. ": " .. result.numElements .. " objects (chunked)")
                    log("GObjects FOUND: " .. result.layout .. " at 0x" .. string.format("%X", addr)
                        .. " numElements=" .. result.numElements .. " itemSize=0x" .. string.format("%X", result.itemSize))
                    return true
                end
            end
            addr = addr + PTR_SIZE
            scan_count = scan_count + 1
            if scan_count % heartbeat_interval == 0 then
                local section_pct = math.floor((si / #dataSections) * 25)
                send({ type = "progress", message = "Scanning GObjects (" .. si .. "/" .. #dataSections .. ")...", percent = section_pct })
            end
        end
        ::next_chunked_section::
    end

    -- FFixedUObjectArray fallback (UE 4.11-4.20).
    self:_log("scanning", "Trying FFixedUObjectArray (pre-4.21)...")
    log("GObjects: Trying FFixedUObjectArray fallback...")
    scan_count = 0
    for si = 1, #dataSections do
        local section = dataSections[si]
        if section.size < 0x30 then goto next_fixed_section end
        local scanSize = math.min(section.size, 0x2000000)
        local endAddr = section.base + scanSize - 0x20

        local addr = section.base
        while addr < endAddr do
            for fi = 1, #FIXED_GOBJECTS_LAYOUTS do
                local result = self:_validateFixed(addr, FIXED_GOBJECTS_LAYOUTS[fi], mod)
                if result then
                    self.result = result
                    self:_log("found", result.layout .. ": " .. result.numElements .. " objects (fixed)")
                    log("GObjects FOUND (fixed): " .. result.layout .. " at 0x" .. string.format("%X", addr))
                    return true
                end
            end
            addr = addr + PTR_SIZE
            scan_count = scan_count + 1
            if scan_count % heartbeat_interval == 0 then
                local section_pct = math.floor((si / #dataSections) * 25)
                send({ type = "progress", message = "Scanning GObjects (" .. si .. "/" .. #dataSections .. ")...", percent = section_pct })
            end
        end
        ::next_fixed_section::
    end

    self:_log("error", "GObjects not found after scanning all sections")
    log("GObjects: NOT FOUND after scanning all data sections")
    return false
end

function GObjectsScanner._validateChunked(self, base, layout)
    local objectsPtr = MemUtil.readPtr(base + layout.objects)
    if not MemUtil.isValidPtr(objectsPtr) then return nil end

    local maxEl = MemUtil.readS32(base + layout.maxEl)
    local numEl = MemUtil.readS32(base + layout.numEl)
    local maxCh = MemUtil.readS32(base + layout.maxCh)
    local numCh = MemUtil.readS32(base + layout.numCh)

    if maxEl == nil or numEl == nil or maxCh == nil or numCh == nil then return nil end
    if numEl < 0x800 or numEl > 0x400000 then return nil end
    if maxEl < 0x10000 or maxEl > 0x400000 then return nil end
    if numEl > maxEl then return nil end
    if numCh < 1 or numCh > 0x100 then return nil end
    if maxCh < numCh or maxCh > 0x200 then return nil end
    if maxEl % 0x10 ~= 0 then return nil end

    local elemPerChunk = math.floor(maxEl / maxCh)
    if elemPerChunk < 0x1000 or elemPerChunk > 0x80000 then return nil end

    local expectedChunks = math.ceil(numEl / elemPerChunk)
    if expectedChunks ~= numCh then return nil end

    local firstChunk = MemUtil.readPtr(objectsPtr)
    if not MemUtil.isValidPtr(firstChunk) then return nil end

    local ci = 1
    while ci < numCh and ci < 20 do
        local chk = MemUtil.readPtr(objectsPtr + ci * PTR_SIZE)
        if not MemUtil.isValidPtr(chk) then return nil end
        ci = ci + 1
    end

    local itemSize = self:_detectItemSize(firstChunk)
    if itemSize == 0 then return nil end

    local obj5 = MemUtil.readPtr(firstChunk + 5 * itemSize)
    if not MemUtil.isValidPtr(obj5) then return nil end
    local vt = MemUtil.readPtr(obj5)
    if not MemUtil.isValidPtr(vt) then return nil end

    return {
        addr = base,
        objectsPtr = objectsPtr,
        numElements = numEl,
        maxElements = maxEl,
        maxChunks = maxCh,
        numChunks = numCh,
        itemSize = itemSize,
        elemPerChunk = elemPerChunk,
        isChunked = true,
        layout = layout.name,
    }
end

function GObjectsScanner._validateFixed(self, base, layout, mod)
    local objectsPtr = MemUtil.readPtr(base + layout.objectsOff)
    if not MemUtil.isValidPtr(objectsPtr) then return nil end
    -- Objects array lives on the heap, never in-module.
    if MemUtil.isInModule(objectsPtr, mod) then return nil end

    local maxObjects = MemUtil.readS32(base + layout.maxOff)
    local numObjects = MemUtil.readS32(base + layout.numOff)

    if maxObjects == nil or numObjects == nil then return nil end
    if numObjects < 0x1000 or numObjects > 0x400000 then return nil end
    if maxObjects < numObjects or maxObjects > 0x400000 then return nil end

    local itemSize = self:_detectItemSize(objectsPtr)
    if itemSize == 0 then return nil end

    -- ≥ half of the first 30 slots should have valid VTables.
    local validCount = 0
    for i = 0, 29 do
        local obj = MemUtil.readPtr(objectsPtr + i * itemSize)
        if obj == nil then break end
        if not is_null(obj) then
            local vt = MemUtil.readPtr(obj)
            if MemUtil.isValidPtr(vt) then validCount = validCount + 1 end
        end
    end
    if validCount < 15 then return nil end

    -- Reject if same pointer repeated (degenerate).
    local obj0 = MemUtil.readPtr(objectsPtr)
    local obj10 = MemUtil.readPtr(objectsPtr + 10 * itemSize)
    if obj0 and obj10 and obj0 == obj10 then return nil end

    return {
        addr = base,
        objectsPtr = objectsPtr,
        numElements = numObjects,
        maxElements = maxObjects,
        itemSize = itemSize,
        isChunked = false,
        layout = layout.name,
    }
end

-- Stride via consecutive-valid-pointer probe.
function GObjectsScanner._detectItemSize(self, arrayBase)
    for si = 1, #ITEM_SIZES_TO_TRY do
        local size = ITEM_SIZES_TO_TRY[si]
        local valid = 0
        local bad = false
        for i = 0, 19 do
            local obj = MemUtil.readPtr(arrayBase + i * size)
            if obj == nil then bad = true; break end
            if not is_null(obj) then
                local vt = MemUtil.readPtr(obj)
                if not MemUtil.isValidPtr(vt) then bad = true; break end
                valid = valid + 1
            end
        end
        if not bad and valid > 10 then return size end
    end
    return 0
end

function GObjectsScanner.getByIndex(self, index)
    if not self.result then return nil end
    local r = self.result

    if r.isChunked then
        local chunkIdx = math.floor(index / r.elemPerChunk)
        local inChunk = index % r.elemPerChunk
        if chunkIdx >= r.numChunks then return nil end
        local chunkPtr = MemUtil.readPtr(r.objectsPtr + chunkIdx * PTR_SIZE)
        if not MemUtil.isValidPtr(chunkPtr) then return nil end
        local obj = MemUtil.readPtr(chunkPtr + inChunk * r.itemSize)
        if MemUtil.isValidPtr(obj) then return obj else return nil end
    else
        if index >= r.numElements then return nil end
        local obj = MemUtil.readPtr(r.objectsPtr + index * r.itemSize)
        if MemUtil.isValidPtr(obj) then return obj else return nil end
    end
end

function GObjectsScanner.getNumElements(self)
    if self.result then return self.result.numElements end
    return 0
end

function GObjectsScanner._log(self, status, detail)
    send({ type = "ue-engine-progress", phase = "gobjects", status = status, detail = detail })
end

local GNamesScanner = {
    result = nil,
}

-- Tries FNamePool (4.23+) then TNameEntryArray (older).
function GNamesScanner.discover(self, mod)
    send({ type = "ue-engine-progress", phase = "gnames", status = "scanning" })

    if self:_discoverFNamePool(mod) then
        send({ type = "ue-engine-progress", phase = "gnames", status = "found", detail = "FNamePool" })
        return true
    end

    if self:_discoverTNameEntryArray(mod) then
        send({ type = "ue-engine-progress", phase = "gnames", status = "found", detail = "TNameEntryArray" })
        return true
    end

    send({ type = "ue-engine-progress", phase = "gnames", status = "error", detail = "GNames not found" })
    return false
end

-- FNamePool (UE 4.23+)

function GNamesScanner._discoverFNamePool(self, mod)
    local dataSections = MemUtil.findDataSections(mod)
    log("GNames: Scanning " .. #dataSections .. " data sections for FNamePool")
    local scan_count = 0
    for si = 1, #dataSections do
        local section = dataSections[si]
        if section.size < 0x20 then goto next_fnamepool_section end
        local scanSize = math.min(section.size, 0x2000000)
        local endAddr = section.base + scanSize - 0x100
        if si == 1 or si == #dataSections or si % 10 == 0 then
            log("GNames: Section " .. si .. "/" .. #dataSections
                .. " base=0x" .. string.format("%X", section.base)
                .. " size=0x" .. string.format("%X", section.size))
        end
        local addr = section.base
        while addr < endAddr do
            local result = self:_validateFNamePool(addr, mod)
            if result then
                self.result = result
                log("GNames FOUND: FNamePool at 0x" .. string.format("%X", addr)
                    .. " currentBlock=" .. tostring(result.currentBlock))
                return true
            end
            addr = addr + PTR_SIZE
            scan_count = scan_count + 1
            if scan_count % 2000 == 0 then
                local section_pct = math.floor(25 + (si / #dataSections) * 15)
                send({ type = "progress", message = "Scanning GNames (" .. si .. "/" .. #dataSections .. ")...", percent = section_pct })
            end
        end
        ::next_fnamepool_section::
    end
    return false
end

function GNamesScanner._validateFNamePool(self, addr, mod)
    -- FNameEntryAllocator: Lock(8) + CurrentBlock(i32) + ByteCursor(i32) + Blocks[].
    local currentBlock = MemUtil.readS32(addr + 0x08)
    local byteCursor = MemUtil.readS32(addr + 0x0C)
    if currentBlock == nil or byteCursor == nil then return nil end
    if currentBlock < 0 or currentBlock > 200 then return nil end
    if byteCursor < 0 or byteCursor > 0x200000 then return nil end

    local block0 = MemUtil.readPtr(addr + 0x10)
    if not MemUtil.isValidPtr(block0) then return nil end
    if MemUtil.isInModule(block0, mod) then return nil end

    -- Non-null block count should equal CurrentBlock + 1.
    local nonNullCount = 0
    local i = 0
    while i <= currentBlock + 2 and i < 512 do
        local blk = MemUtil.readPtr(addr + 0x10 + i * PTR_SIZE)
        if blk ~= nil and not is_null(blk) then
            nonNullCount = nonNullCount + 1
        elseif i <= currentBlock then
            return nil
        end
        i = i + 1
    end
    if nonNullCount ~= currentBlock + 1 then return nil end

    -- Slots past CurrentBlock+1 should be null (allow one stale slot).
    local afterBlock = MemUtil.readPtr(addr + 0x10 + (currentBlock + 1) * PTR_SIZE)
    if afterBlock ~= nil and not is_null(afterBlock) then
        local extraBlock = MemUtil.readPtr(addr + 0x10 + (currentBlock + 2) * PTR_SIZE)
        if extraBlock ~= nil and not is_null(extraBlock) then return nil end
    end

    local headerInfo = self:_detectPoolHeaderFormat(block0)
    if not headerInfo then return nil end

    return {
        type = "FNamePool",
        allocatorAddr = addr,
        blocksAddr = addr + 0x10,
        block0 = block0,
        currentBlock = currentBlock,
        headerShift = headerInfo.shift,
        headerWideBit = headerInfo.wideBit,
        stringOffset = headerInfo.stringOffset,
        blockOffsetBits = 16,
    }
end

function GNamesScanner._detectPoolHeaderFormat(self, block0)
    local header = MemUtil.readU16(block0)
    if header == nil then return nil end

    for fi = 1, #FNAME_HEADER_FORMATS do
        local fmt = FNAME_HEADER_FORMATS[fi]
        local wide = header & 1
        local len = (header >> fmt.shift) & fmt.lenMask
        if len == 4 and wide == 0 then
            local name = MemUtil.readCStr(block0 + 2, 4)
            if name == "None" then
                local entrySize = 2 + 4 -- header(2) + "None"(4)
                entrySize = (entrySize + 1) & ~1 -- stride-2
                local nextHeader = MemUtil.readU16(block0 + entrySize)
                if nextHeader ~= nil then
                    local nextLen = (nextHeader >> fmt.shift) & fmt.lenMask
                    if nextLen > 0 and nextLen < 256 then
                        local nextName = MemUtil.readCStr(block0 + entrySize + 2, nextLen)
                        if nextName and nextName:match("^[%a_]") then
                            return { shift = fmt.shift, wideBit = 0, stringOffset = 2 }
                        end
                    end
                end
            end
        end
    end
    return nil
end

-- TNameEntryArray (pre-4.23)

function GNamesScanner._discoverTNameEntryArray(self, mod)
    local dataSections = MemUtil.findDataSections(mod)
    log("GNames: Trying TNameEntryArray fallback, " .. #dataSections .. " sections")
    local scan_count = 0
    for si = 1, #dataSections do
        local section = dataSections[si]
        if section.size < 0x20 then goto next_tnameentry_section end
        local scanSize = math.min(section.size, 0x2000000)
        local endAddr = section.base + scanSize - 0x100
        local addr = section.base
        while addr < endAddr do
            local result = self:_validateTNameEntryArray(addr, mod)
            if result then
                self.result = result
                log("GNames FOUND: TNameEntryArray at 0x" .. string.format("%X", addr)
                    .. " numChunks=" .. tostring(result.numChunks))
                return true
            end
            addr = addr + PTR_SIZE
            scan_count = scan_count + 1
            if scan_count % 2000 == 0 then
                local section_pct = math.floor(25 + (si / #dataSections) * 15)
                send({ type = "progress", message = "Scanning GNames (" .. si .. "/" .. #dataSections .. ")...", percent = section_pct })
            end
        end
        ::next_tnameentry_section::
    end
    log("GNames: TNameEntryArray not found")
    return false
end

function GNamesScanner._validateTNameEntryArray(self, addr, mod)
    -- Chunk-pointer array → chunks of FNameEntry pointers.
    local chunk0Ptr = MemUtil.readPtr(addr)
    if not MemUtil.isValidPtr(chunk0Ptr) then return nil end
    if MemUtil.isInModule(chunk0Ptr, mod) then return nil end

    -- Entry[0] is FNameEntry("None").
    local entry0Ptr = MemUtil.readPtr(chunk0Ptr)
    if not MemUtil.isValidPtr(entry0Ptr) then return nil end

    local stringOffset = -1
    local off = 0
    while off <= 0x18 do
        local name = MemUtil.readCStr(entry0Ptr + off, 4)
        if name == "None" then stringOffset = off; break end
        off = off + 4
    end
    if stringOffset < 0 then return nil end

    local entry1Ptr = MemUtil.readPtr(chunk0Ptr + PTR_SIZE)
    if not MemUtil.isValidPtr(entry1Ptr) then return nil end
    local name1 = MemUtil.readCStr(entry1Ptr + stringOffset, 64)
    if not name1 or not name1:match("^[%a_]") then return nil end

    -- FNameEntry packs bIsWide in bit 0; actual index = val >> 1.
    local indexOffset = -1
    local entry3Ptr = MemUtil.readPtr(chunk0Ptr + 3 * PTR_SIZE)
    local entry8Ptr = MemUtil.readPtr(chunk0Ptr + 8 * PTR_SIZE)
    if MemUtil.isValidPtr(entry3Ptr) and MemUtil.isValidPtr(entry8Ptr) then
        local ioff = 0
        while ioff < 0x20 do
            if ioff ~= stringOffset then
                local val3 = MemUtil.readU32(entry3Ptr + ioff)
                local val8 = MemUtil.readU32(entry8Ptr + ioff)
                if val3 ~= nil and val8 ~= nil then
                    if (val3 >> 1) == 3 and (val8 >> 1) == 8 then
                        indexOffset = ioff
                        break
                    end
                end
            end
            ioff = ioff + 4
        end
    end

    local numChunks = 0
    for ci = 0, 199 do
        local chk = MemUtil.readPtr(addr + ci * PTR_SIZE)
        if is_null(chk) then break end
        if not MemUtil.isValidPtr(chk) then break end
        numChunks = numChunks + 1
    end
    if numChunks < 1 then return nil end

    -- Some builds store NumElements/NumChunks after the chunk pointers.
    local metaAddr = addr + numChunks * PTR_SIZE
    local numElements = MemUtil.readS32(metaAddr)
    local numChunksStored = MemUtil.readS32(metaAddr + 4)

    if numChunksStored ~= nil and numChunksStored == numChunks
        and numElements ~= nil and numElements > 0 and numElements < 0x400000 then
        -- use stored metadata
    else
        numElements = numChunks * 0x4000 -- estimate
    end

    return {
        type = "TNameEntryArray",
        chunksAddr = addr,
        numChunks = numChunks,
        numElements = numElements,
        elementsPerChunk = 0x4000,
        stringOffset = stringOffset,
        indexOffset = indexOffset,
        blockOffsetBits = 0,
    }
end

local NameResolver = {}

function NameResolver.resolve(self, compIdx)
    if compIdx == nil then return nil end
    local gn = GNamesScanner.result
    if not gn then return nil end

    if gn.type == "FNamePool" then return self:_resolveFromPool(compIdx, gn) end
    if gn.type == "TNameEntryArray" then return self:_resolveFromArray(compIdx, gn) end
    return nil
end

function NameResolver._resolveFromPool(self, compIdx, gn)
    local blockBits = gn.blockOffsetBits
    local blockIdx = compIdx >> blockBits
    local offsetInBlock = compIdx & ((1 << blockBits) - 1)
    if blockIdx > gn.currentBlock then return nil end

    local blockPtr = MemUtil.readPtr(gn.blocksAddr + blockIdx * PTR_SIZE)
    if not MemUtil.isValidPtr(blockPtr) then return nil end

    -- Pool offsets are in stride-2 units.
    local entry = blockPtr + offsetInBlock * 2
    local header = MemUtil.readU16(entry)
    if header == nil then return nil end

    local wide = header & 1
    local lenMask = 0x3FF
    if gn.headerShift ~= 6 then lenMask = 0x7FFF end
    local len = (header >> gn.headerShift) & lenMask
    if len == 0 or len > 1024 then return nil end

    if wide ~= 0 then return MemUtil.readUtf16(entry + gn.stringOffset, len) end
    return MemUtil.readCStr(entry + gn.stringOffset, len)
end

function NameResolver._resolveFromArray(self, compIdx, gn)
    local chunkIdx = math.floor(compIdx / gn.elementsPerChunk)
    local inChunk = compIdx % gn.elementsPerChunk
    if chunkIdx >= gn.numChunks then return nil end

    local chunkPtr = MemUtil.readPtr(gn.chunksAddr + chunkIdx * PTR_SIZE)
    if not MemUtil.isValidPtr(chunkPtr) then return nil end

    local entryPtr = MemUtil.readPtr(chunkPtr + inChunk * PTR_SIZE)
    if not MemUtil.isValidPtr(entryPtr) then return nil end

    if gn.indexOffset >= 0 then
        local indexVal = MemUtil.readU32(entryPtr + gn.indexOffset)
        if indexVal ~= nil and (indexVal & 1) ~= 0 then
            return MemUtil.readUtf16(entryPtr + gn.stringOffset, 256)
        end
    end

    return MemUtil.readCStr(entryPtr + gn.stringOffset, 256)
end

-- Forward declaration.
local ObjectFinder

local UObjectLayout = {
    offsets = nil, -- {index, flags, cls, name, outer, nameSize}
}

function UObjectLayout.bootstrap(self)
    send({ type = "ue-engine-progress", phase = "uobject", status = "bootstrapping" })
    local offsets = {}

    local obj5 = GObjectsScanner:getByIndex(5)
    local obj55 = GObjectsScanner:getByIndex(0x55)
    local obj123 = GObjectsScanner:getByIndex(0x123)
    if not obj5 or not obj55 or not obj123 then
        send({ type = "ue-engine-progress", phase = "uobject", status = "error",
            detail = "Cannot read test objects" })
        return false
    end

    offsets.index = self:_findIndexOffset(obj5, 5, obj55, 0x55)
    if offsets.index < 0 then
        send({ type = "ue-engine-progress", phase = "uobject", status = "error",
            detail = "Index not found" })
        return false
    end

    offsets.flags = self:_findFlagsOffset()
    if offsets.flags < 0 then offsets.flags = -1 end

    offsets.cls = self:_findClassOffset(obj55, obj123)
    if offsets.cls < 0 then
        send({ type = "ue-engine-progress", phase = "uobject", status = "error",
            detail = "Class not found" })
        return false
    end

    offsets.name = self:_findNameOffset(offsets)
    if offsets.name < 0 then
        send({ type = "ue-engine-progress", phase = "uobject", status = "error",
            detail = "Name not found" })
        return false
    end

    offsets.outer = self:_findOuterOffset(offsets)
    offsets.nameSize = self:_detectFNameSize(offsets)

    self.offsets = offsets
    send({ type = "ue-engine-progress", phase = "uobject", status = "found",
        detail = "Idx=0x" .. string.format("%x", offsets.index)
              .. " Cls=0x" .. string.format("%x", offsets.cls)
              .. " Name=0x" .. string.format("%x", offsets.name)
              .. " Sz=" .. offsets.nameSize })
    return true
end

function UObjectLayout.readNameCompIdx(self, objAddr)
    if not self.offsets then return nil end
    return MemUtil.readS32(objAddr + self.offsets.name)
end

function UObjectLayout.readNameNumber(self, objAddr)
    if not self.offsets then return nil end
    if self.offsets.nameSize <= 4 then return 0 end
    return MemUtil.readS32(objAddr + self.offsets.name + 4)
end

function UObjectLayout.readClass(self, objAddr)
    if not self.offsets then return nil end
    return MemUtil.readPtr(objAddr + self.offsets.cls)
end

function UObjectLayout.readOuter(self, objAddr)
    if not self.offsets or self.offsets.outer < 0 then return nil end
    return MemUtil.readPtr(objAddr + self.offsets.outer)
end

function UObjectLayout.readVTable(self, objAddr)
    return MemUtil.readPtr(objAddr)
end

function UObjectLayout.readFlags(self, objAddr)
    if not self.offsets or self.offsets.flags < 0 then return nil end
    return MemUtil.readS32(objAddr + self.offsets.flags)
end

function UObjectLayout.getObjectName(self, objAddr)
    local compIdx = self:readNameCompIdx(objAddr)
    local name = NameResolver:resolve(compIdx)
    if not name then return nil end
    local num = self:readNameNumber(objAddr)
    if num and num > 0 then name = name .. "_" .. (num - 1) end
    return name
end

function UObjectLayout.getFullName(self, objAddr)
    local name = self:getObjectName(objAddr)
    if not name then return nil end
    local outer = self:readOuter(objAddr)
    if outer and not is_null(outer) then
        local outerName = self:getFullName(outer)
        if outerName then return outerName .. "." .. name end
    end
    return name
end

function UObjectLayout.getClassName(self, objAddr)
    local cls = self:readClass(objAddr)
    if not cls then return nil end
    return self:getObjectName(cls)
end

function UObjectLayout._findIndexOffset(self, objA, idxA, objB, idxB)
    local off = 0
    while off < 0x80 do
        local valA = MemUtil.readS32(objA + off)
        local valB = MemUtil.readS32(objB + off)
        if valA == idxA and valB == idxB then return off end
        off = off + 4
    end
    return -1
end

function UObjectLayout._findFlagsOffset(self)
    local testCount = math.min(0x100, GObjectsScanner:getNumElements())
    local bestOff = -1
    local bestCount = 0
    local off = 0
    while off < 0x40 do
        local count43 = 0
        for i = 0, testCount - 1 do
            local obj = GObjectsScanner:getByIndex(i)
            if obj then
                if MemUtil.readS32(obj + off) == 0x43 then count43 = count43 + 1 end
            end
        end
        if count43 > bestCount then bestCount = count43; bestOff = off end
        off = off + 4
    end
    if bestCount > testCount * 0.5 then return bestOff end
    return -1
end

function UObjectLayout._findClassOffset(self, objA, objB)
    local off = 0
    while off < 0x80 do
        if self:_isCyclicClassPtr(objA, off) and self:_isCyclicClassPtr(objB, off) then
            return off
        end
        off = off + PTR_SIZE
    end
    return -1
end

function UObjectLayout._isCyclicClassPtr(self, obj, offset)
    local current = MemUtil.readPtr(obj + offset)
    if not MemUtil.isValidPtr(current) then return false end
    local visited = {}
    for hop = 0, 15 do
        local next = MemUtil.readPtr(current + offset)
        if not MemUtil.isValidPtr(next) then return false end
        if next == current then return true end
        for v = 1, #visited do
            if visited[v] == next then return false end
        end
        visited[#visited + 1] = current
        current = next
    end
    return false
end

function UObjectLayout._findNameOffset(self, knownOffsets)
    local testObjs = {}
    for i = 0, 49 do
        local obj = GObjectsScanner:getByIndex(i)
        if obj then testObjs[#testObjs + 1] = obj end
    end
    if #testObjs < 10 then return -1 end

    local bestOff = -1
    local bestScore = 0
    local off = 0
    while off < 0x80 do
        if off ~= knownOffsets.index and off ~= knownOffsets.cls then
            if knownOffsets.flags < 0 or off ~= knownOffsets.flags then
                local validCount = 0
                local uniqueNames = {}
                for ti = 1, #testObjs do
                    local compIdx = MemUtil.readS32(testObjs[ti] + off)
                    if compIdx ~= nil and compIdx >= 0 and compIdx <= 0x4000000 then
                        if compIdx ~= 0 then -- skip "None"
                            local name = NameResolver:resolve(compIdx)
                            if name and #name > 0 and #name < 256 and name:match("^[%a_]") then
                                validCount = validCount + 1
                                uniqueNames[name] = true
                            end
                        end
                    end
                end
                local uniqueCount = 0
                for _ in pairs(uniqueNames) do uniqueCount = uniqueCount + 1 end
                local score = validCount + uniqueCount
                if score > bestScore then bestScore = score; bestOff = off end
            end
        end
        off = off + 4
    end
    if bestScore > #testObjs * 0.5 then return bestOff end
    return -1
end

function UObjectLayout._findOuterOffset(self, knownOffsets)
    local off = 0
    while off < 0x80 do
        if off ~= 0 and off ~= knownOffsets.index and off ~= knownOffsets.cls
            and off ~= knownOffsets.name then
            if knownOffsets.flags < 0 or off ~= knownOffsets.flags then
                local validOuters = 0
                local nullOuters = 0
                local total = 0
                for i = 0, 99 do
                    local obj = GObjectsScanner:getByIndex(i)
                    if obj then
                        total = total + 1
                        local candidate = MemUtil.readPtr(obj + off)
                        if candidate ~= nil then
                            if is_null(candidate) then
                                nullOuters = nullOuters + 1
                            else
                                local candidateIdx = MemUtil.readS32(candidate + knownOffsets.index)
                                if candidateIdx ~= nil and candidateIdx >= 0
                                    and candidateIdx < GObjectsScanner:getNumElements() then
                                    validOuters = validOuters + 1
                                end
                            end
                        end
                    end
                end
                if validOuters > total * 0.4 and nullOuters > 0 and nullOuters < total * 0.3 then
                    return off
                end
            end
        end
        off = off + PTR_SIZE
    end
    return -1
end

function UObjectLayout._detectFNameSize(self, offsets)
    -- Gap analysis to next known field.
    local candidates = {}
    local fields = { offsets.outer, offsets.cls, offsets.flags, offsets.index }
    for _, o in ipairs(fields) do
        if o > offsets.name then candidates[#candidates + 1] = o end
    end
    table.sort(candidates)
    if #candidates > 0 then
        local gap = candidates[1] - offsets.name
        if gap == 4 or gap == 8 or gap == 12 or gap == 16 then
            if gap <= 12 then return gap else return 12 end
        end
    end

    -- Fallback: Number field at +4 is usually 0 for 8-byte FName.
    local zeroCount = 0
    for i = 0, 49 do
        local obj = GObjectsScanner:getByIndex(i)
        if obj then
            if MemUtil.readS32(obj + offsets.name + 4) == 0 then zeroCount = zeroCount + 1 end
        end
    end
    if zeroCount > 40 then return 8 else return 4 end
end

local ReflectionWalker = {
    offsets = nil,         -- {superStruct, childProps, children, structSize}
    fieldOffsets = nil,    -- {next, name, fieldClass}
    propOffsets = nil,     -- {offsetInternal}
    useFProperty = false,
    vectorPrecision = "vtFloat",
    vectorComponentSize = 4,
    _fieldClassOffset = -1,
    _uFieldNextOffset = -1,
}

function ReflectionWalker.bootstrap(self)
    send({ type = "ue-engine-progress", phase = "reflection", status = "bootstrapping" })

    local vectorStruct = ObjectFinder:findObjectByName("Vector", "ScriptStruct")
    local rotatorStruct = ObjectFinder:findObjectByName("Rotator", "ScriptStruct")
    if not vectorStruct then
        send({ type = "ue-engine-progress", phase = "reflection", status = "error",
            detail = "Vector not found" })
        return false
    end

    local structClass = ObjectFinder:findObjectByName("Struct", "Class")
    local fieldClass = ObjectFinder:findObjectByName("Field", "Class")
    local superStructOff = -1
    if structClass and fieldClass then
        superStructOff = self:_findSuperStructOffset(structClass, fieldClass)
    end

    -- FVector has exactly 3 props (X, Y, Z) — clean calibration target.
    local calibration = self:_calibrateWithVector(vectorStruct)
    if not calibration then
        send({ type = "ue-engine-progress", phase = "reflection", status = "error",
            detail = "Vector calibration failed" })
        return false
    end

    -- FVector.X has Offset_Internal=0; Y=4 (float) or 8 (double/LWC).
    local propCalibration = self:_calibratePropertyOffsets(calibration)
    if not propCalibration then
        send({ type = "ue-engine-progress", phase = "reflection", status = "error",
            detail = "Property offset calibration failed" })
        return false
    end

    self.offsets = {
        superStruct = superStructOff,
        childProps = calibration.childPropsOffset,
        children = -1,
        structSize = -1,
    }
    self.fieldOffsets = {
        next = calibration.nextOffset,
        name = calibration.nameOffset,
        fieldClass = calibration.fieldClassOffset or -1,
    }
    self.propOffsets = {
        offsetInternal = propCalibration.offsetInternalOff,
    }
    self.useFProperty = calibration.isFProperty
    self._fieldClassOffset = calibration.fieldClassOffset or -1
    self.vectorPrecision = propCalibration.isDouble and "vtDouble" or "vtFloat"
    self.vectorComponentSize = propCalibration.isDouble and 8 or 4

    self:_findStructSizeOffset(vectorStruct, rotatorStruct)
    self:_findChildrenOffset()

    send({ type = "ue-engine-progress", phase = "reflection", status = "found",
        detail = "CP=0x" .. string.format("%x", calibration.childPropsOffset)
              .. " Nxt=0x" .. string.format("%x", calibration.nextOffset)
              .. " Nm=0x" .. string.format("%x", calibration.nameOffset)
              .. " OI=0x" .. string.format("%x", propCalibration.offsetInternalOff)
              .. " FProp=" .. tostring(self.useFProperty)
              .. " Vec=" .. self.vectorPrecision })
    return true
end

-- Direct properties only.
function ReflectionWalker.getProperties(self, structAddr)
    if not self.offsets or not self.fieldOffsets then return {} end
    local props = {}
    local child = MemUtil.readPtr(structAddr + self.offsets.childProps)
    local maxIter = 500

    while MemUtil.isValidPtr(child) and maxIter > 0 do
        maxIter = maxIter - 1
        local compIdx = MemUtil.readS32(child + self.fieldOffsets.name)
        local name = NameResolver:resolve(compIdx)
        local memberOffset = -1
        if self.propOffsets.offsetInternal >= 0 then
            memberOffset = MemUtil.readS32(child + self.propOffsets.offsetInternal)
            if memberOffset == nil then memberOffset = -1 end
        end
        local typeName = self:_getPropertyTypeName(child)
        if name then
            props[#props + 1] = { name = name, offset = memberOffset, type = typeName, fieldAddr = child }
        end
        child = MemUtil.readPtr(child + self.fieldOffsets.next)
    end
    return props
end

-- Walks SuperStruct chain for inherited properties.
function ReflectionWalker.getAllProperties(self, structAddr)
    local allProps = {}
    local current = structAddr
    local maxDepth = 30
    while MemUtil.isValidPtr(current) and maxDepth > 0 do
        maxDepth = maxDepth - 1
        local props = self:getProperties(current)
        for i = 1, #props do allProps[#allProps + 1] = props[i] end
        if self.offsets.superStruct >= 0 then
            current = MemUtil.readPtr(current + self.offsets.superStruct)
        else break end
    end
    return allProps
end

function ReflectionWalker.findPropertyOffset(self, structAddr, propName)
    local props = self:getAllProperties(structAddr)
    for i = 1, #props do
        if props[i].name == propName then return props[i].offset end
    end
    return -1
end

function ReflectionWalker.findProperty(self, structAddr, propName)
    local props = self:getAllProperties(structAddr)
    for i = 1, #props do
        if props[i].name == propName then return props[i] end
    end
    return nil
end

-- UFunctions live on UField Children list, not ChildProperties.
function ReflectionWalker.getFunctions(self, structAddr)
    if not self.offsets or self.offsets.children < 0 or self._uFieldNextOffset < 0 then return {} end
    local funcs = {}
    local child = MemUtil.readPtr(structAddr + self.offsets.children)
    local maxIter = 500

    while MemUtil.isValidPtr(child) and maxIter > 0 do
        maxIter = maxIter - 1
        local cls = UObjectLayout:readClass(child)
        if cls then
            local clsName = UObjectLayout:getObjectName(cls)
            if clsName == "Function" then
                local funcName = UObjectLayout:getObjectName(child)
                if funcName then
                    funcs[#funcs + 1] = { name = funcName, addr = child }
                end
            end
        end
        child = MemUtil.readPtr(child + self._uFieldNextOffset)
    end
    return funcs
end

function ReflectionWalker.getAllFunctions(self, structAddr)
    local allFuncs = {}
    local current = structAddr
    local maxDepth = 30
    while MemUtil.isValidPtr(current) and maxDepth > 0 do
        maxDepth = maxDepth - 1
        local funcs = self:getFunctions(current)
        for i = 1, #funcs do allFuncs[#allFuncs + 1] = funcs[i] end
        if self.offsets.superStruct >= 0 then
            current = MemUtil.readPtr(current + self.offsets.superStruct)
        else break end
    end
    return allFuncs
end

function ReflectionWalker.getStructSize(self, structAddr)
    if not self.offsets or self.offsets.structSize < 0 then return -1 end
    local size = MemUtil.readS32(structAddr + self.offsets.structSize)
    if size ~= nil and size > 0 and size < 0x100000 then return size end
    return -1
end

function ReflectionWalker.getSuperStruct(self, structAddr)
    if not self.offsets or self.offsets.superStruct < 0 then return nil end
    return MemUtil.readPtr(structAddr + self.offsets.superStruct)
end

-- FProperty (4.25+) gives type via FField::Class; UProperty via its UObject class.
function ReflectionWalker._getPropertyTypeName(self, fieldAddr)
    if self.useFProperty and self._fieldClassOffset >= 0 then
        local fFieldClass = MemUtil.readPtr(fieldAddr + self._fieldClassOffset)
        if not MemUtil.isValidPtr(fFieldClass) then return nil end
        -- FFieldClass::Name is at offset 0.
        local nameIdx = MemUtil.readS32(fFieldClass)
        return NameResolver:resolve(nameIdx)
    else
        return UObjectLayout:getClassName(fieldAddr)
    end
end

function ReflectionWalker._findSuperStructOffset(self, structClass, fieldClass)
    -- Struct → Field
    local off = PTR_SIZE
    while off < 0x100 do
        local candidate = MemUtil.readPtr(structClass + off)
        if candidate and candidate == fieldClass then return off end
        off = off + PTR_SIZE
    end
    -- Fallback: Class → Struct
    local classObj = ObjectFinder:findObjectByName("Class", "Class")
    if classObj then
        local off2 = PTR_SIZE
        while off2 < 0x100 do
            local candidate2 = MemUtil.readPtr(classObj + off2)
            if candidate2 and candidate2 == structClass then return off2 end
            off2 = off2 + PTR_SIZE
        end
    end
    return -1
end

-- Probe ChildProperties / FField::Next / FField::Name against FVector's
-- 3-entry X/Y/Z linked list.
function ReflectionWalker._calibrateWithVector(self, vectorStruct)
    local cpOff = PTR_SIZE
    while cpOff < 0x100 do
        local firstChild = MemUtil.readPtr(vectorStruct + cpOff)
        if MemUtil.isValidPtr(firstChild) then
            local childVt = MemUtil.readPtr(firstChild)
            if MemUtil.isValidPtr(childVt) then
                -- FProperty isn't in GObjects; UProperty is.
                local isFProperty = true
                local childIdx = MemUtil.readS32(firstChild + UObjectLayout.offsets.index)
                if childIdx ~= nil and childIdx >= 0 and childIdx < GObjectsScanner:getNumElements() then
                    local objAtIdx = GObjectsScanner:getByIndex(childIdx)
                    if objAtIdx and objAtIdx == firstChild then isFProperty = false end
                end

                -- Valid Next offset yields a 3-link list ending in null.
                local nextOff = PTR_SIZE
                while nextOff < 0x60 do
                    local secondChild = MemUtil.readPtr(firstChild + nextOff)
                    if MemUtil.isValidPtr(secondChild) then
                        local thirdChild = MemUtil.readPtr(secondChild + nextOff)
                        if MemUtil.isValidPtr(thirdChild) then
                            local fourthChild = MemUtil.readPtr(thirdChild + nextOff)
                            if is_null(fourthChild) then
                                local nameOff = 4
                                while nameOff < 0x50 do
                                    local comp1 = MemUtil.readS32(firstChild + nameOff)
                                    local comp2 = MemUtil.readS32(secondChild + nameOff)
                                    local comp3 = MemUtil.readS32(thirdChild + nameOff)
                                    if comp1 ~= nil and comp2 ~= nil and comp3 ~= nil
                                        and comp1 >= 0 and comp2 >= 0 and comp3 >= 0 then
                                        local name1 = NameResolver:resolve(comp1)
                                        local name2 = NameResolver:resolve(comp2)
                                        local name3 = NameResolver:resolve(comp3)
                                        if not name1 or not name2 or not name3 then goto next_name_off end
                                        local names = { name1, name2, name3 }
                                        table.sort(names)
                                        if names[1] == "X" and names[2] == "Y" and names[3] == "Z" then
                                            local fieldClassOff = -1
                                            if isFProperty then
                                                fieldClassOff = self:_findFieldClassOffset(
                                                    firstChild, secondChild, thirdChild, nextOff)
                                            end
                                            return {
                                                childPropsOffset = cpOff,
                                                nextOffset = nextOff,
                                                nameOffset = nameOff,
                                                isFProperty = isFProperty,
                                                fieldClassOffset = fieldClassOff,
                                                children = {
                                                    { addr = firstChild, name = name1 },
                                                    { addr = secondChild, name = name2 },
                                                    { addr = thirdChild, name = name3 },
                                                },
                                            }
                                        end
                                    end
                                    ::next_name_off::
                                    nameOff = nameOff + 4
                                end
                            end
                        end
                    end
                    nextOff = nextOff + PTR_SIZE
                end
            end
        end
        cpOff = cpOff + PTR_SIZE
    end
    return nil
end

-- All 3 Vector components share one FFieldClass (Float or Double for LWC).
function ReflectionWalker._findFieldClassOffset(self, child1, child2, child3, nextOff)
    local off = PTR_SIZE
    while off < 0x40 do
        if off ~= nextOff then
            local fc1 = MemUtil.readPtr(child1 + off)
            local fc2 = MemUtil.readPtr(child2 + off)
            local fc3 = MemUtil.readPtr(child3 + off)
            if MemUtil.isValidPtr(fc1) and MemUtil.isValidPtr(fc2) and MemUtil.isValidPtr(fc3) then
                if fc1 == fc2 and fc2 == fc3 then
                    local fcNameIdx = MemUtil.readS32(fc1)
                    if fcNameIdx ~= nil and fcNameIdx > 0 then
                        local fcName = NameResolver:resolve(fcNameIdx)
                        if fcName == "FloatProperty" or fcName == "DoubleProperty" then
                            return off
                        end
                    end
                end
            end
        end
        off = off + PTR_SIZE
    end
    return -1
end

function ReflectionWalker._calibratePropertyOffsets(self, calibration)
    local xChild = nil
    local yChild = nil
    for i = 1, #calibration.children do
        if calibration.children[i].name == "X" then xChild = calibration.children[i].addr end
        if calibration.children[i].name == "Y" then yChild = calibration.children[i].addr end
    end
    if not xChild or not yChild then return nil end

    local off = 0
    while off < 0x100 do
        local xOI = MemUtil.readS32(xChild + off)
        local yOI = MemUtil.readS32(yChild + off)
        if xOI ~= nil and yOI ~= nil then
            if xOI == 0 then
                if yOI == 4 then return { offsetInternalOff = off, isDouble = false } end
                if yOI == 8 then return { offsetInternalOff = off, isDouble = true } end
            end
        end
        off = off + 4
    end
    return nil
end

function ReflectionWalker._findStructSizeOffset(self, vectorStruct, rotatorStruct)
    local expectedSize = self.vectorComponentSize * 3
    local off = PTR_SIZE
    while off < 0x100 do
        local val = MemUtil.readS32(vectorStruct + off)
        if val == expectedSize then
            if rotatorStruct then
                local rotVal = MemUtil.readS32(rotatorStruct + off)
                if rotVal == expectedSize then
                    self.offsets.structSize = off
                    return
                end
            else
                self.offsets.structSize = off
                return
            end
        end
        off = off + 4
    end
end

-- Children is the UField list holding UFunctions; distinct from
-- ChildProperties (FProperties on 4.25+).
function ReflectionWalker._findChildrenOffset(self)
    local testClasses = { "Actor", "PlayerController", "Pawn", "Object" }
    for ti = 1, #testClasses do
        local testClass = ObjectFinder:findObjectByName(testClasses[ti], "Class")
        if testClass then
            local off = PTR_SIZE
            while off < 0x100 do
                if off ~= self.offsets.childProps and off ~= self.offsets.superStruct then
                    if self.offsets.structSize < 0 or off ~= self.offsets.structSize then
                        local child = MemUtil.readPtr(testClass + off)
                        if MemUtil.isValidPtr(child) then
                            -- Must be in GObjects.
                            local childIdx = MemUtil.readS32(child + UObjectLayout.offsets.index)
                            if childIdx ~= nil and childIdx >= 0
                                and childIdx < GObjectsScanner:getNumElements() then
                                local objAtIdx = GObjectsScanner:getByIndex(childIdx)
                                if objAtIdx and objAtIdx == child then
                                    local cls = UObjectLayout:readClass(child)
                                    if cls then
                                        local clsName = UObjectLayout:getObjectName(cls)
                                        if clsName == "Function" then
                                            local nOff = PTR_SIZE
                                            while nOff < 0x80 do
                                                if nOff ~= UObjectLayout.offsets.cls
                                                    and nOff ~= UObjectLayout.offsets.outer
                                                    and nOff ~= 0 then
                                                    local next = MemUtil.readPtr(child + nOff)
                                                    if MemUtil.isValidPtr(next) then
                                                        local nextIdx = MemUtil.readS32(next + UObjectLayout.offsets.index)
                                                        if nextIdx ~= nil and nextIdx >= 0
                                                            and nextIdx < GObjectsScanner:getNumElements() then
                                                            local objAtNext = GObjectsScanner:getByIndex(nextIdx)
                                                            if objAtNext and objAtNext == next then
                                                                self.offsets.children = off
                                                                self._uFieldNextOffset = nOff
                                                                return off
                                                            end
                                                        end
                                                    end
                                                end
                                                nOff = nOff + PTR_SIZE
                                            end
                                            -- Record even if Next unresolved.
                                            self.offsets.children = off
                                            return off
                                        end
                                    end
                                end
                            end
                        end
                    end
                end
                off = off + PTR_SIZE
            end
        end
    end
    return -1
end

ObjectFinder = {
    _nameCache = nil,
}

function ObjectFinder.buildNameCache(self)
    send({ type = "ue-engine-progress", phase = "cache", status = "building" })
    log("ObjectFinder: Building name cache...")
    self._nameCache = {}
    local num = GObjectsScanner:getNumElements()
    local named = 0
    for i = 0, num - 1 do
        local obj = GObjectsScanner:getByIndex(i)
        if obj then
            local name = UObjectLayout:getObjectName(obj)
            if name then
                if not self._nameCache[name] then self._nameCache[name] = {} end
                local entries = self._nameCache[name]
                entries[#entries + 1] = { index = i, addr = obj }
                named = named + 1
            end
        end
        -- Heartbeat keeps the manager's data timer alive.
        if i % 10000 == 0 and i > 0 then
            local cache_pct = math.floor(42 + (i / num) * 6)
            send({ type = "progress", message = "Building object cache (" .. math.floor(i/1000) .. "k/" .. math.floor(num/1000) .. "k)...", percent = cache_pct })
        end
    end
    local uniqueCount = 0
    for _ in pairs(self._nameCache) do uniqueCount = uniqueCount + 1 end
    log("ObjectFinder: Cache built — " .. named .. " named objects, " .. uniqueCount .. " unique names")
    send({ type = "ue-engine-progress", phase = "cache", status = "built",
        detail = uniqueCount .. " unique names" })
end

function ObjectFinder.findObjectByName(self, name, classNameFilter)
    if not self._nameCache then self:buildNameCache() end
    local candidates = self._nameCache[name]
    if not candidates or #candidates == 0 then return nil end
    if not classNameFilter then return candidates[1].addr end
    for i = 1, #candidates do
        local cls = UObjectLayout:readClass(candidates[i].addr)
        if cls then
            if UObjectLayout:getObjectName(cls) == classNameFilter then return candidates[i].addr end
        end
    end
    return candidates[1].addr
end

function ObjectFinder.findObjectsByClassName(self, className)
    if not self._nameCache then self:buildNameCache() end
    local results = {}
    local num = GObjectsScanner:getNumElements()
    for i = 0, num - 1 do
        local obj = GObjectsScanner:getByIndex(i)
        if obj then
            local cls = UObjectLayout:readClass(obj)
            if cls then
                if UObjectLayout:getObjectName(cls) == className then
                    results[#results + 1] = { index = i, addr = obj, name = UObjectLayout:getObjectName(obj) }
                end
            end
        end
    end
    return results
end

function ObjectFinder.enumerateClasses(self)
    local classClass = self:findObjectByName("Class", "Class")
    if not classClass then return {} end
    local results = {}
    local num = GObjectsScanner:getNumElements()
    for i = 0, num - 1 do
        local obj = GObjectsScanner:getByIndex(i)
        if obj then
            local cls = UObjectLayout:readClass(obj)
            if cls and cls == classClass then
                local name = UObjectLayout:getObjectName(obj)
                if name then results[#results + 1] = { name = name, addr = obj } end
            end
        end
    end
    return results
end

function ObjectFinder.enumerateStructs(self)
    local structClass = self:findObjectByName("ScriptStruct", "Class")
    if not structClass then return {} end
    local results = {}
    local num = GObjectsScanner:getNumElements()
    for i = 0, num - 1 do
        local obj = GObjectsScanner:getByIndex(i)
        if obj then
            local cls = UObjectLayout:readClass(obj)
            if cls and cls == structClass then
                local name = UObjectLayout:getObjectName(obj)
                if name then results[#results + 1] = { name = name, addr = obj } end
            end
        end
    end
    return results
end

-- Walks SuperStruct chain for instance-of check.
function ObjectFinder.isA(self, objectAddr, className)
    local cls = UObjectLayout:readClass(objectAddr)
    if not cls then return false end
    local depth = 0
    while MemUtil.isValidPtr(cls) and depth < 50 do
        if UObjectLayout:getObjectName(cls) == className then return true end
        if ReflectionWalker.offsets and ReflectionWalker.offsets.superStruct >= 0 then
            cls = MemUtil.readPtr(cls + ReflectionWalker.offsets.superStruct)
        else break end
        depth = depth + 1
    end
    return false
end

function ObjectFinder.getInheritanceChain(self, classAddr)
    local chain = {}
    local current = classAddr
    local depth = 0
    while MemUtil.isValidPtr(current) and depth < 50 do
        local name = UObjectLayout:getObjectName(current)
        if name then chain[#chain + 1] = name end
        if ReflectionWalker.offsets and ReflectionWalker.offsets.superStruct >= 0 then
            current = MemUtil.readPtr(current + ReflectionWalker.offsets.superStruct)
        else break end
        depth = depth + 1
    end
    return chain
end

-- Find GWorld by locating a live UWorld (not Default__) then scanning
-- data sections for a pointer to it. With `chainOffsets`, each candidate
-- is full-chain-validated so sublevel/streaming slots (non-null OGI but
-- broken deeper chain) get filtered out.
function ObjectFinder.findGWorld(self, mod, chainOffsets)
    log("GWorld: Searching for World class instances...")
    local worldClass = self:findObjectByName("World", "Class")
    if not worldClass then
        log("GWorld: World class not found in GObjects")
        return nil
    end

    local worldInstances = {}
    local num = GObjectsScanner:getNumElements()
    for i = 0, num - 1 do
        local obj = GObjectsScanner:getByIndex(i)
        if obj then
            local cls = UObjectLayout:readClass(obj)
            if cls and cls == worldClass then
                local name = UObjectLayout:getObjectName(obj)
                if not name or name:sub(1, 9) ~= "Default__" then
                    worldInstances[#worldInstances + 1] = obj
                end
            end
        end
    end
    log("GWorld: Found " .. #worldInstances .. " World instances")
    if #worldInstances == 0 then return nil end

    local dataSections = MemUtil.findDataSections(mod)
    log("GWorld: Scanning " .. #dataSections .. " data sections for pointers to ANY World instance")

    -- Single-pass scan over a HashSet of all World addresses — earlier
    -- code iterated per-World and broke on the first hit, making the
    -- picker depend on World creation order and often locking onto a
    -- sublevel slot instead of the persistent GWorld.
    local worldSet = {}
    for wi = 1, #worldInstances do
        worldSet[worldInstances[wi]] = true
    end

    local candidates = {}
    local scan_count = 0
    for si = 1, #dataSections do
        local section = dataSections[si]
        local scanSize = math.min(section.size, 0x2000000)
        local endAddr = section.base + scanSize - PTR_SIZE
        local addr = section.base
        while addr < endAddr do
            local val = MemUtil.readPtr(addr)
            if val and worldSet[val] then
                candidates[#candidates + 1] = addr
            end
            addr = addr + PTR_SIZE
            scan_count = scan_count + 1
            if scan_count % 2000 == 0 then
                local section_pct = math.floor(55 + (si / #dataSections) * 44)
                send({ type = "progress", message = "Resolving GWorld...", percent = section_pct })
            end
        end
    end
    log("GWorld: Found " .. #candidates .. " candidate pointers across all " .. #worldInstances .. " Worlds")

    if #candidates == 0 then return nil end
    if #candidates == 1 then
        return { primary = candidates[1] - mod.base, alternates = {} }
    end

    -- Score each candidate by stability over 30 × 33ms samples. The
    -- persistent GWorld stays non-null and same-valued; sublevel and
    -- streaming bookkeeping slots blip null during level streaming.
    -- Composite score: chain-walk depth + never-blipped-null bonus +
    -- value stability + consensus with other stable slots. Runners-up
    -- become runtime fallbacks so a transient null on the primary can
    -- be papered over without rediscovery.
    local SAMPLES = 30
    local INTERVAL_MS = 33

    -- nonNullCount: how often the slot was non-null (persistent GWorld
    -- is non-null for the entire window).
    -- chainDepthSum: how deep the chain resolved (0..7 per sample, where
    -- 7 = full chain GWorld→OGI→LocalPlayers→LocalPlayer→PC→Pawn→Root).
    -- sameValueCount: how often the slot kept its first value (noisy
    -- slots like GActiveLogWorld drift).
    local nonNullCount = {}
    local chainDepthSum = {}
    local sameValueCount = {}
    local firstValue = {}
    local valueAt = {}
    for ci = 1, #candidates do
        nonNullCount[ci] = 0
        chainDepthSum[ci] = 0
        sameValueCount[ci] = 0
        firstValue[ci] = nil
        valueAt[ci] = {}
    end

    local function walk_depth(world)
        if not chainOffsets then return is_null(world) and 0 or 1 end
        if is_null(world) then return 0 end
        if not chainOffsets.ogi then return 1 end
        local ogi = MemUtil.readPtr(world + chainOffsets.ogi)
        if is_null(ogi) then return 1 end
        if not chainOffsets.localPlayers then return 2 end
        local lp = MemUtil.readPtr(ogi + chainOffsets.localPlayers)
        if is_null(lp) then return 2 end
        local lplayer = MemUtil.readPtr(lp + (chainOffsets.localPlayer or 0))
        if is_null(lplayer) then return 3 end
        if not chainOffsets.playerController then return 4 end
        local pc = MemUtil.readPtr(lplayer + chainOffsets.playerController)
        if is_null(pc) then return 4 end
        if not chainOffsets.pawn then return 5 end
        local pawn = MemUtil.readPtr(pc + chainOffsets.pawn)
        if is_null(pawn) then return 5 end
        if not chainOffsets.root then return 6 end
        local root = MemUtil.readPtr(pawn + chainOffsets.root)
        if is_null(root) then return 6 end
        return 7
    end

    for s = 1, SAMPLES do
        -- Per-sample progress so the 1s scoring isn't a silent pause.
        local sample_pct = math.floor(99 + (s / SAMPLES) * 0.5)
        send({
            type = "progress",
            message = string.format(
                "Validating GWorld candidate (%d/%d sample, %d candidate%s)...",
                s, SAMPLES, #candidates, #candidates == 1 and "" or "s"),
            percent = sample_pct,
        })
        for ci = 1, #candidates do
            local v = MemUtil.readPtr(candidates[ci])
            valueAt[ci][s] = v
            if not is_null(v) then
                nonNullCount[ci] = nonNullCount[ci] + 1
            end
            if firstValue[ci] == nil and not is_null(v) then
                firstValue[ci] = v
            end
            if firstValue[ci] ~= nil and v == firstValue[ci] then
                sameValueCount[ci] = sameValueCount[ci] + 1
            end
            chainDepthSum[ci] = chainDepthSum[ci] + walk_depth(v)
        end
        if s < SAMPLES then MemUtil.sleep(INTERVAL_MS) end
    end

    -- Modal World* across stable candidates.
    local lastValueFreq = {}
    for ci = 1, #candidates do
        if nonNullCount[ci] >= SAMPLES - 1 then
            local v = valueAt[ci][SAMPLES]
            if v then
                lastValueFreq[v] = (lastValueFreq[v] or 0) + 1
            end
        end
    end
    local consensus, bestFreq = nil, 0
    for v, freq in pairs(lastValueFreq) do
        if freq > bestFreq then consensus = v; bestFreq = freq end
    end

    local scored = {}
    for ci = 1, #candidates do
        local stickyConsensus = 0
        if consensus then
            for s = 1, SAMPLES do
                if valueAt[ci][s] == consensus then
                    stickyConsensus = stickyConsensus + 1
                end
            end
        end
        -- Penalty for any null dip. Persistent GWorld never dips;
        -- sublevel/streaming slots do.
        local everNull = SAMPLES - nonNullCount[ci]
        -- Decreasing weights: chain depth (ground truth) >> never-null
        -- bonus > value stability > raw non-null > consensus. Tiny
        -- inverse-offset bias breaks ties toward lower-address slots
        -- (engine globals link earlier than game globals).
        local lowerOffsetBias = 1.0 / (1 + (candidates[ci] - mod.base) / 1024)
        scored[#scored + 1] = {
            offset = candidates[ci] - mod.base,
            nonNull = nonNullCount[ci],
            depthSum = chainDepthSum[ci],
            sameValue = sameValueCount[ci],
            everNull = everNull,
            consensus = stickyConsensus,
            score = chainDepthSum[ci] * 1000000
                + (everNull == 0 and 100000 or 0)
                + sameValueCount[ci] * 1000
                + nonNullCount[ci] * 10
                + stickyConsensus
                + lowerOffsetBias,
        }
    end
    table.sort(scored, function(a, b) return a.score > b.score end)

    -- With full-chain validation, require depthSum > SAMPLES (at least
    -- one sample walked past OGI). If nothing clears the bar the game
    -- is genuinely mid-loading — fall back to temporal-only scoring.
    local filtered = {}
    local hadFullChain = chainOffsets and chainOffsets.ogi
    if hadFullChain then
        for i = 1, #scored do
            if scored[i].depthSum > SAMPLES then
                filtered[#filtered + 1] = scored[i]
            end
        end
        if #filtered == 0 then
            log("GWorld: WARNING — no candidate's chain walked past GWorld "
                .. "during sample window; game may be mid-loading. Falling "
                .. "back to temporal-only scoring; auto-recovery will retry "
                .. "if init verification fails.")
            filtered = scored
        end
    else
        filtered = scored
    end

    local primary = filtered[1].offset
    local alternates = {}
    -- Keep every non-primary with any non-null sample as a runtime
    -- fallback — resolveChain validates before promoting, so marginal
    -- alternates just get skipped on each null.
    for i = 2, #filtered do
        if filtered[i].nonNull > 0 then
            alternates[#alternates + 1] = filtered[i].offset
        end
    end

    -- One-shot diagnostic at discovery time. Logged per discovery only,
    -- not per tick.
    log(string.format(
        "GWorld: scored %d candidates over %dms (full-chain %s)",
        #scored, SAMPLES * INTERVAL_MS,
        hadFullChain and "ON" or "OFF (temporal-only)"))
    for i = 1, #scored do
        local s = scored[i]
        log(string.format(
            "  cand[%d] offset=0x%X depth=%d/%d nonNull=%d/%d sameVal=%d/%d everNull=%d consensus=%d/%d score=%d %s",
            i, s.offset, s.depthSum, SAMPLES * 7, s.nonNull, SAMPLES,
            s.sameValue, SAMPLES, s.everNull, s.consensus, SAMPLES, s.score,
            i == 1 and "<- PICKED" or ""))
    end
    log(string.format("GWorld: kept %d alternates as runtime fallbacks",
        #alternates))
    return { primary = primary, alternates = alternates }
end

local Orchestrator = {
    mainModule = nil,
    initialized = false,
    discoveryState = nil,
}

function Orchestrator.initialize(self)
    if self.initialized then return { success = true, cached = true } end

    log("=== UE Engine Discovery Starting ===")
    send({ type = "progress", message = "Discovering GObjects...", percent = 0 })

    local ok, err = pcall(function()
        local modules = process.enumerate_modules()
        if not modules or #modules == 0 then
            error("No modules found")
        end
        self.mainModule = modules[1]
        log("Main module: " .. tostring(self.mainModule.name)
            .. " base=0x" .. string.format("%X", self.mainModule.base)
            .. " size=0x" .. string.format("%X", self.mainModule.size))
        send({ type = "ue-engine-progress", phase = "modules", status = "found",
            detail = self.mainModule.name .. " @ " .. tostring(self.mainModule.base) })

        log("Phase 1/4: Discovering GObjects...")
        send({ type = "progress", message = "Discovering GObjects...", percent = 0 })
        if not self:_retry(function()
            return GObjectsScanner:discover(Orchestrator.mainModule)
        end, 10, 500, "GObjects") then
            error("GObjects not found")
        end

        log("Phase 2/4: Discovering GNames...")
        send({ type = "progress", message = "Discovering GNames...", percent = 25 })
        if not self:_retry(function()
            return GNamesScanner:discover(Orchestrator.mainModule)
        end, 10, 500, "GNames") then
            error("GNames not found")
        end

        log("Phase 3/4: Bootstrapping UObject layout...")
        send({ type = "progress", message = "Bootstrapping UObject layout...", percent = 40 })
        if not self:_retry(function()
            return UObjectLayout:bootstrap()
        end, 3, 1000, "UObject") then
            error("UObject layout not found")
        end

        self:_adjustBlockOffsetBits()

        log("Phase 4/4: Bootstrapping reflection...")
        send({ type = "progress", message = "Walking reflection...", percent = 42 })
        if not self:_retry(function()
            return ReflectionWalker:bootstrap()
        end, 3, 1000, "Reflection") then
            error("Reflection bootstrap failed")
        end
    end)

    if not ok then
        log("=== UE Engine Discovery FAILED: " .. tostring(err) .. " ===")
        return { success = false, error = tostring(err) }
    end

    self.initialized = true
    self:_buildDiscoveryState()
    log("=== UE Engine Discovery COMPLETE ===")
    log("  Vector precision: " .. tostring(ReflectionWalker.vectorPrecision))
    log("  Vector component size: " .. tostring(ReflectionWalker.vectorComponentSize))
    send({ type = "ue-engine-progress", phase = "complete", status = "ready" })
    return { success = true }
end

function Orchestrator._retry(self, fn, maxRetries, baseDelay, phaseName)
    local delay = baseDelay
    for attempt = 0, maxRetries - 1 do
        if fn() then return true end
        if attempt < maxRetries - 1 then
            send({ type = "ue-engine-progress", phase = phaseName, status = "retrying",
                detail = "Attempt " .. (attempt + 2) .. "/" .. maxRetries })
            MemUtil.sleep(delay)
            delay = math.min(delay * 2, 5000)
        end
    end
    return false
end

function Orchestrator._adjustBlockOffsetBits(self)
    local gn = GNamesScanner.result
    if not gn or gn.type ~= "FNamePool" then return end
    if not UObjectLayout.offsets or UObjectLayout.offsets.name < 0 then return end

    local bestBits = gn.blockOffsetBits
    local bestResolved = 0
    for bits = 14, 20 do
        local allInRange = true
        local resolved = 0
        gn.blockOffsetBits = bits
        for i = 0, 49 do
            local obj = GObjectsScanner:getByIndex(i)
            if obj then
                local compIdx = MemUtil.readS32(obj + UObjectLayout.offsets.name)
                if compIdx ~= nil and compIdx > 0 then
                    if (compIdx >> bits) > gn.currentBlock then allInRange = false; break end
                    local name = NameResolver:resolve(compIdx)
                    if name and #name > 0 and name:match("^[%a_]") then
                        resolved = resolved + 1
                    end
                end
            end
        end
        if allInRange and resolved > bestResolved then
            bestResolved = resolved
            bestBits = bits
        end
    end
    gn.blockOffsetBits = bestBits
    if bestBits ~= 16 then
        send({ type = "ue-engine-progress", phase = "gnames", status = "adjusted",
            detail = "blockOffsetBits=" .. bestBits })
    end
end

function Orchestrator._buildDiscoveryState(self)
    -- Store GNames addresses as offsets from the module base — ASLR
    -- moves the absolute address per process, but the offset is fixed.
    local modBase = self.mainModule and self.mainModule.base or 0
    local gnamesCache
    local gnRes = GNamesScanner.result
    if gnRes and gnRes.type == "FNamePool" and gnRes.allocatorAddr then
        gnamesCache = {
            type = "FNamePool",
            allocatorOffset = gnRes.allocatorAddr - modBase,
            blockOffsetBits = gnRes.blockOffsetBits or 0,
            headerShift = gnRes.headerShift,
            headerWideBit = gnRes.headerWideBit,
            stringOffset = gnRes.stringOffset,
        }
    elseif gnRes and gnRes.type == "TNameEntryArray" and gnRes.chunksAddr then
        gnamesCache = {
            type = "TNameEntryArray",
            chunksOffset = gnRes.chunksAddr - modBase,
            numChunks = gnRes.numChunks,
            elementsPerChunk = gnRes.elementsPerChunk,
            indexOffset = gnRes.indexOffset,
            stringOffset = gnRes.stringOffset,
            stride = gnRes.stride,
        }
    end

    self.discoveryState = {
        module = self.mainModule and self.mainModule.name or nil,
        gobjects = GObjectsScanner.result and {
            layout = GObjectsScanner.result.layout,
            numElements = GObjectsScanner.result.numElements,
            itemSize = GObjectsScanner.result.itemSize,
            isChunked = GObjectsScanner.result.isChunked,
        } or nil,
        gnames = gnamesCache,
        uobject = UObjectLayout.offsets,
        reflection = ReflectionWalker.offsets and {
            childProps = ReflectionWalker.offsets.childProps,
            children = ReflectionWalker.offsets.children,
            superStruct = ReflectionWalker.offsets.superStruct,
            structSize = ReflectionWalker.offsets.structSize,
            fieldNext = ReflectionWalker.fieldOffsets and ReflectionWalker.fieldOffsets.next or -1,
            fieldName = ReflectionWalker.fieldOffsets and ReflectionWalker.fieldOffsets.name or -1,
            fieldClass = ReflectionWalker.fieldOffsets and ReflectionWalker.fieldOffsets.fieldClass or -1,
            propOffsetInternal = ReflectionWalker.propOffsets and ReflectionWalker.propOffsets.offsetInternal or -1,
            useFProperty = ReflectionWalker.useFProperty,
            vectorPrecision = ReflectionWalker.vectorPrecision,
        } or nil,
    }
end

-- Builds the cached offset table: GWorld + chain to RootComponent +
-- position/rotation/camera offsets.

local TrackerConfig = {}

function TrackerConfig.build(self, mod)
    send({ type = "ue-engine-progress", phase = "config", status = "building" })
    send({ type = "progress", message = "Resolving offsets...", percent = 50 })

    local config = {
        offsets = {},
        vectorPrecision = ReflectionWalker.vectorPrecision,
        vectorSize = ReflectionWalker.vectorComponentSize,
    }
    local vecSize = ReflectionWalker.vectorComponentSize

    -- Resolve the full chain BEFORE findGWorld so each candidate is
    -- validated end-to-end. Shallow OGI-only validation was insufficient:
    -- random data can read non-null garbage, and mid-loading states have
    -- a non-null OGI but an empty LocalPlayers array.
    local ogiOffset = self:_resolvePropertyOffset("World", "OwningGameInstance")
    local lpOffset  = self:_resolvePropertyOffset("GameInstance", "LocalPlayers")
    local pcOffset  = self:_resolvePropertyOffset("Player", "PlayerController")
    local pawnOffset = self:_resolvePropertyOffset("Controller", "Pawn")
    local rootOffset = self:_resolvePropertyOffset("Actor", "RootComponent")
    local chainOffsets = {
        ogi = ogiOffset >= 0 and ogiOffset or nil,
        localPlayers = lpOffset >= 0 and lpOffset or nil,
        localPlayer = 0,  -- first entry of LocalPlayers
        playerController = pcOffset >= 0 and pcOffset or nil,
        pawn = pawnOffset >= 0 and pawnOffset or nil,
        root = rootOffset >= 0 and rootOffset or nil,
    }
    if not (chainOffsets.ogi and chainOffsets.localPlayers
        and chainOffsets.playerController and chainOffsets.pawn
        and chainOffsets.root) then
        send({ type = "ue-engine-progress", phase = "config", status = "warning",
            detail = "Some chain offsets unresolved -- GWorld picker will use "
                .. "what it has (resolved depth limited)" })
    end

    local gworldRes = ObjectFinder:findGWorld(mod, chainOffsets)
    if gworldRes == nil then
        send({ type = "ue-engine-progress", phase = "config", status = "error",
            detail = "GWorld not found" })
        return nil
    end
    -- Normalise: new shape is {primary, alternates}; legacy was bare number.
    local primary, alternates
    if type(gworldRes) == "table" then
        primary = gworldRes.primary
        alternates = gworldRes.alternates or {}
    else
        primary = gworldRes
        alternates = {}
    end
    config.offsets.GWorld = {
        offset = primary,
        type = "vtQword",
        alternates = alternates,
    }

    -- Chain: World → GameInstance → LocalPlayers → Controller → Pawn → RootComponent.
    local lookups = {
        { key = "OwningGameInstance", cls = "World", prop = "OwningGameInstance" },
        { key = "LocalPlayers", cls = "GameInstance", prop = "LocalPlayers" },
        { key = "PlayerController", cls = "Player", prop = "PlayerController" },
        { key = "Pawn", cls = "Controller", prop = "Pawn" },
        { key = "Root", cls = "Actor", prop = "RootComponent" },
    }
    for i = 1, #lookups do
        local l = lookups[i]
        local off = self:_resolvePropertyOffset(l.cls, l.prop)
        if off >= 0 then
            config.offsets[l.key] = { offset = off, type = "vtQword" }
        else
            send({ type = "ue-engine-progress", phase = "config", status = "warning",
                detail = l.key .. " not resolved (" .. l.cls .. "." .. l.prop .. ")" })
        end
    end
    config.offsets.LocalPlayer = { offset = 0x0, type = "vtQword" }

    -- Body position (world units).
    local relLocOff = self:_resolvePropertyOffset("SceneComponent", "RelativeLocation")
    if relLocOff >= 0 then
        local vtype = ReflectionWalker.vectorPrecision
        config.offsets.X = { offset = relLocOff, type = vtype }
        config.offsets.Y = { offset = relLocOff + vecSize, type = vtype }
        config.offsets.Z = { offset = relLocOff + vecSize * 2, type = vtype }
    end

    -- Body rotation (pitch/yaw/roll).
    local relRotOff = self:_resolvePropertyOffset("SceneComponent", "RelativeRotation")
    if relRotOff >= 0 then
        local vtype = ReflectionWalker.vectorPrecision
        config.offsets.RotX = { offset = relRotOff, type = vtype }
        config.offsets.RotY = { offset = relRotOff + vecSize, type = vtype }
        config.offsets.RotZ = { offset = relRotOff + vecSize * 2, type = vtype }
    end

    -- Camera/aim rotation, decoupled from body.
    local ctrlRotOff = self:_resolvePropertyOffset("Controller", "ControlRotation")
    if ctrlRotOff >= 0 then
        local vtype = ReflectionWalker.vectorPrecision
        config.offsets.Pitch = { offset = ctrlRotOff, type = vtype }
        config.offsets.Yaw = { offset = ctrlRotOff + vecSize, type = vtype }
    end

    if not config.offsets.GWorld or not config.offsets.X then
        send({ type = "ue-engine-progress", phase = "config", status = "error",
            detail = "Incomplete config" })
        return nil
    end

    local offsetCount = 0
    for _ in pairs(config.offsets) do offsetCount = offsetCount + 1 end
    send({ type = "progress", message = "Config complete (" .. offsetCount .. " offsets)", percent = 99 })
    send({ type = "ue-engine-progress", phase = "config", status = "complete",
        detail = offsetCount .. " offsets resolved" })
    return config
end

function TrackerConfig._resolvePropertyOffset(self, className, propName)
    local classObj = ObjectFinder:findObjectByName(className, "Class")
    if not classObj then classObj = ObjectFinder:findObjectByName(className, "ScriptStruct") end
    if not classObj then return -1 end
    return ReflectionWalker:findPropertyOffset(classObj, propName)
end

-- Reads position/rotation each tick by walking GWorld → ... → Root.

local PositionReader = {
    config = nil,
    cachedAddresses = {},
    lastCacheTime = 0,
    -- 0 = re-resolve every tick. The chain walk is just 7 pointer reads
    -- now that mainModuleBase is cached. Re-resolving every tick catches
    -- engine swaps of Pawn/PC immediately — caching them lets stale memory
    -- read as a frozen-then-teleport sound-stage glitch.
    CACHE_REFRESH_SECONDS = 0.0,
    -- Cached at init time. process.enumerate_modules() is heavy and used
    -- to stall hundreds of ms under Defender, blocking the recv handler.
    -- ASLR randomises per-process load, never after — so this is fixed.
    mainModuleBase = nil,

    -- Re-resolve scene name only on GWorld change (map transition).
    sceneNameCache = {
        gworld = nil,
        name = nil,
        firstReadLogged = false,
    },
}

function PositionReader.init(self, cfg)
    self.config = cfg
    self.cachedAddresses = {}
    self.lastCacheTime = 0
    self.sceneNameCache = {
        gworld = nil,
        name = nil,
        firstReadLogged = false,
    }
    -- Cache once — re-resolving per tick caused multi-second stalls
    -- under Defender.
    local modules = process.enumerate_modules()
    if modules and modules[1] and modules[1].base then
        self.mainModuleBase = modules[1].base
        log(string.format(
            "PositionReader: cached main module '%s' base=0x%X",
            tostring(modules[1].name or "?"), self.mainModuleBase
        ))
    else
        self.mainModuleBase = nil
    end
    -- Tracks which chain link is null so logs show "Pawn null 200 ticks"
    -- instead of just "no data". Cleared on successful resolveChain.
    self.chainFailLink = nil
    self.chainFailCount = 0
end

-- Cooked UPackage names sometimes carry "/Game/Maps/Foo" — the
-- user-facing map name is the last segment.
local function trim_package_path(name)
    if type(name) ~= "string" or name == "" then return name end
    local trimmed = name:match("([^/\\]+)$")
    return trimmed and trimmed ~= "" and trimmed or name
end

function PositionReader.resolveSceneName(self, gworld)
    if is_null(gworld) then return nil end
    if self.sceneNameCache.gworld == gworld and self.sceneNameCache.name then
        return self.sceneNameCache.name
    end

    -- UWorlds sometimes keep generic names ("World" / "PersistentLevel")
    -- with the real map name on the outer UPackage.
    local worldName = UObjectLayout:getObjectName(gworld)
    local outer = UObjectLayout:readOuter(gworld)
    local outerName = (outer and not is_null(outer))
        and UObjectLayout:getObjectName(outer) or nil

    -- Some cooked maps nest a Level inside the Package outer.
    local outerOuterName
    if outer and not is_null(outer) then
        local oo = UObjectLayout:readOuter(outer)
        if oo and not is_null(oo) then
            outerOuterName = UObjectLayout:getObjectName(oo)
        end
    end

    -- Most specific non-generic name; UPackage > outer > world.
    local candidates = {
        trim_package_path(outerOuterName),
        trim_package_path(outerName),
        trim_package_path(worldName),
    }
    local generic = {
        ["World"] = true, ["PersistentLevel"] = true,
        ["Transient"] = true, ["None"] = true, [""] = true,
    }
    local picked
    for _, c in ipairs(candidates) do
        if c and not generic[c] then picked = c; break end
    end
    picked = picked or trim_package_path(worldName) or "Unreal"

    if not self.sceneNameCache.firstReadLogged then
        self.sceneNameCache.firstReadLogged = true
        log(string.format("UE: scene name discovery -- world=%q outer=%q outerOuter=%q picked=%q",
            tostring(worldName), tostring(outerName),
            tostring(outerOuterName), tostring(picked)))
    elseif self.sceneNameCache.name ~= picked then
        log(string.format("UE: scene name changed: %q -> %q",
            tostring(self.sceneNameCache.name), tostring(picked)))
    end

    self.sceneNameCache.gworld = gworld
    self.sceneNameCache.name = picked
    return picked
end

function PositionReader.resolveChain(self)
    if not self.config or not self.config.offsets then return nil end

    local now = clock()
    if self.cachedAddresses.GWorld
        and (now - self.lastCacheTime) < self.CACHE_REFRESH_SECONDS then
        return self.cachedAddresses
    end

    -- Use the init-time cached base — process.enumerate_modules() per
    -- tick was the dominant cause of multi-second stalls.
    local moduleBase = self.mainModuleBase
    if not moduleBase or is_null(moduleBase) then
        self:_logChainFail("mainModuleBase")
        return nil
    end

    local offsets = self.config.offsets
    local resolved = {}

    local gwEntry = offsets.GWorld
    if not gwEntry or type(gwEntry.offset) ~= "number" then return nil end

    -- On null primary, walk alternates and promote the first working
    -- slot so subsequent reads start from a known-good location.
    local gworld = MemUtil.readPtr(moduleBase + gwEntry.offset)
    local pickedAltIdx = 0
    if is_null(gworld) and type(gwEntry.alternates) == "table" then
        for i, altOff in ipairs(gwEntry.alternates) do
            if type(altOff) == "number" then
                local v = MemUtil.readPtr(moduleBase + altOff)
                if not is_null(v) then
                    gworld = v
                    pickedAltIdx = i
                    break
                end
            end
        end
    end
    if is_null(gworld) then
        self:_logChainFail("GWorld")
        return nil
    end
    resolved.GWorld = gworld
    -- Defer the swap until the full chain walks — a non-null GWorld
    -- whose downstream chain still fails isn't a better slot.
    self._pendingPromoteAltIdx = pickedAltIdx

    local function readLink(name, parentPtr)
        local entry = offsets[name]
        if not entry or type(entry.offset) ~= "number" then return nil end
        if is_null(parentPtr) then return nil end
        local value = MemUtil.readPtr(parentPtr + entry.offset)
        if is_null(value) then return nil end
        resolved[name] = value
        return value
    end

    local ogi = readLink("OwningGameInstance", resolved.GWorld)
    if is_null(ogi) then self:_logChainFail("OwningGameInstance"); return nil end

    local lp = readLink("LocalPlayers", ogi)
    if is_null(lp) then self:_logChainFail("LocalPlayers"); return nil end

    local lplayer = readLink("LocalPlayer", lp)
    if is_null(lplayer) then self:_logChainFail("LocalPlayer"); return nil end

    local pc = readLink("PlayerController", lplayer)
    if is_null(pc) then self:_logChainFail("PlayerController"); return nil end

    local pawn = readLink("Pawn", pc)
    if is_null(pawn) then self:_logChainFail("Pawn"); return nil end

    local root = readLink("Root", pawn)
    if is_null(root) then self:_logChainFail("Root"); return nil end

    -- Log recovery so the operator sees freeze duration + holdup link.
    if self.chainFailLink then
        log(string.format(
            "PositionReader: chain recovered after %d consecutive failures on '%s'",
            self.chainFailCount or 0, self.chainFailLink
        ))
        self.chainFailLink = nil
        self.chainFailCount = 0
    end

    -- Promote a working alternate to primary; demote old primary into
    -- the alternate slot (it might come back online — keep as fallback).
    local promoteIdx = self._pendingPromoteAltIdx or 0
    if promoteIdx > 0 then
        local gwEntry = offsets.GWorld
        if gwEntry and type(gwEntry.alternates) == "table"
            and type(gwEntry.alternates[promoteIdx]) == "number" then
            local oldPrimary = gwEntry.offset
            local newPrimary = gwEntry.alternates[promoteIdx]
            gwEntry.offset = newPrimary
            gwEntry.alternates[promoteIdx] = oldPrimary
            log(string.format(
                "PositionReader: promoted GWorld alternate to primary (offset=0x%X, demoted 0x%X to alt[%d])",
                newPrimary, oldPrimary, promoteIdx
            ))
        end
        self._pendingPromoteAltIdx = 0
    end

    self.cachedAddresses = resolved
    self.lastCacheTime = now
    return resolved
end

-- First failure of each link logs immediately; same-link repeats log
-- every 60 ticks (~1s at 60Hz) to track duration without spamming.
function PositionReader._logChainFail(self, linkName)
    if self.chainFailLink ~= linkName then
        log(string.format("PositionReader: chain broke at '%s'", linkName))
        self.chainFailLink = linkName
        self.chainFailCount = 1
        return
    end
    self.chainFailCount = (self.chainFailCount or 0) + 1
    if self.chainFailCount % 60 == 0 then
        log(string.format(
            "PositionReader: still broken at '%s' (%d ticks)",
            linkName, self.chainFailCount
        ))
    end
end

-- float (UE4/early UE5) or double (UE 5.0+ LWC) per calibration.
function PositionReader.readValue(self, address, valueType)
    if valueType == "vtQword" then return MemUtil.readPtr(address) end
    if valueType == "vtDouble" then return MemUtil.readF64(address) end
    return MemUtil.readF32(address)
end

function PositionReader.read(self)
    if not self.config or not self.config.offsets then return nil end

    local addresses = self:resolveChain()
    if not addresses then return nil end
    if is_null(addresses.Root) then return nil end

    local offsets = self.config.offsets
    local vtype = self.config.vectorPrecision or "vtFloat"
    local root = addresses.Root
    local pc = addresses.PlayerController

    local posX, posY, posZ
    if offsets.X and offsets.Y and offsets.Z then
        posX = self:readValue(root + offsets.X.offset, vtype)
        posY = self:readValue(root + offsets.Y.offset, vtype)
        posZ = self:readValue(root + offsets.Z.offset, vtype)
    end
    if posX == nil or posY == nil or posZ == nil then return nil end

    local rotX, rotY, rotZ
    if offsets.RotX and offsets.RotY and offsets.RotZ then
        rotX = self:readValue(root + offsets.RotX.offset, vtype)
        rotY = self:readValue(root + offsets.RotY.offset, vtype)
        rotZ = self:readValue(root + offsets.RotZ.offset, vtype)
    end

    -- ControlRotation lives on the controller, not on root.
    local pitch, yaw
    if not is_null(pc) and offsets.Pitch and offsets.Yaw then
        pitch = self:readValue(pc + offsets.Pitch.offset, vtype)
        yaw = self:readValue(pc + offsets.Yaw.offset, vtype)
    end

    -- Best-effort. Host skips setLevel on the placeholder, so failure
    -- here doesn't affect position/rotation tracking.
    local sceneName = "Unknown"
    local ok_name, name = pcall(function()
        return self:resolveSceneName(addresses.GWorld)
    end)
    if ok_name and type(name) == "string" and name ~= "" then
        sceneName = name
    end

    return {
        type = "data",
        protocol = "unreal_tracker",
        posX = posX,
        posY = posY,
        posZ = posZ,
        rotX = rotX,
        rotY = rotY,
        rotZ = rotZ,
        pitch = pitch,
        yaw = yaw,
        fwdX = 0,
        fwdY = 0,
        fwdZ = 0,
        sceneName = sceneName,
        sceneIndex = 0,
        timestamp = clock() * 1000,
    }
end

local state = {
    initialized = false,
    config = nil,
    consecutiveErrors = 0,
    MAX_CONSECUTIVE_ERRORS = 10,

    -- Auto-recovery: when the cached chain stays broken too long (stale
    -- cache after game update is the common cause), re-run full discovery
    -- in-place without the user having to restart anything.
    chainFailFirstAtMs = 0,
    lastAutoRecoveryAtMs = 0,
    autoRecoveryInProgress = false,
}

-- Backstop trigger: long enough to let natural map transitions / death
-- cams pass without triggering a 5+ second rediscovery scan, short enough
-- that users don't stay in "searching for player" indefinitely.
local AUTO_RECOVERY_TRIGGER_MS = 4000

-- Throttle so failed recoveries don't burn CPU in a tight loop.
local AUTO_RECOVERY_COOLDOWN_MS = 30000

-- Restore the state needed for scene-name resolution from a cached
-- discoveryState. Failure here only disables scene-name tracking —
-- position/rotation still works.
local function rehydrate_scene_state(discoveryState)
    if type(discoveryState) ~= "table" then return false end

    local modules = process.enumerate_modules()
    if not modules or #modules == 0 then return false end
    local mainModule = modules[1]
    Orchestrator.mainModule = mainModule

    if type(discoveryState.uobject) == "table" then
        UObjectLayout.offsets = discoveryState.uobject
    else
        return false
    end

    -- Recompute live GNames address from offset-from-module-base.
    local gn = discoveryState.gnames
    if type(gn) ~= "table" then return false end
    if gn.type == "FNamePool" and type(gn.allocatorOffset) == "number" then
        local allocatorAddr = mainModule.base + gn.allocatorOffset
        local currentBlock = MemUtil.readS32(allocatorAddr + 0x08)
        local block0 = MemUtil.readPtr(allocatorAddr + 0x10)
        if currentBlock == nil or currentBlock < 0 or currentBlock > 1024 then
            return false
        end
        if not MemUtil.isValidPtr(block0) then return false end
        GNamesScanner.result = {
            type = "FNamePool",
            allocatorAddr = allocatorAddr,
            blocksAddr = allocatorAddr + 0x10,
            block0 = block0,
            currentBlock = currentBlock,
            blockOffsetBits = gn.blockOffsetBits or 16,
            headerShift = gn.headerShift,
            headerWideBit = gn.headerWideBit,
            stringOffset = gn.stringOffset,
        }
        return true
    elseif gn.type == "TNameEntryArray" and type(gn.chunksOffset) == "number" then
        GNamesScanner.result = {
            type = "TNameEntryArray",
            chunksAddr = mainModule.base + gn.chunksOffset,
            numChunks = gn.numChunks,
            elementsPerChunk = gn.elementsPerChunk,
            indexOffset = gn.indexOffset,
            stringOffset = gn.stringOffset,
            stride = gn.stride,
        }
        return true
    end
    return false
end

-- Two-round chain stability verification. The gap between rounds is
-- enough for transient fluke states (title-screen pseudo-pawn etc.) to
-- dissolve. Per-round bar is lenient (75%) to tolerate legitimate brief
-- blips during normal play. Returns (ok, successes, attempts, reason).
-- Total time on success: ~2.5s.
local function verify_chain_walks(progress_cb)
    local ROUNDS = 2
    local ROUND_ATTEMPTS = 40        -- ~1s at 25ms intervals
    local ATTEMPT_INTERVAL_MS = 25
    local GAP_BETWEEN_ROUNDS_MS = 500
    local MIN_PER_ROUND = 30         -- 75% per round

    local total_successes = 0
    local total_attempts = 0
    for round = 1, ROUNDS do
        if progress_cb then progress_cb(round, ROUNDS) end

        local round_successes = 0
        for attempt = 1, ROUND_ATTEMPTS do
            local ok, data = pcall(PositionReader.read, PositionReader)
            if ok and type(data) == "table" and type(data.posX) == "number" then
                round_successes = round_successes + 1
                total_successes = total_successes + 1
            end
            total_attempts = total_attempts + 1
            if attempt < ROUND_ATTEMPTS then
                MemUtil.sleep(ATTEMPT_INTERVAL_MS)
            end
        end

        if round_successes < MIN_PER_ROUND then
            return false, total_successes, total_attempts,
                string.format(
                    "round %d/%d only %d/%d reads (need %d)",
                    round, ROUNDS, round_successes, ROUND_ATTEMPTS,
                    MIN_PER_ROUND)
        end

        if round < ROUNDS then
            MemUtil.sleep(GAP_BETWEEN_ROUNDS_MS)
        end
    end

    return true, total_successes, total_attempts, nil
end

local function handle_init(data)
    -- Cached offsets skip discovery entirely.
    if type(data) == "table" and type(data.offsets) == "table" then
        state.config = data
        PositionReader:init(data)
        state.consecutiveErrors = 0

        log("UE Engine (Lua): Using provided offsets, vectorPrecision="
            .. tostring(data.vectorPrecision or "vtFloat"))
        for name, entry in pairs(data.offsets) do
            if type(entry) == "table" and type(entry.offset) == "number" then
                log(string.format("  %s: 0x%X", tostring(name), entry.offset))
            end
        end

        -- Best-effort scene-name rehydration. Never blocks position/
        -- rotation tracking.
        local ok_scene, restored = pcall(rehydrate_scene_state, data.discoveryState)
        if ok_scene and restored then
            log("UE Engine (Lua): Scene-name state restored from cache")
        else
            log("UE Engine (Lua): Scene-name state NOT in cache (older cache " ..
                "or rehydrate failed); level tracking will stay at default " ..
                "until next full discovery")
        end

        -- Cached offsets passed verification when saved, so any failure
        -- now is transient game state (menu/loading) — keep retrying
        -- instead of discarding a known-good cache. Progress messages
        -- escalate so the user knows they may need to leave the menu.
        log("UE Engine (Lua): Verifying cached chain stability (retries until player is reachable)")
        local attempt = 0
        while true do
            attempt = attempt + 1
            local stage_msg
            if attempt == 1 then
                stage_msg = "Verifying player chain..."
            elseif attempt <= 3 then
                stage_msg = string.format(
                    "Verifying player chain (retry %d). Game may be loading.",
                    attempt)
            elseif attempt <= 8 then
                stage_msg = string.format(
                    "Player chain not yet stable (retry %d). If you're in a menu, please enter a game.",
                    attempt)
            else
                stage_msg = string.format(
                    "Still waiting for stable player (retry %d). The bridge will keep trying — make sure you're in actual gameplay.",
                    attempt)
            end
            send({ type = "progress", message = stage_msg, percent = 92 })

            local attempt_ok, succ, total, reason = verify_chain_walks(
                function(round, total_rounds)
                    send({
                        type = "progress",
                        message = string.format(
                            "%s (round %d/%d)", stage_msg, round, total_rounds),
                        percent = 92 + (round / total_rounds) * 7,
                    })
                end)
            if attempt_ok then
                state.initialized = true
                log(string.format(
                    "UE Engine (Lua): Chain verified on attempt %d (%d/%d stable) — init complete",
                    attempt, succ, total))
                send({ type = "init-response", success = true })
                return
            end
            log(string.format(
                "UE Engine (Lua): Verification attempt %d failed (%s); retrying after brief pause",
                attempt, reason or "unstable"))
            MemUtil.sleep(1500)

            -- After ~5 min, try one fresh discovery as a last resort —
            -- maybe the cache really is stale (game updated, exe hash
            -- check missed).
            if attempt == 60 then
                log("UE Engine (Lua): Cached chain has failed 60 attempts (~5 min). "
                    .. "Trying fresh discovery as a last resort.")
                send({ type = "auto-recovery-started" })
                send({ type = "progress",
                    message = "Cache appears stale. Re-discovering offsets...",
                    percent = 50 })
                local result = Orchestrator:initialize()
                if result.success then
                    local config = TrackerConfig:build(Orchestrator.mainModule)
                    if config then
                        state.config = config
                        PositionReader:init(config)
                        log("UE Engine (Lua): Fresh-discovery offsets installed; resuming verification loop")
                    end
                end
                -- Never give up; loop continues regardless.
            end
        end
        -- unreachable (loop only exits via `return` on success)
    end

    -- Full discovery (no cached offsets).
    log("UE Engine (Lua): Running full discovery...")
    local result = Orchestrator:initialize()
    if not result.success then
        send({ type = "init-response", success = false, error = result.error or "discovery failed" })
        return
    end

    local config = TrackerConfig:build(Orchestrator.mainModule)
    if not config then
        send({ type = "init-response", success = false, error = "TrackerConfig build failed" })
        return
    end

    state.config = config
    PositionReader:init(config)
    state.consecutiveErrors = 0
    state.hasSentFatalError = false

    -- Verify BEFORE caching — never lock in bad offsets. Same
    -- indefinite-retry loop as the cached path.
    local fresh_attempt = 0
    while true do
        fresh_attempt = fresh_attempt + 1
        local stage_msg
        if fresh_attempt == 1 then
            stage_msg = "Verifying discovered player chain..."
        elseif fresh_attempt <= 3 then
            stage_msg = string.format(
                "Verifying player chain (retry %d). Game may be loading.",
                fresh_attempt)
        elseif fresh_attempt <= 8 then
            stage_msg = string.format(
                "Player chain not yet stable (retry %d). If you're in a menu, please enter a game.",
                fresh_attempt)
        else
            stage_msg = string.format(
                "Still waiting for stable player (retry %d). Make sure you're in actual gameplay.",
                fresh_attempt)
        end
        send({ type = "progress", message = stage_msg, percent = 92 })
        local attempt_ok, _succ, _total, _reason = verify_chain_walks(
            function(round, total_rounds)
                send({
                    type = "progress",
                    message = string.format(
                        "%s (round %d/%d)", stage_msg, round, total_rounds),
                    percent = 92 + (round / total_rounds) * 7,
                })
            end)
        if attempt_ok then
            state.initialized = true
            log("UE Engine (Lua): Fresh-discovery chain verified — caching offsets")
            send({
                type = "discovery-complete",
                offsets = config.offsets,
                vectorPrecision = config.vectorPrecision,
                vectorSize = config.vectorSize,
                discoveryState = Orchestrator.discoveryState,
            })
            send({ type = "progress", message = "Discovery complete!", percent = 100 })
            send({ type = "init-response", success = true })
            return
        end
        log(string.format(
            "UE Engine (Lua): Fresh-discovery verify attempt %d failed — retrying",
            fresh_attempt))
        MemUtil.sleep(1500)
    end
end

-- Re-run discovery and rebuild PositionReader's config in-place.
-- Blocking, multi-second; host's TICK_STALL_RESET_SECONDS tolerates it.
-- On failure, keeps the old config so the agent at least keeps trying.
local function run_auto_recovery()
    log("UE Engine (Lua): AUTO-RECOVERY: cached chain stale, re-running discovery")
    send({ type = "auto-recovery-started" })

    -- Clear one-shot guard so initialize() runs again instead of
    -- returning early.
    Orchestrator.initialized = false
    Orchestrator.discoveryState = nil
    GObjectsScanner.result = nil
    GNamesScanner.result = nil
    UObjectLayout.offsets = nil
    -- Bootstrap re-derives these; leaving them populated would short-
    -- circuit calibration sentinels.
    ReflectionWalker.offsets = nil
    ReflectionWalker.fieldOffsets = nil
    ReflectionWalker.propOffsets = nil
    ReflectionWalker.useFProperty = false
    ReflectionWalker.vectorPrecision = "vtFloat"
    ReflectionWalker.vectorComponentSize = 4
    ReflectionWalker._fieldClassOffset = -1
    ReflectionWalker._uFieldNextOffset = -1

    local result = Orchestrator:initialize()
    if not result.success then
        log("UE Engine (Lua): AUTO-RECOVERY FAILED at discovery: "
            .. tostring(result.error or "unknown"))
        send({
            type = "auto-recovery-failed",
            error = result.error or "discovery failed",
        })
        return false
    end

    local config = TrackerConfig:build(Orchestrator.mainModule)
    if not config then
        log("UE Engine (Lua): AUTO-RECOVERY FAILED at TrackerConfig:build")
        send({
            type = "auto-recovery-failed",
            error = "TrackerConfig build failed",
        })
        return false
    end

    -- Verify before caching. On failure, apply the new config in-memory
    -- but skip discovery-complete so the next attach re-discovers.
    state.config = config
    PositionReader:init(config)
    state.consecutiveErrors = 0
    state.initialized = true

    local ok_chain, succ, total, reason = verify_chain_walks(function(round, total_rounds)
        send({
            type = "progress",
            message = string.format("Verifying player chain (round %d/%d)...",
                round, total_rounds),
            percent = 92 + (round / total_rounds) * 7,
        })
    end)
    if ok_chain then
        log(string.format(
            "UE Engine (Lua): Auto-recovery chain verified (%d/%d) — caching offsets",
            succ, total))
        send({
            type = "discovery-complete",
            offsets = config.offsets,
            vectorPrecision = config.vectorPrecision,
            vectorSize = config.vectorSize,
            discoveryState = Orchestrator.discoveryState,
        })
    else
        log(string.format(
            "UE Engine (Lua): Auto-recovery chain not stable (%d/%d, %s). "
                .. "Applying offsets in-memory but NOT caching — "
                .. "another auto-recovery cycle will retry.",
            succ, total, reason or "unstable"))
    end

    send({
        type = "init-response",
        success = true,
        auto_recovered = true,
    })

    log("UE Engine (Lua): AUTO-RECOVERY COMPLETE")
    return true
end

-- Wall-clock of the agent's last tick processing — used for backlog
-- drain detection.
local _last_tick_processed_at = 0

-- Two ticks under 5ms apart can only be a drain — natural ticks at 60Hz
-- are 16.67ms apart and stall re-sends fire every 0.5s+. During a drain
-- we return cheap heartbeats so the freshest tick reaches us fast.
local _BACKLOG_DRAIN_THRESHOLD_MS = 5

local function handle_tick(message)
    if not state.initialized then
        send({ type = "heartbeat", status = "not-initialized" })
        return
    end

    -- Backlog-drain shedding: when the IPC pipe unblocks after a stall,
    -- queued ticks arrive back-to-back. Only the LAST one's data isn't
    -- stale (host coalesces anyway), so respond to intermediate ticks
    -- with a cheap heartbeat and let the final tick do the real read.
    local now_ms = clock() * 1000
    local prev = _last_tick_processed_at
    _last_tick_processed_at = now_ms
    if prev > 0 and (now_ms - prev) < _BACKLOG_DRAIN_THRESHOLD_MS then
        send({ type = "heartbeat", status = "drain-backlog" })
        return
    end

    local ok, data_or_err = pcall(function()
        return PositionReader:read()
    end)

    if not ok then
        state.consecutiveErrors = state.consecutiveErrors + 1
        if state.consecutiveErrors <= 3 or state.consecutiveErrors % 50 == 0 then
            log("UE Engine (Lua): tick error #" .. state.consecutiveErrors .. ": " .. tostring(data_or_err))
        end
    elseif type(data_or_err) == "table" then
        send(data_or_err)
        state.consecutiveErrors = 0
        -- Reset failure run so recovery timer only counts consecutive fails.
        state.chainFailFirstAtMs = 0
        return
    else
        -- Chain not ready (player not spawned, loading screen, etc.).
        state.consecutiveErrors = state.consecutiveErrors + 1
    end

    -- Trigger rediscovery once the chain has been broken longer than
    -- AUTO_RECOVERY_TRIGGER_MS, throttled by AUTO_RECOVERY_COOLDOWN_MS.
    if state.chainFailFirstAtMs == 0 then
        state.chainFailFirstAtMs = now_ms
    end
    local fail_age_ms = now_ms - state.chainFailFirstAtMs
    local since_last_attempt_ms = now_ms - state.lastAutoRecoveryAtMs
    if fail_age_ms >= AUTO_RECOVERY_TRIGGER_MS
        and since_last_attempt_ms >= AUTO_RECOVERY_COOLDOWN_MS
        and not state.autoRecoveryInProgress
    then
        state.autoRecoveryInProgress = true
        state.lastAutoRecoveryAtMs = now_ms
        local rec_ok, rec_err = pcall(run_auto_recovery)
        state.autoRecoveryInProgress = false
        if not rec_ok then
            log("UE Engine (Lua): auto-recovery raised: " .. tostring(rec_err))
        end
        -- Re-sample wall clock after the multi-second recovery. Without
        -- this, the next tick reads fail_age_ms as the recovery duration
        -- and immediately re-triggers; cooldown also needs to start from
        -- "recovery done", not "recovery started".
        local post_recovery_ms = clock() * 1000
        state.chainFailFirstAtMs = post_recovery_ms
        state.lastAutoRecoveryAtMs = post_recovery_ms
        -- Keeps backlog-drain shedding correct for the burst of ticks
        -- queued during recovery.
        _last_tick_processed_at = post_recovery_ms
    end

    send({ type = "heartbeat", status = "no-position", errors = state.consecutiveErrors })
end

-- Manager's data timer only resets on Data messages — send one before
-- any heavy work.
send({ type = "heartbeat", status = "loading" })

log("UE Engine - Lua Introspection Library")
log("Supports: UE 4.11 - UE 5.x")

send({ type = "heartbeat", status = "ready" })

local function try_decode_json(text)
    if type(text) ~= "string" then return nil end
    if type(json) == "table" and type(json.decode) == "function" then
        local ok, decoded = pcall(json.decode, text)
        if ok and type(decoded) == "table" then return decoded end
    end
    return nil
end

local function get_message_type(message)
    if type(message) == "table" then
        if type(message.type) == "string" then return message.type end
        if type(message.payload) == "table" and type(message.payload.type) == "string" then
            return message.payload.type
        end
        return nil
    end
    if type(message) == "string" then
        local decoded = try_decode_json(message)
        if type(decoded) == "table" and type(decoded.type) == "string" then
            return decoded.type
        end
        if type(decoded) == "table" and type(decoded.payload) == "table" then
            return decoded.payload.type
        end
        if string.find(message, '"type"%s*:%s*"init"') then return "init" end
        if string.find(message, '"type"%s*:%s*"tick"') then return "tick" end
        if string.find(message, '"type"%s*:%s*"shutdown"') then return "shutdown" end
    end
    return nil
end

local function extract_init_data(message)
    if type(message) == "table" then
        local data = message.data
        if type(data) ~= "table" and type(message.payload) == "table" then
            data = message.payload.data or message.payload
        end
        if type(data) == "table" and type(data.offsets) == "table" then
            return data
        end
        -- init with no offsets → fresh discovery request
        return {}
    end
    if type(message) == "string" then
        local decoded = try_decode_json(message)
        if type(decoded) == "table" then
            local data = decoded.data
            if type(data) ~= "table" and type(decoded.payload) == "table" then
                data = decoded.payload.data or decoded.payload
            end
            if type(data) == "table" and type(data.offsets) == "table" then
                return data
            end
        end
        return {}
    end
    return {}
end

local function extract_now_ms(message)
    if type(message) == "table" then
        if type(message.now_ms) == "number" then return message.now_ms end
        if type(message.payload) == "table" and type(message.payload.now_ms) == "number" then
            return message.payload.now_ms
        end
    end
    if type(message) == "string" then
        local decoded = try_decode_json(message)
        if type(decoded) == "table" then
            if type(decoded.now_ms) == "number" then return decoded.now_ms end
            if type(decoded.payload) == "table" and type(decoded.payload.now_ms) == "number" then
                return decoded.payload.now_ms
            end
        end
        local match = string.match(message, '"now_ms"%s*:%s*(%d+)')
        if match then return tonumber(match) end
    end
    return 0
end

local first_message_logged = false

recv(function(message, data)
    local msg_type = get_message_type(message)
    local ok, err = pcall(function()
        if not first_message_logged then
            first_message_logged = true
            local mt = type(message)
            if mt == "string" then
                log("recv: first message is string (" .. #message .. " bytes)")
            else
                log("recv: first message is " .. mt)
            end
        end

        if msg_type == "init" then
            local init_data = extract_init_data(message)
            handle_init(init_data)
        elseif msg_type == "tick" then
            handle_tick(message)
        elseif msg_type == "shutdown" then
            log("UE Engine (Lua): Shutdown requested")
            state.initialized = false
        end
    end)

    if not ok then
        log("UE Engine (Lua) handler crash: " .. tostring(err), "error")
        if msg_type == "init" then
            send({ type = "init-response", success = false, error = tostring(err) })
        end
    end
end)
