local gg = gg
local info = gg.getTargetInfo()
local orig = {}
local xg = {}
local versionName = info.versionName
local versionCode = info.versionCode
local gameName = info.label
local package = info.packageName
local version = info.versionName


-- gg.setRanges(gg.REGION_ANONYMOUS)
-- gg.searchNumber(";key")
-- gg.getResults(gg.getResultsCount())
-- gg.editAll(";nokey", gg.TYPE_WORD)
-- gg.clearResults()

-- gg.TYPE_DWORD ( int ) = 4
-- gg.TYPE_FLOAT ( float ) = 16
-- gg.TYPE_DOUBLE ( double ) = 64
-- gg.TYPE_BYTE ( bool ) = 1
-- gg.TYPE_QWORD ( long ) = 32

-- gg.refineNumber(999, 16) -- value + type
-- gg.getResults(99)
-- gg.clearResults()
-- gg.editAll(9999,16) -- value + type

-- setValue(0x2ff4dc4 + 0x20, 4, "~A8 MOV X19, XZR")
-- reset(0x2ff4dc4 + 0x20)

-- setHex(0x30efe28, "20 00 80 D2 C0 03 5F D6")
-- reset(0x2ff4dc4 + 0x20)

-- HexPatch("libil2cpp.so", "SVFastFinish", "GetFastFinishCost", "00 00 80 D2 C0 03 5F D6")
-- ResetHexPatch("libil2cpp.so", "SVFastFinish", "GetFastFinishCost")

----------- LIBRARY & ELF HANDLING -----------

-- returns ELF ranges count and the lib ranges
ORIG = {}
I = {}

function getLibIndices(libName)
    local libList = gg.getRangesList(libName)
    local indices = {}

    if not libList or #libList == 0 then
        gg.toast("Error: " .. libName .. " not found")
        return indices, libList
    end

    for i, v in ipairs(libList) do
        if v.state == "Xa" or v.state == "Cd" then
            local elf = {
                {address = v.start, flags = 1},
                {address = v.start + 1, flags = 1},
                {address = v.start + 2, flags = 1},
                {address = v.start + 3, flags = 1}
            }
            elf = gg.getValues(elf)

            local sig = ""
            for j = 1, 4 do
                if elf[j].value > 31 and elf[j].value < 127 then
                    sig = sig .. string.char(elf[j].value)
                else
                    sig = sig .. " "
                end
            end

            if sig:find("ELF") then
                table.insert(indices, i)
            end
        end
    end

    return indices, libList
end


function original()
    local libName = "libil2cpp.so" -- change if needed
    local indices, libList = getLibIndices(libName)
    ORIG = {}
    local xRx = 1

    if #indices == 0 then
        gg.toast("No valid ELF range found for " .. libName)
        return
    end

    for _, idx in ipairs(indices) do
        local baseAddr = libList[idx].start
        for i, v in ipairs(I) do
            for offset = 0, 12, 4 do
                ORIG[xRx] = {
                    address = baseAddr + tonumber(v) + offset,
                    flags = 4
                }
                xRx = xRx + 1
            end
        end
    end
end

----------- RESET FUNCTION -----------

function reset(off, libName)
    libName = libName or 'libil2cpp.so'
    local resetCount = 0

    local indices, libList = getLibIndices(libName)
    if #indices == 0 then
        gg.alert("ERR: No ELF ranges found to reset")
        return false
    end

    for _, index in ipairs(indices) do
        local offsetKey = off .. "_" .. index
        if orig[offsetKey] then
            gg.setValues(orig[offsetKey])   -- restore original values
            orig[offsetKey] = nil           -- clear backup if you want one-time reset
            resetCount = resetCount + 1
            gg.toast("Reset index " .. index)
            gg.sleep(200)
        end
    end

    if resetCount == 0 then
        gg.toast("⚠️ Nothing to reset for offset " .. string.format("0x%X", off))
    else
        gg.toast("[" .. resetCount .. " indices restored]")
    end

    return true
end
----------- ARM64 INJECT FUNCTION -----------

local bit = bit32

local function toHexBytes(num, bytes)
    local t = {}
    for i = 1, bytes do
        t[i] = string.format("%02X", bit.band(num, 0xFF))
        num = bit.rshift(num, 8)
    end
    return table.concat(t, " ")
end

local function genMinimalAsmHexInt64Signed(v)
    -- v expected as Lua number; we handle negatives by sign-extending 32->64
    -- (bit32 only supports 32-bit math)
    if v >= 0 then
        error("This generator currently handles negatives only")
    end

    -- 32-bit two's complement low part
    local lo32 = bit.band(v, 0xFFFFFFFF)
    local p1 = bit.band(lo32, 0xFFFF)
    local p2 = bit.band(bit.rshift(lo32, 16), 0xFFFF)

    -- sign-extension for upper 32 bits (negative → all ones)
    local p3 = 0xFFFF
    local p4 = 0xFFFF

    local movzBase = 0xD2800000 -- MOVZ X0, #imm16
    local movkBase = 0xF2800000 -- MOVK X0, #imm16, LSL #shift

    local hexInstructions, asmLines = {}, {}

    -- MOVZ for lowest 16 bits
    table.insert(hexInstructions, toHexBytes(bit.bor(movzBase, bit.lshift(p1, 5)), 4))
    table.insert(asmLines, string.format("movx0, #0x%X", p1))

    -- MOVK for upper halves with proper shift encoding: (1/2/3)<<21
    local up = {p2, p3, p4}
    for idx, part in ipairs(up) do
        local hw = bit.lshift(idx, 21)       -- 1→#16, 2→#32, 3→#48
        local instr = bit.bor(movkBase, hw, bit.lshift(part, 5))
        table.insert(hexInstructions, toHexBytes(instr, 4))
        table.insert(asmLines, string.format("movkx0, #0x%X, lsl #%d", part, idx * 16))
    end

    -- RET
    table.insert(hexInstructions, toHexBytes(0xD65F03C0, 4))
    table.insert(asmLines, "ret")

    return table.concat(asmLines, "\n"), table.concat(hexInstructions, " ")
end

function hexG(value)
    if value >= 0 then
        gg.toast("support x32 negetive value only")
        return nil
    end
    local asm, hexStr = genMinimalAsmHexInt64Signed(value)
    --print("Assembly:\n" .. asm .. "\n\nHex:\n" .. hexStr)
    return hexStr
end

-- ======================
-- DOUBLE Support
-- ======================
-- Convert double (Lua number) to IEEE-754 64-bit bits using string pack/unpack
local function doubleToBits(d)
    local packed = string.pack(">d", d)  -- big-endian double
    local b1, b2, b3, b4, b5, b6, b7, b8 = packed:byte(1,8)
    -- construct 64-bit integer from bytes
    local high = bit.bor(bit.lshift(b1, 24), bit.lshift(b2, 16), bit.lshift(b3, 8), b4)
    local low = bit.bor(bit.lshift(b5, 24), bit.lshift(b6, 16), bit.lshift(b7,8), b8)
    return high, low
end

-- Modified genMinimalAsmHex64 for separate high, low 32-bit integers
local function genMinimalAsmHex64FromHiLo(high, low)
    -- Extract 16-bit halfwords from low and high 32-bit parts
    local p = {
        bit.band(low, 0xFFFF),                   -- bits 0-15
        bit.band(bit.rshift(low, 16), 0xFFFF),  -- bits 16-31
        bit.band(high, 0xFFFF),                  -- bits 32-47
        bit.band(bit.rshift(high, 16), 0xFFFF)  -- bits 48-63
    }

    local instrs = {}
    local movzBase, movkBase = 0xD2800000, 0xF2800000

    -- MOVZ (lowest 16 bits)
    table.insert(instrs, {
        bit.bor(movzBase, bit.lshift(p[1], 5)),
        string.format("mov x0, #0x%X", p[1])
    })

    -- MOVK (upper halves if nonzero)
    local shifts = {16, 32, 48}
    for i = 2, 4 do
        if p[i] ~= 0 then
            local hw = bit.lshift(i - 1, 21)
            table.insert(instrs, {
                bit.bor(movkBase, hw, bit.lshift(p[i], 5)),
                string.format("movk x0, #0x%X, lsl #%d", p[i], shifts[i-1])
            })
        end
    end

    -- RET
    table.insert(instrs, {0xD65F03C0, "ret"})

    local asm, hex = {}, {}
    for _, ins in ipairs(instrs) do
        table.insert(asm, ins[2])
        table.insert(hex, toHexBytes(ins[1], 4))
    end

    return table.concat(asm, "\n"), table.concat(hex, " ")
end

function hexGF(f)
    local high, low = doubleToBits(f)
    local asm, hexStr = genMinimalAsmHex64FromHiLo(high, low)
    --print("Assembly:\n" .. asm .. "\n\nHex:\n" .. hexStr)
    return hexStr
end





-- Convert float to 32-bit bits
local function floatToBits(f)
    local sign = (f < 0) and 1 or 0
    if f < 0 then f = -f end
    if f ~= f then return 0x7FC00000 end
    if f == math.huge then return 0x7F800000 end
    if f == -math.huge then return 0xFF800000 end
    local m, e = math.frexp(f)
    e = e + 126
    m = (m * 2 - 1) * 0x800000
    return bit32.bor(bit32.lshift(sign, 31), bit32.lshift(e, 23), bit32.band(m, 0x7FFFFF))
end

-- Generate MOVZ/MOVK + RET instructions
local function genMovSequence(val, is64)
    local parts = {}
    if is64 then
        parts[1] = val & 0xFFFF
        parts[2] = (val >> 16) & 0xFFFF
        parts[3] = (val >> 32) & 0xFFFF
        parts[4] = (val >> 48) & 0xFFFF
    else
        parts[1] = val & 0xFFFF
        parts[2] = (val >> 16) & 0xFFFF
    end

    local seq = {}
    local reg = is64 and "X0" or "W0"

    table.insert(seq, string.format("~A8 MOV %s, #%d", reg, parts[1]))
    local shifts = {16, 32, 48}
    for i = 2, (is64 and 4 or 2) do
        if parts[i] ~= 0 then
            table.insert(seq, string.format("~A8 MOVK %s, #%d, LSL #%d", reg, parts[i], shifts[i-1]))
        end
    end
    table.insert(seq, "~A8 RET")

    return seq
end

-- Main injector (auto-saves original for reset)
function injectAssembly(offset, value, valueType, libName)
    libName = libName or 'libil2cpp.so'
    local indices, libList = getLibIndices(libName)
    local patchCount = 0

    if #indices == 0 then
        gg.alert("No valid ELF ranges found for " .. libName)
        return false
    end

    for _, index in ipairs(indices) do
        local currentLib = libList[index].start
        local addr = currentLib + offset
        local offsetKey = offset .. "_" .. index

        local seq = {}

        if type(value) == "boolean" then
            if value then
                seq = {0xD2800020, 0xD65F03C0}  -- MOV X0,#1 ; RET
            else
                seq = {0xD2800000, 0xD65F03C0}  -- MOV X0,#0 ; RET
            end
        elseif valueType == "float" then
            local bits = floatToBits(value)
            seq = genMovSequence(bits, false)
        elseif valueType == "long" then
            seq = genMovSequence(value, true)
        else -- default int
            seq = genMovSequence(value, false)
        end

        -- Backup originals if not already saved
        if not orig[offsetKey] then
            local backup = {}
            for i = 0, (#seq - 1) * 4, 4 do
                table.insert(backup, {address = addr + i, flags = 4})
            end
            orig[offsetKey] = gg.getValues(backup)
        end

        -- Build patch
        local patch = {}
        for i, ins in ipairs(seq) do
            table.insert(patch, {address = addr + (i - 1) * 4, flags = 4, value = ins})
        end
        gg.setValues(patch)

        patchCount = patchCount + 1
        gg.toast("Patched index " .. index)
        gg.sleep(300)
    end

    gg.toast("[" .. patchCount .. " indices injected]")
    return true
end

----------- USAGE EXAMPLES -----------

-- injectAssembly(0x522A24, false)    -- bool false
-- injectAssembly(0x2EB4F0, 999999999)     -- int
-- injectAssembly(0x300000, 3.14, "float")   -- float
-- injectAssembly(0x310000, 123456789123456, "long")  -- 64-bit long
-- reset(0x522A24)   -- restore original at offset

---------- PATCH FUNCTIONS -----------

function setHex(offset, hex, libName)
    libName = libName or 'libil2cpp.so'
    local indices, libList = getLibIndices(libName)
    local patchCount = 0

    if #indices == 0 then
        gg.alert("No valid ELF ranges found for " .. libName)
        return false
    end

    for _, index in ipairs(indices) do
        local currentLib = libList[index].start
        local offsetKey = offset .. "_" .. index

        gg.toast("Patching index " .. index .. "...")

        if not orig[offsetKey] then
            local backup, patch, total = {}, {}, 0
            for h in string.gmatch(hex, "%S%S") do
                local addr = currentLib + offset + total
                table.insert(backup, {address = addr, flags = gg.TYPE_BYTE})
                table.insert(patch, {address = addr, flags = gg.TYPE_BYTE, value = tonumber(h,16)})
                total = total + 1
            end
            orig[offsetKey] = gg.getValues(backup)
            gg.setValues(patch)
        else
            local patch, total = {}, 0
            for h in string.gmatch(hex, "%S%S") do
                table.insert(patch, {address = currentLib + offset + total, flags = gg.TYPE_BYTE, value = tonumber(h,16)})
                total = total + 1
            end
            gg.setValues(patch)
        end

        patchCount = patchCount + 1
        gg.sleep(300)
    end

    gg.toast("[" .. patchCount .. " indices patched]")
    return true
end

function setValue(offset, flags, value, libName)
    libName = libName or 'libil2cpp.so'
    local indices, libList = getLibIndices(libName)
    local setCount = 0

    if #indices == 0 then
        gg.alert("No valid ELF ranges found for " .. libName)
        return false
    end

    for _, index in ipairs(indices) do
        local currentLib = libList[index].start
        local addr = currentLib + offset
        local offsetKey = offset .. "_" .. index

        gg.toast("Setting value at index " .. index .. "...")

        if not orig[offsetKey] then
            orig[offsetKey] = gg.getValues({{address = addr, flags = flags}})
        end
        gg.setValues({{address = addr, flags = flags, value = value}})

        setCount = setCount + 1
        gg.sleep(300)
    end

    gg.toast("Set values at " .. setCount .. " indices")
    return true
end


function call_void(cc, ref, g, libName)
    libName = libName or 'libil2cpp.so'
    local indices, libList = getLibIndices(libName)
    local callCount = 0
    
    if #indices == 0 then
        gg.alert("No valid indices found for " .. libName)
        return false
    end
    
    for _, index in ipairs(indices) do
        local currentLib = libList[index].start
        
        gg.toast("Applying call_void at index " .. index .. "...")
        
        local p = {}
        p[1] = {address = currentLib + cc, flags = gg.TYPE_DWORD}
        gg.addListItems(p)
        gg.loadResults(p)
        local current_hook = gg.getResults(1)
        
        if not xg[g] then xg[g] = {} end
        if not xg[g][index] then
            gg.loadResults(current_hook)
            xg[g][index] = gg.getResults(gg.getResultsCount())
        end
        gg.clearResults()
        
        local a = currentLib + ref
        local b = currentLib + cc
        local aaaa = a - b
        
        local editVal
        if tonumber(aaaa) < 0 then 
            editVal = ISAOffsetNeg(a, b) 
        else 
            editVal = ISAOffset(aaaa) 
        end
        
        p[1] = {address = currentLib + cc, flags = gg.TYPE_DWORD, value = editVal, freeze = true}
        gg.addListItems(p)
        gg.clearList()
        
        callCount = callCount + 1
        gg.sleep(300)
    end
    
    gg.toast("Applied call_void at " .. callCount .. " indices")
    return true
end

function endhook(cc, g, libName)
    libName = libName or 'libil2cpp.so'
    local indices, libList = getLibIndices(libName)
    local resetCount = 0
    
    if not xg[g] then
        gg.alert("No hooks to reset for group " .. g)
        return false
    end
    
    for index, value in pairs(xg[g]) do
        if libList and libList[index] then
            local currentLib = libList[index].start
            local eh = {}
            eh[1] = {address = currentLib + cc, flags = gg.TYPE_DWORD, value = value[1].value, freeze = true}
            gg.addListItems(eh)
            gg.clearList()
            
            gg.toast("Reset hook at index " .. index)
            resetCount = resetCount + 1
            gg.sleep(300)
        end
    end
    
    if resetCount > 0 then
        gg.toast("Reset " .. resetCount .. " hooks")
    else
        gg.alert("No hooks were reset")
    end
    return true
end

function ISAOffset(aaaa)
    local xHEX = string.format("%X", aaaa)
    if #xHEX > 8 then xHEX = xHEX:sub(#xHEX - 7) end
    return "~A8 B [PC,#0x" .. xHEX .. "]"
end

function ISAOffsetNeg(a, b)
    local xHEX = string.format("%X", b - a)
    if #xHEX > 8 then xHEX = xHEX:sub(#xHEX - 7) end
    return "~A8 B [PC,#-0x" .. xHEX .. "]"
end


local gg = gg;
local ti = gg.getTargetInfo();
local arch = ti.x64;
local p_size = arch and 8 or 4;
local p_type = arch and 32 or 4;

-- helper count
local count = function()
    return gg.getResultsCount();
end;

-- read value
local getvalue = function(address, flags)
    return gg.getValues({{address = address, flags = flags}})[1].value;
end;

-- pointer deref
local ptr = function(address)
    return getvalue(address, p_type);
end;

-- check C-style string at address
local CString = function(address, str)
    local bytes = gg.bytes(str);
    for i = 1, #bytes do
        if (getvalue(address + (i - 1), 1) & 0xFF ~= bytes[i]) then
            return false;
        end;
    end;
    return getvalue(address + #bytes, 1) == 0;
end;

-- Hex patch with ELF index
local savedPatches = {}

function HexPatch(lib, class, method, newHex)
    local results = gg.getRangesList(lib)
    if #results == 0 then
        return false
    end

    local base = results[1].start
    local endAddr = results[1]["end"]

    -- Search for method
    gg.clearResults()
    gg.searchNumber(string.format("Q 00 '%s' 00", method), gg.TYPE_BYTE, false, gg.SIGN_EQUAL, base, endAddr)
    local res = gg.getResults(1)
    if #res == 0 then
        return false
    end

    local addr = res[1].address

    -- Save original bytes if not already saved
    local key = lib .. ":" .. class .. ":" .. method
    if not savedPatches[key] then
        savedPatches[key] = gg.getValues({{address = addr, flags = gg.TYPE_QWORD}})
    end

    -- Write new hex
    local bytes = {}
    local hex = {}
    for b in string.gmatch(newHex, "%S+") do
        table.insert(hex, tonumber(b, 16))
    end
    for i, v in ipairs(hex) do
        bytes[#bytes+1] = {address = addr + (i-1), flags = gg.TYPE_BYTE, value = v}
    end
    gg.setValues(bytes)
    return true
end

function ResetHexPatch(lib, class, method)
    local key = lib .. ":" .. class .. ":" .. method
    if savedPatches[key] then
        gg.setValues(savedPatches[key])
        savedPatches[key] = nil
        return true
    end
    return false
end
gg.clearResults()
--========================
-- GameGuardian Helper Script
--========================

-- Clear all results
function clearAll()
    gg.getResults(gg.getResultsCount())
    gg.clearResults()
end

-- Get all results
function getAll()
    gg.getResults(gg.getResultsCount())
end

-- Search number
function searchNum()
    gg.getResults(gg.getResultsCount())
    gg.clearResults()
    gg.searchNumber(x, t)
end

-- Refine search
function refineNum()
    gg.refineNumber(x, t)
end

-- Refine not equal
function refineNot()
    gg.refineNumber(x, t, false, gg.SIGN_NOT_EQUAL)
end

-- Edit all results
function editAll()
    gg.getResults(gg.getResultsCount())
    gg.editAll(x, t)
end

-- Set header for search
function setHeader()
    header = gg.getResults(1)
    gg.getResults(gg.getResultsCount())
    gg.clearResults()
    gg.searchNumber(tostring(header[1].value), t)
end

-- Repeat header search
function repeatHeader()
    gg.getResults(gg.getResultsCount())
    gg.clearResults()
    gg.searchNumber(tostring(header[1].value), t)
    gg.getResults(gg.getResultsCount())
end

-- Get header value
function getHeader()
    gg.getResults(gg.getResultsCount())
    header = gg.getResults(1)
end

-- Edit using header
function editHeader()
    gg.editAll(tostring(header[1].value), t)
end

-- Check results
function checkResults()
    local cnt = gg.getResultsCount()
    E = (cnt == 0) and 0 or 1
end

-- Apply offset
function applyOffset()
    local off = tonumber(o)
    local res = gg.getResults(gg.getResultsCount())
    for i, v in ipairs(res) do
        res[i].address = res[i].address + off
        res[i].flags = t
    end
    gg.loadResults(res)
end

-- Apply offset and edit value
function offsetEdit()
    local off = tonumber(o)
    local res = gg.getResults(gg.getResultsCount())
    for i, v in ipairs(res) do
        res[i].address = res[i].address + off
        res[i].flags = t
        res[i].value = header[1].value
    end
    gg.setValues(res)
end

-- Freeze values
function freezeValues()
    local res = gg.getResults(gg.getResultsCount())
    for i, v in ipairs(res) do
        res[i].freeze = true
    end
    gg.addListItems(res)
end

function freeze()
    frz = nil
    frz = gg.getResults(gg.getResultsCount())
    gg.addListItems(frz)
end

-- Cancel operation
function cancel()
    gg.toast("CANCELLED")
end

-- Wait toast
function waitMsg()
    gg.toast("Please Wait..")
end

-- Search pointer
function searchPtr()
    gg.searchPointer(0)
end

-- Check string pointer
function checkString()
    local off = tonumber(o)
    local results = gg.getResults(gg.getResultsCount())
    local addrs, vals = {}, {}

    for i, v in ipairs(results) do
        local ptr = {{address = v.value + off, flags = gg.TYPE_DWORD}}
        local val = gg.getValues(ptr)
        table.insert(addrs, v.address)
        table.insert(vals, val[1].value)
    end

    local matches = {}
    for i, val in ipairs(vals) do
        if val == sv then table.insert(matches, addrs[i]) end
    end

    if #matches > 0 then
        local res = {}
        for i, addr in ipairs(matches) do
            table.insert(res, {address = addr, flags = t})
        end
        gg.loadResults(res)
    else
        gg.alert("No matching addresses found")
        gg.clearResults()
        os.exit()
    end
end

function script()
    y3 = gg.getListItems()
    gg.setRanges(gg.REGION_ANONYMOUS)

    x = y1
    t = 32
    searchNum()
    checkResults()
    if E == 0 then
        gg.alert("Error : Meoww Happened")
        return nil
    end

    o = 0x4
    t = 4
    applyOffset()

    x = -1
    t = 4
    refineNum()
    checkResults()
    if E == 0 then
        gg.alert("Error : Meoww Happened")
        return nil
    end

    o = 0x4
    t = 4
    applyOffset()
    r1 = gg.getResults(1)
    x1 = r1[1].value

    o = 0x4
    t = 4
    applyOffset()
    r2 = gg.getResults(1)
    x2 = r2[1].value

    clearAll()
    gg.loadResults(y3)

    x = x1
    t = 4
    editAll()

    o = 0x4
    t = 4
    applyOffset()

    x = x2
    t = 4
    editAll()

    o = 0x4
    t = 4
    applyOffset()

    x = pv1
    t = 4
    editAll()

    clearAll()
    gg.alert("FINISH")
end

function scripNew()
    local y3 = gg.getListItems()
    gg.setRanges(gg.REGION_ANONYMOUS)

    x = y1; t = 4; searchNum()
    checkResults()
    if E == 0 then
        gg.alert("Error : Meoww Happened [1]")
        return nil
    end
    o = 0x4; t = 4; applyOffset()
    
    x = y2; t = 4; refineNum()
    checkResults()
    if E == 0 then
        gg.alert("Error : Meoww Happened [2]")
        return nil
    end
    o = 0x4; t = 4; applyOffset()

    local r1 = gg.getResults(1)
    local x1 = r1[1].value
    o = 0x4; t = 4; applyOffset()

    local r2 = gg.getResults(1)
    local x2 = r2[1].value
    clearAll()

    gg.loadResults(y3)

    x = x1; t = 4; editAll()
    o = 0x4; t = 4; applyOffset()

    x = x2; t = 4; editAll()
    o = 0x4; t = 4; applyOffset()

    x = pv1; t = 4; editAll()
    clearAll()

    gg.alert("FINISH")
end
--========================
-- Class/Pointer Finder
--========================
function findClass()
    gg.clearResults()
    gg.setRanges(gg.REGION_C_ALLOC | gg.REGION_OTHER)
    
    gg.searchNumber(":"..x, 1)
    if gg.getResultsCount() == 0 then E = 0 return end

    local res = gg.getResults(1)
    gg.getResults(gg.getResultsCount())
    gg.refineNumber(tonumber(res[1].value), 1)

    local results = gg.getResults(gg.getResultsCount())
    gg.clearResults()
    for i, v in ipairs(results) do
        results[i].address = results[i].address - 1
        results[i].flags = 1
    end

    results = gg.getValues(results)
    local zeroAddrs = {}
    for i, v in ipairs(results) do
        if v.value == 0 then table.insert(zeroAddrs, {address=v.address, flags=1}) end
    end
    if #zeroAddrs == 0 then gg.clearResults() E = 0 return end

    for i, v in ipairs(zeroAddrs) do
        zeroAddrs[i].address = zeroAddrs[i].address + #x + 1
    end

    zeroAddrs = gg.getValues(zeroAddrs)
    local finalAddrs = {}
    for i, v in ipairs(zeroAddrs) do
        if v.value == 0 then table.insert(finalAddrs, {address=v.address - #x, flags=1}) end
    end
    if #finalAddrs == 0 then gg.clearResults() E = 0 return end

    gg.loadResults(finalAddrs)

    -- Check memory region
    local memRange = gg.getResults(gg.getResultsCount())
    local hasC, hasO = false, false
    for i, v in ipairs(memRange) do
        local r = gg.getValuesRange(v)
        if r.address == "Ca" then hasC = true end
        if r.address == "O" then hasO = true end
    end
    if (hasC and not hasO) or (not hasC and hasO) then
        gg.setRanges(gg.REGION_C_ALLOC | gg.REGION_OTHER | gg.REGION_ANONYMOUS)
    end

    local fix = gg.getResults(gg.getResultsCount())
    gg.clearResults()
    gg.loadResults(fix)

    -- Pointer search
    gg.searchPointer(0)
    if gg.getResultsCount() == 0 then E = 0 return end
    local ptrs = gg.getResults(gg.getResultsCount())
    gg.clearResults()

    local off1, off2, vt = 0, 0, 0
    if gg.getTargetInfo().x64 then off1, off2, vt = 48, 56, 32 else off1, off2, vt = 24, 28, 4 end

    local errorFlag = 0
    local matched = {}
    ::TRYAGAIN::
    local vals1, vals2 = {}, {}
    for i, v in ipairs(ptrs) do
        table.insert(vals1, {address=v.address+off1, flags=vt})
        table.insert(vals2, {address=v.address+off2, flags=vt})
    end
    vals1 = gg.getValues(vals1)
    vals2 = gg.getValues(vals2)

    matched = {}
    for i, v in ipairs(vals1) do
        if vals1[i].value == vals2[i].value and #(tostring(vals1[i].value)) >= 8 then
            table.insert(matched, vals1[i].value)
        end
    end

    if #matched == 0 and errorFlag == 0 then
        if gg.getTargetInfo().x64 then off1, off2 = 32, 40 else off1, off2 = 16, 20 end
        errorFlag = 2
        goto TRYAGAIN
    end
    if #matched == 0 and errorFlag == 2 then E = 0 return end

    gg.setRanges(gg.REGION_ANONYMOUS)
    gg.clearResults()

    for i, v in ipairs(matched) do
        gg.searchNumber(tonumber(v), vt)
        if gg.getResultsCount() ~= 0 then
            local tmp = gg.getResults(gg.getResultsCount())
            gg.clearResults()
            for j = 1, #tmp do tmp[j].name = "Cheatcode" end
            gg.addListItems(tmp)
        end
        gg.clearResults()
    end

    -- Load and offset
    local finalLoad, finalRemove = {}, {}
    local list = gg.getListItems()
    local idx = 1
    for i, v in ipairs(list) do
        if v.name == "Cheatcode" then
            finalLoad[idx] = {address=v.address+o, flags=t}
            finalRemove[idx] = v
            idx = idx + 1
        end
    end
    finalLoad = gg.getValues(finalLoad)
    gg.loadResults(finalLoad)
    gg.removeListItems(finalRemove)
end



gg.setVisible(false)
gg.alert(
    "────୨ৎ────────୨ৎ────\n" ..
    "🌹 MANAV PREMIUM SCRIPT\n" ..
    "✨ Script By: CheatCode Revolution\n" ..
    "📱 Telegram: @BadLuck_69\n" ..
    "🎮 YouTube: CheatCode Revolution\n" ..
    "────୨ৎ────────୨ৎ────\n\n" ..
    "🕹️ : " .. gameName .. "\n" ..
    "📦 : " .. package .. "\n" ..
    "🔖 : " .. version
)

----------- OFFSET LIST ----------------
local offsets = {
    ["28.2.169"] = {
        Remove = 0x3151B78, -- SVInventory::Remove
        CanExpandWithCoins = 0x31FEC10, -- LandExpansionManager::CanExpandWithCoins
        GetItemCost = 0x31E1610, -- ItemManager::GetItemCost
        GetFastFinishCost = 0x34B7B48, -- SVFastFinish::GetFastFinishCost
        CalculateBuyThroughCost = 0x28267AC, -- MerchantOfferCell::CalculateBuyThroughCost
        GetCraftingTimeMultiplierForBuildingLevel = 0x2978764, -- UpgradeableBuilding::GetCraftingTimeMultiplierForBuildingLevel
        get_KnightRequestIntervalSeconds = 0x2D97A58, -- AllianceKnightsManager::get_KnightRequestIntervalSeconds
        get_HandsToSend = 0x2D9D8A0, -- AllianceManager::get_HandsToSend
        CreateOffer = 0x365E090, -- SeafarerManager::CreateOffer
        get_getAmountHas = 0x25FE744, -- CoopOrderCard_ViewModel::get_getAmountHas
        get_getAmountRequired = 0x25FE8E4, -- CoopOrderCard_ViewModel::get_getAmountRequired
        GetAutoBuyTime = 0x3651014, -- SeafarerManager::GetAutoBuyTime
        GetCountyFairPointsMultiplierForBuildingLevel = 0x297C7D4, -- UpgradeableBuilding::GetCountyFairPointsMultiplierForBuildingLevel
        StartCrafting = 0x29CC844, -- WorkshopManager::StartCrafting
        GetNumCoopOnlySlotsInUse = 0x3654C68, -- SeafarerManager::GetNumCoopOnlySlotsInUse
        canShowThanksGivingStickers = 0x307027C, -- GameExpression::canShowThanksGivingStickers
        canShowChristmasStickers = 0x30703B8, -- GameExpression::canShowChristmasStickers
        CanPlayForFree = 0x3771E00, -- GameOfChanceGame::CanPlayForFree
        get_totalItemsCount = 0x3509628, -- ProtoStorageLevel::get_totalItemsCount
        get_IsCheaterFixOn = 0x370B574, -- BoatRaceV4Context::get_IsCheaterFixOn
        get_CheaterTrackingEnabled = 0x36FF3D0, -- BoatRaceV4Context::get_CheaterTrackingEnabled
        set_CheaterTrackingEnabled = 0x36FF3D8, -- BoatRaceV4Context::set_CheaterTrackingEnabled
        CheaterFixedScore = 0x370BB60, -- BoatRaceV4Context::CheaterFixedScore
        get_Suspended = 0x2CBB3E4, -- ZyngaUsersession::get_Suspended
        set_Suspended = 0x2CBB3EC, -- ZyngaUsersession::set_Suspended
        Start = 0x29E030C, -- ZyngaPlayerSuspensionManager::Start
        get_amount = 0x3270E7C, -- ProtoQuestReward::get_amount
        get_GetCurrentLeaguePersonalQuota = 0x36D3788, -- BoatRaceLeagueManager::get_GetCurrentLeaguePersonalQuota
        get_personalQuotaCompleted = 0x2B88C08, -- BaseBoatRaceContext::get_personalQuotaCompleted
        get_GetBonusTaskSkipPrice = 0x25E824C, -- BoatRace_TaskTabViewModel::get_GetBonusTaskSkipPrice
        getAmount = 0x3271F00, -- ProtoQuestTask::getAmount
        set_MyWeeklyContribution = 0x3734C48, -- CoopOrderHelpContext::set_MyWeeklyContribution
        get_inventoryTokens = 0x2E3FA94, -- BattlePassManager::get_inventoryTokens
        isEntityObstructed = 0x2F0C258, -- EntityPlacementController::isEntityObstructed
        get_IsAvailable = 0x31A0018, -- HeroBehavior::get_IsAvailable
        OnTamperDetected = 0x3279D74, -- SecureVarInt::OnTamperDetected
        get_isCoopOrderExpired = 0x25FECD8, --CoopOrderCard_ViewModel::get_isCoopOrderExpired
        CurrentUnix = 0x344CB50, --PartnerAnimalTime::CurrentUnix
        get_bonusTaskCount = 0x2B88BC8,--Game.StateMachine.Machines.BaseBoatRace.BaseBoatRaceContext::get_bonusTaskCount
        get_SpinLeft = 0x36770AC, --SocialDailyBonusManager::get_SpinLeft
    },
    -- ["1.2.4"] = {
    --     Remove = 0x40AFE28,
    --     CanExpandWithCoins = 0x41853B8
    -- },
}




local version = gg.getTargetInfo().versionName
local currentOffset = offsets[version]
if not currentOffset then
  gg.alert("🤷 Game version is too old or not supported!\n🔖 Current Version: " .. version, "","")
  os.exit()
end

gg.toast("Bypass Is Running Please Waite...!!")
setValue(currentOffset.Start, 4, "~A8 RET")
setValue(currentOffset.get_Suspended, 4, "~A8 RET")
setValue(currentOffset.set_Suspended, 4, "~A8 RET")
setValue(currentOffset.get_IsCheaterFixOn, 4, "~A8 RET") 
setValue(currentOffset.get_CheaterTrackingEnabled, 4, "~A8 RET")
setValue(currentOffset.set_CheaterTrackingEnabled, 4, "~A8 RET")
setValue(currentOffset.CheaterFixedScore, 4, "~A8 RET")
setValue(currentOffset.OnTamperDetected, 4, "~A8 RET")

x = "BoatRaceV4Context" 
o = 0x18A --<CheaterTrackingEnabled>k__BackingField
t = 1 
findClass()

local count = gg.getResultsCount()
if count == 0 then
    gg.toast("💥")
else
    x = 1 
    t = 1 
    refineNum()

    local count2 = gg.getResultsCount()
    if count2 == 0 then
        gg.toast("💥")
    else
        x = 0 
        t = 1 
        editAll()
    end
    clearAll()
end
  

function Translate(InputText, SystemLangCode, TargetLangCode)
  _ = InputText __ = SystemLangCode ___ = TargetLangCode
  _ = InputText:gsub("\n", "\r\n")
  _ = _:gsub("([^%w])", function(c) return string.format("%%%02X", string.byte(c)) end)
  _ = _:gsub(" ", "%%20")

  Data = gg.makeRequest("https://translate.googleapis.com/translate_a/single?client=gtx&sl="..__.."&tl="..___.."&dt=t&q=".._, 
    {['User-Agent']="Mozilla/5.0"}).content

  if Data == nil then 
    return InputText -- fallback to original text if translation fails
  end

  tData = {} 
  for _ in Data:gmatch("\"(.-)\"") do 
    tData[#tData + 1] = _ 
  end
  return tData[1] or InputText
end

-- 🌐 Language Options
langtable = {
    {"English","en"},
    {"Español","es"},
    {"Türkçe","tr"},
    {"Português","pt"},
    {"Italiano","it"},
    {"Русский","ru"}
}

-- 🌐 Show language selection once at startup
gg.setVisible(false)
local langChoice = gg.choice(
    {
    "🇬🇧 English", 
    "🇪🇸 Español", 
    "🇹🇷 Türkçe", 
    "🇵🇹 Português", 
    "🇮🇹 Italiano", 
    "🇷🇺 Русский"
}, nil, "- SELECT YOUR LANGUAGE -\n_______________________________" )

if not langChoice then os.exit() end
local TargetLang = langtable[langChoice][2]

----------- PATCH METHODS -----------

function Remove_ON()
    injectAssembly(currentOffset.Remove, true)
    gg.toast("- Hack Enabled -")
    return true
end

function Remove_OFF()
    reset(currentOffset.Remove)
    gg.toast("- Hack Disabled -")
    return nil
end
----------------

function CanExpandWithCoins_ON()
    setHex(currentOffset.CanExpandWithCoins, "20 00 80 D2 C0 03 5F D6")
    gg.toast("- Hack Enabled -")
    return true
end

function CanExpandWithCoins_OFF()
    setHex(currentOffset.CanExpandWithCoins, "00 00 80 D2 C0 03 5F D6")
    gg.toast("- Hack Disabled -")
    return nil
end
----------------

function ItemCost_ON()
    injectAssembly(currentOffset.GetItemCost, false)
    injectAssembly(currentOffset.GetFastFinishCost, false)
    injectAssembly(currentOffset.CalculateBuyThroughCost, false)
    return true
end

function ItemCost_OFF()
    reset(currentOffset.GetItemCost)
    reset(currentOffset.GetFastFinishCost)
    reset(currentOffset.CalculateBuyThroughCost)
    gg.toast("- Hack Disabled -")
    return nil
end
----------------

function FFC_ON()
    setHex(currentOffset.GetCraftingTimeMultiplierForBuildingLevel, "00 00 80 D2 C0 03 5F D6")
    gg.toast("- Hack Enabled -")
    return true
end
function FFC_OFF()
    reset(currentOffset.GetCraftingTimeMultiplierForBuildingLevel)
    gg.toast("- Hack Disabled -")
    return nil
end
----------------

function FHND_ON()
    setHex(currentOffset.get_KnightRequestIntervalSeconds, "00 00 80 D2 C0 03 5F D6")
    gg.toast("- Hack Enabled -")
    return true
end
function FHND_OFF()
    reset(currentOffset.get_KnightRequestIntervalSeconds)
    gg.toast("- Hack Disabled -")
    return nil
end
----------------

function SHND_ON()
    setHex(currentOffset.get_HandsToSend, "E0 E1 84 D2 C0 03 5F D6")
    gg.toast("- Hack Enabled -")
    return true
end
function SHND_OFF()
    reset(currentOffset.get_HandsToSend)
    gg.toast("- Hack Disabled -")
    return nil
end
----------------

function SG_ON()
    setValue(currentOffset.CreateOffer+0x34, 4, "~A8 MOV W22, WZR")
    gg.toast("- Hack Enabled -")
    return true
end
function SG_OFF()
    reset(currentOffset.CreateOffer+0x34)
    gg.toast("- Hack Disabled -")
    return nil
end
----------------

function QuestBookFastFinish_ON()
    setHex(currentOffset.getAmount, "00 00 80 D2 C0 03 5F D6")
    gg.toast("- Quest Book Fast Finish Enabled -")
    return true
end

function QuestBookFastFinish_OFF()
    reset(currentOffset.getAmount)
    gg.toast("- Quest Book Fast Finish Disabled -")
    return nil
end

function MariesOrdersAskButton_ON()
    setHex(currentOffset.get_getAmountHas, "00 00 80 D2 C0 03 5F D6")
    gg.toast("- Maries Orders Ask Button Enabled -")
    return true
end

function MariesOrdersAskButton_OFF()
    reset(currentOffset.get_getAmountHas)
    gg.toast("- Maries Orders Ask Button Disabled -")
    return nil
end

function MariesOrdersSellActive_ON()
    setHex(currentOffset.get_getAmountRequired, "00 00 80 D2 C0 03 5F D6")
    gg.toast("- Maries Orders Sell Active Enabled -")
    return true
end

function MariesOrdersSellActive_OFF()
    reset(currentOffset.get_getAmountRequired)
    gg.toast("- Maries Orders Sell Active Disabled -")
    return nil
end

function AutoBuyMarket_ON()
    setHex(currentOffset.GetAutoBuyTime, "20 00 80 D2 C0 03 5F D6")
    gg.toast("- Auto Buy (Market) Enabled -")
    return true
end

function AutoBuyMarket_OFF()
    reset(currentOffset.GetAutoBuyTime)
    gg.toast("- Auto Buy (Market) Disabled -")
    return nil
end


function GetCountyFairPointsMultiplierForBuildingLevel_ON()
    I[1] = currentOffset.GetCountyFairPointsMultiplierForBuildingLevel
    original()
    gg.loadResults(ORIG)
    gg.setVisible(false)

    -- Perform the refine search with original known pattern
    local get_ = "-65073176;-117438466;822084671;1409286209"
    x = get_
    t = 4
    refineNum()

    -- Check if results found
    checkResults()
    if E == 0 then
        gg.alert("Error: Something went wrong during search")
        return
    end

    -- Save original values for restore (turning hack OFF)
    Rvrt = gg.getResults(gg.getResultsCount())

    -- Selection menu for multiplier
    local multiplier = {"[1] 50", "[2] 100", "[3] 1000", "[4] 10000", "[5] 100000"}
    local menu4 = gg.choice(multiplier)
    if not menu4 then gg.clearResults() return end

    local edv1 = nil
    if menu4 == 1 then
        edv1 = "1384775680;1923676256;505872384;hC0035FD6"
    elseif menu4 == 2 then
        edv1 = "1384120320;1923631360;505872384;hC0035FD6"
    elseif menu4 == 3 then
        edv1 = "1384120320;1923649344;505872384;hC0035FD6"
    elseif menu4 == 4 then
        edv1 = "1384644608;1923662720;505872384;hC0035FD6"
    elseif menu4 == 5 then
        edv1 = "1384775680;1923676256;505872384;hC0035FD6"
    end

    if edv1 then
        x = edv1
        t = 4
        editAll()
        gg.clearResults()
        gg.toast("Country Fair Workshop Multiplier ON: " .. multiplier[menu4])
    end
  return true
end

function GetCountyFairPointsMultiplierForBuildingLevel_OFF()
   reset(currentOffset.GetCountyFairPointsMultiplierForBuildingLevel)
   gg.toast('Country Fair Workshop Multiplier OFF')
   return nil
end


function WorkshopsCraftingAmount_ON()
    ::SELECT::
    local pr1 = gg.prompt({'Input Amount (1~65535)'}, nil, {[1] = 'number'})
    if pr1 == nil then return end
    if tostring(pr1[1]) == "" then return end
    if type(tonumber(pr1[1])) ~= "number" then
        gg.alert("INPUT VALUE")
        return
    end
    if tonumber(pr1[1]) < 1 or tonumber(pr1[1]) > 65535 then
        gg.alert("INPUT VALUE 1~65535")
        return
    end

    local pv1 = tonumber(pr1[1])
    local y1 = 65536
    local mth1 = pv1 / y1
    local mth2 = math.floor(mth1) * y1
    local mth3 = pv1 - mth2
    local x2 = string.format("%X", mth3)
    local edv1 = "~A8 MOV W22, #0x" .. x2

    -- Set the offset for the hack (replace 0x29CC844+0x38 with actual offset if needed)
    I[1] = currentOffset.WorkshopsCraftingAmount+0x38

    original()
    gg.loadResults(ORIG)

    -- Search and refine to find the target instruction to patch
    local sv1 = 704840694
    x = sv1
    t = 4
    refineNum()

    checkResults()
    if E == 0 then
        gg.alert("Error: Could not find the pattern to patch")
        return
    end

    -- Save original results to RVT8 for restoring later
    RVT8 = gg.getResults(gg.getResultsCount())

    -- Patch all results with the constructed hex command
    x = edv1
    t = 4
    editAll()

    gg.clearResults()
    gg.toast("Workshops Crafting Amount ON")
    return true
end

function WorkshopsCraftingAmount_OFF()
    if RVT8 then
        gg.setValues(RVT8)
        gg.toast("Workshops Crafting Amount OFF")
        return nil
    else
        gg.alert("No original values found to restore")
        return true
    end
end

function CoopSlots8_ON()
    setHex(currentOffset.GetNumCoopOnlySlotsInUse, "00 00 80 D2 C0 03 5F D6")
    gg.toast("- Enable 8 Co-op slots Enabled -")
    return true
end

function CoopSlots8_OFF()
    reset(currentOffset.GetNumCoopOnlySlotsInUse)
    gg.toast("- Enable 8 Co-op slots Disabled -")
    return nil
end

function UnlockChatEmoji_ON()
    setValue(currentOffset.canShowThanksGivingStickers+0x20, 4, "~A8 MOV X19, XZR")
    setValue(currentOffset.canShowChristmasStickers+0x20, 4, "~A8 MOV X19, XZR")
    gg.toast("- Unlock Chat Emoji Enabled -")
    return true
end

function UnlockChatEmoji_OFF()
    reset(currentOffset.canShowThanksGivingStickers+0x20)
    reset(currentOffset.canShowChristmasStickers+0x20)
    gg.toast("- Unlock Chat Emoji Disabled -")
    return nil
end


function ProspectorCornerFreePlay_ON()
    setHex(currentOffset.CanPlayForFree, "20 00 80 D2 C0 03 5F D6")
    gg.toast("- PORSPECTOR CORNER FREE PLAY Enabled -")
    return true
end

function ProspectorCornerFreePlay_OFF()
    reset(currentOffset.CanPlayForFree)
    gg.toast("- PORSPECTOR CORNER FREE PLAY Disabled -")
    return nil
end

function SetBarnSeaway_ON()
    local pr = gg.prompt({'Set Seaway Barn Capacity (Negative or 1~99999)'}, nil, {[1] = 'number'})
    if pr == nil then return end

    local userInput = tonumber(pr[1])
    if userInput == nil then
        gg.alert("Invalid input")
        return
    end

    -- Accept either negative or positive within allowed range
    if userInput >= 1 and userInput <= 99999 then
        -- Positive number branch: normal 32-bit int inject
        injectAssembly(currentOffset.get_totalItemsCount, userInput) -- 32-bit int inject
        gg.toast("- Set Barn Seaway: " .. userInput .. " -")
    elseif userInput < 0 then
        -- Negative number branch: generate hex patch via hexG & setHex
        local hexValue = hexG(userInput)
        if hexValue then
            setHex(currentOffset.get_totalItemsCount, hexValue)
            gg.toast("- Set Barn Seaway (Negative) patched -")
        else
            gg.alert("Error generating hex for negative value")
            return
        end
    else
        -- Invalid input
        gg.alert("INPUT VALUE Negative or 1~99999 only")
        return
    end

    return true
end


function SetBarnSeaway_OFF()
    reset(currentOffset.get_totalItemsCount)
    gg.toast("- Set Barn Seaway Hack Disabled -")
    return nil
end


function BonusTaskPoints_ON()
  local input = gg.prompt({'Enter Bonus Task Points (1~2000000):'}, nil, {[1] = 'number'})
  if input == nil then return end -- user cancelled
  local bonusValue = tonumber(input[1])
  if not bonusValue or bonusValue < 1 or bonusValue > 2000000 then
    gg.alert("Invalid input! Please enter a number between 1 and 2000000.")
    return
  end
  injectAssembly(currentOffset.get_amount, bonusValue)
  gg.toast("- ⛵ (BR) BONUS TASK POINTS set to " .. bonusValue .. " -")
  return true
end

function BonusTaskPoints_OFF()
  reset(currentOffset.get_amount)
  gg.toast("- ⛵ (BR) BONUS TASK POINTS Disabled -")
  return nil
end

function UnlimitedBRDiscardTask_ON()
  injectAssembly(currentOffset.get_GetCurrentLeaguePersonalQuota, 10000)
  gg.toast("- Unlimited BR Discard Task Enabled -")
  return true
end

function UnlimitedBRDiscardTask_OFF()
  reset(currentOffset.get_GetCurrentLeaguePersonalQuota)
  gg.toast("- Unlimited BR Discard Task Disabled -")
  return nil
end

function EnterBonusMode_ON()
    injectAssembly(currentOffset.get_personalQuotaCompleted, 100001)
    gg.toast("- ⛵ (BR) Enter Bonus Mode Enabled -")
    return true
end

function EnterBonusMode_OFF()
    reset(currentOffset.get_personalQuotaCompleted)
    gg.toast("- ⛵ (BR) Enter Bonus Mode Disabled -")
    return nil
end

function BonusTaskSkipPrice_ON()
    injectAssembly(currentOffset.get_GetBonusTaskSkipPrice, false)
    gg.toast("- ⛵ (BR) Bonus Task Skip Price Enabled -")
    return true
end

function BonusTaskSkipPrice_OFF()
    reset(currentOffset.get_GetBonusTaskSkipPrice)
    gg.toast("- ⛵ (BR) Bonus Task Skip Price Disabled -")
    return nil
end


function BoatRaceTaskRequirement_ON()
    injectAssembly(currentOffset.getAmount, 1)
    gg.toast("- ⛵ Boat Race Task Requirement (1) Enabled -")
    return true
end

function BoatRaceTaskRequirement_OFF()
    reset(currentOffset.getAmount)
    gg.toast("- ⛵ Boat Race Task Requirement Disabled -")
    return nil
end

function Deco_ON()
  x = "ProtoDecoration" o = 0x74 t = 4 findClass()
  x = 4 t = 4 refineNum() o = -0x44 t = 4 applyOffset()
  x = "1~999" t = 4 refineNum() o = 0x44 t = 4 applyOffset()
  local rsv1 = gg.getResults(gg.getResultsCount())
  clearAll()
  gg.loadResults(rsv1)
  o = -0x44 t = 4 applyOffset()
  x = 6 t = 4 refineNum()
  o = 0x18 t = 4 applyOffset()
  x = 3 t = 4 refineNum()
  o = -0x20 t = 4 applyOffset()
  local rsv2 = gg.getResults(1)
  local srv1 = rsv2[1].value
  clearAll()
  gg.loadResults(rsv1)
  o = -0x4C t = 4 applyOffset()
  x = srv1 t = 4 editAll()
  o = 0x8 t = 4 applyOffset() x = 4 t = 4 editAll()
  o = 0x4 t = 4 applyOffset()
  x = 1 t = 4 editAll()
  o = 0x4 t = 4 applyOffset()
  x = 0 t = 4 editAll()
  o = 0x4 t = 4 applyOffset()
  x = 0 t = 4 editAll()
  o = 0x4 t = 4 applyOffset()
  x = 0 t = 4 editAll()
  o = 0x4 t = 4 applyOffset()
  x = 0 t = 4 editAll()
  o = 0x8 t = 4 applyOffset() 
  x = 0 t = 4 editAll()
  o = 0xC t = 4 applyOffset()
  x = 0 t = 4 editAll()
  o = 0x24 t = 4 applyOffset()
  x = 1 t = 4 editAll()
  clearAll()
  gg.toast("- Decoration Unlocked -")
  return true
end


function Deco_OFF()
    gg.toast("-  Can't turn Off This hack -")
    return true
end

function AHM_ON()
  gg.setRanges(gg.REGION_ANONYMOUS)
  gg.searchNumber("1705391653", gg.TYPE_DWORD)
  gg.getResults(gg.getResultsCount())
  gg.editAll("1705391652", gg.TYPE_DWORD)
  gg.clearResults()
  gg.toast("ALL MARKET HIDDEN ITEMS ACTIVE")
  return true
end


function AHM_OFF()
    gg.toast("-  Can't turn Off This hack -")
    return true
end


strv1=16
strv2=7274563
strv3=7340143
strv4=7471183


function MWS_ON()
  x="CoopOrderHelpContext" 
  o=0x0 t=4 findClass()
  o=0x8 t=4 applyOffset()
  x=0 t=4 refineNum()
  checkResults() 
  if E==0 then 
     gg.alert("Sorry something wrong happened") 
     return nil
  end
  o=0x10 t=32 applyOffset()
  o=0x10 t=32 sv=strv1 checkString()
  o=0x14 t=32 sv=strv2 checkString()
  o=0x18 t=32 sv=strv3 checkString()
  o=0x1C t=32 sv=strv4 checkString()
  o=0xC8 t=4 applyOffset()
  x=0 t=4 editAll()
  freezeValues()
  clearAll()
  setValue(currentOffset.set_MyWeeklyContribution+0x28, 4, "~A8 MOV W20, #0x64")
  gg.toast("- Marie weekly score enabled -")
  return true
end


function MWS_OFF()
    reset(currentOffset.set_MyWeeklyContribution+0x28)
    gg.toast("- Weekly  Score Disabled-")
    return nil
end



function HPass_ON()
  x="FarmDiaryFeaturePassManager"
  o=0x18 t=1 findClass()
  checkResults() 
  if E==0 then 
     gg.alert("Error : Meoww Happened") 
     return nil 
  end
  x=0 t=1 refineNum()
  x=1 t=1 editAll()
  clearAll()
  gg.alert("🙂 Hairloom Pass Purchased ...\n👉 Now Restart Your Game To See Changes....")
  return true
end


function HPass_OFF()
    gg.toast("-  Can't turn Off This hack -")
    return true
end


function MPass_ON()
  x="MysteryCollectionSeasonPassManager"
  o=0x20 t=1 findClass()
  checkResults() 
  if E==0 then 
     gg.alert("Error : Meoww Happened") 
     return nil 
  end
  x=0 t=1 refineNum()
  x=1 t=1 editAll()
  clearAll()
  gg.alert("🙂 Mystery Master Pass Purchased ...\n👉 Now Restart Your Game To See Changes....")
  return true
end


function MPass_OFF()
    gg.toast("-  Can't turn Off This hack -")
    return true
end

function ELPass_ON()
  x="BattlePassFeaturePassManager"
  o=0x38 t=4 findClass()
  checkResults() 
  if E==0 then 
     gg.alert("Error : Meoww Happened") 
     return nil 
  end
  x="0~1" t=4 refineNum()
  x=2 t=4 editAll()
  clearAll()
  gg.alert("🙂 Elite Plus Badge Purchased ...\n👉 Now Restart Your Game To See Changes....")
  return true
end


function ELPass_OFF()
    gg.toast("-  Can't turn Off This hack -")
    return true
end

function ELtoken_ON()
  x="BattlePassTask"
  o=0x20 t=4 findClass()
  checkResults() 
  if E==0 then 
     gg.alert("Error : Meoww Happened") 
     return nil 
  end
  x="1~10000" t=4 refineNum()
  x=0 t=4 editAll()
  clearAll()
  gg.alert("🔓 Success.....")
  return true
end


function ELtoken_OFF()
    gg.toast("-  Can't turn Off This hack -")
    return true
end


function ELItoken_ON()
  local userInput = gg.prompt({"Enter Bonus Task Points (greater than 0):"}, nil, {[1] = "number"})
  if userInput == nil then
    return nil
  end
  local ELInventory = tonumber(userInput[1])
  if not ELInventory or ELInventory <= 0 then
    gg.alert("Invalid input! Please enter a number greater than 0.")
    return
  end
  injectAssembly(currentOffset.get_inventoryTokens, ELInventory)
  gg.toast("- Success....."..ELInventory)
  return true
end



function ELItoken_OFF()
    reset(currentOffset.get_inventoryTokens)
    gg.toast("- Reset To The Orginal -")
    return nil
end


function EVP_ON()
  x="SeasonPassManager"
  o=0x28 t=1 findClass()
  x="0" t=1 refineNum()
  x="1" t=1 editAll()
  clearAll()
  gg.toast("🔓 Success.....")
  return true
end


function EVP_OFF()
    gg.toast("-  Can't turn Off This hack -")
    return true
end

function PEA_ON()
  x="EntityPlacementController"
  o=0x31 t=1 findClass()
  x="1" t=1 refineNum()
  x="0" t=1 editAll()
  clearAll()
  injectAssembly(currentOffset.isEntityObstructed, false)
  gg.toast("🔓 Success.....")
  return true
end


function PEA_OFF()
    x="EntityPlacementController"
    o=0x31 t=1 findClass()
    x="0" t=1 refineNum()
    x="1" t=1 editAll()
    clearAll()
    reset(currentOffset.isEntityObstructed)
    gg.toast("- Reset To The Orginal -")
    return nil
end


function SE_ON()
  x="HoldToEdit"
  o=0x20 t=4 findClass()
  x="0" t=4 refineNum()
  x="1" t=4 editAll()
  clearAll()
  gg.toast("- Sell Enabled -")
  return true
end


function SE_OFF()
    x="HoldToEdit"
    o=0x20 t=4 findClass()
    x="1" t=4 refineNum()
    x="0" t=4 editAll()
    clearAll()
    gg.toast("- Sell Disabled  -")
    return nil
end

function UB_ON()
  x="UpgradeableBuilding"
  o=0x20 t=4 findClass()
  x="0~5" t = 4 refineNum()
  x=3 t=4 editAll()
  o=0x4 t=4 applyOffset()
  x=4 t=4 refineNum()
  o=-0x4 t=4 applyOffset()
  x=3 t=4 refineNum()
  x=5 t=4 editAll()
  clearAll()
  gg.alert("⛩️ All Farm Building's Are Upgraded..Now Restart Your Game To See Full Changes")
  return true
end


function UB_OFF()
    x="UpgradeableBuilding"
    o=0x20 t=4 findClass()
    x="1~5" t = 4 refineNum()
    x=0 t=4 editAll()
    clearAll()
    gg.toast("- Building's Are Downgraded -")
    return nil
end

function UC_ON()
  x="ProtoMill"
  o=0x74 t=4 findClass()
  x="1~3" t=4 refineNum()
  rsv1=gg.getResults(gg.getResultsCount())
  clearAll()
  gg.loadResults(rsv1)
  o=-0x44 t=4 applyOffset()
  x=1 t=4 refineNum()
  o=0x48 t=4 applyOffset()
  x=2 t=4 refineNum()
  o=-0x50 t=4 applyOffset()
  rsv2=gg.getResults(1)
  srv1=rsv2[1].value
  clearAll()
  gg.loadResults(rsv1)
  o=-0x4C t=4 applyOffset()
  x=srv1 t=4 editAll()
  o=0x8 t=4 applyOffset()
  x=4 t=4 editAll()
  o=0x4 t=4 applyOffset()
  x=1 t=4 editAll()
  o=0x4 t=4 applyOffset()
  x=0 t=4 editAll()
  o=0x4 t=4 applyOffset()
  x=0 t=4 editAll()
  o=0x4 t=4 applyOffset()
  x=0 t=4 editAll()
  o=0x4 t=4 applyOffset()
  x=0 t=4 editAll()
  o=0x8 t=4 applyOffset()
  x=0 t=4 editAll()
  o=0xC t=4 applyOffset()
  x=0 t=4 editAll()
  o=0x24 t=4 applyOffset()
  x=1 t=4 editAll()
  clearAll()
  gg.alert("- 🎁 CROPS, ANIMALS, KEY MAKER(WORKSHOPS) ACTIVE -","","")
  return true
end

function UC_OFF()
    gg.toast("- Can't Turn This Hack Off -")
    return true
end


function HH_ON()
  injectAssembly(currentOffset.get_IsAvailable, true)
  gg.toast("- Activated -")
  return true
end


function HH_OFF()
    reset(currentOffset.get_IsAvailable)
    gg.toast("- Deactivated -")
    return nil
end

function MB_ON()
    local inputs = gg.prompt({
        'Enter XP Amount (1~99999):',
        'Enter Timber Amount (1~99999):',
        'Enter Coin Amount (1~99999):'
    }, nil, { [1] = 'number', [2] = 'number', [3] = 'number' })
    
    if inputs == nil then return end -- User cancelled

    local xp, timber, coin = tonumber(inputs[1]), tonumber(inputs[2]), tonumber(inputs[3])

    -- Validation for each input
    local function isValid(num)
        return num and num >= 1 and num <= 99999
    end

    if not isValid(xp) or not isValid(timber) or not isValid(coin) then
        gg.alert("Invalid input! Please enter values between 1 and 99999.")
        return
    end
    x="MerchantOffer"
    o=0x58 t=4 findClass() --xp
    x="1~99999" t=4 refineNum()
    x=xp t=4 editAll()
    clearAll()
    gg.toast("- Xp ["..xp.."]")
    
    x="MerchantOffer"
    o=0x5C t=4 findClass() --timber
    x="1~99999" t=4 refineNum()
    x=timber t=4 editAll()
    clearAll()
    gg.toast("- Timber ["..timber.."]")
    
    x="MerchantOffer"
    o=0x64 t=4 findClass() --coinPrice
    x="1~99999" t=4 refineNum()
    x=coin t=4 editAll()
    clearAll()
    gg.toast("- Coin ["..coin.."]")
    return true
end


function MB_OFF()
    gg.toast("- Can't Restore To The Orginal -")
    return nil
end


function EVI_ON()
    gg.alert("@credit - Ertan Hancer\n@ertanhancer", "","")
    local saved = gg.getListItems()
    
    if #saved == 0 then
        -- Run only if no saved items
        x = "ProtoFixedLootInfo"
        o = 0x10 t = 32 findClass()
        o = 0x10 t = 32 sv = 8 checkString()
        o = 0x14 t = 32 sv = 6357079 checkString()
        o = 0x18 t = 32 sv = 6619252 checkString()
        o = 0x1C t = 32 sv = 6226034 checkString()
        o = 0x20 t = 32 sv = 3211312 checkString()
        o = 0x0  t = 4 applyOffset()
        checkResults()
        if E == 0 then 
            gg.alert("Error : Meoww Happened") 
            return nil
        end
        freeze()
        clearAll()
        gg.setValues(frz)
    else
        frz = saved
    end
    
    -- Item selection menu
    local items = {
        "[ + ] Event Supplies", --1
        "[ + ] Event Phase 1 Item 1", --2
        "[ + ] Event Phase 2 Item 1", --3
        "[ + ] Event Phase 2 Item 2", --4
        "[ + ] Event Phase 3 Item 1", --5
        "[ + ] Event Phase 3 Item 2", --6
        "[ + ] Event Phase 4 Item 1", --7
        "[ + ] Event Phase 4 Item 2", --8
        "[ + ] Event Phase 5 Item 1", --9
        "[ + ] Event Phase 5 Item 2", --10
        "[ + ] Event Leaderboard Item 1", --11
        "[ + ] Event Leaderboard Item 2", --12
        "[ + ] Event Leaderboard Item 3" --13
    }
    sel = gg.choice(items, nil, "💥 Select an item: \n────୨ৎ────────୨ৎ────")
    
    if not sel then
        gg.alert("No item selected")
        return
    end
    
    -- Ask for amount
    p = gg.prompt({"Input Amount"}, nil, {[1] = "number"})
    if not p or not tonumber(p[1]) or tonumber(p[1]) < 1 then
        gg.alert("Invalid input")
        return nil
    end
    pv1 = p[1]
    
    -- Execute the selected script
    if sel == 1 then y1=-2746901165 script() end
    if sel == 2 then y1=-4060807895 script() end
    if sel == 3 then y1=-3080051784 script() end
    if sel == 4 then y1=-3080051783 script() end
    if sel == 5 then y1=-3699042381 script() end
    if sel == 6 then y1=-3699042380 script() end
    if sel == 7 then y1=-2718286270 script() end
    if sel == 8 then y1=-2718286269 script() end
    if sel == 9 then y1=-3337276867 script() end
    if sel == 10 then y1=-3337276866 script() end
    if sel == 11 then y1=-3222333007 script() end
    if sel == 12 then y1=-3222333006 script() end
    if sel == 13 then y1=-3222333005 script() end
    gg.toast("- Activated -")
    return nil
end


function EVI_OFF()
    gg.toast("- Meowww -")
    return nil
end


function ITM_ON()
    gg.alert("@credit - Ertan Hancer\n@ertanhancer", "","")
    local saved = gg.getListItems()
    if #saved == 0 then
        x = "ProtoFixedLootInfo"
        o = 0x10 t = 32 findClass()
        o = 0x10 t = 32 sv = 8 checkString()
        o = 0x14 t = 32 sv = 6357079 checkString()
        o = 0x18 t = 32 sv = 6619252 checkString()
        o = 0x1C t = 32 sv = 6226034 checkString()
        o = 0x20 t = 32 sv = 3211312 checkString()
        o = 0x0  t = 4 applyOffset()
        checkResults()
        if E == 0 then
            gg.alert("Error : Meoww Happened")
            return nil
        end
        freeze()
        clearAll()
        gg.setValues(frz)
    else
        frz = saved
    end

    local items = {
        "[ + ] Ale Mug",
        "[ + ] Antique Diving Helmet",
        "[ + ] Apple",
        "[ + ] Apple Pie",
        "[ + ] Baked Herring",
        "[ + ] Baked Potato",
        "[ + ] Bass",
        "[ + ] Beeswax Candle",
        "[ + ] Birdhouse",
        "[ + ] Black Rice",
        "[ + ] Black Rice and Salmon",
        "[ + ] Black Rice Pudding",
        "[ + ] Black Rice Risotto",
        "[ + ] Blackrice Sushi",
        "[ + ] Black Veggie Risotto",
        "[ + ] Blackberries",
        "[ + ] Blackberry Custard",
        "[ + ] Blackberry Jam",
        "[ + ] Blackberry Pie",
        "[ + ] Blackberry Tart",
        "[ + ] Blanket",
        "[ + ] Blueberries",
        "[ + ] Blueberry Granola Muffin",
        "[ + ] Blueberry Jam",
        "[ + ] Blueberry Pancakes",
        "[ + ] Bottle",
        "[ + ] Brass",
        "[ + ] Brie Cheese",
        "[ + ] Butter",
        "[ + ] Cajun Crab",
        "[ + ] Candied Cranberries",
        "[ + ] Canvas",
        "[ + ] Canvas Tote",
        "[ + ] Carrot",
        "[ + ] Carrot Cake",
        "[ + ] Cedar Plank Trout",
        "[ + ] Cedar Wood",
        "[ + ] Champagne",
        "[ + ] Chardonnay",
        "[ + ] Cheesy Urchin Risotto",
        "[ + ] Chives",
        "[ + ] Clam",
        "[ + ] Clam Chowder",
        "[ + ] Clam Urchin Paella",
        "[ + ] Clay",
        "[ + ] Compass",
        "[ + ] Copper",
        "[ + ] Copper Button",
        "[ + ] Corn",
        "[ + ] Corn Husk Doll",
        "[ + ] Country Biscuits",
        "[ + ] Cove Punch",
        "[ + ] Cow Milk",
        "[ + ] Crab",
        "[ + ] Crab Cake",
        "[ + ] Crab Souffle",
        "[ + ] Cranberries",
        "[ + ] Cranberry Jam",
        "[ + ] Cranberry Muffin",
        "[ + ] Cranberry Scones",
        "[ + ] Deviled Eggs",
        "[ + ] Dried Fruits",
        "[ + ] Duck Feathers",
        "[ + ] Eggs",
        "[ + ] Egg White",
        "[ + ] Farmer's Soup",
        "[ + ] Fish & Chips",
        "[ + ] Fish Bowl",
        "[ + ] Fish Sauce",
        "[ + ] Fishermans Hat",
        "[ + ] Flour",
        "[ + ] Gelato",
        "[ + ] Glass Float",
        "[ + ] Glass Horse",
        "[ + ] Goat Cheese",
        "[ + ] Goat Milk",
        "[ + ] Granola Bar",
        "[ + ] Grape Juice",
        "[ + ] Herb Butter",
        "[ + ] Herring",
        "[ + ] Herring Potato Salad",
        "[ + ] Honey Butter",
        "[ + ] Honeycomb",
        "[ + ] Jacket",
        "[ + ] Jar",
        "[ + ] Knit Cap",
        "[ + ] Krill",
        "[ + ] Krill Cakes",
        "[ + ] Krill Fries",
        "[ + ] Krill Potato",
        "[ + ] Krill Salad",
        "[ + ] Krill Tortilla",
        "[ + ] Lemon",
        "[ + ] Lemon Gelato",
        "[ + ] Lemon Tart",
        "[ + ] Lemon Yogurt",
        "[ + ] Lemon Zest",
        "[ + ] Lemonade",
        "[ + ] Lemon-Scented Candle",
        "[ + ] Loaded Baked Potato",
        "[ + ] Lobsters",
        "[ + ] Lobster Mac & Cheese",
        "[ + ] Mac&Cheese",
        "[ + ] Mermaid Figure",
        "[ + ] Mint",
        "[ + ] Mint Chip Cookies",
        "[ + ] Mixed Pepper",
        "[ + ] Oars",
        "[ + ] Oatmeal Cookie",
        "[ + ] Oil Lantern",
        "[ + ] Ornate Stein",
        "[ + ] Overalls",
        "[ + ] Pan Fries",
        "[ + ] Pan-Seared Trout",
        "[ + ] Peach",
        "[ + ] Peach Yogurt",
        "[ + ] Pear",
        "[ + ] Pear Jam",
        "[ + ] Pear Juice",
        "[ + ] Pearl",
        "[ + ] Pen Shell",
        "[ + ] Pen Shell Box",
        "[ + ] Pen Shell Candle",
        "[ + ] Pen Shell Jar",
        "[ + ] Pen Shell Mermaid",
        "[ + ] Pen Shell Mirror",
        "[ + ] Pepper Poppers",
        "[ + ] Pillow",
        "[ + ] Pinot Noir",
        "[ + ] Plush Cat",
        "[ + ] Plush Dog",
        "[ + ] Plush Duck",
        "[ + ] Porcelain Doll",
        "[ + ] Pot Pie",
        "[ + ] Potato",
        "[ + ] Prized Chiken Feed",
        "[ + ] Prized Cow Feed",
        "[ + ] Prized Goat Feed",
        "[ + ] Prized Horse Feed",
        "[ + ] Prized Pig Feed",
        "[ + ] Prized Sheep Feed",
        "[ + ] Quartz",
        "[ + ] Quilt",
        "[ + ] Raggety Doll",
        "[ + ] Rain Slicker",
        "[ + ] Red Grapes",
        "[ + ] Rocking Chair",
        "[ + ] Rose Wine",
        "[ + ] Royal Sextant",
        "[ + ] Salmon",
        "[ + ] Salmon Bisque",
        "[ + ] Sandwich and Fries",
        "[ + ] Scone",
        "[ + ] Sea Biscuit",
        "[ + ] Sea Salt",
        "[ + ] Sea Urchin",
        "[ + ] Sea Urchin Gratin",
        "[ + ] Sea Urchin Ice Cream",
        "[ + ] Seafood Bruschetta",
        "[ + ] Seafood Chowder",
        "[ + ] Seafood Creole",
        "[ + ] Seasoned Clams",
        "[ + ] Ship In A Bottle",
        "[ + ] Shovel",
        "[ + ] Shrimp",
        "[ + ] Shrimp and Spinach",
        "[ + ] Shrimp Gumbo",
        "[ + ] Shrimp Pasta",
        "[ + ] Shrimp Skewers",
        "[ + ] Silver Anchor",
        "[ + ] Smoked Salmon",
        "[ + ] Smoked Trout",
        "[ + ] Socks",
        "[ + ] Sparkling Cider",
        "[ + ] Spinach Bread",
        "[ + ] Spinach Caesar",
        "[ + ] Spinach Casserole",
        "[ + ] Spinach Salad",
        "[ + ] Spyglass",
        "[ + ] Strawberry",
        "[ + ] Strawberry Jam",
        "[ + ] Strawberry Milk",
        "[ + ] Strawberry Shortcake",
        "[ + ] Strawberry Sundae",
        "[ + ] Stuffed Bass",
        "[ + ] Sugar",
        "[ + ] Sushi and Wasabi",
        "[ + ] Sweet Potato Bites",
        "[ + ] Swiss Cheese",
        "[ + ] Tangy Ceviche",
        "[ + ] Teddy Bear",
        "[ + ] Tin",
        "[ + ] Tin Button",
        "[ + ] Tomato",
        "[ + ] Tomato Juice",
        "[ + ] Trouser",
        "[ + ] Trout",
        "[ + ] Trout and Wilted Spinach",
        "[ + ] Trout Souffle",
        "[ + ] Wasabi",
        "[ + ] Wasabi Bread",
        "[ + ] Water Spinach",
        "[ + ] Wheat",
        "[ + ] Whistle",
        "[ + ] White Grapes",
        "[ + ] Wind Chime",
        "[ + ] Wool",
        "[ + ] Woolen Scarf",
        "[ + ] Yarn Doll"
    }
    local menu2 = gg.choice(items, nil, "💥 Select an item:\n────୨ৎ────────୨ৎ────")
    if not menu2 then
        gg.alert("No item selected")
        return
    end

    local p = gg.prompt({ "Input Amount" }, nil, { [1] = "number" })
    if not p or not tonumber(p[1]) or tonumber(p[1]) < 1 then
        gg.alert("Invalid input")
        return nil
    end
    pv1 = tonumber(p[1])
    
    if menu2==1 then y1=584708988 y2=-1 scripNew() end
    if menu2==2 then y1=580532843 y2=-1 scripNew() end
    if menu2==3 then y1=2056534324 y2=-1 scripNew() end
    if menu2==4 then y1=757373017 y2=-1 scripNew() end
    
    if menu2==5 then y1=438771353 y2=-1 scripNew() end
    if menu2==6 then y1=2033540097 y2=-1 scripNew() end
    if menu2==7 then y1=1662852189 y2=-1 scripNew() end
    if menu2==8 then y1=1380533299 y2=-1 scripNew() end
    if menu2==9 then y1=1114600953 y2=-1 scripNew() end
    if menu2==10 then y1=1024151519 y2=-1 scripNew() end
    if menu2==11 then y1=1043083818 y2=-1 scripNew() end
    if menu2==12 then y1=1099305937 y2=-1 scripNew() end
    if menu2==13 then y1=1511367070 y2=-1 scripNew() end
    if menu2==14 then y1=1187808016 y2=-1 scripNew() end
    if menu2==15 then y1=233723854 y2=-1 scripNew() end
    if menu2==16 then y1=767570657 y2=-1 scripNew() end
    if menu2==17 then y1=1096487734 y2=-1 scripNew() end
    if menu2==18 then y1=2137899422 y2=-1 scripNew() end
    if menu2==19 then y1=1206796448 y2=-1 scripNew() end
    if menu2==20 then y1=983962679 y2=-1 scripNew() end
    if menu2==21 then y1=1842858245 y2=-1 scripNew() end
    if menu2==22 then y1=1882411672 y2=-1 scripNew() end
    if menu2==23 then y1=1830790717 y2=-1 scripNew() end
    if menu2==24 then y1=190331075 y2=-1 scripNew() end
    if menu2==25 then y1=162591925 y2=-1 scripNew() end
    if menu2==26 then y1=1583217416 y2=-1 scripNew() end
    if menu2==27 then y1=957927607 y2=-1 scripNew() end
    if menu2==28 then y1=997605494 y2=-1 scripNew() end
    if menu2==29 then y1=474415542 y2=-1 scripNew() end
    
    
    if menu2==30 then y1=43045268 y2=-1 scripNew() end
    if menu2==31 then y1=819748063 y2=-1 scripNew() end
    if menu2==32 then y1=1200527644 y2=-1 scripNew() end
    if menu2==33 then y1=1962459799 y2=-1 scripNew() end
    if menu2==34 then y1=1528702703 y2=-1 scripNew() end
    if menu2==35 then y1=1969829604 y2=-1 scripNew() end
    if menu2==36 then y1=1905547111 y2=-1 scripNew() end
    if menu2==37 then y1=1527285887 y2=-1 scripNew() end
    if menu2==38 then y1=429824234 y2=-1 scripNew() end
    if menu2==39 then y1=1045025557 y2=-1 scripNew() end
    if menu2==40 then y1=1741694226 y2=-1 scripNew() end
    if menu2==41 then y1=1135390172 y2=-1 scripNew() end
    if menu2==42 then y1=370046541 y2=-1 scripNew() end
    if menu2==43 then y1=762617362 y2=-1 scripNew() end
    if menu2==44 then y1=1408793715 y2=-1 scripNew() end
    if menu2==45 then y1=1341434345 y2=-1 scripNew() end
    if menu2==46 then y1=2135483436 y2=-1 scripNew() end
    if menu2==47 then y1=181127829 y2=-1 scripNew() end
    if menu2==48 then y1=1290443054 y2=-1 scripNew() end
    if menu2==49 then y1=480560382 y2=-1 scripNew() end
    if menu2==50 then y1=401641490 y2=-1 scripNew() end
    if menu2==51 then y1=629271241 y2=-1 scripNew() end
    if menu2==52 then y1=524467268 y2=-1 scripNew() end
    if menu2==53 then y1=487289217 y2=-1 scripNew() end
    if menu2==54 then y1=307344386 y2=-1 scripNew() end
    if menu2==55 then y1=1165551304 y2=-1 scripNew() end
    if menu2==56 then y1=953227955 y2=-1 scripNew() end
    if menu2==57 then y1=550869814 y2=-1 scripNew() end
    if menu2==58 then y1=1032148527 y2=-1 scripNew() end
    if menu2==59 then y1=1501635289 y2=-1 scripNew() end
    if menu2==60 then y1=1299066260 y2=-1 scripNew() end
    
    if menu2==61 then y1=484431750 y2=-1 scripNew() end
    if menu2==62 then y1=511408819 y2=-1 scripNew() end
    if menu2==63 then y1=821387058 y2=-1 scripNew() end
    
    if menu2==64 then y1=2120430547 y2=-1 scripNew() end
    if menu2==65 then y1=915020220 y2=-1 scripNew() end
    
    if menu2==66 then y1=433242438 y2=-1 scripNew() end
    if menu2==67 then y1=1876776112 y2=-1 scripNew() end
    if menu2==68 then y1=288018039 y2=-1 scripNew() end
    if menu2==69 then y1=720272854 y2=-1 scripNew() end
    if menu2==70 then y1=1071319662 y2=-1 scripNew() end
    if menu2==71 then y1=1357751624 y2=-1 scripNew() end
    
    if menu2==72 then y1=427969226 y2=-1 scripNew() end
    if menu2==73 then y1=1191344987 y2=-1 scripNew() end
    if menu2==74 then y1=1223292370 y2=-1 scripNew() end
    if menu2==75 then y1=793980477 y2=-1 scripNew() end
    if menu2==76 then y1=641975235 y2=-1 scripNew() end
    if menu2==77 then y1=1652496164 y2=-1 scripNew() end
    if menu2==78 then y1=1785717968 y2=-1 scripNew() end
    
    if menu2==79 then y1=865983102 y2=-1 scripNew() end
    if menu2==80 then y1=630212251 y2=-1 scripNew() end
    if menu2==81 then y1=1815886685 y2=-1 scripNew() end
    if menu2==82 then y1=559718598 y2=-1 scripNew() end
    if menu2==83 then y1=815092402 y2=-1 scripNew() end
    
    if menu2==84 then y1=1973304702 y2=-1 scripNew() end
    if menu2==85 then y1=1393658783 y2=-1 scripNew() end
    
    if menu2==86 then y1=1251119939 y2=-1 scripNew() end
    if menu2==87 then y1=1124071716 y2=-1 scripNew() end
    if menu2==88 then y1=1444414566 y2=-1 scripNew() end
    if menu2==89 then y1=1067522712 y2=-1 scripNew() end
    if menu2==90 then y1=1513204702 y2=-1 scripNew() end
    if menu2==91 then y1=1769277298 y2=-1 scripNew() end
    if menu2==92 then y1=1527700848 y2=-1 scripNew() end
    
    if menu2==93 then y1=67782079 y2=-1 scripNew() end
    if menu2==94 then y1=427453308 y2=-1 scripNew() end
    if menu2==95 then y1=1169376651 y2=-1 scripNew() end
    if menu2==96 then y1=451500238 y2=-1 scripNew() end
    if menu2==97 then y1=1493295682 y2=-1 scripNew() end
    if menu2==98 then y1=1045153543 y2=-1 scripNew() end
    if menu2==99 then y1=1664945974 y2=-1 scripNew() end
    if menu2==100 then y1=558634293 y2=-1 scripNew() end
    if menu2==101 then y1=1460784375 y2=-1 scripNew() end
    if menu2==102 then y1=1509271265 y2=-1 scripNew() end
    
    if menu2==103 then y1=813854671 y2=-1 scripNew() end
    if menu2==104 then y1=1722438611 y2=-1 scripNew() end
    if menu2==105 then y1=2136698672 y2=-1 scripNew() end
    if menu2==106 then y1=705842545 y2=-1 scripNew() end
    if menu2==107 then y1=463804525 y2=-1 scripNew() end
    
    if menu2==108 then y1=1663026233 y2=-1 scripNew() end
    if menu2==109 then y1=1745807241 y2=-1 scripNew() end
    if menu2==110 then y1=1952515553 y2=-1 scripNew() end
    if menu2==111 then y1=960361411 y2=-1 scripNew() end
    if menu2==112 then y1=561584978 y2=-1 scripNew() end
    
    if menu2==113 then y1=1679071937 y2=-1 scripNew() end
    if menu2==114 then y1=572283885 y2=-1 scripNew() end
    if menu2==115 then y1=1242858541 y2=-1 scripNew() end
    if menu2==116 then y1=1400004712 y2=-1 scripNew() end
    if menu2==117 then y1=771091012 y2=-1 scripNew() end
    if menu2==118 then y1=2131121158 y2=-1 scripNew() end
    if menu2==119 then y1=1596593543 y2=-1 scripNew() end
    if menu2==120 then y1=1307858964 y2=-1 scripNew() end
    if menu2==121 then y1=615183866 y2=-1 scripNew() end
    if menu2==122 then y1=1339770052 y2=-1 scripNew() end
    if menu2==123 then y1=316413778 y2=-1 scripNew() end
    if menu2==124 then y1=2111909728 y2=-1 scripNew() end
    if menu2==125 then y1=649499202 y2=-1 scripNew() end
    if menu2==126 then y1=172280464 y2=-1 scripNew() end
    if menu2==127 then y1=1733178416 y2=-1 scripNew() end
    if menu2==128 then y1=1179965051 y2=-1 scripNew() end
    if menu2==129 then y1=743323227 y2=-1 scripNew() end
    if menu2==130 then y1=639603949 y2=-1 scripNew() end
    if menu2==131 then y1=1664295631 y2=-1 scripNew() end
    if menu2==132 then y1=1961104322 y2=-1 scripNew() end
    if menu2==133 then y1=584053963 y2=-1 scripNew() end
    if menu2==134 then y1=1249969726 y2=-1 scripNew() end
    if menu2==135 then y1=854672031 y2=-1 scripNew() end
    if menu2==136 then y1=1343728189 y2=-1 scripNew() end
    if menu2==137 then y1=152318775 y2=-1 scripNew() end
    if menu2==138 then y1=185328661 y2=-1 scripNew() end
    if menu2==139 then y1=637076475 y2=-1 scripNew() end
    if menu2==140 then y1=1426907328 y2=-1 scripNew() end
    if menu2==141 then y1=1885804815 y2=-1 scripNew() end
    
    if menu2==142 then y1=1583451799 y2=-1 scripNew() end
    if menu2==143 then y1=87061843 y2=-1 scripNew() end
    
    if menu2==144 then y1=2022755633 y2=-1 scripNew() end
    if menu2==145 then y1=2104545058 y2=-1 scripNew() end
    if menu2==146 then y1=1393281460 y2=-1 scripNew() end
    if menu2==147 then y1=923583125 y2=-1 scripNew() end
    if menu2==148 then y1=773438943 y2=-1 scripNew() end
    if menu2==149 then y1=1833304037 y2=-1 scripNew() end
    
    if menu2==150 then y1=1956180846 y2=-1 scripNew() end
    if menu2==151 then y1=1797195464 y2=-1 scripNew() end
    if menu2==152 then y1=2126719907 y2=-1 scripNew() end
    if menu2==153 then y1=96923818 y2=-1 scripNew() end
    if menu2==154 then y1=517077252 y2=-1 scripNew() end
    if menu2==155 then y1=1141606664 y2=-1 scripNew() end
    if menu2==156 then y1=2018490605 y2=-1 scripNew() end
    if menu2==157 then y1=1045445505 y2=-1 scripNew() end
    if menu2==158 then y1=2042400386 y2=-1 scripNew() end
    if menu2==159 then y1=688451769 y2=-1 scripNew() end
    if menu2==160 then y1=1051916352 y2=-1 scripNew() end
    if menu2==161 then y1=1232836718 y2=-1 scripNew() end
    if menu2==162 then y1=1222853125 y2=-1 scripNew() end
    if menu2==163 then y1=1982316285 y2=-1 scripNew() end
    if menu2==164 then y1=1103768341 y2=-1 scripNew() end
    if menu2==165 then y1=1196605883 y2=-1 scripNew() end
    if menu2==166 then y1=1345218702 y2=-1 scripNew() end
    if menu2==167 then y1=2110017236 y2=-1 scripNew() end
    if menu2==168 then y1=440022827 y2=-1 scripNew() end
    if menu2==169 then y1=1204170634 y2=-1 scripNew() end
    if menu2==170 then y1=471405435 y2=-1 scripNew() end
    if menu2==171 then y1=536387662 y2=-1 scripNew() end
    if menu2==172 then y1=2097887426 y2=-1 scripNew() end
    if menu2==173 then y1=672992513 y2=-1 scripNew() end
    if menu2==174 then y1=1060946504 y2=-1 scripNew() end
    if menu2==175 then y1=1320888967 y2=-1 scripNew() end
    if menu2==176 then y1=99612818 y2=-1 scripNew() end
    if menu2==177 then y1=1745400274 y2=-1 scripNew() end
    if menu2==178 then y1=1653841770 y2=-1 scripNew() end
    if menu2==179 then y1=1046337774 y2=-1 scripNew() end
    if menu2==180 then y1=1023354295 y2=-1 scripNew() end
    if menu2==181 then y1=1022651770 y2=0 scripNew() end
    if menu2==182 then y1=923150903 y2=-1 scripNew() end
    if menu2==183 then y1=1255365216 y2=-1 scripNew() end
    if menu2==184 then y1=1858908406 y2=-1 scripNew() end
    if menu2==185 then y1=1273205001 y2=-1 scripNew() end
    if menu2==186 then y1=1438718190 y2=-1 scripNew() end
    if menu2==187 then y1=2067431436 y2=-1 scripNew() end
    if menu2==188 then y1=1553338358 y2=-1 scripNew() end
    if menu2==189 then y1=1327425141 y2=-1 scripNew() end
    
    if menu2==190 then y1=1852930163 y2=-1 scripNew() end
    if menu2==191 then y1=282742189 y2=-1 scripNew() end
    if menu2==192 then y1=2042227065 y2=-1 scripNew() end
    if menu2==193 then y1=771608676 y2=-1 scripNew() end
    if menu2==194 then y1=850790506 y2=-1 scripNew() end
    if menu2==195 then y1=257027305 y2=-1 scripNew() end
    if menu2==196 then y1=2054828325 y2=-1 scripNew() end
    if menu2==197 then y1=1685235254 y2=-1 scripNew() end
    if menu2==198 then y1=1387698379 y2=-1 scripNew() end
    if menu2==199 then y1=2016456592 y2=-1 scripNew() end
    
    if menu2==200 then y1=322235033 y2=-1 scripNew() end
    if menu2==201 then y1=2031378012 y2=-1 scripNew() end
    if menu2==202 then y1=357001560 y2=-1 scripNew() end
    if menu2==203 then y1=756102493 y2=-1 scripNew() end
    if menu2==204 then y1=1365093926 y2=-1 scripNew() end
    if menu2==205 then y1=1666948854 y2=-1 scripNew() end
    if menu2==206 then y1=395809115 y2=-1 scripNew() end
    if menu2==207 then y1=763312769 y2=-1 scripNew() end
    if menu2==208 then y1=184046900 y2=-1 scripNew() end
    
    
    if menu2==209 then y1=1398167486 y2=-1 scripNew() end
    
    gg.toast("- Activated -")
end


function ITM_OFF()
    gg.toast("- Meowww -")
    return nil
end

function OFG_ON()
  x="ProtoPartnerAnimalBreed" 
  o=0x20 t=16 findClass()
  x="70~80" t=16 refineNum()
  x="100000" t=16 editAll()
  clearAll()
  gg.toast("- One Feed Gold Activated -")
  return true
end


function OFG_OFF()
    gg.toast("Can't Restore to Orginal")
    return true
end

local originalValues = {} -- Store original values here

function MIA_ON()
    local inputs = gg.prompt({
        'Input Amount (1~999):'
    }, nil, {'number'})
    
    if inputs == nil then return nil end -- User cancelled

    local itAmount = tonumber(inputs[1])

    -- Simplified validation
    if not itAmount or itAmount < 1 or itAmount > 999 then
        gg.alert("Invalid input! Please enter values between 1 and 999.")
        return
    end
    
    -- Clear previous values
    originalValues = {}
    
    -- Find class and get results
    x = "MerchantOfferItem" 
    o = 0x18 
    t = 4 
    findClass()
    
    -- Refine to target range and RECORD original values
    x = "1~999" 
    t = 4 
    refineNum()
    
    -- Get results before editing and store original values
    local results = gg.getResults(gg.getResultsCount())
    for i, v in ipairs(results) do
        originalValues[i] = {
            address = v.address,
            flags = v.flags,
            value = v.value,
            freeze = v.freeze
        }
    end
    
    -- Edit to new value
    x = itAmount 
    t = 4 
    editAll()
    
    clearAll()
    gg.toast("- Active -")
    return true
end

function MIA_OFF()
    if #originalValues == 0 then
        gg.alert("No original values stored or hack was not activated!")
        return true
    end
    
    -- Restore original values
    gg.setValues(originalValues)
    gg.toast("Restored to original values")
    return nil
end



function PC_ON()
    gg.alert("@credit - Ertan Hancer\n@ertanhancer", "","")
    local items = { 
        "[ + ] Anchor", 
        "[ + ] Animal Cash", 
        "[ + ] Axes", 
        "[ + ] Blue Ribbon", 
        "[ + ] Bronze Stamp", 
        "[ + ] Dinner Bell", 
        "[ + ] Eddie Certificate", 
        "[ + ] Farm Cup Points", 
        "[ + ] Gold Net", 
        "[ + ] Gold Stamp", 
        "[ + ] Golden Glove", 
        "[ + ] Hook", 
        "[ + ] Marcos Mart Token", 
        "[ + ] Marie Certificate", 
        "[ + ] Mariner Certificate", 
        "[ + ] Mineral", 
        "[ + ] Park Stamps", 
        "[ + ] Rakes", 
        "[ + ] Red Ribbon", 
        "[ + ] Rope", 
        "[ + ] Rubber", 
        "[ + ] Ruby Glove", 
        "[ + ] Sand Dollar", 
        "[ + ] Shears", 
        "[ + ] Silver Stamp", 
        "[ + ] Snack Bell", 
        "[ + ] Speed Seed", 
        "[ + ] The Crown Society", 
        "[ + ] The Melon Mystery Aid Token", 
        "[ + ] Yellow Ribbon",
        "[ + ] Key"
    }

    sel2 = gg.choice(items, nil, "💥 Select an item: \n────୨ৎ────────୨ৎ────")
    if not sel2 then
        gg.alert("No item selected")
        return
    end

    pr1 = gg.prompt({"Input Amount"}, nil, {[1] = "number"})
    if not pr1 or not tonumber(pr1[1]) or tonumber(pr1[1]) < 1 then
        gg.alert("Invalid input")
        return nil
    end
    y2 = pr1[1]

    if sel2 == 1 then y1 = -4172143379 end
    if sel2 == 2 then y1 = -2929526377 end
    if sel2 == 3 then y1 = 2583189040429 end
    if sel2 == 4 then y1 = 31141687881 end
    if sel2 == 5 then y1 = -3423685853 end
    if sel2 == 6 then y1 = 838159600732 end
    if sel2 == 7 then y1 = 1423692758 end
    if sel2 == 8 then y1 = -2350909532 end
    if sel2 == 9 then y1 = -2662329848 end
    if sel2 == 10 then y1 = -4211869540 end
    if sel2 == 11 then y1 = -2161124554 end
    if sel2 == 12 then y1 = -4172143378 end
    if sel2 == 13 then y1 = -3227389232 end
    if sel2 == 14 then y1 = -3896863109 end
    if sel2 == 15 then y1 = -3374039300 end
    if sel2 == 16 then y1 = -3633768666 end
    if sel2 == 17 then y1 = -2737649758 end
    if sel2 == 18 then y1 = -2343555106 end
    if sel2 == 19 then y1 = 5319776532 end
    if sel2 == 20 then y1 = -4172143381 end
    if sel2 == 21 then y1 = -2936877243 end
    if sel2 == 22 then y1 = 1403241851 end
    if sel2 == 23 then y1 = -3212264721 end
    if sel2 == 24 then y1 = -2707345160 end
    if sel2 == 25 then y1 = -2858874734 end
    if sel2 == 26 then y1 = -4023434665 end
    if sel2 == 27 then y1 = -2488230316 end
    if sel2 == 28 then y1 = -2674184633 end
    if sel2 == 29 then y1 = -4217367217 end
    if sel2 == 30 then y1 = 1496248903 end

    if sel2 == 31 then 
        gg.setRanges(gg.REGION_ANONYMOUS)
        x = "2576980464000" t = 32 searchNum()
        local count = gg.getResultsCount()
        if count == 0 then
            gg.alert("Error : Meoww Happened [1] - No results found")
            return nil
        end
        o = 0x8 t = 4 applyOffset()
        r1 = gg.getResults(1)
        x1 = r1[1].value
        o = 0x4 t = 4 applyOffset()
        r2 = gg.getResults(1)
        x2 = r2[1].value
        clearAll()
        x = "GameOfChanceReward"
        o = 0x3C t = 4 findClass()
        x = "65536" t = 4 refineNum()
        local count = gg.getResultsCount()
        if count == 0 then
            gg.alert("Error : Meoww Happened [2] - No results found")
            return nil
        end
        o = -0x4 t = 4 applyOffset()
        x = y2 t = 4 editAll()
        o = -0x4 t = 4 applyOffset()
        x = x2 t = 4 editAll()
        o = -0x4 t = 4 applyOffset()
        x = x1 t = 4 editAll()
        clearAll()
        gg.alert("🟡 Open Porspector Corner Now....", "", "")
        return nil
    end

    gg.setRanges(gg.REGION_ANONYMOUS)
    x = y1 t = 32 searchNum()
    local count = gg.getResultsCount()
    if count == 0 then
        gg.alert("Error : Meoww Happened [1] - No results found")
        return nil
    end

    o = 0x8 t = 4 applyOffset()
    r1 = gg.getResults(1)
    x1 = r1[1].value
    o = 0x4 t = 4 applyOffset()
    r2 = gg.getResults(1)
    x2 = r2[1].value
    clearAll()

    x = "GameOfChanceReward"
    o = 0x3C t = 4 findClass()
    x = 65536 t = 4 refineNum()
    count = gg.getResultsCount()
    if count == 0 then
        gg.alert("Error : Meoww Happened [2] - No refined results")
        return nil
    end

    o = -0x4 t = 4 applyOffset()
    x = y2 t = 4 editAll()
    o = -0x4 t = 4 applyOffset()
    x = x2 t = 4 editAll()
    o = -0x4 t = 4 applyOffset()
    x = x1 t = 4 editAll()
    clearAll()

    gg.alert("🟡 Open Porspector Corner Now....", "", "")
    return nil
end


function PC_OFF()
    return nil
end


function CEX_ON()
    injectAssembly(currentOffset.get_isCoopOrderExpired, true)
    gg.toast("- Enabled -")
    return true
end

function CEX_OFF()
    reset(currentOffset.get_isCoopOrderExpired)
    gg.toast("- Disabled -")
    return nil
end


function AWI_ON()
    setHex(currentOffset.CurrentUnix, "E0FF9FD2E0FF9FF2E0FFBFF2E0FFCFF2C0035FD6")
    gg.toast("- 🐷 Enabled -")
    return true
end

function AWI_OFF()
    reset(currentOffset.CurrentUnix)
    gg.toast("- Disabled -")
    return nil
end


-- function NC_ON()
    -- gg.alert("@credit - Ertan Hancer\n@ertanhancer", "","")
    -- local choice = gg.alert(
        -- "📝 TUTORIAL 📝\n-----------------\n" ..
        -- "1️⃣ Go to settings → rename your name to: 12345678901234567890\n" ..
        -- "2️⃣ Close settings and choose Step 1 complete\n" ..
        -- "3️⃣ Then choose Go to Step 2",
        -- "✅ OK, I understand",
        -- "✅ Step 1 complete",
        -- "✅ Go to Step 2"
    -- )

    -- -- Step 0: Copy Name
    -- if choice == 1 then
        -- gg.copyText("12345678901234567890")
        -- gg.toast("Name copied 📋")
        -- return
    -- end

    -- -- Step 1: Search & Patch
    -- if choice == 2 then
        -- -- Prompt for character length with maximum of 148
        -- local charLengthPrompt = gg.prompt(
            -- {"Enter character length (max 148):"},
            -- {63},
            -- {"number"}
        -- )
        
        -- if not charLengthPrompt then 
            -- gg.toast("❌ Cancelled")
            -- return 
        -- end
        
        -- local charLength = tonumber(charLengthPrompt[1]) or 63
        
        -- -- Enforce maximum limit of 148
        -- if charLength > 148 then
            -- charLength = 148
            -- gg.toast("Character length limited to 148")
        -- elseif charLength < 1 then
            -- charLength = 1
            -- gg.toast("Character length set to minimum 1")
        -- end
        
        -- gg.setRanges(gg.REGION_ANONYMOUS)
        -- gg.searchNumber(";12345678901234567890")
        -- o = -0x4 t = 4 applyOffset()
        -- x = 20 t = 4 refineNum()
        -- x = charLength -- Use the input character length
        -- t = 4 editAll()
        -- clearAll()
        -- gg.alert("✅ Done!\nRestart your game.\nThen choose 'Go to Step 2'.", "OK")
        -- return
    -- end

    -- -- Step 2: Rename
    -- if choice == 3 then
        -- gg.alert("🔑 Step 2: Change Name", "CONTINUE")

        -- local pr1 = gg.prompt({"Enter new name length:"}, {63}, {[1] = 'number'})
        -- if not pr1 then return end
        -- local nameLength = pr1[1]

        -- -- UTF16 Handling
        -- local function isUTF16(flag)
            -- return flag and ";" or ":", flag and 2 or 1
        -- end

        -- -- Replace name with new one
        -- local function setNewName(editname, playername)
            -- local stringTag, step = isUTF16(playername[2])
            -- local results = gg.getResults(gg.getResultsCount())
            -- local replace, sizes = {}, {}
            
            -- gg.clearResults()
            -- for _, res in ipairs(results) do
                -- sizes[#sizes+1] = {address = res.address - 0x4, flags = gg.TYPE_WORD}
                -- local addr = res.address
                -- for i = 1, #editname do
                    -- replace[#replace+1] = {address = addr, flags = gg.TYPE_WORD, value = string.byte(editname:sub(i,i))}
                    -- addr = addr + step
                -- end
            -- end
            
            -- sizes = gg.getValues(sizes)
            -- for i, v in ipairs(sizes) do
                -- if v.value == #playername[1] then
                    -- v.value = #editname
                -- end
            -- end

            -- gg.setValues(sizes)
            -- gg.setValues(replace)
            -- gg.alert("✅ New name set: " .. editname)
        -- end

        -- -- Search for name in memory
        -- local function findName64(playername, nameLength)
            -- local stringTag, step = isUTF16(playername[2])
            -- gg.setRanges(gg.REGION_ANONYMOUS)
            -- gg.searchNumber(stringTag .. playername[1])

            -- if gg.getResultsCount() == 0 then
                -- gg.toast("⚠️ Name not found, try again")
                -- return
            -- end

            -- local length = #playername[1]
            -- for i = 1, length do
                -- gg.refineNumber(stringTag .. playername[1]:sub(1, length))
                -- length = length - 1
            -- end

            -- -- Refinements (your fixed pattern)
            -- local refineVals = {3407923, 3538997, 3670071, 3145785}
            -- for _, val in ipairs(refineVals) do
                -- o = 0x4 t = 4 applyOffset()
                -- x = val t = 4 refineNum()
                -- gg.sleep(800)
            -- end

            -- o = -0x14 t = 4 applyOffset()
            -- x = nameLength t = 4 refineNum()
            -- o = -0x10 t = 4 applyOffset()
            -- x = "C351h~FFFF3CAFh" t = 4 refineNum()
            -- o = 0x14 t = 2 applyOffset()

            -- local newname = gg.prompt({"Enter new name:"}, nil, {[1] = 'text'})
            -- if newname and newname[1] ~= "" then
                -- setNewName(newname[1], playername)
            -- end
        -- end

        -- -- Start Step 2
        -- local playername = gg.prompt(
            -- {"Input current name to search", "UTF-16 Encoding"},
            -- {"12345678901234567890", true},
            -- {"text", "checkBox"}
        -- )

        -- if playername then
            -- findName64(playername, nameLength)
        -- end

        -- gg.toast("Step 2 complete ✅")
        -- return
    -- end

    -- -- Cancel
    -- gg.toast("❌ Cancelled")
    -- return nil
-- end


function NC_ON()
    gg.alert("@credit - Ertan Hancer\n@ertanhancer", "","")
    
    local choice = gg.alert(
        "📝 TUTORIAL 📝\n-----------------\n" ..
        "1️⃣ Go to settings → rename your name to: 12345678901234567890\n" ..
        "2️⃣ Close settings and choose Step 1 complete\n" ..
        "3️⃣ Then choose Go to Step 2",
        "✅ OK, I understand",
        "✅ Step 1 complete",
        "✅ Go to Step 2"
    )

    -- Step 0: Copy Name  
    if choice == 1 then  
        gg.copyText("12345678901234567890")  
        gg.toast("Name copied 📋")  
        return  
    end  

    -- Step 1: Search & Patch (Always use 63 characters)
    if choice == 2 then  
        local charLength = 63
        gg.setRanges(gg.REGION_ANONYMOUS)  
        gg.searchNumber(";12345678901234567890")  
        o = -0x4 t = 4 applyOffset()  
        x = 20 t = 4 refineNum()  
        x = charLength
        t = 4 editAll()  
        clearAll()  
        gg.alert("✅ Done!\nRestart your game.\nThen choose 'Go to Step 2'.", "OK")  
        return  
    end  

    -- Step 2: Rename with color options
    if choice == 3 then  
        gg.alert("🔑 Step 2: Change Name", "CONTINUE")  

        -- Always use 63 character length
        local nameLength = 63

        -- UTF16 Handling  
        local function isUTF16(flag)  
            return flag and ";" or ":", flag and 2 or 1  
        end  

        -- Color selection menu
        local colorChoice = gg.multiChoice({
            "🌈 Rainbow Color",
            "🔴 Red",
            "🟡 Yellow",
            "🟣 Purple",
            "🟢 Green",
            "🔵 Blue",
            "💖 Pink"
        }, nil, "🎨 Choose Name Color:")

        if not colorChoice then 
            gg.toast("❌ Color selection cancelled")
            return 
        end

        -- Get new name from user (minimum 7 characters)
        local newname = gg.prompt(
            {"Enter new name (min 7 characters):"}, 
            {""}, 
            {"text"}
        )
        
        if not newname or newname[1] == "" then
            gg.toast("❌ No name entered")
            return
        end
        
        -- Validate name length
        if #newname[1] < 7 then
            gg.alert("❌ Name must be at least 7 characters long!")
            return
        end
        
        -- Apply color formatting
        local coloredName = ""
        local colorCode = ""
        
        if colorChoice[1] then -- Rainbow
            local rainbowColors = {"ff0000", "ffa500", "ffff00", "008000", "0000ff", "4b0082", "ee82ee"}
            for i = 1, #newname[1] do
                local colorIndex = ((i-1) % #rainbowColors) + 1
                coloredName = coloredName .. "[" .. rainbowColors[colorIndex] .. "]" .. newname[1]:sub(i, i)
            end
        elseif colorChoice[2] then -- Red
            colorCode = "ff0000"
        elseif colorChoice[3] then -- Yellow
            colorCode = "ffff00"
        elseif colorChoice[4] then -- Purple
            colorCode = "4b0082"
        elseif colorChoice[5] then -- Green
            colorCode = "008000"
        elseif colorChoice[6] then -- Blue
            colorCode = "0000ff"
        elseif colorChoice[7] then -- Pink
            colorCode = "ee82ee"
        end
        
        -- For single colors, apply to all characters
        if colorCode ~= "" then
            for i = 1, #newname[1] do
                coloredName = coloredName .. "[" .. colorCode .. "]" .. newname[1]:sub(i, i)
            end
        end

        -- Replace name with new one  
        local function setNewName(editname, playername)  
            local stringTag, step = isUTF16(playername[2])  
            local results = gg.getResults(gg.getResultsCount())  
            local replace, sizes = {}, {}  
              
            gg.clearResults()  
            for _, res in ipairs(results) do  
                sizes[#sizes+1] = {address = res.address - 0x4, flags = gg.TYPE_WORD}  
                local addr = res.address  
                for i = 1, #editname do  
                    replace[#replace+1] = {address = addr, flags = gg.TYPE_WORD, value = string.byte(editname:sub(i,i))}  
                    addr = addr + step  
                end  
            end  
              
            sizes = gg.getValues(sizes)  
            for i, v in ipairs(sizes) do  
                if v.value == #playername[1] then  
                    v.value = #editname  
                end  
            end  

            gg.setValues(sizes)  
            gg.setValues(replace)  
            gg.alert("✅ New name set: " .. editname)  
        end  

        -- Search for name in memory (automatically search for 12345678901234567890)
        local function findName64(nameLength)  
            local playername = {"12345678901234567890", true}
            local stringTag, step = isUTF16(playername[2])  
            gg.setRanges(gg.REGION_ANONYMOUS)  
            gg.searchNumber(stringTag .. playername[1])  

            if gg.getResultsCount() == 0 then  
                gg.toast("⚠️ Name not found, try again")  
                return  
            end  

            local length = #playername[1]  
            for i = 1, length do  
                gg.refineNumber(stringTag .. playername[1]:sub(1, length))  
                length = length - 1  
            end  

            -- Refinements (your fixed pattern)  
            local refineVals = {3407923, 3538997, 3670071, 3145785}  
            for _, val in ipairs(refineVals) do  
                o = 0x4 t = 4 applyOffset()  
                x = val t = 4 refineNum()  
                gg.sleep(800)  
            end  

            o = -0x14 t = 4 applyOffset()  
            x = nameLength t = 4 refineNum()  
            o = -0x10 t = 4 applyOffset()  
            x = "C351h~FFFF3CAFh" t = 4 refineNum()  
            o = 0x14 t = 2 applyOffset()  

            setNewName(coloredName, playername)  
        end  

        -- Start Step 2  
        findName64(nameLength)  
        gg.toast("Step 2 complete ✅")  
        return  
    end  

    -- Cancel  
    gg.toast("❌ Cancelled")  
    return nil
end


function NC_OFF()
    gg.toast("- Hollyy Meowwwww -")
    return nil
end


function RBM_ON()
    local userInput = gg.prompt(
        { 'Enter Bonus Task Points (1~100):' },
        nil,
        { [1] = 'number' }
    )

    if userInput == nil then 
        return -- user cancelled input
    end

    local bonusTask = tonumber(userInput[1])

    -- Validation
    if not (bonusTask and bonusTask >= 1 and bonusTask <= 100) then
        gg.alert("Invalid input! Please enter a value between 1 and 100.")
        return
    end

    -- Bonus Task Patch
    injectAssembly(currentOffset.get_bonusTaskCount, bonusTask)

    gg.toast("- Bonus Task set to [" .. bonusTask .. "]")
    return true
end

function RBM_OFF()
    reset(currentOffset.get_bonusTaskCount)
    gg.toast("- Restored Bonus Task -")
    return nil
end

function SPN_ON()
    injectAssembly(currentOffset.get_SpinLeft, 9999)
    gg.toast("- Activated -")
    return true
end

function SPN_OFF()
    reset(currentOffset.get_SpinLeft)
    gg.toast("- Restored -")
    return nil
end

----------- MENU -----------

gg.setVisible(true)
local menuList = {
    -- 🐾 Items & Selling
    "❄️ Freez All Items",
    "💰 Sell Goods For Free",
    "💰 Sell Anything In Farm",
    "🎉 Porspector Corner Item",

    -- 💰 Expansions & Buildings
    "💰 Expend Farm With Coins",
    "⛩️ Upgrade All Buildings",

    -- 🗝️ Costs & Keys
    "🗝️ Item Cost 0 Key",
    "🆓 Porspector Corner Free Play",

    -- 🐷 Animals
    "🐷 One Feed Gold",
    "🐷 Show Animal Wiegh-in",

    -- 🏕️ Farming & Barn
    "🏕️ Fast Farming",
    "🐾 Set Barn Seaway",
    "💂 Farm Hands Always Available For Use",

    -- 🙌 Helpers
    "🙌 Request Farmhands",
    "🎁 Send Helping Hands",

    -- ⚡ Quest & Orders
    "⚡ Quest Book Fast Finish",
    "📝 Maries Orders Ask Button",
    "🛒 Maries Orders Sell Active",
    "📋 Marie Order Item Amount",
    "📋 Maries Board Get/Send Xp, Coin, Timber",
    "🎯 Maries Order Weekly Score",

    -- 🛒 Market
    "🛒 Auto Buy (Market)",
    "🎖️ Active Hidden Market Items",

    -- 🎄 Fair & Workshops
    "🎄 Country Fair Workshop Multiplier",
    "⛏️ Workshops Crafting Amount",

    -- 🎰 Co-Op
    "🎰 Enable 8 Co-Op Slots",
    "⛔ Co-op Order Instant Expire",

    -- 🙃 Chat & Social
    "🙃 Unlock Chat Emoji",
    "🌈 Edit UserName With Rainbow Colour",

    -- ⛵ Boat Race
    "⛵ (Br) Bonus Task Points",
    "⛵ (Br) Set Bonus Task Points",
    "⛵ (Br) Unlimited Discard Task",
    "⛵ (Br) Enter Bonus Mode",
    "⛵ (Br) Bonus Task Skip Price",
    "⛵ (Br) Task Requirement (1)",

    -- ♻️ Wheel & Spins
    "♻️ Prize Whell Unlimited Spins",

    -- ⭐ Decoration
    "⭐ Unlimited Decoration",

    -- 🔓 Unlocks & Passes
    "🔓 Unlock Hairloom Pass",
    "🔓 Unlock Mystery Master Pass",
    "🔓 Unlock Elite Plus Badge",
    "🔓 Unlock Event Pass",

    -- 🎃 Elite Features
    "🎃 Auto Complete Elite Tokens",
    "🧩 Get Elite Badge Tokens",

    -- 🤷 Place & Entity
    "🤷 Place Entity Anywhere (Water/Land)",

    -- 🔓 Unlimited Resources
    "🔓 Unlimited Crops, Animals, Key Maker",

    -- 🔥 Water Items
    "🔥 Get Event Items (From Water)",
    "⚽ Get Normal Items (From Water)",

    -- 🚫 Exit
    "🚫 Exit Script...."
}

-- 🌐 Auto-translate menu
gg.setVisible(false)
gg.toast("- Translation Started.....-")
for i, v in ipairs(menuList) do
    menuList[i] = Translate(v, "en", TargetLang)
end
gg.toast("- Translation Completed! -")
gg.setVisible(true)

-- The rest of your code remains exactly the same...
local checkList = {
    nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
    nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
    nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
    nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
    nil, nil, nil, nil, nil, nil, nil
}

-- All function definitions remain exactly the same...
function menu()
    local tsu = gg.multiChoice(menuList, checkList, "🌹 Script By : @CheatCode\n🔖 Bypass Protection Is Running.....\n🟢 Script Mode : Full Safe\n────୨ৎ────────୨ৎ────")
    if not tsu  then
        return
    end
    -- All the if statements for each option remain exactly the same...
    -- Only the order of checks has changed to match the new menu organization
    if tsu[1] ~= checkList[1]  then
        if tsu[1]  then
            checkList[1] = Remove_ON()
        else
            checkList[1] = Remove_OFF()
        end
    end
    if tsu[2] ~= checkList[2]  then
        if tsu[2]  then
            checkList[2] = SG_ON()
        else
            checkList[2] = SG_OFF()
        end
    end
    if tsu[3] ~= checkList[3]  then
        if tsu[3]  then
            checkList[3] = SE_ON()
        else
            checkList[3] = SE_OFF()
        end
    end
    if tsu[4] ~= checkList[4]  then
        if tsu[4]  then
            checkList[4] = PC_ON()
        else
            checkList[4] = PC_OFF()
        end
    end
    if tsu[5] ~= checkList[5]  then
        if tsu[5]  then
            checkList[5] = CanExpandWithCoins_ON()
        else
            checkList[5] = CanExpandWithCoins_OFF()
        end
    end
    if tsu[6] ~= checkList[6]  then
        if tsu[6]  then
            checkList[6] = UB_ON()
        else
            checkList[6] = UB_OFF()
        end
    end
    if tsu[7] ~= checkList[7]  then
        if tsu[7]  then
            checkList[7] = ItemCost_ON()
        else
            checkList[7] = ItemCost_OFF()
        end
    end
    if tsu[8] ~= checkList[8]  then
        if tsu[8]  then
            checkList[8] = ProspectorCornerFreePlay_ON()
        else
            checkList[8] = ProspectorCornerFreePlay_OFF()
        end
    end
    if tsu[9] ~= checkList[9]  then
        if tsu[9]  then
            checkList[9] = OFG_ON()
        else
            checkList[9] = OFG_OFF()
        end
    end
    if tsu[10] ~= checkList[10]  then
        if tsu[10]  then
            checkList[10] = AWI_ON()
        else
            checkList[10] = AWI_OFF()
        end
    end
    if tsu[11] ~= checkList[11]  then
        if tsu[11]  then
            checkList[11] = FFC_ON()
        else
            checkList[11] = FFC_OFF()
        end
    end
    if tsu[12] ~= checkList[12]  then
        if tsu[12]  then
            checkList[12] = SetBarnSeaway_ON()
        else
            checkList[12] = SetBarnSeaway_OFF()
        end
    end
    if tsu[13] ~= checkList[13]  then
        if tsu[13]  then
            checkList[13] = HH_ON()
        else
            checkList[13] = HH_OFF()
        end
    end
    if tsu[14] ~= checkList[14]  then
        if tsu[14]  then
            checkList[14] = FHND_ON()
        else
            checkList[14] = FHND_OFF()
        end
    end
    if tsu[15] ~= checkList[15]  then
        if tsu[15]  then
            checkList[15] = SHND_ON()
        else
            checkList[15] = SHND_OFF()
        end
    end
    if tsu[16] ~= checkList[16]  then
        if tsu[16]  then
            checkList[16] = QuestBookFastFinish_ON()
        else
            checkList[16] = QuestBookFastFinish_OFF()
        end
    end
    if tsu[17] ~= checkList[17]  then
        if tsu[17]  then
            checkList[17] = MariesOrdersAskButton_ON()
        else
            checkList[17] = MariesOrdersAskButton_OFF()
        end
    end
    if tsu[18] ~= checkList[18]  then
        if tsu[18]  then
            checkList[18] = MariesOrdersSellActive_ON()
        else
            checkList[18] = MariesOrdersSellActive_OFF()
        end
    end
    if tsu[19] ~= checkList[19]  then
        if tsu[19]  then
            checkList[19] = MIA_ON()
        else
            checkList[19] = MIA_OFF()
        end
    end
    if tsu[20] ~= checkList[20]  then
        if tsu[20]  then
            checkList[20] = MB_ON()
        else
            checkList[20] = MB_OFF()
        end
    end
    if tsu[21] ~= checkList[21]  then
        if tsu[21]  then
            checkList[21] = MWS_ON()
        else
            checkList[21] = MWS_OFF()
        end
    end
    if tsu[22] ~= checkList[22]  then
        if tsu[22]  then
            checkList[22] = AutoBuyMarket_ON()
        else
            checkList[22] = AutoBuyMarket_OFF()
        end
    end
    if tsu[23] ~= checkList[23]  then
        if tsu[23]  then
            checkList[23] = AHM_ON()
        else
            checkList[23] = AHM_OFF()
        end
    end
    if tsu[24] ~= checkList[24]  then
        if tsu[24]  then
            checkList[24] = GetCountyFairPointsMultiplierForBuildingLevel_ON()
        else
            checkList[24] = GetCountyFairPointsMultiplierForBuildingLevel_OFF()
        end
    end
    if tsu[25] ~= checkList[25]  then
        if tsu[25]  then
            checkList[25] = WorkshopsCraftingAmount_ON()
        else
            checkList[25] = WorkshopsCraftingAmount_OFF()
        end
    end
    if tsu[26] ~= checkList[26]  then
        if tsu[26]  then
            checkList[26] = CoopSlots8_ON()
        else
            checkList[26] = CoopSlots8_OFF()
        end
    end
    if tsu[27] ~= checkList[27]  then
        if tsu[27]  then
            checkList[27] = CEX_ON()
        else
            checkList[27] = CEX_OFF()
        end
    end
    if tsu[28] ~= checkList[28]  then
        if tsu[28]  then
            checkList[28] = UnlockChatEmoji_ON()
        else
            checkList[28] = UnlockChatEmoji_OFF()
        end
    end
    if tsu[29] ~= checkList[29]  then
        if tsu[29]  then
            checkList[29] = NC_ON()
        else
            checkList[29] = NC_OFF()
        end
    end
    if tsu[30] ~= checkList[30]  then
        if tsu[30]  then
            checkList[30] = BonusTaskPoints_ON()
        else
            checkList[30] = BonusTaskPoints_OFF()
        end
    end
    if tsu[31] ~= checkList[31]  then
        if tsu[31]  then
            checkList[31] = RBM_ON()
        else
            checkList[31] = RBM_OFF()
        end
    end
    if tsu[32] ~= checkList[32]  then
        if tsu[32]  then
            checkList[32] = UnlimitedBRDiscardTask_ON()
        else
            checkList[32] = UnlimitedBRDiscardTask_OFF()
        end
    end
    if tsu[33] ~= checkList[33]  then
        if tsu[33]  then
            checkList[33] = EnterBonusMode_ON()
        else
            checkList[33] = EnterBonusMode_OFF()
        end
    end
    if tsu[34] ~= checkList[34]  then
        if tsu[34]  then
            checkList[34] = BonusTaskSkipPrice_ON()
        else
            checkList[34] = BonusTaskSkipPrice_OFF()
        end
    end
    if tsu[35] ~= checkList[35]  then
        if tsu[35]  then
            checkList[35] = BoatRaceTaskRequirement_ON()
        else
            checkList[35] = BoatRaceTaskRequirement_OFF()
        end
    end
    if tsu[36] ~= checkList[36]  then
        if tsu[36]  then
            checkList[36] = SPN_ON()
        else
            checkList[36] = SPN_OFF()
        end
    end
    if tsu[37] ~= checkList[37]  then
        if tsu[37]  then
            checkList[37] = Deco_ON()
        else
            checkList[37] = Deco_OFF()
        end
    end
    if tsu[38] ~= checkList[38]  then
        if tsu[38]  then
            checkList[38] = HPass_ON()
        else
            checkList[38] = HPass_OFF()
        end
    end
    if tsu[39] ~= checkList[39]  then
        if tsu[39]  then
            checkList[39] = MPass_ON()
        else
            checkList[39] = MPass_OFF()
        end
    end
    if tsu[40] ~= checkList[40]  then
        if tsu[40]  then
            checkList[40] = ELPass_ON()
        else
            checkList[40] = ELPass_OFF()
        end
    end
    if tsu[41] ~= checkList[41]  then
        if tsu[41]  then
            checkList[41] = EVP_ON()
        else
            checkList[41] = EVP_OFF()
        end
    end
    if tsu[42] ~= checkList[42]  then
        if tsu[42]  then
            checkList[42] = ELtoken_ON()
        else
            checkList[42] = ELtoken_OFF()
        end
    end
    if tsu[43] ~= checkList[43]  then
        if tsu[43]  then
            checkList[43] = ELItoken_ON()
        else
            checkList[43] = ELItoken_OFF()
        end
    end
    if tsu[44] ~= checkList[44]  then
        if tsu[44]  then
            checkList[44] = PEA_ON()
        else
            checkList[44] = PEA_OFF()
        end
    end
    if tsu[45] ~= checkList[45]  then
        if tsu[45]  then
            checkList[45] = UC_ON()
        else
            checkList[45] = UC_OFF()
        end
    end
    if tsu[46] ~= checkList[46]  then
        if tsu[46]  then
            checkList[46] = EVI_ON()
        else
            checkList[46] = EVI_OFF()
        end
    end
    if tsu[47] ~= checkList[47]  then
        if tsu[47]  then
            checkList[47] = ITM_ON()
        else
            checkList[47] = ITM_OFF()
        end
    end
    if tsu[48]  then
        gg.getListItems()
        gg.clearList()
        print("────୨ৎ────────୨ৎ────")
        print("TG : @BadLuck_69")
        print("YT : CheatCode Revolution")
        print("────୨ৎ────────୨ৎ────")
        os.exit()
    end
end
while true  do
    if gg.isVisible(true)  then
        gg.setVisible(false)
        menu()
    end
    gg.sleep(100)
end