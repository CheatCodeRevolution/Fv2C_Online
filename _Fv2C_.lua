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
  Remove=0x3151B78, --SVInventory::Remove
  CanExpandWithCoins=0x31FEC10, --LandExpansionManager::CanExpandWithCoins
  GetItemCost=0x31E1610, --ItemManager::GetItemCost
  GetFastFinishCost=0x34B7B48, --SVFastFinish::GetFastFinishCost
  CalculateBuyThroughCost=0x28267AC, --MerchantOfferCell::CalculateBuyThroughCost
  GetCraftingTimeMultiplierForBuildingLevel=0x2978764, --UpgradeableBuilding::GetCraftingTimeMultiplierForBuildingLevel
  get_KnightRequestIntervalSeconds=0x2D97A58, --AllianceKnightsManager::get_KnightRequestIntervalSeconds
  get_HandsToSend=0x2D998A0, --AllianceManager::get_HandsToSend
  CreateOffer=0x365A090+0x34, --SeafarerManager::CreateOffer
  MariesOrdersAskButton=0x25FA744, --CoopOrderCard_ViewModel::get_getAmountHas
  MariesOrdersSellActive=0x25FA8E4, --CoopOrderCard_ViewModel::get_getAmountRequired
  AutoBuyMarket=0x3651014, --SeafarerManager::GetAutoBuyTime
  GetCountyFairPointsMultiplierForBuildingLevel=0x297C7D4, --UpgradeableBuilding::GetCountyFairPointsMultiplierForBuildingLevel
  WorkshopsCraftingAmount=0x29CC844+0x38, --WorkshopManager::StartCrafting
  CoopSlots8=0x3654C68, --SeafarerManager::GetNumCoopOnlySlotsInUse
  UnlockChatEmoji_1=0x307027C+0x20, --GameExpression::canShowThanksGivingStickers
  UnlockChatEmoji_2=0x30703B8+0x20, --GameExpression::canShowChristmasStickers
  ProspectorCornerFreePlay=0x3771E00, --GameOfChanceGame::CanPlayForFree
  SetBarnSeaway=0x3509628, --ProtoStorageLevel::get_totalItemsCount
  get_IsCheaterFixOn=0x370B574, --BoatRaceV4Context::get_IsCheaterFixOn
  get_CheaterTrackingEnabled=0x36FB3D0, --BoatRaceV4Context::get_CheaterTrackingEnabled
  set_CheaterTrackingEnabled=0x36FB3D8, --BoatRaceV4Context::set_CheaterTrackingEnabled
  CheaterFixedScore=0x3707B60, --BoatRaceV4Context::CheaterFixedScore
  get_Suspended=0x2CBB3E4, --ZyngaUsersession::get_Suspended
  set_Suspended=0x2CBB3EC, --ZyngaUsersession::set_Suspended
  Start=0x29E030C, --ZyngaPlayerSuspensionManager::Start
  get_amount=0x3270E7C, --ProtoQuestReward::get_amount
  get_GetCurrentLeaguePersonalQuota=0x36D3788, --BoatRaceLeagueManager::get_GetCurrentLeaguePersonalQuota
  get_personalQuotaCompleted=0x2B88C08, --BaseBoatRaceContext::get_personalQuotaCompleted
  get_GetBonusTaskSkipPrice=0x25E824C, --BoatRace_TaskTabViewModel::get_GetBonusTaskSkipPrice
  getAmount=0x3271F00, --ProtoQuestTask::getAmount
  set_MyWeeklyContribution=0x3734C48+0x28, --CoopOrderHelpContext::set_MyWeeklyContribution
  
  },
  -- ["1.2.4"] = {
  -- Remove=0x40afe28, 
  -- CanExpandWithCoins=0x41853b8
  -- },
}

local version = gg.getTargetInfo().versionName
local currentOffset = offsets[version]
if not currentOffset then
  gg.alert("🤷 Game version is too old or not supported!\n🔖 Current Version: " .. version, "","")
  os.exit()
end

gg.toast("Bypass Is Running Please Waite...!!")
setValue(currentOffset.get_IsCheaterFixOn, 4, "~A8 RET") 
setValue(currentOffset.get_CheaterTrackingEnabled, 4, "~A8 RET")
setValue(currentOffset.set_CheaterTrackingEnabled, 4, "~A8 RET")
setValue(currentOffset.CheaterFixedScore, 4, "~A8 RET")
setValue(currentOffset.get_Suspended, 4, "~A8 RET")
setValue(currentOffset.set_Suspended, 4, "~A8 RET")
setValue(currentOffset.Start, 4, "~A8 RET")


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
    setValue(currentOffset.CreateOffer, 4, "~A8 MOV W22, WZR")
    gg.toast("- Hack Enabled -")
    return true
end
function SG_OFF()
    reset(currentOffset.CreateOffer)
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
    setHex(currentOffset.MariesOrdersAskButton, "00 00 80 D2 C0 03 5F D6")
    gg.toast("- Maries Orders Ask Button Enabled -")
    return true
end

function MariesOrdersAskButton_OFF()
    reset(currentOffset.MariesOrdersAskButton)
    gg.toast("- Maries Orders Ask Button Disabled -")
    return nil
end

function MariesOrdersSellActive_ON()
    setHex(currentOffset.MariesOrdersSellActive, "00 00 80 D2 C0 03 5F D6")
    gg.toast("- Maries Orders Sell Active Enabled -")
    return true
end

function MariesOrdersSellActive_OFF()
    reset(currentOffset.MariesOrdersSellActive)
    gg.toast("- Maries Orders Sell Active Disabled -")
    return nil
end

function AutoBuyMarket_ON()
    setHex(currentOffset.AutoBuyMarket, "20 00 80 D2 C0 03 5F D6")
    gg.toast("- Auto Buy (Market) Enabled -")
    return true
end

function AutoBuyMarket_OFF()
    reset(currentOffset.AutoBuyMarket)
    gg.toast("- Auto Buy (Market) Disabled -")
    return nil
end


function GetCountyFairPointsMultiplierForBuildingLevel_ON()
  local pr = gg.prompt({'Enter Workshop Points Multiplier (float):'}, nil, {[1] = 'number'})
  if pr == nil then return end
  local inputVal = tonumber(pr[1])
  if inputVal == nil then
    gg.alert('Invalid input')
    return
  end
  local getCountyhex = hexGF(inputVal)
  setHex(currentOffset.GetCountyFairPointsMultiplierForBuildingLevel, getCountyhex)
  gg.toast('- ⚒️ Workshop Points Multiplier set to ' .. inputVal .. ' -')
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
    I[1] = currentOffset.WorkshopsCraftingAmount

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
    setHex(currentOffset.CoopSlots8, "00 00 80 D2 C0 03 5F D6")
    gg.toast("- Enable 8 Co-op slots Enabled -")
    return true
end

function CoopSlots8_OFF()
    reset(currentOffset.CoopSlots8)
    gg.toast("- Enable 8 Co-op slots Disabled -")
    return nil
end

function UnlockChatEmoji_ON()
    setValue(currentOffset.UnlockChatEmoji_1, 4, "~A8 MOV X19, XZR")
    setValue(currentOffset.UnlockChatEmoji_2, 4, "~A8 MOV X19, XZR")
    gg.toast("- Unlock Chat Emoji Enabled -")
    return true
end

function UnlockChatEmoji_OFF()
    reset(currentOffset.UnlockChatEmoji_1)
    reset(currentOffset.UnlockChatEmoji_2)
    gg.toast("- Unlock Chat Emoji Disabled -")
    return nil
end


function ProspectorCornerFreePlay_ON()
    setHex(currentOffset.ProspectorCornerFreePlay, "20 00 80 D2 C0 03 5F D6")
    gg.toast("- PORSPECTOR CORNER FREE PLAY Enabled -")
    return true
end

function ProspectorCornerFreePlay_OFF()
    reset(currentOffset.ProspectorCornerFreePlay)
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
        injectAssembly(currentOffset.SetBarnSeaway, userInput) -- 32-bit int inject
        gg.toast("- Set Barn Seaway: " .. userInput .. " -")
    elseif userInput < 0 then
        -- Negative number branch: generate hex patch via hexG & setHex
        local hexValue = hexG(userInput)
        if hexValue then
            setHex(currentOffset.SetBarnSeaway, hexValue)
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
    reset(currentOffset.SetBarnSeaway)
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
    return nil
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
    return nil
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
  checkResults() if E==0 then gg.alert("Sorry something wrong happened") return end
  o=0x10 t=32 applyOffset()
  o=0x10 t=32 sv=strv1 checkString()
  o=0x14 t=32 sv=strv2 checkString()
  o=0x18 t=32 sv=strv3 checkString()
  o=0x1C t=32 sv=strv4 checkString()
  o=0xC8 t=4 applyOffset()
  x=0 t=4 editAll()
  freezeValues()
  clearAll()
  setValue(currentOffset.set_MyWeeklyContribution, 4, "~A8 MOV W20, #0x64")
  gg.toast("- Marie weekly score enabled -")
  return true
end


function MWS_OFF()
    reset(currentOffset.set_MyWeeklyContribution)
    gg.toast("- Weekly  Score Disabled-")
    return nil
end




----------- MENU -----------

gg.setVisible(true)
local menuList = {
    "❄️ FREEZ ALL ITEMS",
    "🪙 EXPEND FARM WITH COINS",
    "🗝️ ITEM COST 0 KEY",
    "🏕️ FAST FARMING",
    "🙌 REQUEST FARMHANDS",
    "🎁 SEND HELPING HANDS",
    "💰 SELL GOODS FOR FREE",
    "⚡ QUEST BOOK FAST FINISH",
    "📝 MARIES ORDERS ASK BUTTON",
    "🛒 MARIES ORDERS SELL ACTIVE",
    "🛒 AUTO BUY (MARKET)",
    "🎲 COUNTRY FAIR WORKSHOP MULTIPLIER",
    "⛏️ WORKSHOPS CRAFTING AMOUNT",
    "🎰 ENABLE 8 CO-OP SLOTS",
    "🙃 UNLOCK CHAT EMOJI",
    "🆓 PORSPECTOR CORNER FREE PLAY",
    "🐾 SET BARN SEAWAY",
    "⛵ (BR) BONUS TASK POINTS",
    "⛵ (BR) UNLIMITED DISCARD TASK",
    "⛵ (BR) ENTER BONUS MODE",
    "⛵ (BR) BONUS TASK SKIP PRICE",
    "⛵ (BR) TASK REQUIREMENT (1)",
    "🪩 UNLIMITED DECORATION",
    "🎖️ ACTIVE HIDDEN MARKET ITEMS",
    "🫅 MARIES ORDER WEEKLY SCORE",
    "🚫 EXIT SCRIPT...."
}

-- 🌐 Auto-translate menu
gg.setVisible(false)
for i, v in ipairs(menuList) do
    menuList[i] = Translate(v, "en", TargetLang)
end
gg.toast("- Translation Completed! -")
gg.setVisible(true)
local checkList = {
    nil,
    nil,
    nil,
    nil,
    nil,
    nil,
    nil,
    nil,
    nil,
    nil,
    nil,
    nil,
    nil,
    nil,
    nil,
    nil,
    nil,
    nil,
    nil,
    nil,
    nil,
    nil,
    nil,
    nil,
    nil,
    nil
}


function menu()
    local tsu = gg.multiChoice(menuList, checkList, "Script By : @CheatCode\n────୨ৎ────────୨ৎ────")
    if not tsu then return end

    if tsu[1] ~= checkList[1] then
        if tsu[1] then
            checkList[1] = Remove_ON()
        else
            checkList[1] = Remove_OFF()
        end
    end

    if tsu[2] ~= checkList[2] then
        if tsu[2] then
            checkList[2] = CanExpandWithCoins_ON()
        else
            checkList[2] = CanExpandWithCoins_OFF()
        end
    end

    if tsu[3] ~= checkList[3] then
        if tsu[3] then
            checkList[3] = ItemCost_ON()
        else
            checkList[3] = ItemCost_OFF()
        end
    end

    if tsu[4] ~= checkList[4] then
        if tsu[4] then
            checkList[4] = FFC_ON()
        else
            checkList[4] = FFC_OFF()
        end
    end

    if tsu[5] ~= checkList[5] then
        if tsu[5] then
            checkList[5] = FHND_ON()
        else
            checkList[5] = FHND_OFF()
        end
    end

    if tsu[6] ~= checkList[6] then
        if tsu[6] then
            checkList[6] = SHND_ON()
        else
            checkList[6] = SHND_OFF()
        end
    end

    if tsu[7] ~= checkList[7] then
        if tsu[7] then
            checkList[7] = SG_ON()
        else
            checkList[7] = SG_OFF()
        end
    end

    if tsu[8] ~= checkList[8] then
        if tsu[8] then
            checkList[8] = QuestBookFastFinish_ON()
        else
            checkList[8] = QuestBookFastFinish_OFF()
        end
    end

    if tsu[9] ~= checkList[9] then
        if tsu[9] then
            checkList[9] = MariesOrdersAskButton_ON()
        else
            checkList[9] = MariesOrdersAskButton_OFF()
        end
    end

    if tsu[10] ~= checkList[10] then
        if tsu[10] then
            checkList[10] = MariesOrdersSellActive_ON()
        else
            checkList[10] = MariesOrdersSellActive_OFF()
        end
    end

    if tsu[11] ~= checkList[11] then
        if tsu[11] then
            checkList[11] = AutoBuyMarket_ON()
        else
            checkList[11] = AutoBuyMarket_OFF()
        end
    end

    if tsu[12] ~= checkList[12] then
        if tsu[12] then
            checkList[12] = GetCountyFairPointsMultiplierForBuildingLevel_ON()
        else
            checkList[12] = GetCountyFairPointsMultiplierForBuildingLevel_OFF()
        end
    end

    if tsu[13] ~= checkList[13] then
        if tsu[13] then
            checkList[13] = WorkshopsCraftingAmount_ON()
        else
            checkList[13] = WorkshopsCraftingAmount_OFF()
        end
    end

    if tsu[14] ~= checkList[14] then
        if tsu[14] then
            checkList[14] = CoopSlots8_ON()
        else
            checkList[14] = CoopSlots8_OFF()
        end
    end

    if tsu[15] ~= checkList[15] then
        if tsu[15] then
            checkList[15] = UnlockChatEmoji_ON()
        else
            checkList[15] = UnlockChatEmoji_OFF()
        end
    end

    if tsu[16] ~= checkList[16] then
        if tsu[16] then
            checkList[16] = ProspectorCornerFreePlay_ON()
        else
            checkList[16] = ProspectorCornerFreePlay_OFF()
        end
    end
    
    if tsu[17] ~= checkList[17] then
        if tsu[17] then
            checkList[17] = SetBarnSeaway_ON()
        else
            checkList[17] = SetBarnSeaway_OFF()
       end
    end
    
    if tsu[18] ~= checkList[18] then
  if tsu[18] then
    checkList[18] = BonusTaskPoints_ON()
  else
    checkList[18] = BonusTaskPoints_OFF()
  end
end

if tsu[19] ~= checkList[19] then
  if tsu[19] then
    checkList[19] = UnlimitedBRDiscardTask_ON()
  else
    checkList[19] = UnlimitedBRDiscardTask_OFF()
  end
end


if tsu[20] ~= checkList[20] then
    if tsu[20] then
        checkList[20] = EnterBonusMode_ON()
    else
        checkList[20] = EnterBonusMode_OFF()
    end
end

if tsu[21] ~= checkList[21] then
    if tsu[21] then
        checkList[21] = BonusTaskSkipPrice_ON()
    else
        checkList[21] = BonusTaskSkipPrice_OFF()
    end
end

if tsu[22] ~= checkList[22] then
    if tsu[22] then
        checkList[22] = BoatRaceTaskRequirement_ON()
    else
        checkList[22] = BoatRaceTaskRequirement_OFF()
    end
end

if tsu[23] ~= checkList[23] then
    if tsu[23] then
        checkList[23] = Deco_ON()
    else
        checkList[23] = Deco_OFF()
    end
end

if tsu[24] ~= checkList[24] then
    if tsu[24] then
        checkList[24] = AHM_ON()
    else
        checkList[24] = AHM_OFF()
    end
end

if tsu[25] ~= checkList[25] then
    if tsu[25] then
        checkList[25] = MWS_ON()
    else
        checkList[25] = MWS_OFF()
    end
end







    if tsu[26] then
        print("────୨ৎ────────୨ৎ────")
        print("TG : @BadLuck_69")
        print("YT : CheatCode Revolution")
        print("────୨ৎ────────୨ৎ────")
        os.exit()
    end
end

while true do
    if gg.isVisible(true) then
        gg.setVisible(false)
        menu()
    end
    gg.sleep(100)
end
