-- test_pdu_framing.lua
--
-- Regression tests for TCP protobuf PDU framing (split, sticky, undersize,
-- oversize/overflow, truncated-at-length-field).  Extracts the
-- "-- BEGIN EVIL_FRAMING" .. "-- END EVIL_FRAMING" block from packet-evil.lua
-- and exercises it with a plain Lua interpreter (no Wireshark, no build).
--
-- Run from the repository root or from lua/:
--   lua lua/test_pdu_framing.lua
--
-- SPDX-License-Identifier: GPL-2.0-or-later

local function script_dir()
    local src = debug.getinfo(1, "S").source
    if type(src) == "string" and src:sub(1, 1) == "@" then
        local dir = src:sub(2):match("^(.*[/\\])")
        if dir and dir ~= "" then
            return dir
        end
    end
    return "./"
end

local function load_framing()
    local path = script_dir() .. "packet-evil.lua"
    local f, err = io.open(path, "r")
    if not f then
        error("cannot open " .. path .. ": " .. tostring(err))
    end
    local src = f:read("*a")
    f:close()
    local block = src:match("%-%- BEGIN EVIL_FRAMING\n(.-)\n%-%- END EVIL_FRAMING")
    if not block then
        error("EVIL_FRAMING block not found in " .. path)
    end
    local chunk, load_err = load(block, path .. ":EVIL_FRAMING", "t")
    if not chunk then
        error("failed to load framing block: " .. tostring(load_err))
    end
    chunk()
    if not evil_framing or type(evil_framing.decide) ~= "function" then
        error("evil_framing.decide was not defined by the framing block")
    end
    return evil_framing
end

local framing = load_framing()
local failed = 0
local passed = 0

local function fail(msg)
    failed = failed + 1
    io.stderr:write("[FAIL] " .. msg .. "\n")
end

local function pass(name)
    passed = passed + 1
    print("[PASS] " .. name)
end

local function check(cond, name, detail)
    if cond then
        pass(name)
    else
        fail(name .. (detail and (": " .. detail) or ""))
    end
end

-- Walk a byte string as the Lua dissector loop does (without Wireshark).
local function split_pdus(buf)
    local offset = 0
    local results = {}
    local n = #buf
    while offset < n do
        local remaining = n - offset
        if remaining < framing.LEN_FIELD_SIZE then
            results[#results + 1] = {
                status = "need_more",
                offset = offset,
                need = 0,
            }
            break
        end
        local b1, b2, b3, b4 = buf:byte(offset + 1, offset + 4)
        local datasize = b1 * 0x1000000 + b2 * 0x10000 + b3 * 0x100 + b4
        local d = framing.decide(remaining, datasize)
        if d.status == "malformed" then
            results[#results + 1] = {
                status = "malformed",
                offset = offset,
                reason = d.reason,
                datasize = datasize,
            }
            break
        elseif d.status == "need_more" then
            results[#results + 1] = {
                status = "need_more",
                offset = offset,
                need = d.need,
                datasize = datasize,
            }
            break
        else
            results[#results + 1] = {
                status = "ok",
                offset = offset,
                pdu_len = d.pdu_len,
                datasize = datasize,
            }
            offset = offset + d.pdu_len
        end
    end
    return results
end

local function be32(n)
    local b1 = math.floor(n / 0x1000000) % 256
    local b2 = math.floor(n / 0x10000) % 256
    local b3 = math.floor(n / 0x100) % 256
    local b4 = n % 256
    return string.char(b1, b2, b3, b4)
end

local function be16(n)
    return string.char(math.floor(n / 256) % 256, n % 256)
end

-- A minimal well-formed frame: datasize=2, packet-id=1001, empty body.
-- Total 6 bytes. This is a legal protocol PDU (no protobuf payload).
local function empty_frame(packid)
    return be32(2) .. be16(packid or 1001)
end

-- datasize = 2 + body_len
local function frame(packid, body)
    body = body or ""
    return be32(2 + #body) .. be16(packid or 1001) .. body
end

print("=== PDU framing tests (lua/packet-evil.lua EVIL_FRAMING) ===")
print(string.format("MAX_PDU_LEN=%d FRAME_HDR_LEN=%d",
    framing.MAX_PDU_LEN, framing.FRAME_HDR_LEN))

-- Constants stay aligned with evil/evil_framing.h
check(framing.LEN_FIELD_SIZE == 4, "LEN_FIELD_SIZE is 4")
check(framing.FRAME_HDR_LEN == 6, "FRAME_HDR_LEN is 6")
check(framing.MIN_DATASIZE == 2, "MIN_DATASIZE is 2")
check(framing.MAX_PDU_LEN == 16 * 1024 * 1024, "MAX_PDU_LEN is 16 MiB")

-- Keep Lua constants aligned with evil/evil_framing.h (not executed as C).
do
    local hdr_path = script_dir() .. "../evil/evil_framing.h"
    local hf = io.open(hdr_path, "r")
    if not hf then
        fail("cannot open " .. hdr_path .. " to compare constants")
    else
        local hdr = hf:read("*a")
        hf:close()
        local function def_u(name)
            return tonumber(hdr:match("#define%s+" .. name .. "%s+%((%d+)u%s*%*%s*%d+u%s*%*%s*%d+u%)"))
                or tonumber(hdr:match("#define%s+" .. name .. "%s+%((%d+)u%)"))
                or tonumber(hdr:match("#define%s+" .. name .. "%s+(%d+)u"))
        end
        check(def_u("EVIL_LEN_FIELD_SIZE") == framing.LEN_FIELD_SIZE,
            "C EVIL_LEN_FIELD_SIZE matches Lua")
        check(def_u("EVIL_FRAME_HDR_LEN") == framing.FRAME_HDR_LEN,
            "C EVIL_FRAME_HDR_LEN matches Lua")
        check(def_u("EVIL_MIN_DATASIZE") == framing.MIN_DATASIZE,
            "C EVIL_MIN_DATASIZE matches Lua")
        local max = hdr:match("#define%s+EVIL_MAX_PDU_LEN%s+%((%d+)u%s*%*%s*(%d+)u%s*%*%s*(%d+)u%)")
        if max then
            -- match() in this branch: need all three factors
            local a, b, c = hdr:match("#define%s+EVIL_MAX_PDU_LEN%s+%((%d+)u%s*%*%s*(%d+)u%s*%*%s*(%d+)u%)")
            check(tonumber(a) * tonumber(b) * tonumber(c) == framing.MAX_PDU_LEN,
                "C EVIL_MAX_PDU_LEN matches Lua")
        else
            fail("could not parse EVIL_MAX_PDU_LEN from evil_framing.h")
        end
    end
end

-- Incomplete length field (拆包 before the 4-byte size is here)
do
    local d = framing.decide(0, 0)
    check(d.status == "need_more" and d.need == 0,
        "remaining=0 -> need one more segment",
        "got " .. tostring(d.status) .. " need=" .. tostring(d.need))
    d = framing.decide(3, 0)
    check(d.status == "need_more" and d.need == 0,
        "remaining=3 -> need one more segment (length field incomplete)")
end

-- Too-small datasize (0 and 1 cannot hold the 2-byte packet-id)
do
    local d0 = framing.decide(6, 0)
    check(d0.status == "malformed",
        "datasize=0 is malformed",
        "got " .. tostring(d0.status))
    local d1 = framing.decide(6, 1)
    check(d1.status == "malformed",
        "datasize=1 is malformed",
        "got " .. tostring(d1.status))
    local d1b = framing.decide(100, 1)
    check(d1b.status == "malformed",
        "datasize=1 stays malformed even when more bytes follow")
end

-- Minimum legal PDU: datasize=2, total=6, empty body
do
    local d = framing.decide(6, 2)
    check(d.status == "ok" and d.pdu_len == 6,
        "datasize=2, remaining=6 -> ok pdu_len=6",
        "got status=" .. tostring(d.status) .. " pdu_len=" .. tostring(d.pdu_len))
    local short = framing.decide(5, 2)
    check(short.status == "need_more" and short.need == 1,
        "datasize=2, remaining=5 -> need 1 more byte")
    local short4 = framing.decide(4, 2)
    check(short4.status == "need_more" and short4.need == 2,
        "datasize=2, remaining=4 -> need 2 more bytes")
end

-- Normal payload
do
    local body_len = 23
    local datasize = 2 + body_len
    local total = 4 + datasize
    local d = framing.decide(total, datasize)
    check(d.status == "ok" and d.pdu_len == total,
        "normal 29-byte PDU is ok")
    local split = framing.decide(10, datasize)
    check(split.status == "need_more" and split.need == total - 10,
        "split 29-byte PDU with 10 bytes available -> need the rest",
        "need=" .. tostring(split.need))
end

-- Overflow / huge length: must be malformed, never a huge need_more
do
    local samples = {
        0xFFFFFFFF,           -- 4 + datasize wraps uint32 to 3
        0xFFFFFFFC,           -- 4 + datasize wraps uint32 to 0
        0x80000000,           -- 2 GiB
        framing.MAX_PDU_LEN - 3, -- just over the cap (total would be MAX+1)
        framing.MAX_PDU_LEN,     -- datasize itself already at the cap
        framing.MAX_PDU_LEN + 1,
    }
    for _, ds in ipairs(samples) do
        local d = framing.decide(6, ds)
        check(d.status == "malformed",
            string.format("datasize=0x%X is malformed (no huge desegment)", ds),
            "got " .. tostring(d.status) .. " need=" .. tostring(d.need))
    end
    -- Max legal: datasize = MAX - 4, remaining = MAX -> ok
    local max_ds = framing.MAX_PDU_LEN - 4
    local dmax = framing.decide(framing.MAX_PDU_LEN, max_ds)
    check(dmax.status == "ok" and dmax.pdu_len == framing.MAX_PDU_LEN,
        "datasize at MAX_PDU_LEN-4 is accepted when fully present")
    local dmax_short = framing.decide(100, max_ds)
    check(dmax_short.status == "need_more" and dmax_short.need == framing.MAX_PDU_LEN - 100,
        "max-legal PDU that is not yet complete still desegments the exact remainder")
end

-- 粘包: two complete PDUs in one buffer
do
    local a = frame(1001, "abc")
    local b = frame(1002, "xyz")
    check(#a == 4 + 2 + 3 and #b == 9, "test frames have expected size")
    local r = split_pdus(a .. b)
    check(#r == 2 and r[1].status == "ok" and r[2].status == "ok",
        "sticky: two complete PDUs are both parsed",
        "count=" .. #r)
    check(r[1].pdu_len == #a and r[1].offset == 0, "sticky: first PDU length/offset")
    check(r[2].pdu_len == #b and r[2].offset == #a, "sticky: second PDU length/offset")
    check(r[1].datasize == 5 and r[2].datasize == 5, "sticky: datasize is packet-id + body")
end

-- 粘包 + 拆包: complete PDU followed by a partial next PDU
do
    local a = empty_frame(1001)
    local b = frame(1002, "0123456789")
    local partial = (a .. b):sub(1, #a + 7) -- 6 + 7 bytes; b is 16 bytes
    local r = split_pdus(partial)
    check(#r == 2, "complete+partial yields two decisions", "count=" .. #r)
    check(r[1].status == "ok" and r[1].pdu_len == 6, "complete+partial: first PDU ok")
    check(r[2].status == "need_more" and r[2].need == (#b - 7),
        "complete+partial: second PDU asks for the exact remainder",
        "need=" .. tostring(r[2] and r[2].need))
end

-- 拆包: only the length field of a larger PDU
do
    local body = string.rep("x", 20)
    local full = frame(1001, body)
    local r = split_pdus(full:sub(1, 4))
    check(#r == 1 and r[1].status == "need_more" and r[1].need == #full - 4,
        "only 4-byte length field present -> need the rest of the PDU")
end

-- Leftover 1-3 bytes after a complete PDU (incomplete next length field)
do
    local a = empty_frame(1001)
    local r = split_pdus(a .. "\x00\x00")
    check(#r == 2 and r[1].status == "ok" and r[2].status == "need_more" and r[2].need == 0,
        "complete PDU + 2 leftover bytes -> need one more segment for length field")
end

-- Valid PDU then an illegal length of 0: first is kept, then stop (no resync)
do
    local a = frame(1001, "ok")
    local bad = be32(0) .. be16(1) .. "junkjunk"
    local r = split_pdus(a .. bad)
    check(#r == 2 and r[1].status == "ok" and r[2].status == "malformed",
        "valid PDU followed by datasize=0: parse first, then stop as malformed")
    check(r[2].offset == #a, "malformed length is reported at the second PDU offset")
end

-- A huge length in the middle of a sticky buffer must not produce need_more
do
    local a = empty_frame(1001)
    local huge = be32(0xFFFFFFFF) .. be16(1)
    local r = split_pdus(a .. huge)
    check(#r == 2 and r[1].status == "ok" and r[2].status == "malformed",
        "valid PDU followed by datasize=0xFFFFFFFF is malformed, not a multi-GB desegment")
end

-- Empty input
do
    local r = split_pdus("")
    check(#r == 0, "empty buffer yields no PDUs")
end

print(string.format("=== %d passed, %d failed ===", passed, failed))
if failed > 0 then
    os.exit(1)
end
print("=== All PDU framing tests passed ===")
os.exit(0)
