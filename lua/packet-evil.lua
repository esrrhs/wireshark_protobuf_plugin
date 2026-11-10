-- packet-evil.lua
--
-- Wireshark Protobuf Dissector Plugin in Lua
-- Supports Wireshark 2.6 / 3.x / 4.x with Lua enabled.
--
-- Features:
--   1. TCP Desegmentation / Reassembly (handles fragmentation and sticky packets)
--   2. Dissects 4-byte Data Size + 2-byte Packet ID header
--   3. Delegates Protobuf payload to Wireshark built-in Protobuf dissector
--   4. Configurable TCP port and Packet ID -> Message mapping
--   5. Rejects invalid / overflowing length fields without unbounded reassembly
--
-- SPDX-License-Identifier: GPL-2.0-or-later

-- BEGIN EVIL_FRAMING
-- Pure PDU-length policy. Keep in sync with evil/evil_framing.h.
-- This block is extracted and unit-tested by lua/test_pdu_framing.lua;
-- it must not depend on any Wireshark API.
--
-- Frame: [4-byte BE datasize][2-byte BE packet-id][datasize-2 bytes body]
-- Total length = 4 + datasize. Minimum valid datasize is 2.
--
-- evil_framing.decide(remaining, datasize) assumes remaining and datasize
-- are non-negative integers. datasize is a uint32 (0..2^32-1).
--
-- Returns one of:
--   { status = "ok",        pdu_len = N }
--   { status = "need_more", need = N }   -- N extra bytes; 0 means one more segment
--   { status = "malformed", reason = "..." }
--
-- Callers must NOT request TCP desegmentation on "malformed" (avoids
-- multi-GB reassembly) and must NOT continue parsing later PDUs in the
-- same buffer (the stream is no longer trusted).

local EVIL_LEN_FIELD_SIZE = 4
local EVIL_FRAME_HDR_LEN  = 6
local EVIL_MIN_DATASIZE   = 2
-- 16 MiB cap: see EVIL_MAX_PDU_LEN in evil/evil_framing.h
local EVIL_MAX_PDU_LEN    = 16 * 1024 * 1024

local function evil_decide_pdu(remaining, datasize)
    remaining = remaining or 0
    datasize  = datasize or 0
    if remaining < EVIL_LEN_FIELD_SIZE then
        return { status = "need_more", need = 0 }
    end
    if datasize < EVIL_MIN_DATASIZE then
        return { status = "malformed", reason = "data size smaller than packet-id field" }
    end
    -- Single check covers both the 16 MiB cap and 32-bit 4+datasize overflow
    -- (datasize == 0xFFFFFFFF would wrap a uint32 total to 3).
    if datasize > EVIL_MAX_PDU_LEN - EVIL_LEN_FIELD_SIZE then
        return { status = "malformed", reason = "data size exceeds maximum or would overflow" }
    end
    local pdu_len = EVIL_LEN_FIELD_SIZE + datasize
    if remaining < pdu_len then
        return { status = "need_more", need = pdu_len - remaining }
    end
    return { status = "ok", pdu_len = pdu_len }
end

evil_framing = {
    LEN_FIELD_SIZE = EVIL_LEN_FIELD_SIZE,
    FRAME_HDR_LEN  = EVIL_FRAME_HDR_LEN,
    MIN_DATASIZE   = EVIL_MIN_DATASIZE,
    MAX_PDU_LEN    = EVIL_MAX_PDU_LEN,
    decide         = evil_decide_pdu,
}
-- END EVIL_FRAMING

local evil_proto = Proto("myname", "MyName Protocol (Lua)")

-- Header fields
local f_datasize   = ProtoField.uint32("myname.datasize",   "Data Size",   base.DEC, nil, 0x0, "Size of the message data (packet-id + body)")
local f_packetid   = ProtoField.uint16("myname.packetid",   "Packet ID",   base.DEC, nil, 0x0, "Numeric identifier of the message type")
local f_packetname = ProtoField.string("myname.packetname", "Packet Name", base.ASCII)

evil_proto.fields = { f_datasize, f_packetid, f_packetname }

-- Preferences
local default_port = 12345
evil_proto.prefs.port = Pref.uint("TCP Port", default_port, "TCP port to dissect")

-- Default message mapping (id -> full protobuf message type name)
-- Wireshark built-in Protobuf dissector looks up message in its proto search path
local msg_map = {
    [1]    = "ntesgame.MsgName1",
    [2]    = "ntesgame.MsgName2",
    [1001] = "testpkg.LoginRequest",
    [1002] = "testpkg.LoginResponse"
}

-- Simple XML config loader for config.xml if present in working directory or plugins directory
local function try_load_config()
    local search_paths = {
        "config.xml",
        PERSISTENT_DIR .. "/plugins/config.xml",
        USER_DIR .. "/plugins/config.xml"
    }

    local content = nil
    for _, path in ipairs(search_paths) do
        local f = io.open(path, "r")
        if f then
            content = f:read("*all")
            f:close()
            break
        end
    end

    if not content then return end

    -- Extract port from <Config port="..."
    local port_str = content:match('<Config%s+[^>]*port="([%d]+)"')
    if port_str then
        local p = tonumber(port_str)
        if p and p > 0 then
            evil_proto.prefs.port = p
        end
    end

    -- Extract <MsgId id="..." name="..." />
    for id_str, name_str in content:gmatch('<MsgId%s+[^>]*id="([%d]+)"%s+[^>]*name="([^"]+)"') do
        local id = tonumber(id_str)
        if id then
            msg_map[id] = name_str
        end
    end
end

-- Attempt to parse config.xml on startup
pcall(try_load_config)

-- Get Wireshark built-in protobuf dissector
local pb_dissector = Dissector.get("protobuf")

-- Frame layout:
-- [4 bytes datasize (BE)][2 bytes packetid (BE)][body (datasize - 2 bytes)]
local FRAME_HDR_LEN = evil_framing.FRAME_HDR_LEN

local function tvb_reported_len(tvb)
    local ok, n = pcall(function()
        if tvb.reported_len then
            return tvb:reported_len()
        end
        if tvb.reported_length then
            return tvb:reported_length()
        end
        return tvb:len()
    end)
    if ok and type(n) == "number" then
        return n
    end
    return tvb:len()
end

local function add_malformed(ti, text)
    ti:append_text(" [" .. text .. "]")
    if ti.add_expert_info then
        pcall(function()
            ti:add_expert_info(PI_MALFORMED, PI_ERROR, text)
        end)
    end
end

local function add_truncated(ti, text)
    ti:append_text(" [" .. text .. "]")
    if ti.add_expert_info then
        pcall(function()
            ti:add_expert_info(PI_MALFORMED, PI_WARN, text)
        end)
    end
end

-- Snapshot / short-frame truncation: missing bytes will not arrive later.
-- Only display fields that are fully present (do not read a 4-byte length
-- or 2-byte packet-id from a shorter remainder).
local function show_truncated_pdu(tvb, pinfo, tree, offset, remaining)
    pinfo.cols.protocol = "myname"
    pinfo.cols.info = "Truncated PDU"
    local ti = tree:add(evil_proto, tvb(offset, remaining))
    if remaining >= evil_framing.LEN_FIELD_SIZE then
        ti:add(f_datasize, tvb(offset, 4))
        if remaining >= FRAME_HDR_LEN then
            local packid = tvb(offset + 4, 2):uint()
            local msg_name = msg_map[packid] or "unknown"
            ti:add(f_packetid, tvb(offset + 4, 2))
            ti:add(f_packetname, tvb(offset + 4, 2), msg_name)
            local body_len = remaining - FRAME_HDR_LEN
            if body_len > 0 and pb_dissector then
                local pb_tvb = tvb(offset + FRAME_HDR_LEN, body_len):tvb()
                pinfo.private["pb_msg_type"] = "message," .. msg_name
                pcall(function()
                    pb_dissector:call(pb_tvb, pinfo, ti)
                end)
            end
        end
    end
    add_truncated(ti, "Truncated PDU")
end

local function is_snaplen_truncated(tvb, available)
    return available < tvb_reported_len(tvb)
end

-- Per-message dissect routine (full, validated PDU)
local function dissect_message(tvb, pinfo, tree)
    local total_len = tvb:len()
    if total_len < FRAME_HDR_LEN then return 0 end

    pinfo.cols.protocol = "myname"

    local datasize = tvb(0, 4):uint()
    local packid = tvb(4, 2):uint()
    local msg_name = msg_map[packid] or "unknown"

    pinfo.cols.info = string.format("PacketId=%d (%s)", packid, msg_name)

    local ti = tree:add(evil_proto, tvb(0, total_len))
    ti:add(f_datasize, tvb(0, 4))
    ti:add(f_packetid, tvb(4, 2))
    ti:add(f_packetname, tvb(4, 2), msg_name)

    -- Delegate Protobuf body to Wireshark built-in protobuf dissector
    local body_len = total_len - FRAME_HDR_LEN
    if body_len > 0 and pb_dissector then
        local pb_tvb = tvb(FRAME_HDR_LEN, body_len):tvb()
        -- Wireshark 2.6+ / 3.x / 4.x passes message type via pinfo.private["pb_msg_type"]
        pinfo.private["pb_msg_type"] = "message," .. msg_name
        pcall(function()
            pb_dissector:call(pb_tvb, pinfo, ti)
        end)
    end

    return total_len
end

-- Main dissector with TCP desegmentation (reassembly) support
function evil_proto.dissector(tvb, pinfo, tree)
    local offset = 0
    local available = tvb:len()

    while offset < available do
        local remaining = available - offset

        -- Need at least 4 bytes to read the length field.
        -- If this tvbuff was already cut short by snapshot length, the
        -- missing bytes will not arrive later -- do not desegment.
        if remaining < evil_framing.LEN_FIELD_SIZE then
            if is_snaplen_truncated(tvb, available) then
                show_truncated_pdu(tvb, pinfo, tree, offset, remaining)
                return
            end
            pinfo.desegment_offset = offset
            pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
            return
        end

        local datasize = tvb(offset, 4):uint()
        local decision = evil_framing.decide(remaining, datasize)

        if decision.status == "malformed" then
            -- Do not desegment and do not parse further PDUs: framing is lost.
            pinfo.cols.protocol = "myname"
            pinfo.cols.info = "Invalid data size " .. tostring(datasize)
            local ti = tree:add(evil_proto, tvb(offset, remaining))
            ti:add(f_datasize, tvb(offset, 4))
            add_malformed(ti, decision.reason)
            return
        end

        if decision.status == "need_more" then
            -- If this tvbuff was already cut short by snapshot length (or a
            -- short frame), the missing bytes will not arrive in a later
            -- segment. Show a truncated PDU instead of requesting reassembly.
            if is_snaplen_truncated(tvb, available) then
                show_truncated_pdu(tvb, pinfo, tree, offset, remaining)
                return
            end

            pinfo.desegment_offset = offset
            if decision.need and decision.need > 0 then
                pinfo.desegment_len = decision.need
            else
                pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
            end
            return
        end

        local pdu_tvb = tvb(offset, decision.pdu_len):tvb()
        dissect_message(pdu_tvb, pinfo, tree)

        offset = offset + decision.pdu_len
    end
end

-- Register protocol to TCP port
local current_port = nil
local tcp_table = DissectorTable.get("tcp.port")

function evil_proto.init()
    if current_port and current_port ~= evil_proto.prefs.port then
        tcp_table:remove(current_port, evil_proto)
    end
    current_port = evil_proto.prefs.port
    if current_port and current_port > 0 then
        tcp_table:add(current_port, evil_proto)
    end
end
