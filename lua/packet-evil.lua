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
--
-- SPDX-License-Identifier: GPL-2.0-or-later

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
local FRAME_HDR_LEN = 6

-- Per-message dissect routine
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

        -- We need at least 4 bytes to know the total PDU length
        if remaining < 4 then
            pinfo.desegment_offset = offset
            pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
            return
        end

        local datasize = tvb(offset, 4):uint()
        local pdu_total_len = 4 + datasize

        -- Sanity check: minimal frame must be at least 6 bytes (4 byte datasize + 2 byte id)
        if pdu_total_len < FRAME_HDR_LEN then
            -- Invalid frame length
            return
        end

        -- Check if entire PDU is available in this buffer
        if remaining < pdu_total_len then
            pinfo.desegment_offset = offset
            pinfo.desegment_len = pdu_total_len - remaining
            return
        end

        local pdu_tvb = tvb(offset, pdu_total_len):tvb()
        dissect_message(pdu_tvb, pinfo, tree)

        offset = offset + pdu_total_len
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
