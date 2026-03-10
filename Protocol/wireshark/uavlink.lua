-- UAVLink Protocol Dissector for Wireshark
-- Version: 1.2
-- Author: UAVLink Project
-- Description: Decodes UAVLink binary protocol packets including headers,
--              encryption metadata, and payload types
--
-- Installation:
--   1. Save this file as: uavlink.lua
--   2. Copy to Wireshark plugins folder:
--      - Windows: %APPDATA%\Wireshark\plugins\
--      - Linux: ~/.local/lib/wireshark/plugins/
--      - macOS: ~/.wireshark/plugins/
--   3. Restart Wireshark
--
-- Usage:
--   - Capture UDP traffic on ports 14550 or 14551
--   - Filter: uavlink
--   - Right-click packet → Decode As → UDP → uavlink

-- Create protocol object
local uavlink_proto = Proto("uavlink", "UAVLink Protocol")

-- Protocol fields definitions
local f_sof = ProtoField.uint8("uavlink.sof", "Start of Frame", base.HEX)
local f_payload_len = ProtoField.uint16("uavlink.payload_len", "Payload Length", base.DEC)
local f_priority = ProtoField.uint8("uavlink.priority", "Priority", base.DEC, {
    [0] = "Bulk",
    [1] = "Normal",
    [2] = "High",
    [3] = "Emergency"
})
local f_stream_type = ProtoField.uint8("uavlink.stream_type", "Stream Type", base.DEC, {
    [0] = "Telemetry Fast",
    [1] = "Telemetry Slow",
    [2] = "Command",
    [3] = "Command ACK",
    [4] = "Mission",
    [5] = "Video",
    [6] = "Sensor",
    [7] = "Heartbeat",
    [8] = "Alert",
    [15] = "Custom"
})
local f_encrypted = ProtoField.bool("uavlink.encrypted", "Encrypted")
local f_fragmented = ProtoField.bool("uavlink.fragmented", "Fragmented")
local f_sequence = ProtoField.uint16("uavlink.sequence", "Sequence", base.DEC)
local f_sys_id = ProtoField.uint8("uavlink.sys_id", "System ID", base.DEC)
local f_comp_id = ProtoField.uint8("uavlink.comp_id", "Component ID", base.DEC)
local f_target_sys = ProtoField.uint8("uavlink.target_sys", "Target System ID", base.DEC)
local f_target_comp = ProtoField.uint8("uavlink.target_comp", "Target Component ID", base.DEC)
local f_msg_id = ProtoField.uint16("uavlink.msg_id", "Message ID", base.HEX, {
    [0x001] = "Heartbeat",
    [0x002] = "Attitude",
    [0x003] = "GPS Raw",
    [0x004] = "Battery",
    [0x005] = "RC Input",
    [0x006] = "Command",
    [0x007] = "Command ACK",
    [0x008] = "Mode Change",
    [0x009] = "Mission Item",
    [0x3FF] = "Batch"
})
local f_frag_index = ProtoField.uint8("uavlink.frag_index", "Fragment Index", base.DEC)
local f_frag_total = ProtoField.uint8("uavlink.frag_total", "Fragment Total", base.DEC)
local f_nonce = ProtoField.bytes("uavlink.nonce", "Nonce (8 bytes)")
local f_payload = ProtoField.bytes("uavlink.payload", "Payload")
local f_mac = ProtoField.bytes("uavlink.mac", "MAC Tag (Poly1305)")
local f_crc = ProtoField.uint16("uavlink.crc", "CRC-16", base.HEX)

-- Register all fields
uavlink_proto.fields = {
    f_sof, f_payload_len, f_priority, f_stream_type,
    f_encrypted, f_fragmented, f_sequence,
    f_sys_id, f_comp_id, f_target_sys, f_target_comp,
    f_msg_id, f_frag_index, f_frag_total,
    f_nonce, f_payload, f_mac, f_crc
}

-- Message type names for info column
local msg_type_names = {
    [0x001] = "Heartbeat",
    [0x002] = "Attitude",
    [0x003] = "GPS",
    [0x004] = "Battery",
    [0x005] = "RC Input",
    [0x006] = "Command",
    [0x007] = "Command ACK",
    [0x008] = "Mode Change",
    [0x009] = "Mission Item",
    [0x3FF] = "Batch"
}

-- Main dissector function
function uavlink_proto.dissector(buffer, pinfo, tree)
    local length = buffer:len()
    if length < 10 then return 0 end  -- Minimum packet size
    
    -- Check start of frame marker
    local sof = buffer(0, 1):uint()
    if sof ~= 0xA5 then return 0 end  -- Not a UAVLink packet
    
    pinfo.cols.protocol = "UAVLink"
    
    -- Create protocol subtree
    local subtree = tree:add(uavlink_proto, buffer(), "UAVLink Protocol")
    
    -- Parse base header (4 bytes)
    local byte1 = buffer(1, 1):uint()
    local byte2 = buffer(2, 1):uint()
    local byte3 = buffer(3, 1):uint()
    
    -- Extract bit-packed fields
    local payload_len = bit32.bor(
        bit32.lshift(bit32.band(byte1, 0xF0), 4),
        bit32.lshift(bit32.band(byte2, 0x3F), 2),
        bit32.rshift(bit32.band(byte3, 0xC0), 6)
    )
    
    local priority = bit32.rshift(bit32.band(byte1, 0x0C), 2)
    
    local stream_type = bit32.bor(
        bit32.lshift(bit32.band(byte1, 0x03), 2),
        bit32.rshift(bit32.band(byte2, 0xC0), 6)
    )
    
    local encrypted = bit32.band(byte3, 0x08) ~= 0
    local fragmented = bit32.band(byte3, 0x04) ~= 0
    
    local seq_hi = bit32.band(byte3, 0x03)
    local byte4 = buffer(4, 1):uint()
    local seq_lo = byte4
    local sequence = bit32.bor(bit32.lshift(seq_hi, 8), seq_lo)
    
    -- Add base header fields
    subtree:add(f_sof, buffer(0, 1))
    subtree:add(f_payload_len, payload_len)
    subtree:add(f_priority, priority)
    subtree:add(f_stream_type, stream_type)
    subtree:add(f_encrypted, encrypted)
    subtree:add(f_fragmented, fragmented)
    subtree:add(f_sequence, sequence)
    
    -- Parse extended header
    local offset = 4
    
    -- System/Component IDs
    if length > offset then
        local sys_id = buffer(offset, 1):uint()
        subtree:add(f_sys_id, buffer(offset, 1))
        offset = offset + 1
    end
    
    if length > offset then
        local comp_id = buffer(offset, 1):uint()
        subtree:add(f_comp_id, buffer(offset, 1))
        offset = offset + 1
    end
    
    -- Target IDs (for command streams)
    if stream_type == 2 or stream_type == 3 then  -- CMD or CMD_ACK
        if length > offset then
            subtree:add(f_target_sys, buffer(offset, 1))
            offset = offset + 1
        end
    end
    
    -- Message ID (12-bit, split across bytes)
    if length > offset + 1 then
        local msg_byte1 = buffer(offset, 1):uint()
        local msg_byte2 = buffer(offset + 1, 1):uint()
        local msg_id = bit32.bor(
            bit32.lshift(bit32.band(msg_byte1, 0x0F), 8),
            msg_byte2
        )
        subtree:add(f_msg_id, msg_id)
        offset = offset + 2
        
        -- Update info column with message type
        local msg_name = msg_type_names[msg_id] or string.format("Unknown (0x%03X)", msg_id)
        pinfo.cols.info = string.format("UAVLink: %s [Seq=%d, Len=%d]", 
                                       msg_name, sequence, payload_len)
        if encrypted then
            pinfo.cols.info = pinfo.cols.info .. " [Encrypted]"
        end
        if fragmented then
            pinfo.cols.info = pinfo.cols.info .. " [Fragmented]"
        end
    end
    
    -- Fragmentation info
    if fragmented and length > offset + 1 then
        subtree:add(f_frag_index, buffer(offset, 1))
        subtree:add(f_frag_total, buffer(offset + 1, 1))
        offset = offset + 2
    end
    
    -- Nonce (if encrypted)
    if encrypted and length > offset + 7 then
        subtree:add(f_nonce, buffer(offset, 8))
        offset = offset + 8
    end
    
    -- Payload
    if payload_len > 0 and length >= offset + payload_len then
        local payload_tree = subtree:add(f_payload, buffer(offset, payload_len))
        
        if encrypted then
            payload_tree:append_text(" [Encrypted - Cannot decode without key]")
        else
            -- Could add payload parsing here for unencrypted packets
            payload_tree:append_text(string.format(" (%d bytes)", payload_len))
        end
        
        offset = offset + payload_len
    end
    
    -- MAC tag (if encrypted)
    if encrypted and length >= offset + 16 then
        subtree:add(f_mac, buffer(offset, 16))
        offset = offset + 16
    end
    
    -- CRC-16 (last 2 bytes)
    if length >= offset + 2 then
        subtree:add(f_crc, buffer(offset, 2))
        offset = offset + 2
    end
    
    return offset
end

-- Register protocol for UDP ports
local udp_port_table = DissectorTable.get("udp.port")
udp_port_table:add(14550, uavlink_proto)  -- UAV -> GCS telemetry
udp_port_table:add(14551, uavlink_proto)  -- GCS -> UAV commands

-- Also allow manual "Decode As"
udp_port_table:add(0, uavlink_proto)

print("UAVLink dissector loaded successfully")
print("  - Listening on UDP ports 14550 and 14551")
print("  - Use filter: uavlink")
print("  - Version: 1.2")
