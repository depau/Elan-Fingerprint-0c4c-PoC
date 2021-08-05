local elanmoc_proto = Proto("elanmoc", "ELAN FP Match-on-Chip")

local f_header = ProtoField.uint8("elanmoc.header", "Header", base.HEX)
local f_cmd = ProtoField.bytes("elanmoc.cmd", "Command", base.SPACE)
local f_payload = ProtoField.bytes("elanmoc.payload", "Payload", base.SPACE)

elanmoc_proto.fields = { f_header, f_cmd, f_payload };


function cmd_name(cmd)
    local name = "Unknown"

    if     cmd == 0xFF03 then name = "Check finger"
    elseif cmd == 0xFF12 then name = "Get finger info"
    elseif cmd == 0xFF10 then name = "Something after enroll"
    elseif cmd == 0xFF11 then name = "Commit"
    elseif cmd ==   0x19 then name = "Firmware version"
    elseif cmd ==   0x0c then name = "lfp Sensor dim"
    elseif cmd == 0xff00 then name = "lfp Get status - enrolled count"
    elseif cmd == 0xff04 then name = "Get enrolled count"
    elseif cmd == 0xff73 then name = "lfp Verify"
    elseif cmd == 0xff02 then name = "Abort"
    elseif cmd == 0xff01 then name = "Enroll"
    elseif cmd == 0xff13 then name = "Delete finger"
    elseif cmd == 0xff98 then name = "lfp Delete all"
    elseif cmd == 0x2100 then name = "lfp Get user ID"
    elseif cmd == 0xff15 then name = "lfp Set mod"
    elseif cmd == 0xff22 then name = "lfp Check reenroll"
    end

    return name
end


local function heuristic(buffer, pinfo, tree)
    if buffer(0,1):uint() ~= 0x40 then
        return false
    end
    local length = buffer:len()
    if length < 2 then
        return false
    end
    return true
end

function elanmoc_proto.dissector(buffer, pinfo, tree)
    local length = buffer:len()
    if length < 2 then
        return
    end
    if buffer(0,1):uint() ~= 0x40 then
        return
    end
    pinfo.cols.protocol = elanmoc_proto.name

    local cmdname = "Unknown"
    local cmd = buffer(1,1)
    if tostring(pinfo.src) == "host" then 
        if length > 2 then
            cmd = buffer(1,2)
        end
        cmdname = "Request: " .. cmd_name(cmd:uint())
    else
        cmdname = "Reply"
    end

    local subtree = tree:add(elanmoc_proto, buffer(), "ELAN Fingerprint Match-on-Chip (" .. cmdname .. ")")
    pinfo.cols.info = "ELAN MoC " .. cmdname
    
    subtree:add(f_header, buffer(0,1))

    if tostring(pinfo.src) == "host" then
        subtree:add(f_cmd, cmd):append_text(" (" .. cmdname .. ")")
        if length > 3 then
            subtree:add(f_payload, buffer(3,length-3))
        end
    else
        subtree:add(f_payload, buffer(1,length-1))
    end
end


elanmoc_proto:register_heuristic("usb.bulk", heuristic)

local usb_product_table = DissectorTable.get("usb.product")
usb_product_table:add(0x0c4c, elanmoc_proto)
