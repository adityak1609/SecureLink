-- Decode the observer envelope of SecureLink application-stream PCAPs.
-- These records are not TCP packets. Payload may contain partial/multiple frames.
local p = Proto('securelink_stream', 'SecureLink application stream observation')
local direction = ProtoField.uint8('securelink_stream.direction', 'Direction', base.DEC, {[0]='Client to server',[1]='Server to client'})
local connection = ProtoField.uint32('securelink_stream.connection', 'Observed connection', base.DEC)
local bytes = ProtoField.bytes('securelink_stream.bytes', 'Actual socket bytes')
p.fields = {direction,connection,bytes}
function p.dissector(buffer,info,tree)
    if buffer:len()<5 then return end
    info.cols.protocol='SecureLink stream'
    local node=tree:add(p,buffer())
    node:add(direction,buffer(0,1))
    node:add(connection,buffer(1,4))
    node:add(bytes,buffer(5))
end
DissectorTable.get('wtap_encap'):add(wtap.USER0,p)
