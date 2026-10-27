-- "wbpc", a made-up lidar point cloud on UDP port 7502, little-endian:
--   "WBPC", u32 scan, u16 part, u16 parts, u16 points, u16 flags
--   then per point: i16 x, y, z (cm), u8 intensity, u8 ring
local wbpc = Proto("wbpc", "WireBuddy point cloud")
local f = {
  magic = ProtoField.string("wbpc.magic", "Magic"),
  scan = ProtoField.uint32("wbpc.scan", "Scan"),
  part = ProtoField.uint16("wbpc.part", "Part"),
  parts = ProtoField.uint16("wbpc.parts", "Parts"),
  count = ProtoField.uint16("wbpc.count", "Points"),
  flags = ProtoField.uint16("wbpc.flags", "Flags", base.HEX),
  points = ProtoField.bytes("wbpc.points", "Point data"),
}
wbpc.fields = f
local short = ProtoExpert.new("wbpc.short", "Shorter than its point count says", expert.group.MALFORMED, expert.severity.ERROR)
wbpc.experts = { short }

function wbpc.dissector(tvb, pinfo, tree)
  if tvb:len() < 16 or tvb(0, 4):string() ~= "WBPC" then return 0 end
  pinfo.cols.protocol = "WBPC"
  local t = tree:add(wbpc, tvb())
  local scan, part, parts, n = tvb(4, 4):le_uint(), tvb(8, 2):le_uint(), tvb(10, 2):le_uint(), tvb(12, 2):le_uint()
  t:add(f.magic, tvb(0, 4))
  t:add_le(f.scan, tvb(4, 4))
  t:add_le(f.part, tvb(8, 2))
  t:add_le(f.parts, tvb(10, 2))
  t:add_le(f.count, tvb(12, 2))
  t:add_le(f.flags, tvb(14, 2))
  pinfo.cols.info = string.format("scan %d part %d/%d, %d points", scan, part + 1, parts, n)
  if tvb:len() < 16 + n * 8 then
    t:add_proto_expert_info(short)
    return tvb:len()
  end
  if n > 0 then t:add(f.points, tvb(16, n * 8)) end
  return tvb:len()
end

DissectorTable.get("udp.port"):add(7502, wbpc)
