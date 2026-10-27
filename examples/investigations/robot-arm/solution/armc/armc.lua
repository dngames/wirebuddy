-- ARMC v1, the arm controller's protocol (the vendor's PROTOCOL.md), all integers big-endian:
--   commands on TCP port 7700: "AM", u8 version 1, u8 type, u16 seq, u16 payload length, payload
--   telemetry on UDP port 7701, 36 bytes: "AT", u8 version, u8 flags, u32 seq, u32 device time (ms),
--   actual j1..j3 and target j1..j3 as i32 millidegrees
-- Angles are degrees in the fields, times ms.
local PORT, TELEMETRY = 7700, 7701
local HEADER = 8

local armc = Proto("armc", "ARMC robot arm protocol")

local TYPES = { [0x01] = "MOVE", [0x02] = "HOME", [0x03] = "STOP", [0x10] = "PING", [0x81] = "ACK", [0x82] = "NACK", [0x90] = "PONG" }
local NACK_CODES = { [1] = "bad magic", [2] = "bad version", [3] = "unknown type", [4] = "bad length", [5] = "out of range" }
-- Payload length per type; a NACK has at least its code
local LENGTHS = { [0x01] = 14, [0x02] = 0, [0x03] = 0, [0x10] = 0, [0x81] = 4, [0x90] = 0 }
local LIMITS = { 170, 90, 135 }
local DEG = { "°" }
local MS = { " ms" }

local f = {
  magic = ProtoField.string("armc.magic", "Magic"),
  version = ProtoField.uint8("armc.version", "Version"),
  type = ProtoField.uint8("armc.type", "Type", base.HEX, TYPES),
  seq = ProtoField.uint16("armc.seq", "Sequence"),
  len = ProtoField.uint16("armc.len", "Payload length"),
  move_j1 = ProtoField.double("armc.move.j1", "J1 target", DEG),
  move_j2 = ProtoField.double("armc.move.j2", "J2 target", DEG),
  move_j3 = ProtoField.double("armc.move.j3", "J3 target", DEG),
  move_speed = ProtoField.uint16("armc.move.speed", "Max speed", base.UNIT_STRING, { " °/s" }),
  ack_status = ProtoField.uint8("armc.ack.status", "Status", base.DEC, { [0] = "ok" }),
  ack_queue = ProtoField.uint8("armc.ack.queue", "Queue depth"),
  ack_proc = ProtoField.uint16("armc.ack.proc_us", "Processing time", base.UNIT_STRING, { " µs" }),
  nack_code = ProtoField.uint8("armc.nack.code", "Error code", base.DEC, NACK_CODES),
  nack_reason = ProtoField.string("armc.nack.reason", "Reason", base.UNICODE),
  data = ProtoField.bytes("armc.data", "Data"),
  started_in = ProtoField.framenum("armc.started_in", "Message started in"),
  assembly = ProtoField.double("armc.assembly_time", "First to last byte", MS),
  request_in = ProtoField.framenum("armc.request_in", "Request in", base.NONE, frametype.REQUEST),
  response_in = ProtoField.framenum("armc.response_in", "Response in", base.NONE, frametype.RESPONSE),
  time = ProtoField.double("armc.time", "Time since the request's last byte", MS),
  latency = ProtoField.double("armc.latency", "Time since the request's first byte", MS),
  tel_magic = ProtoField.string("armc.tel.magic", "Magic"),
  tel_version = ProtoField.uint8("armc.tel.version", "Version"),
  tel_flags = ProtoField.uint8("armc.tel.flags", "Flags", base.HEX),
  tel_moving = ProtoField.bool("armc.tel.flags.moving", "Moving", 8, nil, 0x01),
  tel_reached = ProtoField.bool("armc.tel.flags.reached", "Target reached", 8, nil, 0x02),
  tel_seq = ProtoField.uint32("armc.tel.seq", "Sequence"),
  tel_time = ProtoField.uint32("armc.tel.time", "Device time", base.UNIT_STRING, MS),
  tel_j1 = ProtoField.double("armc.tel.actual.j1", "J1 actual", DEG),
  tel_j2 = ProtoField.double("armc.tel.actual.j2", "J2 actual", DEG),
  tel_j3 = ProtoField.double("armc.tel.actual.j3", "J3 actual", DEG),
  tel_t1 = ProtoField.double("armc.tel.target.j1", "J1 target", DEG),
  tel_t2 = ProtoField.double("armc.tel.target.j2", "J2 target", DEG),
  tel_t3 = ProtoField.double("armc.tel.target.j3", "J3 target", DEG),
  tel_error = ProtoField.double("armc.tel.error", "Largest tracking error", DEG),
}
armc.fields = f
local MOVE_J = { f.move_j1, f.move_j2, f.move_j3 }
local TEL_J = { f.tel_j1, f.tel_j2, f.tel_j3 }
local TEL_T = { f.tel_t1, f.tel_t2, f.tel_t3 }

local e = {
  bad_magic = ProtoExpert.new("armc.bad_magic", 'Not an ARMC message: no "AM" magic', expert.group.MALFORMED, expert.severity.ERROR),
  bad_version = ProtoExpert.new("armc.bad_version", "Unknown ARMC version", expert.group.MALFORMED, expert.severity.ERROR),
  unknown_type = ProtoExpert.new("armc.unknown_type", "Unknown message type", expert.group.MALFORMED, expert.severity.WARN),
  bad_length = ProtoExpert.new("armc.bad_length", "Payload length doesn't fit the message type", expert.group.MALFORMED, expert.severity.ERROR),
  nack = ProtoExpert.new("armc.nack.expert", "The device refused the request (NACK)", expert.group.RESPONSE_CODE, expert.severity.WARN),
  not_ok = ProtoExpert.new("armc.ack.not_ok", "ACK with a status other than ok", expert.group.RESPONSE_CODE, expert.severity.WARN),
  limit = ProtoExpert.new("armc.move.limit", "Joint target outside the joint's limits (the device answers NACK 5)", expert.group.PROTOCOL, expert.severity.WARN),
  split = ProtoExpert.new("armc.split", "Message split over frames: its last byte came over 1 ms after its first", expert.group.SEQUENCE, expert.severity.WARN),
  tel_bad = ProtoExpert.new("armc.tel.malformed", "Not ARMC telemetry: shorter than 36 bytes or no \"AT\" magic", expert.group.MALFORMED, expert.severity.ERROR),
}
armc.experts = e

-- sharkd reads the file once in order, then dissects single packets in any order: key state by frame
local started, first_of, pending, replies, answered = {}, {}, {}, {}, {}
function armc.init()
  started, first_of, pending, replies, answered = {}, {}, {}, {}, {}
end

local function endpoints(pinfo, back)
  local a, b = tostring(pinfo.src) .. ":" .. pinfo.src_port, tostring(pinfo.dst) .. ":" .. pinfo.dst_port
  if back then return b .. ">" .. a end
  return a .. ">" .. b
end

-- Several messages in one frame: their summaries one after the other
local function info(pinfo, text)
  if pinfo.private.armc_info then
    pinfo.cols.info:append(", " .. text)
  else
    pinfo.cols.info = text
  end
  pinfo.private.armc_info = "1"
end

local function degrees(range)
  return range:int() / 1000
end

-- Seconds between two times as ms, to the µs
local function ms(from, to)
  return math.floor((to - from) * 1e6 + 0.5) / 1000
end

local function pdu_len(tvb, pinfo, offset)
  -- Out of step: the rest of the segment is one malformed message
  if tvb(offset, 2):string() ~= "AM" then return tvb:len() - offset end
  return HEADER + tvb(offset + 6, 2):uint()
end

-- Whether the data ends inside a message
local function partial(tvb)
  local offset, n = 0, tvb:len()
  while offset < n do
    if n - offset < HEADER then return true end
    offset = offset + pdu_len(tvb, nil, offset)
  end
  return offset > n
end

local function dissect_message(tvb, pinfo, tree)
  pinfo.cols.protocol = "ARMC"
  local key = endpoints(pinfo)
  local n = tvb:len()
  -- The first message ending here may have begun frames before
  if not pinfo.visited and started[key] then
    first_of[pinfo.number] = { frame = started[key].frame, ts = started[key].ts, seq = n >= HEADER and tvb(4, 2):uint() or -1 }
    started[key] = nil
  end
  local t = tree:add(armc, tvb())
  if n < HEADER or tvb(0, 2):string() ~= "AM" then
    t:add_proto_expert_info(e.bad_magic)
    t:add(f.data, tvb())
    info(pinfo, string.format("Malformed (%d bytes without an ARMC header)", n))
    return n
  end
  local version, kind, seq, len = tvb(2, 1):uint(), tvb(3, 1):uint(), tvb(4, 2):uint(), tvb(6, 2):uint()
  t:add(f.magic, tvb(0, 2))
  local vi = t:add(f.version, tvb(2, 1))
  if version ~= 1 then vi:add_proto_expert_info(e.bad_version) end
  local ti = t:add(f.type, tvb(3, 1))
  t:add(f.seq, tvb(4, 2))
  local li = t:add(f.len, tvb(6, 2))
  local name = TYPES[kind]
  if not name then
    ti:add_proto_expert_info(e.unknown_type)
    name = string.format("Type 0x%02x", kind)
  end
  t:append_text(string.format(", %s seq=%d", name, seq))
  local payload = len > 0 and tvb(HEADER, len) or nil
  if (LENGTHS[kind] and len ~= LENGTHS[kind]) or (kind == 0x82 and len < 1) then
    li:add_proto_expert_info(e.bad_length)
    if payload then t:add(f.data, payload) end
    info(pinfo, string.format("%s seq=%d, malformed (payload %d bytes)", name, seq, len))
    return n
  end

  local first = first_of[pinfo.number]
  if first and first.seq ~= seq then first = nil end
  -- Request and reply matched by seq, on the first pass
  if not pinfo.visited then
    local msg = { frame = pinfo.number, first = first and first.ts or pinfo.abs_ts, last = pinfo.abs_ts }
    if kind < 0x80 then
      pending[key .. "#" .. seq] = msg
    else
      local req = pending[endpoints(pinfo, true) .. "#" .. seq]
      if req then
        pending[endpoints(pinfo, true) .. "#" .. seq] = nil
        replies[pinfo.number .. "#" .. seq] = req
        answered[req.frame .. "#" .. seq] = pinfo.number
      end
    end
  end
  local spread = first and ms(first.ts, pinfo.abs_ts) or 0
  if first then t:add(f.started_in, first.frame):set_generated() end
  local ai = t:add(f.assembly, spread)
  ai:set_generated()
  if spread > 1 then ai:add_proto_expert_info(e.split) end
  if answered[pinfo.number .. "#" .. seq] then t:add(f.response_in, answered[pinfo.number .. "#" .. seq]):set_generated() end
  local req = replies[pinfo.number .. "#" .. seq]
  if req then
    t:add(f.request_in, req.frame):set_generated()
    t:add(f.time, ms(req.last, pinfo.abs_ts)):set_generated()
    t:add(f.latency, ms(req.first, pinfo.abs_ts)):set_generated()
  end

  local text = string.format("%s seq=%d", name, seq)
  if version ~= 1 then text = string.format("%s (version %d)", text, version) end
  if kind == 0x01 then
    local p = t:add(payload, "MOVE payload")
    local j = {}
    for i = 1, 3 do
      local r = payload((i - 1) * 4, 4)
      j[i] = degrees(r)
      local item = p:add(MOVE_J[i], r, j[i])
      if math.abs(j[i]) > LIMITS[i] then item:add_proto_expert_info(e.limit) end
    end
    p:add(f.move_speed, payload(12, 2))
    text = string.format("%s j1=%.2f° j2=%.2f° j3=%.2f° speed %d", text, j[1], j[2], j[3], payload(12, 2):uint())
  elseif kind == 0x81 then
    local p = t:add(payload, "ACK payload")
    local si = p:add(f.ack_status, payload(0, 1))
    p:add(f.ack_queue, payload(1, 1))
    p:add(f.ack_proc, payload(2, 2))
    local status = payload(0, 1):uint()
    if status ~= 0 then
      si:add_proto_expert_info(e.not_ok)
      text = string.format("%s status %d", text, status)
    end
    text = string.format("%s %.3f ms", text, payload(2, 2):uint() / 1000)
  elseif kind == 0x82 then
    local p = t:add(payload, "NACK payload")
    local code = payload(0, 1):uint()
    p:add(f.nack_code, payload(0, 1))
    local reason = ""
    if len > 1 then
      p:add_packet_field(f.nack_reason, payload(1), ENC_UTF_8)
      reason = payload(1):string(ENC_UTF_8)
    end
    local why = NACK_CODES[code] or string.format("code %d", code)
    p:add_proto_expert_info(e.nack, "NACK: " .. why)
    text = string.format("%s %s%s", text, why, reason ~= "" and ": " .. reason or "")
  elseif payload then
    t:add(f.data, payload)
  end
  info(pinfo, text)
  return n
end

local function dissect_telemetry(tvb, pinfo, tree)
  pinfo.cols.protocol = "ARMC"
  local t = tree:add(armc, tvb(), "ARMC telemetry")
  if tvb:len() < 36 or tvb(0, 2):string() ~= "AT" then
    t:add_proto_expert_info(e.tel_bad)
    t:add(f.data, tvb())
    info(pinfo, string.format("Telemetry, malformed (%d bytes)", tvb:len()))
    return tvb:len()
  end
  t:add(f.tel_magic, tvb(0, 2))
  local vi = t:add(f.tel_version, tvb(2, 1))
  if tvb(2, 1):uint() ~= 1 then vi:add_proto_expert_info(e.bad_version) end
  local fi = t:add(f.tel_flags, tvb(3, 1))
  fi:add(f.tel_moving, tvb(3, 1))
  fi:add(f.tel_reached, tvb(3, 1))
  t:add(f.tel_seq, tvb(4, 4))
  t:add(f.tel_time, tvb(8, 4))
  local actual, target, worst = {}, {}, 0
  for i = 1, 3 do
    actual[i] = degrees(tvb(8 + i * 4, 4))
    target[i] = degrees(tvb(20 + i * 4, 4))
    worst = math.max(worst, math.abs(target[i] - actual[i]))
  end
  for i = 1, 3 do t:add(TEL_J[i], tvb(8 + i * 4, 4), actual[i]) end
  for i = 1, 3 do t:add(TEL_T[i], tvb(20 + i * 4, 4), target[i]) end
  t:add(f.tel_error, worst):set_generated()
  local flags = tvb(3, 1):uint()
  local state = flags % 2 == 1 and " moving" or (math.floor(flags / 2) % 2 == 1 and " reached" or "")
  info(pinfo, string.format("Telemetry seq=%d j1=%.2f° j2=%.2f° j3=%.2f°%s", tvb(4, 4):uint(), actual[1], actual[2], actual[3], state))
  return tvb:len()
end

function armc.dissector(tvb, pinfo, tree)
  -- 3: UDP
  if pinfo.port_type == 3 then return dissect_telemetry(tvb, pinfo, tree) end
  dissect_tcp_pdus(tvb, tree, HEADER, pdu_len, dissect_message)
  -- A message whose first bytes are here and the rest in later frames
  if not pinfo.visited and partial(tvb) then
    local key = endpoints(pinfo)
    started[key] = started[key] or { frame = pinfo.number, ts = pinfo.abs_ts }
  end
  return tvb:len()
end

DissectorTable.get("tcp.port"):add(PORT, armc)
DissectorTable.get("udp.port"):add(TELEMETRY, armc)
