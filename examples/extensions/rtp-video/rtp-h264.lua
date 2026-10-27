-- RTP on UDP port 5004 (like Decode As), its dynamic payload type 96 as H.264
DissectorTable.get("udp.port"):add(5004, Dissector.get("rtp"))
DissectorTable.get("rtp.pt"):add(96, Dissector.get("h264"))
