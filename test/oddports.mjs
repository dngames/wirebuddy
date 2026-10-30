// Protocols Wireshark knows, on ports it doesn't expect them on, for the Decode As tests: DNS on
// UDP port 123 (frames 1-4, read as malformed NTP), RTP from 10.0.0.4:30000 to 10.0.0.5:50000
// (5-9) and an MQTT CONNECT and CONNACK on TCP port 18830 (10-11), both read as Data.
import { writeFileSync } from "node:fs";
import { eth, ip4, pcapHeader, pcapRecord, tcp, udp } from "./capgen.mjs";

const name = Buffer.from("\x07example\x03com\x00\x00\x01\x00\x01", "latin1");
const dnsQuery = (id) => Buffer.concat([Buffer.from([id >> 8, id & 255, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]), name]);
const dnsAnswer = (id) => Buffer.concat([Buffer.from([id >> 8, id & 255, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]), name, Buffer.from([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0x0e, 0x10, 0, 4, 93, 184, 216, 34])]);

/** RTP version 2, payload type 0, with 160 bytes of audio. */
function rtp(seq) {
  const b = Buffer.alloc(12 + 160);
  b[0] = 0x80;
  b.writeUInt16BE(seq, 2);
  b.writeUInt32BE(seq * 160, 4);
  b.writeUInt32BE(0x12345678, 8);
  return b;
}

const mqttConnect = Buffer.from([0x10, 0x10, 0, 4, ...Buffer.from("MQTT"), 4, 2, 0, 60, 0, 4, ...Buffer.from("test")]);
const mqttConnack = Buffer.from([0x20, 2, 0, 0]);

/** Writes the 11 packets as a pcap to `path`. */
export function writeOddPortsCapture(path) {
  const v4 = (proto, body, src, dst) => eth(0x0800, ip4(proto, body, { src: [10, 0, 0, src], dst: [10, 0, 0, dst] }));
  const frames = [];
  for (const id of [10, 11]) {
    frames.push(v4(17, udp(41000 + id, 123, dnsQuery(id)), 1, 3));
    frames.push(v4(17, udp(123, 41000 + id, dnsAnswer(id)), 3, 1));
  }
  for (let i = 0; i < 5; i++) frames.push(v4(17, udp(30000, 50000, rtp(100 + i)), 4, 5));
  frames.push(v4(6, tcp(46000, 18830, mqttConnect, { seq: 1000, ack: 5000 }), 1, 7));
  frames.push(v4(6, tcp(18830, 46000, mqttConnack, { seq: 5000, ack: 1000 + mqttConnect.length }), 7, 1));
  writeFileSync(path, Buffer.concat([pcapHeader(), ...frames.map((f, i) => pcapRecord(1_700_000_000, i * 1000, f))]));
}
