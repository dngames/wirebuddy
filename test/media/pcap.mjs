// A small pcap writer for the showcase fixtures: Ethernet, IPv4, UDP and TCP, microsecond timestamps.
import { writeFileSync } from "node:fs";

const ip4 = (s) => s.split(".").map(Number);
const mac = (s) => [2, 0, ...ip4(s)];

export class Pcap {
  /** `start`: epoch seconds of time 0. */
  constructor(start = 1700000000) {
    this.start = start;
    this.parts = [];
    const header = Buffer.alloc(24);
    header.writeUInt32LE(0xa1b2c3d4, 0);
    header.writeUInt16LE(2, 4);
    header.writeUInt16LE(4, 6);
    header.writeUInt32LE(262144, 16);
    header.writeUInt32LE(1, 20);
    this.parts.push(header);
    this.count = 0;
  }

  /** An IPv4 packet in an Ethernet frame, `t` seconds after the start. */
  ip(t, src, dst, proto, l4) {
    const ip = Buffer.alloc(20);
    ip.writeUInt8(0x45, 0);
    ip.writeUInt16BE(20 + l4.length, 2);
    ip.writeUInt16BE(this.count & 0xffff, 4);
    ip.writeUInt8(64, 8);
    ip.writeUInt8(proto, 9);
    ip.set(ip4(src), 12);
    ip.set(ip4(dst), 16);
    let sum = 0;
    for (let i = 0; i < 20; i += 2) sum += ip.readUInt16BE(i);
    while (sum > 0xffff) sum = (sum & 0xffff) + (sum >>> 16);
    ip.writeUInt16BE(~sum & 0xffff, 10);
    const frame = Buffer.concat([Buffer.from([...mac(dst), ...mac(src), 8, 0]), ip, l4]);
    const rec = Buffer.alloc(16);
    const usec = Math.round(t * 1e6);
    rec.writeUInt32LE(this.start + Math.floor(usec / 1e6), 0);
    rec.writeUInt32LE(usec % 1e6, 4);
    rec.writeUInt32LE(frame.length, 8);
    rec.writeUInt32LE(frame.length, 12);
    this.parts.push(rec, frame);
    this.count++;
  }

  udp(t, src, sport, dst, dport, payload) {
    const udp = Buffer.alloc(8 + payload.length);
    udp.writeUInt16BE(sport, 0);
    udp.writeUInt16BE(dport, 2);
    udp.writeUInt16BE(udp.length, 4);
    Buffer.from(payload.buffer, payload.byteOffset, payload.length).copy(udp, 8);
    this.ip(t, src, dst, 17, udp);
  }

  tcp(t, src, sport, dst, dport, seq, ack, flags, payload = Buffer.alloc(0)) {
    const tcp = Buffer.alloc(20 + payload.length);
    tcp.writeUInt16BE(sport, 0);
    tcp.writeUInt16BE(dport, 2);
    tcp.writeUInt32BE(seq >>> 0, 4);
    tcp.writeUInt32BE(ack >>> 0, 8);
    tcp.writeUInt8(0x50, 12);
    tcp.writeUInt8(flags, 13);
    tcp.writeUInt16BE(65535, 14);
    payload.copy(tcp, 20);
    this.ip(t, src, dst, 6, tcp);
  }

  /**
   * One TCP connection from `client` to `server`:80: handshake, the request, the
   * response in 1400-byte segments, and the close. Returns the time after it.
   */
  http(t, client, port, server, request, response) {
    const step = 0.0005;
    let c = 1000;
    let s = 5000;
    this.tcp(t, client, port, server, 80, c, 0, 0x02);
    this.tcp((t += step), server, 80, client, port, s, c + 1, 0x12);
    c++;
    s++;
    this.tcp((t += step), client, port, server, 80, c, s, 0x10);
    this.tcp((t += step), client, port, server, 80, c, s, 0x18, request);
    c += request.length;
    for (let at = 0; at < response.length; at += 1400) {
      const seg = response.subarray(at, at + 1400);
      this.tcp((t += step), server, 80, client, port, s, c, 0x18, seg);
      s += seg.length;
    }
    this.tcp((t += step), client, port, server, 80, c, s, 0x10);
    this.tcp((t += step), server, 80, client, port, s, c, 0x11);
    this.tcp((t += step), client, port, server, 80, c, s + 1, 0x11);
    this.tcp((t += step), server, 80, client, port, s + 1, c + 1, 0x10);
    return t + step;
  }

  write(path) {
    writeFileSync(path, Buffer.concat(this.parts));
  }
}
