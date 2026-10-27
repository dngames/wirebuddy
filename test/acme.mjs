// A made-up protocol for the extension tests: "ACME" on UDP port 50000, which
// Wireshark only shows as Data. Payload: magic 0xACE1, u32 sequence, u8 kind,
// then 4 point bytes for kind 2. The last packet is cut short (3 bytes).
import { writeFileSync } from "node:fs";

function checksum(b) {
  let sum = 0;
  for (let i = 0; i < b.length; i += 2) sum += (b[i] << 8) | (b[i + 1] ?? 0);
  while (sum > 0xffff) sum = (sum & 0xffff) + (sum >>> 16);
  return ~sum & 0xffff;
}

/**
 * Writes 20 ACME packets (10.0.0.1:40000 -> 10.0.0.2:50000, 100 ms apart) as a pcap to `path`.
 * `lead` puts a non-ACME packet first; `start` is the first packet's time in seconds.
 */
export function writeAcmeCapture(path, { lead = false, start = 1700000000 } = {}) {
  const header = Buffer.alloc(24);
  header.writeUInt32LE(0xa1b2c3d4, 0);
  header.writeUInt16LE(2, 4);
  header.writeUInt16LE(4, 6);
  header.writeUInt32LE(65535, 16);
  header.writeUInt32LE(1, 20);
  const parts = [header];
  const packets = [];
  for (let i = 0; i < 20; i++) {
    const kind = i % 2 ? 1 : 2;
    let payload = Buffer.alloc(7 + (kind === 2 ? 4 : 0));
    payload.writeUInt16BE(0xace1, 0);
    payload.writeUInt32BE(i, 2);
    payload.writeUInt8(kind, 6);
    if (kind === 2) payload.set([1, 2, 3, 4], 7);
    if (i === 19) payload = Buffer.from([0xac, 0xe1, 0x00]);
    packets.push(payload);
  }
  if (lead) packets.unshift(Buffer.from("not acme"));
  packets.forEach((payload, i) => {
    const udp = Buffer.alloc(8 + payload.length);
    udp.writeUInt16BE(40000, 0);
    udp.writeUInt16BE(lead && i === 0 ? 40001 : 50000, 2);
    udp.writeUInt16BE(udp.length, 4);
    payload.copy(udp, 8);
    const ip = Buffer.alloc(20);
    ip.writeUInt8(0x45, 0);
    ip.writeUInt16BE(20 + udp.length, 2);
    ip.writeUInt16BE(i, 4);
    ip.writeUInt8(64, 8);
    ip.writeUInt8(17, 9);
    ip.set([10, 0, 0, 1], 12);
    ip.set([10, 0, 0, 2], 16);
    ip.writeUInt16BE(checksum(ip), 10);
    const eth = Buffer.from([2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1, 8, 0]);
    const frame = Buffer.concat([eth, ip, udp]);
    const rec = Buffer.alloc(16);
    rec.writeUInt32LE(start + Math.floor(i / 10), 0);
    rec.writeUInt32LE((i % 10) * 100000, 4);
    rec.writeUInt32LE(frame.length, 8);
    rec.writeUInt32LE(frame.length, 12);
    parts.push(rec, frame);
  });
  writeFileSync(path, Buffer.concat(parts));
}
