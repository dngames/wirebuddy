// HTTP downloads of small PNG images, for the panel tests: each image on a TCP
// connection of its own (10.0.0.1 -> 10.0.0.2:80), its response in 1400-byte segments.
import { writeFileSync } from "node:fs";
import { crc32, deflateSync } from "node:zlib";

/** A w x h PNG in one hue, lighter to the right and darker to the bottom. */
export function png(w, h, hue) {
  const rows = [];
  for (let y = 0; y < h; y++) {
    const row = Buffer.alloc(1 + w * 3);
    for (let x = 0; x < w; x++) {
      const [r, g, b] = hsl(hue, 0.7, 0.25 + 0.5 * (x / w) * (1 - (0.5 * y) / h));
      row.set([r, g, b], 1 + x * 3);
    }
    rows.push(row);
  }
  const chunk = (type, data) => {
    const out = Buffer.alloc(12 + data.length);
    out.writeUInt32BE(data.length, 0);
    out.write(type, 4, "latin1");
    data.copy(out, 8);
    out.writeUInt32BE(crc32(out.subarray(4, 8 + data.length)), 8 + data.length);
    return out;
  };
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(w, 0);
  ihdr.writeUInt32BE(h, 4);
  ihdr.set([8, 2, 0, 0, 0], 8);
  return Buffer.concat([Buffer.from("89504e470d0a1a0a", "hex"), chunk("IHDR", ihdr), chunk("IDAT", deflateSync(Buffer.concat(rows))), chunk("IEND", Buffer.alloc(0))]);
}

function hsl(h, s, l) {
  const k = (n) => (n + h / 30) % 12;
  const a = s * Math.min(l, 1 - l);
  const f = (n) => Math.round(255 * (l - a * Math.max(-1, Math.min(k(n) - 3, 9 - k(n), 1))));
  return [f(0), f(8), f(4)];
}

/** Writes `count` image downloads as a pcap to `path`; returns the images. */
export function writeGalleryCapture(path, { count = 6, start = 1700000000 } = {}) {
  const header = Buffer.alloc(24);
  header.writeUInt32LE(0xa1b2c3d4, 0);
  header.writeUInt16LE(2, 4);
  header.writeUInt16LE(4, 6);
  header.writeUInt32LE(65535, 16);
  header.writeUInt32LE(1, 20);
  const parts = [header];
  let usec = 0;
  const packet = (fromClient, port, seq, ack, flags, payload = Buffer.alloc(0)) => {
    const tcp = Buffer.alloc(20 + payload.length);
    tcp.writeUInt16BE(fromClient ? port : 80, 0);
    tcp.writeUInt16BE(fromClient ? 80 : port, 2);
    tcp.writeUInt32BE(seq >>> 0, 4);
    tcp.writeUInt32BE(ack >>> 0, 8);
    tcp.writeUInt8(0x50, 12);
    tcp.writeUInt8(flags, 13);
    tcp.writeUInt16BE(65535, 14);
    payload.copy(tcp, 20);
    const ip = Buffer.alloc(20);
    ip.writeUInt8(0x45, 0);
    ip.writeUInt16BE(20 + tcp.length, 2);
    ip.writeUInt8(64, 8);
    ip.writeUInt8(6, 9);
    ip.set(fromClient ? [10, 0, 0, 1] : [10, 0, 0, 2], 12);
    ip.set(fromClient ? [10, 0, 0, 2] : [10, 0, 0, 1], 16);
    const eth = Buffer.from(fromClient ? [2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1, 8, 0] : [2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2, 8, 0]);
    const frame = Buffer.concat([eth, ip, tcp]);
    const rec = Buffer.alloc(16);
    usec += 2000;
    rec.writeUInt32LE(start + Math.floor(usec / 1e6), 0);
    rec.writeUInt32LE(usec % 1e6, 4);
    rec.writeUInt32LE(frame.length, 8);
    rec.writeUInt32LE(frame.length, 12);
    parts.push(rec, frame);
  };
  const images = [];
  for (let i = 0; i < count; i++) {
    const body = png(96, 64, (i * 360) / count);
    images.push(body);
    const port = 40000 + i;
    let c = 1000;
    let s = 5000;
    packet(true, port, c, 0, 0x02);
    packet(false, port, s, c + 1, 0x12);
    c++;
    s++;
    packet(true, port, c, s, 0x10);
    const req = Buffer.from(`GET /img/${i}.png HTTP/1.1\r\nHost: 10.0.0.2\r\n\r\n`);
    packet(true, port, c, s, 0x18, req);
    c += req.length;
    const res = Buffer.concat([Buffer.from(`HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: ${body.length}\r\n\r\n`), body]);
    for (let at = 0; at < res.length; at += 1400) {
      const seg = res.subarray(at, at + 1400);
      packet(false, port, s, c, 0x18, seg);
      s += seg.length;
    }
    packet(true, port, c, s, 0x10);
  }
  writeFileSync(path, Buffer.concat(parts));
  return images;
}
