// H.264 video over RTP (RFC 6184), for the rtp-video example: two streams to UDP port 5004,
// payload type 96, 90 kHz clock, 25 fps; SPS and PPS in a STAP-A, large NAL units in FU-A
// fragments of at most 1200 bytes, the marker bit on each picture's last packet.
// Usage: node test/media/rtp-h264.mjs <out.pcap>
import { fileURLToPath } from "node:url";
import { bouncingBall, encode } from "./h264.mjs";
import { Pcap } from "./pcap.mjs";

const MTU = 1200;
export const PORT = 5004;
export const STREAMS = [
  { ssrc: 0x1234abcd, src: "10.0.0.5", sport: 40000, width: 160, height: 112, frames: 60, hue: 20 },
  { ssrc: 0x0badcafe, src: "10.0.0.6", sport: 40002, width: 96, height: 64, frames: 40, hue: 200 },
];

/** RTP payloads of one access unit. */
function packetize(au) {
  const out = [];
  const params = au.filter((n) => (n[0] & 0x1f) === 7 || (n[0] & 0x1f) === 8);
  const rest = au.filter((n) => !params.includes(n));
  if (params.length) {
    const parts = [Uint8Array.of(Math.max(...params.map((n) => n[0] & 0x60)) | 24)];
    for (const n of params) parts.push(Uint8Array.of(n.length >> 8, n.length & 0xff), n);
    out.push(Buffer.concat(parts));
  }
  for (const n of rest) {
    if (n.length <= MTU) {
      out.push(n);
      continue;
    }
    const body = n.subarray(1);
    for (let at = 0; at < body.length; at += MTU - 2) {
      const start = at === 0 ? 0x80 : 0;
      const end = at + MTU - 2 >= body.length ? 0x40 : 0;
      out.push(Buffer.concat([Uint8Array.of((n[0] & 0xe0) | 28, start | end | (n[0] & 0x1f)), body.subarray(at, at + MTU - 2)]));
    }
  }
  return out;
}

/** Writes the capture; returns its streams with their picture and packet counts. */
export function writeRtpCapture(path) {
  const pcap = new Pcap();
  const sends = [];
  for (const [k, s] of STREAMS.entries()) {
    const units = encode(bouncingBall(s.width, s.height, s.frames, s.hue), 30);
    let seq = 1000 * (k + 1);
    s.packets = 0;
    units.forEach((au, i) => {
      const payloads = packetize(au);
      payloads.forEach((p, j) => {
        const rtp = Buffer.alloc(12);
        rtp.writeUInt8(0x80, 0);
        rtp.writeUInt8((j === payloads.length - 1 ? 0x80 : 0) | 96, 1);
        rtp.writeUInt16BE(seq++ & 0xffff, 2);
        rtp.writeUInt32BE((90000 * k + i * 3600) >>> 0, 4);
        rtp.writeUInt32BE(s.ssrc, 8);
        sends.push({ t: 0.1 + i * 0.04 + j * 0.0002 + k * 0.013, s, data: Buffer.concat([rtp, p]) });
        s.packets++;
      });
    });
  }
  sends.sort((a, b) => a.t - b.t);
  for (const { t, s, data } of sends) pcap.udp(t, s.src, s.sport, "10.0.0.9", PORT, data);
  pcap.write(path);
  return STREAMS;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const streams = writeRtpCapture(process.argv[2] ?? "rtp-h264.pcap");
  for (const s of streams) console.log(`ssrc 0x${s.ssrc.toString(16)}: ${s.frames} pictures ${s.width}x${s.height}, ${s.packets} packets`);
}
