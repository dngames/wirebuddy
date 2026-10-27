// A made-up lidar protocol, "wbpc", for the lidar-wbpc example: a 16-beam spinning sensor in a
// room with crates and a car driving past, 10 scans at 10 Hz to UDP port 7502.
//   header, 16 bytes, little-endian: "WBPC", u32 scan, u16 part, u16 parts, u16 points, u16 flags
//   then per point, 8 bytes: i16 x, y, z in cm, u8 intensity, u8 ring
// At most 172 points a packet. The last packet is malformed (fewer points than it says).
// Usage: node test/media/lidar-wbpc.mjs <out.pcap>
import { fileURLToPath } from "node:url";
import { Pcap } from "./pcap.mjs";

export const PORT = 7502;
export const SCANS = 10;
const RINGS = 16;
const STEPS = 512;
const PER_PACKET = 172;

/** [min, max] corners in metres and an intensity; the sensor sits 1.5 m above the floor at 0,0. */
const crates = [
  { min: [3, 2, -1.5], max: [4.2, 3.2, -0.3], intensity: 150 },
  { min: [3.2, 2.2, -0.3], max: [4, 3, 0.5], intensity: 170 },
  { min: [-4, 3, -1.5], max: [-2.5, 4.5, -0.5], intensity: 140 },
  { min: [6, -1, -1.5], max: [6.4, -0.6, 1.5], intensity: 90 },
];
const room = { min: [-8, -6, -1.5], max: [12, 6, 1.5] };

/** Distance along a ray to an axis-aligned box, entering it (or leaving it when inside); Infinity if missed. */
function hit(o, d, box, inside = false) {
  let near = -Infinity;
  let far = Infinity;
  let axisNear = 0;
  let axisFar = 0;
  for (let a = 0; a < 3; a++) {
    if (Math.abs(d[a]) < 1e-9) {
      if (o[a] < box.min[a] || o[a] > box.max[a]) return { t: Infinity };
      continue;
    }
    let t1 = (box.min[a] - o[a]) / d[a];
    let t2 = (box.max[a] - o[a]) / d[a];
    if (t1 > t2) [t1, t2] = [t2, t1];
    if (t1 > near) [near, axisNear] = [t1, a];
    if (t2 < far) [far, axisFar] = [t2, a];
  }
  if (near > far || far < 0) return { t: Infinity };
  return inside ? { t: far, axis: axisFar } : near > 0 ? { t: near, axis: axisNear } : { t: Infinity };
}

/** The points of scan `n`: [x, y, z (cm), intensity, ring] each. */
export function scan(n) {
  const car = { min: [-6 + n * 1.2, -3.4, -1.5], max: [-1.8 + n * 1.2, -1.6, -0.1], intensity: 220 };
  const objects = [...crates, car];
  let seed = 12345 + n;
  const noise = () => ((seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff - 0.5) * 0.02;
  const points = [];
  for (let s = 0; s < STEPS; s++) {
    const az = (s / STEPS) * 2 * Math.PI;
    for (let ring = 0; ring < RINGS; ring++) {
      const el = ((-15 + ring * 2) * Math.PI) / 180;
      const d = [Math.cos(el) * Math.cos(az), Math.cos(el) * Math.sin(az), Math.sin(el)];
      let best = { ...hit([0, 0, 0], d, room, true), intensity: d[2] < -0.05 ? 40 : d[2] > 0.05 ? 30 : 60 };
      for (const o of objects) {
        const h = hit([0, 0, 0], d, o);
        if (h.t < best.t) best = { ...h, intensity: o.intensity };
      }
      if (!Number.isFinite(best.t) || best.t > 30) continue;
      const t = best.t + noise();
      const falloff = Math.abs(d[best.axis]) * 0.6 + 0.4;
      points.push([
        Math.round(d[0] * t * 100),
        Math.round(d[1] * t * 100),
        Math.round(d[2] * t * 100),
        Math.min(255, Math.round(best.intensity * falloff * (1 - t / 60))),
        ring,
      ]);
    }
  }
  return points;
}

function packet(scanId, part, parts, points, count = points.length) {
  const buf = Buffer.alloc(16 + points.length * 8);
  buf.write("WBPC", 0, "latin1");
  buf.writeUInt32LE(scanId, 4);
  buf.writeUInt16LE(part, 8);
  buf.writeUInt16LE(parts, 10);
  buf.writeUInt16LE(count, 12);
  buf.writeUInt16LE(0, 14);
  points.forEach(([x, y, z, intensity, ring], i) => {
    buf.writeInt16LE(x, 16 + i * 8);
    buf.writeInt16LE(y, 18 + i * 8);
    buf.writeInt16LE(z, 20 + i * 8);
    buf.writeUInt8(intensity, 22 + i * 8);
    buf.writeUInt8(ring, 23 + i * 8);
  });
  return buf;
}

/** Writes the capture; returns the points of each scan. */
export function writeLidarCapture(path) {
  const pcap = new Pcap();
  const scans = [];
  for (let n = 0; n < SCANS; n++) {
    const points = scan(n);
    scans.push(points);
    const parts = Math.ceil(points.length / PER_PACKET);
    for (let p = 0; p < parts; p++) {
      pcap.udp(0.1 * n + p * 0.001, "192.168.1.201", 7501, "192.168.1.100", PORT, packet(100 + n, p, parts, points.slice(p * PER_PACKET, (p + 1) * PER_PACKET)));
    }
  }
  pcap.udp(0.1 * SCANS, "192.168.1.201", 7501, "192.168.1.100", PORT, packet(100 + SCANS, 0, 1, scan(0).slice(0, 10), 50));
  pcap.write(path);
  return scans;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const scans = writeLidarCapture(process.argv[2] ?? "lidar-wbpc.pcap");
  console.log(`${scans.length} scans, ${scans.map((s) => s.length).join(" ")} points`);
}
