// The robot-arm investigation (examples/investigations/robot-arm) as a capture on lo: the control
// app streams ARMC v1 commands from 127.0.0.1 to the arm controller on 127.0.0.1:7700, which
// answers each at once and sends 100 Hz telemetry to UDP port 7701.
//   By default with the app's bug: it writes each MOVE's header and payload in two writes, so with
//   Nagle the payload waits for the header's ACK, which the controller's stack delays by about 40 ms;
//   the app gets about 22 commands a second through and the arm stops and goes in jerks.
//   --fixed: one write per message, a MOVE every 20 ms, answered within 0.1 ms; the arm tracks.
// Usage: node test/media/robot-arm.mjs <out.pcap> [--fixed]
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { Pcap } from "./pcap.mjs";

export const PORT = 7700;
export const TELEMETRY = 7701;
const HOST = "127.0.0.1";
const APP_PORT = 46718;
const DEVICE_UDP_PORT = 51807;
const RATE = 50;
const SPEED = 120;
const HOME_SPEED = 60;
const TICK = 0.01;
export const TYPE = { MOVE: 0x01, HOME: 0x02, STOP: 0x03, PING: 0x10, ACK: 0x81, NACK: 0x82, PONG: 0x90 };
const SYN = 0x02;
const FIN = 0x01;
const PSH = 0x08;
const ACK = 0x10;

/** Where the app sends the joints `t` seconds into its run, in degrees. */
export const trajectory = (t) => [40 * Math.sin((2 * Math.PI * t) / 3), 25 * Math.sin((2 * Math.PI * t) / 1.5), 30 * Math.cos((2 * Math.PI * t) / 3)];

export function header(type, seq, len) {
  const b = Buffer.alloc(8);
  b.write("AM", 0, "latin1");
  b[2] = 1;
  b[3] = type;
  b.writeUInt16BE(seq & 0xffff, 4);
  b.writeUInt16BE(len, 6);
  return b;
}

/** A MOVE's payload: joints in millidegrees, speed in deg/s. */
export function movePayload(joints, speed) {
  const b = Buffer.alloc(14);
  joints.forEach((j, i) => b.writeInt32BE(j, i * 4));
  b.writeUInt16BE(speed, 12);
  return b;
}

export function ackMessage(seq, queue, procUs, status = 0) {
  const b = Buffer.alloc(4);
  b[0] = status;
  b[1] = queue;
  b.writeUInt16BE(procUs, 2);
  return Buffer.concat([header(TYPE.ACK, seq, 4), b]);
}

export function telemetry(seq, ms, flags, actual, target) {
  const b = Buffer.alloc(36);
  b.write("AT", 0, "latin1");
  b[2] = 1;
  b[3] = flags;
  b.writeUInt32BE(seq >>> 0, 4);
  b.writeUInt32BE(ms >>> 0, 8);
  [...actual, ...target].forEach((j, i) => b.writeInt32BE(j, 12 + i * 4));
  return b;
}

/** p50 by nearest rank, as the panel computes it. */
export const median = (xs) => [...xs].sort((a, b) => a - b)[Math.max(0, Math.ceil(xs.length / 2) - 1)];

/**
 * Writes the capture; returns what is in it: MOVEs and the frames they end in, telemetry packets,
 * the frames the armc dissector shows, the MOVEs' p50 ACK latency (header's first byte to the
 * ACK) and their rate.
 */
export function writeArmCapture(path, { fixed = false, seconds = 6 } = {}) {
  let seed = fixed ? 1907 : 2207;
  const rand = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
  const packets = [];
  const app = { ip: HOST, port: APP_PORT, seq: 0x1c2a3b4c };
  const dev = { ip: HOST, port: PORT, seq: 0x6f5e4d3c };
  // Sent in time order, so the other side's seq is what it has sent so far
  const tcp = (t, from, to, flags, payload = Buffer.alloc(0)) => {
    const seq = from.seq;
    const ack = flags & ACK ? to.seq : 0;
    const packet = { t, write: (p) => p.tcp(t, from.ip, from.port, to.ip, to.port, seq, ack, flags, payload) };
    packets.push(packet);
    from.seq = (from.seq + payload.length + (flags & (SYN | FIN) ? 1 : 0)) >>> 0;
    return packet;
  };
  // Linux's delayed ACK: 40 ms and up to two 4 ms ticks more
  const delayedAck = () => 0.04 + 0.004 * [0, 1, 1, 2][Math.floor(rand() * 4)] + rand() * 0.0006;

  /** What reaches the controller when, for its motion. */
  const commands = [];
  const moves = [];
  let armc = 0;
  let seq = 1;
  /** One request and its ACK; returns when the ACK arrived. */
  const request = (t, type, payload, split) => {
    const h = header(type, seq, payload.length);
    let done = t;
    let last;
    if (split && payload.length) {
      tcp(t, app, dev, PSH | ACK, h);
      const acked = t + delayedAck();
      tcp(acked, dev, app, ACK);
      done = acked + 0.000012 + rand() * 0.00001;
      last = tcp(done, app, dev, PSH | ACK, payload);
    } else last = tcp(t, app, dev, PSH | ACK, Buffer.concat([h, payload]));
    const proc = 3 + Math.floor(rand() * 6);
    const reply = done + 0.00004 + proc / 1e6 + rand() * 0.00003;
    tcp(reply, dev, app, PSH | ACK, ackMessage(seq, type === TYPE.MOVE ? 1 : 0, proc));
    commands.push({ t: done + proc / 1e6, type, payload });
    if (type === TYPE.MOVE) moves.push({ seq, t, latency: reply - t, packet: last });
    armc += 2;
    seq++;
    return reply;
  };

  let t = 0.15 + rand() * 0.01;
  tcp(t, app, dev, SYN);
  tcp((t += 0.000018), dev, app, SYN | ACK);
  tcp((t += 0.000011), app, dev, ACK);
  t = request(t + 0.00025, TYPE.HOME, Buffer.alloc(0), false);
  const start = t + 0.0005;
  for (let k = 0; ; k++) {
    // At the next 20 ms tick, or as soon as the ACK came when that has passed
    const send = Math.max(start + k / RATE + 0.00005 + rand() * 0.0002, t + 0.00008 + rand() * 0.00012);
    if (send - start >= seconds) break;
    const joints = trajectory(send - start).map((d) => Math.round(d * 1000));
    t = request(send, TYPE.MOVE, movePayload(joints, SPEED), !fixed);
  }
  t = request(t + 0.0002, TYPE.STOP, Buffer.alloc(0), false);
  tcp((t += 0.0003), app, dev, FIN | ACK);
  tcp((t += 0.00003), dev, app, FIN | ACK);
  tcp((t += 0.00001), app, dev, ACK);
  const end = t + 0.3;

  // The controller's 100 Hz loop: each joint toward the newest target at the commanded speed
  const actual = [0, 0, 0];
  let target = [0, 0, 0];
  let speed = HOME_SPEED;
  let next = 0;
  let ticks = 0;
  for (let i = 0; ; i++) {
    const at = 0.0043 + i * TICK + (rand() - 0.5) * 0.0001;
    if (at > end) break;
    for (; next < commands.length && commands[next].t <= at; next++) {
      const c = commands[next];
      if (c.type === TYPE.MOVE) {
        target = [0, 4, 8].map((o) => c.payload.readInt32BE(o));
        speed = c.payload.readUInt16BE(12);
      } else if (c.type === TYPE.HOME) {
        target = [0, 0, 0];
        speed = HOME_SPEED;
      } else if (c.type === TYPE.STOP) target = [...actual];
    }
    const step = speed * TICK * 1000;
    let moving = false;
    for (let j = 0; j < 3; j++) {
      const d = Math.max(-step, Math.min(step, target[j] - actual[j]));
      if (d) moving = true;
      actual[j] += d;
    }
    const reached = actual.every((a, j) => a === target[j]);
    const b = telemetry(48213 + i, 912340 + i * 10, (moving ? 1 : 0) | (reached ? 2 : 0), actual, target);
    packets.push({ t: at + 0.00002, write: (p) => p.udp(at + 0.00002, HOST, DEVICE_UDP_PORT, HOST, TELEMETRY, b) });
    ticks++;
  }

  const pcap = new Pcap();
  packets.sort((a, b) => a.t - b.t);
  packets.forEach((p, i) => {
    p.frame = i + 1;
    p.write(pcap);
  });
  pcap.write(path);
  const span = moves.length > 1 ? moves[moves.length - 1].t - moves[0].t : 0;
  return {
    frames: packets.length,
    moves: moves.length,
    moveFrames: moves.map((m) => m.packet.frame),
    telemetry: ticks,
    armc: armc + ticks,
    p50: median(moves.map((m) => m.latency)) * 1000,
    rate: span > 0 ? (moves.length - 1) / span : 0,
  };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const { values, positionals } = parseArgs({ allowPositionals: true, options: { fixed: { type: "boolean", default: false } } });
  const s = writeArmCapture(positionals[0] ?? "robot-arm.pcap", { fixed: values.fixed });
  console.log(`${s.frames} frames: ${s.moves} MOVEs, ${s.telemetry} telemetry packets; p50 ACK latency ${s.p50.toFixed(2)} ms, ${s.rate.toFixed(1)} commands/s`);
}
