#!/usr/bin/env node
// Pick-and-place cell: streams a joint trajectory to the ARMC arm controller and reports how
// closely the arm followed it.
// Usage: node app.mjs [--port 7700] [--telemetry 7701] [--seconds 6] [--rate 50]
import { connect } from "node:net";
import { createSocket } from "node:dgram";
import { parseArgs } from "node:util";
import { setTimeout as sleep } from "node:timers/promises";

const { values } = parseArgs({
  options: {
    port: { type: "string", default: "7700" },
    telemetry: { type: "string", default: "7701" },
    seconds: { type: "string", default: "6" },
    rate: { type: "string", default: "50" },
  },
});
const CONTROLLER_HOST = "127.0.0.1";

const PROTOCOL_VERSION = 1;
const HEADER_SIZE = 8;
const MSG = { MOVE: 0x01, HOME: 0x02, STOP: 0x03, PING: 0x10, ACK: 0x81, NACK: 0x82, PONG: 0x90 };
const MSG_NAME = Object.fromEntries(Object.entries(MSG).map(([k, v]) => [v, k]));
const REPLY_TIMEOUT_MS = 1000;
const MOVE_SPEED = 120;

/** ARMC v1 client: one TCP connection to the controller, replies matched to requests by sequence number. */
class ArmClient {
  constructor(socket) {
    this.socket = socket;
    this.seq = 0;
    this.pending = new Map();
    this.rx = Buffer.alloc(0);
    socket.on("data", (chunk) => this.onData(chunk));
    socket.on("error", (err) => this.failAll(err));
    socket.on("close", () => this.failAll(new Error("controller closed the connection")));
  }

  static connect(host, port) {
    return new Promise((resolve, reject) => {
      const socket = connect({ host, port }, () => {
        socket.off("error", reject);
        resolve(new ArmClient(socket));
      });
      socket.once("error", reject);
    });
  }

  /** Sends one message and returns its sequence number. */
  send(type, payload = Buffer.alloc(0)) {
    this.seq = (this.seq + 1) & 0xffff;
    const header = Buffer.alloc(HEADER_SIZE);
    header.write("AM", 0, "latin1");
    header.writeUInt8(PROTOCOL_VERSION, 2);
    header.writeUInt8(type, 3);
    header.writeUInt16BE(this.seq, 4);
    header.writeUInt16BE(payload.length, 6);
    this.socket.write(header);
    if (payload.length > 0) this.socket.write(payload);
    return this.seq;
  }

  /** Sends a request; resolves with the reply's payload, rejects on NACK or timeout. */
  request(type, payload) {
    return new Promise((resolve, reject) => {
      const seq = this.send(type, payload);
      const timer = setTimeout(() => {
        this.pending.delete(seq);
        reject(new Error(`no reply to ${MSG_NAME[type]} #${seq} within ${REPLY_TIMEOUT_MS} ms`));
      }, REPLY_TIMEOUT_MS);
      this.pending.set(seq, { type, resolve, reject, timer });
    });
  }

  onData(chunk) {
    this.rx = this.rx.length ? Buffer.concat([this.rx, chunk]) : chunk;
    while (this.rx.length >= HEADER_SIZE) {
      if (this.rx.toString("latin1", 0, 2) !== "AM") {
        this.socket.destroy(new Error("lost framing: bad magic from controller"));
        return;
      }
      const length = this.rx.readUInt16BE(6);
      if (this.rx.length < HEADER_SIZE + length) return;
      const type = this.rx[3];
      const seq = this.rx.readUInt16BE(4);
      const payload = this.rx.subarray(HEADER_SIZE, HEADER_SIZE + length);
      this.rx = this.rx.subarray(HEADER_SIZE + length);
      this.reply(type, seq, payload);
    }
  }

  reply(type, seq, payload) {
    const req = this.pending.get(seq);
    if (!req) return;
    this.pending.delete(seq);
    clearTimeout(req.timer);
    if (type === MSG.NACK) req.reject(new Error(`controller refused ${MSG_NAME[req.type]} (error ${payload[0]}): ${payload.toString("utf8", 1)}`));
    else req.resolve(payload);
  }

  failAll(err) {
    for (const req of this.pending.values()) {
      clearTimeout(req.timer);
      req.reject(err);
    }
    this.pending.clear();
  }

  ping() {
    return this.request(MSG.PING);
  }

  home() {
    return this.request(MSG.HOME);
  }

  stop() {
    return this.request(MSG.STOP);
  }

  /** Joint targets in degrees; resolves with the ACK's queue depth and processing time. */
  async move([j1, j2, j3], speed) {
    const payload = Buffer.alloc(14);
    payload.writeInt32BE(Math.round(j1 * 1000), 0);
    payload.writeInt32BE(Math.round(j2 * 1000), 4);
    payload.writeInt32BE(Math.round(j3 * 1000), 8);
    payload.writeUInt16BE(speed, 12);
    const ack = await this.request(MSG.MOVE, payload);
    return { queue: ack[1], deviceUs: ack.readUInt16BE(2) };
  }

  close() {
    this.socket.end();
  }
}

/** Telemetry from the controller: joint positions every 10 ms. */
class Telemetry {
  constructor(socket) {
    this.socket = socket;
    this.samples = [];
    this.latest = null;
    socket.on("message", (msg) => this.onMessage(msg));
  }

  static listen(port) {
    return new Promise((resolve, reject) => {
      const socket = createSocket("udp4");
      socket.once("error", reject);
      socket.bind(port, CONTROLLER_HOST, () => {
        socket.off("error", reject);
        resolve(new Telemetry(socket));
      });
    });
  }

  onMessage(msg) {
    if (msg.length < 36 || msg.toString("latin1", 0, 2) !== "AT" || msg[2] !== PROTOCOL_VERSION) return;
    const deg = (o) => [0, 4, 8].map((i) => msg.readInt32BE(o + i) / 1000);
    this.latest = { at: performance.now(), flags: msg[3], actual: deg(12), target: deg(24) };
    this.samples.push(this.latest);
  }

  /** Waits until the controller reports the given target reached. */
  async reached(target, timeoutMs) {
    const end = performance.now() + timeoutMs;
    while (performance.now() < end) {
      const s = this.latest;
      if (s && s.flags & 2 && s.target.every((t, j) => Math.abs(t - target[j]) < 0.001)) return true;
      await sleep(10);
    }
    return false;
  }

  close() {
    this.socket.close();
  }
}

/** The pick-and-place cycle in degrees, t in seconds. */
function trajectory(t) {
  return [40 * Math.sin((2 * Math.PI * t) / 3), 25 * Math.sin((2 * Math.PI * t) / 1.5), 30 * Math.cos((2 * Math.PI * t) / 3)];
}

const percentile = (sorted, p) => sorted[Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))];
const ms = (v) => `${v.toFixed(1)} ms`;

async function main() {
  const port = Number(values.port);
  const seconds = Number(values.seconds);
  const rate = Number(values.rate);
  const period = 1000 / rate;
  if (!(seconds > 0 && rate > 0)) throw new Error("--seconds and --rate must be positive");

  const telemetry = await Telemetry.listen(Number(values.telemetry));
  const arm = await ArmClient.connect(CONTROLLER_HOST, port);
  let t = performance.now();
  await arm.ping();
  console.log(`connected to ARMC controller at ${CONTROLLER_HOST}:${port} (ping ${(performance.now() - t).toFixed(2)} ms)`);

  await arm.home();
  if (!(await telemetry.reached([0, 0, 0], 5000))) console.log("warning: no telemetry, tracking is not measured");
  const startPose = trajectory(0);
  await arm.move(startPose, MOVE_SPEED);
  await telemetry.reached(startPose, 2000);
  console.log(`at start pose, streaming the trajectory for ${seconds} s at ${rate} Hz`);

  // One MOVE per slot, each acknowledged before the next
  const slots = Math.round(seconds * rate);
  const latencies = [];
  const deviceUs = [];
  let missed = 0;
  const t0 = performance.now();
  for (let slot = 0; slot < slots; ) {
    const due = t0 + slot * period;
    const wait = due - performance.now();
    if (wait > 0) await sleep(wait);
    t = performance.now();
    const target = trajectory((t - t0 + period) / 1000); // where the arm should be at the next slot
    const ack = await arm.move(target, MOVE_SPEED);
    latencies.push(performance.now() - t);
    deviceUs.push(ack.deviceUs);
    const current = Math.floor((performance.now() - t0) / period);
    const next = Math.min(Math.max(slot + 1, current), slots);
    missed += next - slot - 1;
    slot = next;
  }
  const elapsed = (performance.now() - t0) / 1000;
  await arm.stop();
  arm.close();
  telemetry.close();

  // Tracking: the arm's joints against the trajectory
  const during = telemetry.samples.filter((s) => s.at >= t0 && s.at <= t0 + elapsed * 1000);
  let worst = { error: 0, joint: 0 };
  let squares = 0;
  for (const s of during) {
    const want = trajectory((s.at - t0) / 1000);
    s.actual.forEach((a, j) => {
      const error = Math.abs(a - want[j]);
      squares += error * error;
      if (error > worst.error) worst = { error, joint: j };
    });
  }

  const sorted = [...latencies].sort((a, b) => a - b);
  const sent = latencies.length;
  const achieved = sent / elapsed;
  const lines = [
    "",
    "Trajectory report",
    `  MOVE commands     ${sent} sent, ${achieved.toFixed(1)}/s achieved (requested ${rate}/s)`,
    `  deadlines missed  ${missed} of ${slots} command slots`,
    `  ACK latency       p50 ${ms(percentile(sorted, 50))}, p95 ${ms(percentile(sorted, 95))}, max ${ms(sorted.at(-1))}`,
    `  controller time   p50 ${percentile([...deviceUs].sort((a, b) => a - b), 50)} µs (reported in the ACKs)`,
  ];
  if (during.length > 0) {
    lines.push(`  tracking error    max ${worst.error.toFixed(1)}° (j${worst.joint + 1}), rms ${Math.sqrt(squares / (3 * during.length)).toFixed(1)}°`);
  }
  if (achieved < 0.9 * rate) lines.push("", `WARNING: command rate ${achieved.toFixed(1)}/s is below the required ${rate}/s, motion will not be smooth`);
  console.log(lines.join("\n"));
}

main().catch((err) => {
  console.error(`app: ${err.message}`);
  process.exit(1);
});
