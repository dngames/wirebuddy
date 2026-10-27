#!/usr/bin/env node
// Emulated ARMC v1 arm controller (see PROTOCOL.md): three joints, commands over TCP, telemetry
// over UDP at 100 Hz.
// Usage: node device.mjs [--port 7700] [--telemetry 7701]
import { createServer } from "node:net";
import { createSocket } from "node:dgram";
import { parseArgs } from "node:util";

const { values } = parseArgs({
  options: { port: { type: "string", default: "7700" }, telemetry: { type: "string", default: "7701" } },
});
const HOST = "127.0.0.1";
const PORT = Number(values.port);
const TELEMETRY_PORT = Number(values.telemetry);

const VERSION = 1;
const HEADER_SIZE = 8;
const MAX_PAYLOAD = 64;
const MSG = { MOVE: 0x01, HOME: 0x02, STOP: 0x03, PING: 0x10, ACK: 0x81, NACK: 0x82, PONG: 0x90 };
const ERR = { BAD_MAGIC: 1, BAD_VERSION: 2, UNKNOWN_TYPE: 3, BAD_LENGTH: 4, OUT_OF_RANGE: 5 };
const PAYLOAD_SIZE = { [MSG.MOVE]: 14, [MSG.HOME]: 0, [MSG.STOP]: 0, [MSG.PING]: 0 };
/** Joint limits in millidegrees, both directions. */
const LIMITS = [170_000, 90_000, 135_000];
const SPEED_MAX = 180;
const HOME_SPEED = 60;
const TICK_MS = 10;
const TELEMETRY_SIZE = 36;

/** Joint angles in millidegrees; speed in deg/s. */
const arm = { actual: [0, 0, 0], target: [0, 0, 0], speed: HOME_SPEED };
/** Targets not reached yet: a new MOVE replaces the current one. */
const queueDepth = () => (arm.actual.some((a, j) => a !== arm.target[j]) ? 1 : 0);

function message(type, seq, payload = Buffer.alloc(0)) {
  const header = Buffer.alloc(HEADER_SIZE);
  header.write("AM", 0, "latin1");
  header[2] = VERSION;
  header[3] = type;
  header.writeUInt16BE(seq, 4);
  header.writeUInt16BE(payload.length, 6);
  return Buffer.concat([header, payload]);
}

function ack(seq, started) {
  const payload = Buffer.alloc(4);
  payload[0] = 0;
  payload[1] = queueDepth();
  payload.writeUInt16BE(Math.min(0xffff, Number((process.hrtime.bigint() - started) / 1000n)), 2);
  return message(MSG.ACK, seq, payload);
}

function nack(seq, code, reason) {
  return message(MSG.NACK, seq, Buffer.concat([Buffer.from([code]), Buffer.from(reason, "utf8")]));
}

/** The reply to one complete request. */
function handle(type, seq, payload, started) {
  if (!(type in PAYLOAD_SIZE)) return nack(seq, ERR.UNKNOWN_TYPE, `unknown message type 0x${type.toString(16).padStart(2, "0")}`);
  if (payload.length !== PAYLOAD_SIZE[type]) return nack(seq, ERR.BAD_LENGTH, `payload of ${payload.length} bytes, expected ${PAYLOAD_SIZE[type]}`);
  switch (type) {
    case MSG.MOVE: {
      const target = [0, 4, 8].map((o) => payload.readInt32BE(o));
      const speed = payload.readUInt16BE(12);
      const j = target.findIndex((t, i) => Math.abs(t) > LIMITS[i]);
      if (j >= 0) return nack(seq, ERR.OUT_OF_RANGE, `j${j + 1} target ${target[j] / 1000}° outside ±${LIMITS[j] / 1000}°`);
      if (speed < 1 || speed > SPEED_MAX) return nack(seq, ERR.OUT_OF_RANGE, `speed ${speed} deg/s outside 1..${SPEED_MAX}`);
      arm.target = target;
      arm.speed = speed;
      return ack(seq, started);
    }
    case MSG.HOME:
      arm.target = [0, 0, 0];
      arm.speed = HOME_SPEED;
      return ack(seq, started);
    case MSG.STOP:
      arm.target = arm.actual.map(Math.round);
      arm.actual = [...arm.target];
      return ack(seq, started);
    default:
      return message(MSG.PONG, seq);
  }
}

const server = createServer((socket) => {
  const peer = `${socket.remoteAddress}:${socket.remotePort}`;
  console.log(`host connected from ${peer}`);
  let buffer = Buffer.alloc(0);
  socket.on("data", (chunk) => {
    if (socket.writableEnded) return;
    const started = process.hrtime.bigint();
    buffer = buffer.length ? Buffer.concat([buffer, chunk]) : chunk;
    const replies = [];
    while (buffer.length >= HEADER_SIZE) {
      const seq = buffer.readUInt16BE(4);
      const length = buffer.readUInt16BE(6);
      if (buffer.toString("latin1", 0, 2) !== "AM" || length > MAX_PAYLOAD) {
        // No way to find the next message boundary
        const code = length > MAX_PAYLOAD ? ERR.BAD_LENGTH : ERR.BAD_MAGIC;
        replies.push(nack(seq, code, code === ERR.BAD_MAGIC ? "bad magic" : `payload length ${length} over ${MAX_PAYLOAD}`));
        socket.end(Buffer.concat(replies));
        buffer = Buffer.alloc(0);
        return;
      }
      if (buffer.length < HEADER_SIZE + length) break;
      const version = buffer[2];
      const type = buffer[3];
      const payload = buffer.subarray(HEADER_SIZE, HEADER_SIZE + length);
      buffer = buffer.subarray(HEADER_SIZE + length);
      replies.push(version === VERSION ? handle(type, seq, payload, started) : nack(seq, ERR.BAD_VERSION, `version ${version} not supported`));
    }
    if (replies.length) socket.write(Buffer.concat(replies));
  });
  socket.on("error", () => {});
  socket.on("close", () => console.log(`host ${peer} disconnected`));
});

const telemetry = createSocket("udp4");
telemetry.on("error", () => {});
const start = performance.now();
let seq = 0;
let last = start;
let next = start;

/** One control cycle: move each joint toward its target, then report. */
function tick() {
  const now = performance.now();
  const step = arm.speed * Math.min(now - last, 5 * TICK_MS); // deg/s times ms: millidegrees
  last = now;
  let moving = false;
  arm.actual = arm.actual.map((a, j) => {
    const diff = arm.target[j] - a;
    if (diff === 0) return a;
    moving = true;
    return Math.abs(diff) <= step ? arm.target[j] : a + Math.sign(diff) * step;
  });
  const datagram = Buffer.alloc(TELEMETRY_SIZE);
  datagram.write("AT", 0, "latin1");
  datagram[2] = VERSION;
  datagram[3] = (moving ? 1 : 0) | (queueDepth() ? 0 : 2);
  datagram.writeUInt32BE(seq++ >>> 0, 4);
  datagram.writeUInt32BE(Math.floor(now - start) >>> 0, 8);
  arm.actual.forEach((a, j) => datagram.writeInt32BE(Math.round(a), 12 + 4 * j));
  arm.target.forEach((t, j) => datagram.writeInt32BE(t, 24 + 4 * j));
  telemetry.send(datagram, TELEMETRY_PORT, HOST);
  next += TICK_MS;
  if (next < now) next = now + TICK_MS;
  setTimeout(tick, Math.max(0, next - performance.now()));
}

server.on("error", (err) => {
  console.error(`device: ${err.message}`);
  process.exit(1);
});
server.listen(PORT, HOST, () => {
  console.log(`ARMC controller listening on ${HOST}:${PORT}, telemetry to ${HOST}:${TELEMETRY_PORT} at ${1000 / TICK_MS} Hz`);
  tick();
});
for (const signal of ["SIGINT", "SIGTERM"]) process.on(signal, () => process.exit(0));
