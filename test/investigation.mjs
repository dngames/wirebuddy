// The robot-arm investigation example without a capture: the emulated controller speaks ARMC v1
// as its PROTOCOL.md says, the app as shipped falls behind its rate, and solution/fix.diff fixes it.
// Usage: node test/investigation.mjs   (loopback TCP and UDP only, no capture)
import { execFileSync, spawn } from "node:child_process";
import { createSocket } from "node:dgram";
import { connect, createServer } from "node:net";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const example = join(root, "examples/investigations/robot-arm");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let failures = 0;
async function check(name, fn) {
  try {
    await fn();
    console.log(`ok   ${name}`);
  } catch (err) {
    failures++;
    console.log(`FAIL ${name}: ${err.message}`);
  }
}

/** A loopback port nothing listens on right now. */
async function freePort(udp) {
  if (udp) {
    const s = createSocket("udp4");
    await new Promise((r) => s.bind(0, "127.0.0.1", r));
    const { port } = s.address();
    await new Promise((r) => s.close(r));
    return port;
  }
  const s = createServer();
  await new Promise((r) => s.listen(0, "127.0.0.1", r));
  const { port } = s.address();
  await new Promise((r) => s.close(r));
  return port;
}

/** An ARMC message: 8-byte header, then the payload. */
function message(type, seq, payload = Buffer.alloc(0), { magic = "AM", version = 1 } = {}) {
  const header = Buffer.alloc(8);
  header.write(magic, 0, "latin1");
  header[2] = version;
  header[3] = type;
  header.writeUInt16BE(seq, 4);
  header.writeUInt16BE(payload.length, 6);
  return Buffer.concat([header, payload]);
}
function movePayload(j1, j2, j3, speed) {
  const p = Buffer.alloc(14);
  [j1, j2, j3].forEach((v, i) => p.writeInt32BE(v, 4 * i));
  p.writeUInt16BE(speed, 12);
  return p;
}

/** A raw TCP client that collects the controller's replies. */
async function rawClient(port) {
  const socket = connect({ host: "127.0.0.1", port, noDelay: true });
  await new Promise((resolve, reject) => socket.once("connect", resolve).once("error", reject));
  const replies = [];
  let buf = Buffer.alloc(0);
  let closed = false;
  socket.on("data", (d) => {
    buf = Buffer.concat([buf, d]);
    while (buf.length >= 8 && buf.length >= 8 + buf.readUInt16BE(6)) {
      const n = 8 + buf.readUInt16BE(6);
      replies.push({ magic: buf.toString("latin1", 0, 2), version: buf[2], type: buf[3], seq: buf.readUInt16BE(4), payload: buf.subarray(8, n) });
      buf = buf.subarray(n);
    }
  });
  socket.on("close", () => (closed = true));
  return {
    socket,
    replies,
    isClosed: () => closed,
    async next(count = 1, timeoutMs = 1000) {
      const end = Date.now() + timeoutMs;
      while (replies.length < count && Date.now() < end) await sleep(5);
      assert.ok(replies.length >= count, `expected ${count} replies, got ${replies.length}`);
      return replies.splice(0, count);
    },
  };
}

function startDevice(port, telemetry) {
  const device = spawn(process.execPath, [join(example, "device.mjs"), "--port", String(port), "--telemetry", String(telemetry)], { stdio: ["ignore", "pipe", "pipe"] });
  const ready = new Promise((resolve, reject) => {
    let out = "";
    device.stdout.setEncoding("utf8").on("data", (d) => {
      out += d;
      if (/listening on/.test(out)) resolve();
    });
    device.stderr.setEncoding("utf8").on("data", (d) => (out += d));
    device.on("exit", (code) => reject(new Error(`device exited with ${code}: ${out}`)));
  });
  return { device, ready };
}

/** Runs the app and reads its report. */
function runApp(app, port, telemetry, seconds) {
  return new Promise((resolve, reject) => {
    const p = spawn(process.execPath, [app, "--port", String(port), "--telemetry", String(telemetry), "--seconds", String(seconds)], { stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    p.stdout.setEncoding("utf8").on("data", (d) => (out += d));
    p.stderr.setEncoding("utf8").on("data", (d) => (out += d));
    const timer = setTimeout(() => p.kill(), (seconds + 20) * 1000);
    p.on("exit", (code) => {
      clearTimeout(timer);
      if (code !== 0) return reject(new Error(`app exited with ${code}: ${out}`));
      const num = (re) => {
        const m = re.exec(out);
        if (!m) throw new Error(`no ${re} in the report:\n${out}`);
        return Number(m[1]);
      };
      try {
        resolve({
          out,
          sent: num(/MOVE commands\s+(\d+) sent/),
          rate: num(/([\d.]+)\/s achieved/),
          missed: num(/deadlines missed\s+(\d+) of/),
          p50: num(/ACK latency\s+p50 ([\d.]+) ms/),
          deviceUs: num(/controller time\s+p50 (\d+) µs/),
          tracking: num(/tracking error\s+max ([\d.]+)°/),
        });
      } catch (err) {
        reject(err);
      }
    });
  });
}
const summary = (r) => `${r.sent} MOVEs, ${r.rate}/s, ACK p50 ${r.p50} ms, ${r.missed} slots missed, tracking error ${r.tracking}°`;

const port = await freePort(false);
let telemetry = await freePort(true);
while (telemetry === port) telemetry = await freePort(true);
const { device, ready } = startDevice(port, telemetry);
const work = mkdtempSync(join(tmpdir(), "wirebuddy-arm-"));
try {
  await ready;

  await check("controller answers requests that come in one data event, and split ones", async () => {
    const c = await rawClient(port);
    try {
      c.socket.write(Buffer.concat([message(0x10, 1), message(0x10, 2)]));
      const pongs = await c.next(2);
      assert.deepEqual(pongs.map((r) => [r.magic, r.version, r.type, r.seq, r.payload.length]), [["AM", 1, 0x90, 1, 0], ["AM", 1, 0x90, 2, 0]]);
      const move = message(0x01, 3, movePayload(10_000, -20_000, 30_000, 120));
      for (const part of [move.subarray(0, 5), move.subarray(5, 11), move.subarray(11)]) {
        c.socket.write(part);
        await sleep(20);
      }
      const [ack] = await c.next();
      assert.equal(ack.type, 0x81);
      assert.equal(ack.seq, 3);
      assert.equal(ack.payload.length, 4);
      assert.equal(ack.payload[0], 0, "status ok");
      assert.ok(ack.payload.readUInt16BE(2) < 1000, `processing time ${ack.payload.readUInt16BE(2)} µs`);
    } finally {
      c.socket.destroy();
    }
  });

  await check("controller refuses bad requests with the documented NACK codes", async () => {
    const c = await rawClient(port);
    try {
      const nack = async (msg) => {
        c.socket.write(msg);
        const [r] = await c.next();
        assert.equal(r.type, 0x82, JSON.stringify(r));
        assert.equal(r.seq, msg.readUInt16BE(4));
        return [r.payload[0], r.payload.toString("utf8", 1)];
      };
      assert.equal((await nack(message(0x01, 10, movePayload(0, 95_000, 0, 120))))[0], 5, "j2 beyond 90°");
      assert.equal((await nack(message(0x01, 11, movePayload(-171_000, 0, 0, 120))))[0], 5, "j1 beyond -170°");
      assert.equal((await nack(message(0x07, 12)))[0], 3, "unknown type");
      assert.equal((await nack(message(0x10, 13, Buffer.from([1, 2]))))[0], 4, "PING with a payload");
      assert.equal((await nack(message(0x01, 14, Buffer.alloc(10))))[0], 4, "short MOVE");
      assert.equal((await nack(message(0x10, 15, undefined, { version: 2 })))[0], 2, "version 2");
      const [code, reason] = await nack(message(0x10, 16, undefined, { magic: "XY" }));
      assert.equal(code, 1, "bad magic");
      assert.ok(reason.length > 0);
      for (let i = 0; i < 50 && !c.isClosed(); i++) await sleep(10);
      assert.ok(c.isClosed(), "the controller closes the connection after bad magic");
    } finally {
      c.socket.destroy();
    }
  });

  await check("telemetry: 36-byte datagrams at 100 Hz, the arm reaches its MOVE target", async () => {
    const udp = createSocket("udp4");
    const datagrams = [];
    udp.on("message", (m) => datagrams.push({ at: performance.now(), m }));
    await new Promise((r) => udp.bind(telemetry, "127.0.0.1", r));
    const c = await rawClient(port);
    try {
      c.socket.write(message(0x01, 20, movePayload(-5_000, 15_000, 45_000, 150)));
      const [ack] = await c.next();
      assert.equal(ack.type, 0x81);
      await sleep(600);
    } finally {
      c.socket.destroy();
      await new Promise((r) => udp.close(r));
    }
    assert.ok(datagrams.length >= 40, `${datagrams.length} datagrams in 0.6 s`);
    const span = datagrams.at(-1).at - datagrams[0].at;
    const hz = ((datagrams.length - 1) * 1000) / span;
    assert.ok(hz > 80 && hz < 120, `${hz.toFixed(0)} Hz`);
    for (const { m } of datagrams) {
      assert.equal(m.length, 36);
      assert.equal(m.toString("latin1", 0, 2), "AT");
      assert.equal(m[2], 1);
    }
    const seqs = datagrams.map(({ m }) => m.readUInt32BE(4));
    assert.ok(seqs.every((s, i) => i === 0 || s === seqs[i - 1] + 1), "consecutive sequence numbers");
    const last = datagrams.at(-1).m;
    const joints = (o) => [0, 4, 8].map((i) => last.readInt32BE(o + i));
    assert.deepEqual(joints(24), [-5_000, 15_000, 45_000], "target");
    assert.deepEqual(joints(12), [-5_000, 15_000, 45_000], "actual");
    assert.equal(last[3] & 3, 2, "flags: not moving, target reached");
    assert.ok(datagrams.some(({ m }) => m[3] & 1), "flags: moving on the way");
  });

  let buggy;
  await check("the app as shipped: ACKs take over 30 ms, under 35 commands/s", async () => {
    buggy = await runApp(join(example, "app.mjs"), port, telemetry, 3);
    console.log(`     ${summary(buggy)}`);
    assert.ok(buggy.p50 > 30, `p50 ${buggy.p50} ms`);
    assert.ok(buggy.rate < 35, `${buggy.rate}/s`);
    assert.ok(buggy.deviceUs < 1000, `the controller itself took ${buggy.deviceUs} µs`);
    assert.match(buggy.out, /WARNING: command rate/);
  });

  await check("solution/fix.diff changes only app.mjs, to one write per message", async () => {
    const diff = readFileSync(join(example, "solution/fix.diff"), "utf8");
    const files = [...diff.matchAll(/^\+\+\+ (\S+)/gm)].map((m) => m[1]);
    assert.deepEqual(files, ["b/examples/investigations/robot-arm/app.mjs"]);
    const dir = join(work, "examples/investigations/robot-arm");
    mkdirSync(dir, { recursive: true });
    copyFileSync(join(example, "app.mjs"), join(dir, "app.mjs"));
    // As from the repository root, outside any repository
    execFileSync("git", ["apply", join(example, "solution/fix.diff")], { cwd: work, env: { ...process.env, GIT_CEILING_DIRECTORIES: dirname(work) }, stdio: "pipe" });
    const fixed = readFileSync(join(dir, "app.mjs"), "utf8");
    assert.equal(fixed.match(/socket\.write\(/g)?.length, 1, "one socket write");
    assert.notEqual(fixed, readFileSync(join(example, "app.mjs"), "utf8"));
  });

  await check("the fixed app: ACKs under 5 ms, over 45 commands/s, follows the trajectory", async () => {
    const fixed = await runApp(join(work, "examples/investigations/robot-arm/app.mjs"), port, telemetry, 3);
    console.log(`     ${summary(fixed)}`);
    assert.ok(fixed.p50 < 5, `p50 ${fixed.p50} ms`);
    assert.ok(fixed.rate > 45, `${fixed.rate}/s`);
    assert.doesNotMatch(fixed.out, /WARNING/);
    if (buggy) assert.ok(fixed.tracking < buggy.tracking, `tracking error ${fixed.tracking}° vs ${buggy.tracking}° before`);
  });
} finally {
  device.kill();
  rmSync(work, { recursive: true, force: true });
}
console.log(failures ? `${failures} check(s) failed` : "all checks passed");
process.exit(failures ? 1 : 0);
