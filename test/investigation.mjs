// The investigation examples without a capture. Robot arm: the emulated controller speaks ARMC v1
// as its PROTOCOL.md says, the app as shipped falls behind its rate, and solution/fix.diff fixes it.
// CT archive: the archive answers as DICOM PS3.8 and its CONFORMANCE.md say, the exporter as shipped
// gets Success for every image but the archive keeps 100 of the 160 thin slices, and
// solution/fix.diff makes it keep them all, next to the old images in an archive not restarted.
// Usage: node test/investigation.mjs   (loopback TCP and UDP only, no capture)
import { execFileSync, spawn } from "node:child_process";
import { createSocket } from "node:dgram";
import { connect, createServer } from "node:net";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync } from "node:fs";
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

// --- Robot arm

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

// --- CT archive

const ct = join(root, "examples/investigations/ct-archive");
const UID = {
  context: "1.2.840.10008.3.1.1.1",
  ct: "1.2.840.10008.5.1.4.1.1.2",
  mr: "1.2.840.10008.5.1.4.1.1.4",
  verification: "1.2.840.10008.1.1",
  explicit: "1.2.840.10008.1.2.1",
  implicit: "1.2.840.10008.1.2",
  jpeg: "1.2.840.10008.1.2.4.50",
};
const TEST_SERIES = "2.25.271828182845904523536";
const ascii = (s) => Buffer.from(s, "latin1");
const u16 = (n) => Buffer.from([n & 0xff, n >> 8]);

function pdu(type, body) {
  const head = Buffer.alloc(6);
  head[0] = type;
  head.writeUInt32BE(body.length, 2);
  return Buffer.concat([head, body]);
}
function item(type, body) {
  const head = Buffer.alloc(4);
  head[0] = type;
  head.writeUInt16BE(body.length, 2);
  return Buffer.concat([head, body]);
}
function items(b, at) {
  const out = [];
  for (; at + 4 <= b.length; at += 4 + b.readUInt16BE(at + 2)) out.push({ type: b[at], value: b.subarray(at + 4, at + 4 + b.readUInt16BE(at + 2)) });
  return out;
}

/** An A-ASSOCIATE-RQ; contexts as [id, abstract syntax, ...transfer syntaxes]. */
function associateRq({ called = "ARCHIVE", version = 1, context = UID.context, contexts = [[1, UID.ct, UID.explicit]] } = {}) {
  const head = Buffer.alloc(68);
  head.writeUInt16BE(version, 0);
  head.write(called.padEnd(16), 4, "latin1");
  head.write("TESTSCU".padEnd(16), 20, "latin1");
  const max = Buffer.alloc(4);
  max.writeUInt32BE(16384);
  const proposed = contexts.map(([id, abstract, ...syntaxes]) => item(0x20, Buffer.concat([Buffer.from([id, 0, 0, 0]), item(0x30, ascii(abstract)), ...syntaxes.map((s) => item(0x40, ascii(s)))])));
  return pdu(1, Buffer.concat([head, item(0x10, ascii(context)), ...proposed, item(0x50, Buffer.concat([item(0x51, max), item(0x52, ascii("2.25.1"))]))]));
}

/** An A-ASSOCIATE-AC: the called AE title, each context's result and transfer syntax, the max PDU. */
function accepted(p) {
  assert.equal(p.type, 2, `PDU type ${p.type} instead of A-ASSOCIATE-AC`);
  const out = { called: p.body.toString("latin1", 4, 20).trim(), contexts: {}, maxPdu: 0 };
  for (const { type, value } of items(p.body, 68)) {
    if (type === 0x21) out.contexts[value[0]] = [value[2], items(value, 4).find((s) => s.type === 0x40)?.value.toString("latin1")];
    if (type === 0x50) out.maxPdu = items(value, 0).find((s) => s.type === 0x51)?.value.readUInt32BE(0);
  }
  return out;
}

/** Elements [tag, vr, value] in Explicit or Implicit VR Little Endian. */
function encode(elements, explicit) {
  return Buffer.concat(
    elements.map(([tag, vr, value]) => {
      const v = typeof value === "string" ? ascii(value.length % 2 ? value + (vr === "UI" ? "\0" : " ") : value) : value;
      const long = explicit && (vr === "OW" || vr === "OB");
      const head = Buffer.alloc(long ? 12 : 8);
      head.writeUInt16LE(tag >>> 16, 0);
      head.writeUInt16LE(tag & 0xffff, 2);
      if (!explicit) head.writeUInt32LE(v.length, 4);
      else {
        head.write(vr, 4, "latin1");
        if (long) head.writeUInt32LE(v.length, 8);
        else head.writeUInt16LE(v.length, 6);
      }
      return Buffer.concat([head, v]);
    }),
  );
}

/** A command set (Implicit VR Little Endian), its group length first. */
function command(fields) {
  const body = encode(fields, false);
  const length = Buffer.alloc(4);
  length.writeUInt32LE(body.length);
  return Buffer.concat([encode([[0, "UL", length]], false), body]);
}
const storeRq = (id, sop, sopClass = UID.ct) =>
  command([
    [0x00000002, "UI", sopClass],
    [0x00000100, "US", u16(0x0001)],
    [0x00000110, "US", u16(id)],
    [0x00000700, "US", u16(0)],
    [0x00000800, "US", u16(0)],
    [0x00001000, "UI", sop],
  ]);
const echoRq = (id) =>
  command([
    [0x00000002, "UI", UID.verification],
    [0x00000100, "US", u16(0x0030)],
    [0x00000110, "US", u16(id)],
    [0x00000800, "US", u16(0x0101)],
  ]);

/** A small CT dataset of series 7 with a sequence of undefined length in it. */
function ctDataset(sop, instance, explicit) {
  const tag = (t, length) => {
    const b = Buffer.alloc(8);
    b.writeUInt16LE(t >>> 16, 0);
    b.writeUInt16LE(t & 0xffff, 2);
    b.writeUInt32LE(length, 4);
    return b;
  };
  const sq = explicit ? Buffer.from([0x08, 0x00, 0x40, 0x11, 0x53, 0x51, 0, 0, 0xff, 0xff, 0xff, 0xff]) : tag(0x00081140, 0xffffffff);
  return Buffer.concat([
    encode([[0x00080016, "UI", UID.ct], [0x00080018, "UI", sop]], explicit),
    sq,
    tag(0xfffee000, 0xffffffff),
    encode([[0x00081150, "UI", UID.ct]], explicit),
    tag(0xfffee00d, 0),
    tag(0xfffee0dd, 0),
    encode([[0x00180050, "DS", "1"], [0x0020000e, "UI", TEST_SERIES], [0x00200011, "IS", "7"], [0x00200013, "IS", String(instance)], [0x7fe00010, "OW", Buffer.alloc(2048, instance)]], explicit),
  ]);
}

/** P-DATA-TF PDUs: the command and dataset cut into PDVs of sizes() bytes, `perPdu` PDVs to a PDU. */
function pData(context, cmd, data, sizes, perPdu) {
  const pdvs = [];
  for (const [bytes, isCommand] of [[cmd, true], [data, false]]) {
    for (let at = 0; bytes && at < bytes.length; ) {
      const part = bytes.subarray(at, at + sizes());
      at += part.length;
      const head = Buffer.alloc(6);
      head.writeUInt32BE(part.length + 2, 0);
      head[4] = context;
      head[5] = (isCommand ? 1 : 0) | (at >= bytes.length ? 2 : 0);
      pdvs.push(head, part);
    }
  }
  const out = [];
  for (let i = 0; i < pdvs.length; i += 2 * perPdu) out.push(pdu(4, Buffer.concat(pdvs.slice(i, i + 2 * perPdu))));
  return Buffer.concat(out);
}

/** A P-DATA-TF with one command PDV: its context, control header and fields. */
function response(p) {
  assert.equal(p.type, 4, `PDU type ${p.type} instead of P-DATA-TF`);
  const b = p.body.subarray(6, 4 + p.body.readUInt32BE(0));
  const fields = new Map();
  for (let at = 0; at + 8 <= b.length; at += 8 + b.readUInt32LE(at + 4)) fields.set(((b.readUInt16LE(at) << 16) | b.readUInt16LE(at + 2)) >>> 0, b.subarray(at + 8, at + 8 + b.readUInt32LE(at + 4)));
  const n = (tag) => fields.get(tag)?.readUInt16LE(0);
  return { context: p.body[4], control: p.body[5], field: n(0x00000100), id: n(0x00000120), dataSet: n(0x00000800), status: n(0x00000900), sop: fields.get(0x00001000)?.toString("latin1").replace(/\0$/, "") };
}

/** Writes `bytes` in pieces of 1 to 64 bytes, pausing now and then so the archive reads them apart. */
async function trickle(socket, bytes, rand) {
  for (let at = 0, k = 0; at < bytes.length; k++) {
    const n = 1 + Math.floor(rand() * 64);
    socket.write(bytes.subarray(at, at + n));
    at += n;
    if (k % 8 === 7) await sleep(1);
  }
}

/** A raw DICOM connection that collects the archive's PDUs. */
async function dicomClient(port) {
  const socket = connect({ host: "127.0.0.1", port, noDelay: true });
  await new Promise((resolve, reject) => socket.once("connect", resolve).once("error", reject));
  socket.on("error", () => {});
  const pdus = [];
  let buf = Buffer.alloc(0);
  let closed = false;
  socket.on("data", (d) => {
    buf = Buffer.concat([buf, d]);
    while (buf.length >= 6 && buf.length >= 6 + buf.readUInt32BE(2)) {
      const n = 6 + buf.readUInt32BE(2);
      pdus.push({ type: buf[0], body: buf.subarray(6, n) });
      buf = buf.subarray(n);
    }
  });
  socket.on("close", () => (closed = true));
  const until = async (ok, what) => {
    for (const end = Date.now() + 2000; !ok() && Date.now() < end; ) await sleep(5);
    assert.ok(ok(), what);
  };
  return {
    socket,
    async next() {
      await until(() => pdus.length > 0, "no PDU from the archive");
      return pdus.shift();
    },
    closed: () => until(() => closed, "the archive did not close the connection"),
  };
}

function startArchive(port) {
  const p = spawn(process.execPath, [join(ct, "device.mjs"), "--port", String(port)], { stdio: ["ignore", "pipe", "pipe"] });
  const archive = { p, log: "" };
  archive.ready = new Promise((resolve, reject) => {
    p.stdout.setEncoding("utf8").on("data", (d) => {
      archive.log += d;
      if (/listening on/.test(archive.log)) resolve();
    });
    p.stderr.setEncoding("utf8").on("data", (d) => (archive.log += d));
    p.on("exit", (code) => reject(new Error(`archive exited with ${code}: ${archive.log}`)));
  });
  return archive;
}

/** The first line of the archive's log after `from` characters that matches `re`. */
async function logged(archive, re, from) {
  for (const end = Date.now() + 3000; Date.now() < end; await sleep(10)) {
    const m = re.exec(archive.log.slice(from));
    if (m) return m;
  }
  throw new Error(`no ${re} in the archive's log:\n${archive.log.slice(from)}`);
}

/** What the archive holds of the 5 mm and the 0.625 mm series after an export that began at `from`. */
async function held(archive, from) {
  const five = await logged(archive, /series 2 \(5 mm\): (\d+) instances/, from);
  const thin = await logged(archive, /series 3 \(0\.625 mm\): (\d+) instances/, from);
  return [Number(five[1]), Number(thin[1])];
}

/** Runs the exporter and reads its summary line. */
function runExporter(app, port) {
  return new Promise((resolve, reject) => {
    const p = spawn(process.execPath, [app, "--port", String(port)], { stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    p.stdout.setEncoding("utf8").on("data", (d) => (out += d));
    p.stderr.setEncoding("utf8").on("data", (d) => (out += d));
    const timer = setTimeout(() => p.kill(), 30_000);
    p.on("exit", (code) => {
      clearTimeout(timer);
      const m = /^(\d+) images sent, (\d+) Success$/m.exec(out);
      if (code !== 0 || !m) return reject(new Error(`app exited with ${code}: ${out}`));
      resolve({ out, sent: Number(m[1]), success: Number(m[2]) });
    });
  });
}

const archivePort = await freePort(false);
const archive = startArchive(archivePort);
let fresh = null;
const ctWork = mkdtempSync(join(tmpdir(), "wirebuddy-ct-"));
try {
  await archive.ready;

  await check("archive rejects associations as PS3.8 says: called AE title, protocol version, application context", async () => {
    for (const [rq, expect, logs] of [
      [associateRq({ called: "NOBODY" }), [1, 1, 7], /association rejected, called AE title not recognized \("NOBODY"\)/],
      [associateRq({ version: 2 }), [1, 2, 2], /association rejected, protocol version not supported/],
      [associateRq({ context: "1.2.3.4" }), [1, 1, 2], /association rejected, application context not supported/],
    ]) {
      const from = archive.log.length;
      const c = await dicomClient(archivePort);
      try {
        c.socket.write(rq);
        const rj = await c.next();
        assert.equal(rj.type, 3, `PDU type ${rj.type} instead of A-ASSOCIATE-RJ`);
        assert.deepEqual([...rj.body.subarray(1, 4)], expect, "result, source, reason");
        await c.closed();
        await logged(archive, logs, from);
      } finally {
        c.socket.destroy();
      }
    }
  });

  await check("archive accepts CT Image Storage in Explicit VR before Implicit, refuses other syntaxes, takes PDUs of 16384", async () => {
    const c = await dicomClient(archivePort);
    try {
      c.socket.write(associateRq({ contexts: [[1, UID.ct, UID.jpeg, UID.implicit, UID.explicit], [3, UID.ct, UID.implicit], [5, UID.mr, UID.explicit], [7, UID.ct, UID.jpeg], [9, UID.verification, UID.implicit]] }));
      const ac = accepted(await c.next());
      assert.equal(ac.called, "ARCHIVE");
      assert.equal(ac.maxPdu, 16384);
      assert.deepEqual(Object.fromEntries(Object.entries(ac.contexts).map(([id, [result]]) => [id, result])), { 1: 0, 3: 0, 5: 3, 7: 4, 9: 0 }, "0 accepted, 3 abstract syntax, 4 transfer syntaxes not supported");
      assert.deepEqual([ac.contexts[1][1], ac.contexts[3][1], ac.contexts[9][1]], [UID.explicit, UID.implicit, UID.implicit]);
    } finally {
      c.socket.destroy();
    }
  });

  await check("archive puts C-STOREs together from PDVs and reads split at any byte, keeps a re-send once, releases", async () => {
    const from = archive.log.length;
    const c = await dicomClient(archivePort);
    let seed = 11;
    const rand = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
    const sizes = () => 1 + Math.floor(rand() * 600);
    const store = async (context, id, sop, data) => {
      await trickle(c.socket, pData(context, storeRq(id, sop), data, sizes, 3), rand);
      return response(await c.next());
    };
    try {
      c.socket.write(associateRq({ contexts: [[1, UID.ct, UID.explicit], [3, UID.ct, UID.implicit], [9, UID.verification, UID.implicit]] }));
      accepted(await c.next());
      const sop = `${TEST_SERIES}.1`;
      assert.deepEqual(await store(1, 1, sop, ctDataset(sop, 1, true)), { context: 1, control: 3, field: 0x8001, id: 1, dataSet: 0x0101, status: 0, sop });
      // The same SOP Instance UID again, in Implicit VR: a corrected re-send
      assert.equal((await store(3, 2, sop, ctDataset(sop, 2, false))).status, 0);
      assert.equal((await store(1, 3, `${TEST_SERIES}.3`, ctDataset(`${TEST_SERIES}.3`, 3, true))).status, 0);
      assert.equal((await store(9, 4, `${TEST_SERIES}.4`, ctDataset(`${TEST_SERIES}.4`, 4, false))).status, 0x0122, "a C-STORE on the Verification context");
      await trickle(c.socket, pData(9, echoRq(5), null, sizes, 2), rand);
      const echo = response(await c.next());
      assert.deepEqual([echo.field, echo.id, echo.status], [0x8030, 5, 0], "C-ECHO-RSP");
      c.socket.write(pdu(5, Buffer.alloc(4)));
      assert.equal((await c.next()).type, 6, "A-RELEASE-RP");
      await c.closed();
    } finally {
      c.socket.destroy();
    }
    await logged(archive, /released after 4 C-STORE: 3 Success, 1 failed/, from);
    await logged(archive, /series 7 \(1 mm\): 2 instances/, from);
  });

  await check("archive aborts on PDUs out of place: P-DATA-TF before an association, an unknown type, one over 16384 bytes", async () => {
    for (const [associate, bad, reason] of [
      [false, pdu(4, Buffer.from([0, 0, 0, 2, 1, 3])), 2],
      [false, pdu(9, Buffer.alloc(4)), 1],
      [true, pdu(4, Buffer.alloc(16385)), 6],
    ]) {
      const c = await dicomClient(archivePort);
      try {
        if (associate) {
          c.socket.write(associateRq());
          accepted(await c.next());
        }
        c.socket.write(bad);
        const abort = await c.next();
        assert.equal(abort.type, 7, `PDU type ${abort.type} instead of A-ABORT`);
        assert.deepEqual([abort.body[2], abort.body[3]], [2, reason], "source, reason");
        await c.closed();
      } finally {
        c.socket.destroy();
      }
    }
  });

  await check("the exporter as shipped: 184 images sent, 184 Success, the archive keeps 24 of 24 and 100 of 160", async () => {
    const from = archive.log.length;
    const r = await runExporter(join(ct, "app.mjs"), archivePort);
    const kept = await held(archive, from);
    console.log(`     ${r.sent} sent, ${r.success} Success; the archive holds ${kept.join(" and ")}`);
    assert.deepEqual([r.sent, r.success], [184, 184], r.out);
    assert.deepEqual(kept, [24, 100]);
  });

  await check("the exporter runs through a symlinked path and fails without an archive", async () => {
    symlinkSync(ct, join(ctWork, "linked"));
    await assert.rejects(runExporter(join(ctWork, "linked/app.mjs"), await freePort(false)), /^Error: app exited with 1: app: connect ECONNREFUSED /);
  });

  await check("solution/fix.diff changes one line of app.mjs", async () => {
    const diff = readFileSync(join(ct, "solution/fix.diff"), "utf8");
    assert.deepEqual([...diff.matchAll(/^\+\+\+ (\S+)/gm)].map((m) => m[1]), ["b/examples/investigations/ct-archive/app.mjs"]);
    assert.equal(diff.split("\n").filter((l) => /^[-+](?![-+]{2} )/.test(l)).length, 2, "one line out, one in");
    const dir = join(ctWork, "examples/investigations/ct-archive");
    mkdirSync(dir, { recursive: true });
    copyFileSync(join(ct, "app.mjs"), join(dir, "app.mjs"));
    execFileSync("git", ["apply", join(ct, "solution/fix.diff")], { cwd: ctWork, env: { ...process.env, GIT_CEILING_DIRECTORIES: dirname(ctWork) }, stdio: "pipe" });
    assert.notEqual(readFileSync(join(dir, "app.mjs"), "utf8"), readFileSync(join(ct, "app.mjs"), "utf8"));
  });

  await check("the fixed exporter to the archive not restarted: the old images of both series stay, 48 and 260", async () => {
    const from = archive.log.length;
    const r = await runExporter(join(ctWork, "examples/investigations/ct-archive/app.mjs"), archivePort);
    assert.deepEqual([r.sent, r.success], [184, 184], r.out);
    assert.deepEqual(await held(archive, from), [48, 260]);
  });

  await check("the fixed exporter: the archive keeps 24 and 160, 184 UIDs, and a second export replaces them", async () => {
    // A fresh archive: the one above holds the old UIDs
    const port = await freePort(false);
    fresh = startArchive(port);
    await fresh.ready;
    for (const run of [1, 2]) {
      const from = fresh.log.length;
      const r = await runExporter(join(ctWork, "examples/investigations/ct-archive/app.mjs"), port);
      const kept = await held(fresh, from);
      if (run === 1) console.log(`     ${r.sent} sent, ${r.success} Success; the archive holds ${kept.join(" and ")}`);
      assert.deepEqual([r.sent, r.success], [184, 184], r.out);
      assert.deepEqual(kept, [24, 160], `export ${run}`);
    }
  });
} finally {
  archive.p.kill();
  fresh?.p.kill();
  rmSync(ctWork, { recursive: true, force: true });
}
console.log(failures ? `${failures} check(s) failed` : "all checks passed");
process.exit(failures ? 1 : 0);
