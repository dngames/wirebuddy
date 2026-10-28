// The live view's provisional tail: flows, slices, renumbering and the memory guard, and how
// close provisional rows and filter matches come to Wireshark's reading of the file cut at the
// same packet, with and without TLS keys, and rows that read the same from then on to its reading
// of the whole file.
// Usage: node test/slices.mjs   (bundles the sources itself; needs sharkd)
import { build } from "esbuild";
import { appendFileSync, closeSync, mkdirSync, mkdtempSync, openSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync, writeSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import * as g from "./capgen.mjs";
import { header, packet, writeTraffic } from "./media/traffic.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const out = mkdtempSync(join(tmpdir(), "wirebuddy-slices-"));
const entry = join(out, "entry.ts");
writeFileSync(entry, ["livetail", "flows", "framestore", "sharkd"].map((m) => `export * from ${JSON.stringify(join(root, `src/server/${m}.ts`))};`).join("\n") + `\nexport { memoryShort } from ${JSON.stringify(join(root, "src/server/viewer.ts"))};`);
await build({ entryPoints: [entry], outfile: join(out, "slices.mjs"), bundle: true, platform: "node", format: "esm", packages: "external", logLevel: "silent" });
const { LiveTail, FlowIndex, FrameStore, Sharkd, Superseded, CHUNK, CONTEXT, sliceFrames, toGlobal, toLocal, renumberRow, renumberInfo, renumberTree, heldReason, streamNumbered, matchingFrames, memoryShort } = await import(join(out, "slices.mjs"));

// sharkd with an empty home, so the user's Wireshark settings don't count
const home = join(out, "home");
mkdirSync(home);
const env = { ...process.env, HOME: home, XDG_CONFIG_HOME: join(home, ".config"), XDG_DATA_HOME: join(home, ".local/share"), WIREBUDDY_EXTENSIONS: "" };
const engines = [];
/** A sharkd like the view's, with the TLS key log `keylog`. */
const newSharkd = (keylog) => {
  const e = new Sharkd("sharkd", undefined, () => env);
  if (keylog) e.setPref("tls.keylog_file", keylog).catch(() => {});
  engines.push(e);
  return e;
};
/** sharkd processes this one started that still run. */
const sharkdChildren = () =>
  readdirSync("/proc").filter((pid) => {
    try {
      const m = /^\d+ \((.*)\) \S (\d+)/.exec(readFileSync(`/proc/${pid}/stat`, "utf8"));
      return m?.[1] === "sharkd" && Number(m[2]) === process.pid;
    } catch {
      return false;
    }
  }).length;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
/** Bytes of `frames` of `store` as a slice writes them. */
const sliceBytes = (store, frames) => frames.reduce((n, f) => n + store.size(f), 0);

/** Accuracy and timing, printed at the end. */
const report = [];
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

/** A TCP packet between 10.0.0.1:1000 and 10.0.0.2:80 (`back`: the other way) with `flags`, and `data` bytes or `text` as payload. */
const tcpFrame = (flags, { back = false, sport = 1000, data = 0, text } = {}) => {
  const t = g.tcp(back ? 80 : sport, back ? sport : 80, text === undefined ? Buffer.alloc(data, 0x61) : Buffer.from(text));
  t[13] = flags;
  return g.eth(0x0800, g.ip4(6, t, back ? { src: [10, 0, 0, 2], dst: [10, 0, 0, 1] } : {}));
};
const fed = (frames) => {
  const flows = new FlowIndex();
  frames.forEach((f, i) => flows.feed(i + 1, "eth", f));
  return flows;
};
const range = (a, b) => Array.from({ length: b - a + 1 }, (_, i) => a + i);
/** A budget of `frames` frames and `bytes` bytes, a frame counting 100. */
const budget = (frames, bytes = Infinity) => ({ frames, bytes, size: () => 100 });

try {
  await check("flows: a SYN after other packets starts a new flow, repeated SYNs don't; heads and the last packet per direction", () => {
    const SYN = 0x02;
    const ACK = 0x10;
    const frames = [
      g.udpFrame(1), // 1: UDP, its own flow
      tcpFrame(SYN), tcpFrame(SYN), tcpFrame(0x12, { back: true }), tcpFrame(ACK), // 2-5: one connection, the SYN sent twice
      ...Array.from({ length: 20 }, (_, i) => tcpFrame(ACK, { back: i % 2 === 1 })), // 6-25
      g.eth(0x0806, Buffer.alloc(28)), // 26: ARP, no flow
      tcpFrame(SYN), tcpFrame(0x12, { back: true }), // 27-28: the same ports again: a new connection
      tcpFrame(ACK, { sport: 2000 }), // 29: another connection, no handshake seen
    ];
    const flows = fed(frames);
    assert.equal(flows.count, 29);
    assert.equal(flows.firstOf(5), 2);
    assert.equal(flows.firstOf(25), 2);
    assert.equal(flows.firstOf(26), null);
    assert.equal(flows.firstOf(28), 27);
    // Slice 24..29: frame 1 and the old connection, which never sent data, from its start;
    // the new connection and the other one started inside it
    assert.deepEqual([...flows.context(24, 29, budget(1000))], range(1, 23));
    // A budget: frame 1 and the last packet each way come first, then the first packets
    assert.deepEqual([...flows.context(24, 29, budget(3))], [1, 22, 23]);
    assert.deepEqual([...flows.context(24, 29, budget(20))], [1, ...range(2, 17), 22, 23]);
    assert.deepEqual([...flows.context(24, 29, budget(1000, 1900))], [1, ...range(2, 17), 22, 23]);
    assert.deepEqual([...flows.context(24, 29, budget(1000, 1800))], [1, ...range(2, 16), 22, 23]);
    assert.deepEqual([...flows.context(1, 29, budget(1000))], []);
    // The ports used again: the old connection's last packets come along
    assert.deepEqual([...flows.context(27, 29, budget(1000))].slice(-2), [24, 25]);
  });

  await check("flows: a response under way comes from its request on", () => {
    const ACK = 0x10;
    const frames = [
      tcpFrame(0x02), tcpFrame(0x12, { back: true }), tcpFrame(ACK), // 1-3
      tcpFrame(0x18, { data: 80 }), // 4: request
      ...Array.from({ length: 30 }, (_, i) => (i % 3 === 2 ? tcpFrame(ACK) : tcpFrame(0x18, { back: true, data: 1000 }))), // 5-34: response, ACKs
      tcpFrame(0x18, { data: 80 }), // 35: the next request
      ...Array.from({ length: 6 }, () => tcpFrame(0x18, { back: true, data: 1000 })), // 36-41: its response
    ];
    const heads = range(1, 16);
    // Slice from 39: the request (after the ACK of the response before) and its response so far, and the flow's first packets
    assert.deepEqual([...fed(frames).context(39, 41, budget(30))], [...heads, 34, 35, 36, 37, 38]);
    // With room, the exchange before too (requests may have been pipelined into a response)
    assert.deepEqual([...fed(frames).context(39, 41, budget(1000))], range(1, 38));
    // The first download of a connection: from its start
    const oneWay = fed([tcpFrame(0x18, { data: 80 }), ...Array.from({ length: 300 }, () => tcpFrame(0x18, { back: true, data: 1000 })), tcpFrame(ACK)]);
    assert.deepEqual([...oneWay.context(302, 302, budget(1000))], range(1, 301));
    // More than the budget: its last packet each way and its first packets
    assert.deepEqual([...oneWay.context(302, 302, budget(100))], [...heads, 301]);
  });

  await check("flows: a response of hundreds of segments comes from its request on, however long", () => {
    const ACK = 0x10;
    const frames = [
      tcpFrame(0x02), tcpFrame(0x12, { back: true }), tcpFrame(ACK), // 1-3
      tcpFrame(0x18, { data: 80 }), // 4: request
      ...Array.from({ length: 30 }, () => tcpFrame(0x18, { back: true, data: 1000 })), // 5-34: its response
      tcpFrame(0x18, { data: 80 }), // 35: the next request
      ...Array.from({ length: 600 }, (_, i) => (i % 3 === 2 ? tcpFrame(ACK) : tcpFrame(0x18, { back: true, data: 1448 }))), // 36-635: 400 segments, ACKs
    ];
    const flows = fed(frames);
    assert.deepEqual([...flows.context(500, 635, budget(490))], [...range(1, 16), ...range(35, 499)]);
    // With room, the exchange before too
    assert.deepEqual([...flows.context(500, 635, budget(20_000))], range(1, 499));
    // Over the budget: the last packet each way
    assert.deepEqual([...flows.context(500, 635, budget(300))], [...range(1, 16), 497, 499]);
  });

  await check("flows: a response requests were pipelined into, and an upload after a 100 Continue, come from their start", () => {
    const ACK = 0x10;
    const request = () => tcpFrame(0x18, { data: 80 });
    const answer = (n) => Array.from({ length: n }, (_, i) => (i % 3 === 2 ? tcpFrame(ACK) : tcpFrame(0x18, { back: true, data: 1448 })));
    const exchanges = (k) => Array.from({ length: k }, () => [request(), ...answer(3)]).flat();
    // 1-3 handshake, 4-35 eight exchanges, 36 a request, 37-66 its response, 67 a pipelined request, 68-97 the same response goes on
    const piped = fed([tcpFrame(0x02), tcpFrame(0x12, { back: true }), tcpFrame(ACK), ...exchanges(8), request(), ...answer(30), request(), ...answer(30)]);
    const has = (got, frames) => frames.every((f) => got.includes(f));
    assert.ok(has([...piped.context(90, 97, budget(1000))], range(36, 89)));
    // Three pipelined requests: from the response's request on too
    const piped3 = fed([tcpFrame(0x02), tcpFrame(0x12, { back: true }), tcpFrame(ACK), ...exchanges(8), request(), ...[1, 2, 3].flatMap(() => [...answer(30), request()]), ...answer(30)]);
    assert.ok(has([...piped3.context(150, 160, budget(1000))], range(36, 149)));
    // 36 the PUT's headers, 37 the 100 Continue, 38-97 the upload
    const upload = fed([tcpFrame(0x02), tcpFrame(0x12, { back: true }), tcpFrame(ACK), ...exchanges(8), request(), tcpFrame(0x18, { back: true, data: 25 }), ...Array.from({ length: 60 }, (_, i) => (i % 3 === 2 ? tcpFrame(ACK, { back: true }) : tcpFrame(0x18, { data: 1448 })))]);
    assert.ok(has([...upload.context(90, 97, budget(1000))], range(36, 89)));
    // Only the current exchange fits: the run from the other side's last message on
    assert.deepEqual([...upload.context(90, 97, budget(70))].filter((f) => f > 16), range(37, 89));
  });

  const ACK = 0x10;
  const request = () => tcpFrame(0x18, { data: 80 });
  const response = (n) => Array.from({ length: n }, (_, i) => (i % 3 === 2 ? tcpFrame(ACK) : tcpFrame(0x18, { back: true, data: 1448 })));
  const close = [tcpFrame(0x11), tcpFrame(0x11, { back: true }), tcpFrame(ACK)];
  // 1-3 handshake, 4 request, 5-104 response, 105 the next request (it may have been pipelined into the response), 106 an answer, 107-109 the close
  const exchange = [tcpFrame(0x02), tcpFrame(0x12, { back: true }), tcpFrame(ACK), request(), ...response(100), request(), tcpFrame(0x18, { back: true, data: 100 }), ...close];

  await check("flows: data under way at a chunk's end comes along from after the slice, past requests pipelined into it, until the other side's next message", () => {
    assert.deepEqual(fed(exchange).after(1, 40, 50, budget(1000)), { frames: Int32Array.from(range(51, 106)), open: false });
    // The file so far ends in the middle of the response, or right after it: more may come
    assert.deepEqual(fed(exchange.slice(0, 80)).after(1, 40, 50, budget(1000)), { frames: Int32Array.from(range(51, 80)), open: true });
    assert.deepEqual(fed(exchange.slice(0, 104)).after(1, 40, 104, budget(1000)), { frames: new Int32Array(0), open: true });
    assert.deepEqual(fed(exchange.slice(0, 107)).after(1, 40, 50, budget(1000)), { frames: Int32Array.from(range(51, 106)), open: true });
    // Past four requests is past the response: the other side's next message ends the walk
    const more = fed([...exchange.slice(0, 104), ...Array.from({ length: 4 }, () => [request(), tcpFrame(0x18, { back: true, data: 100 })]).flat()]);
    assert.deepEqual(more.after(1, 40, 50, budget(1000)), { frames: Int32Array.from(range(51, 110)), open: false });
    // The request pipelined into the response is the chunk's last data: the response's end comes along all the same
    const pipedLast = fed([...exchange.slice(0, 105), ...response(60), ...close]);
    assert.deepEqual(pipedLast.after(1, 105, 105, budget(1000)), { frames: Int32Array.from(range(106, 164)), open: false });
    // A 100 Continue is short: the upload after it comes along
    const upload = fed([...exchange.slice(0, 105), tcpFrame(0x18, { back: true, data: 25 }), ...Array.from({ length: 30 }, () => tcpFrame(0x18, { data: 1448 })), tcpFrame(0x18, { back: true, data: 100 }), ...close]);
    assert.deepEqual(upload.after(1, 105, 105, budget(1000)), { frames: Int32Array.from(range(106, 136)), open: false });
  });

  await check("flows: a chunk stays open while the budget cuts short what its data under way needs", () => {
    const flows = fed(exchange);
    assert.deepEqual(flows.after(1, 40, 50, budget(10)), { frames: Int32Array.from(range(51, 60)), open: true });
    assert.deepEqual(flows.after(1, 40, 50, budget(1000, 1000)), { frames: Int32Array.from(range(51, 60)), open: true });
  });

  await check("flows: past the other side's request a new message (HTTP/1, a TLS record) is no continuation: a keep-alive connection's next download doesn't come along", () => {
    const get = (k) => tcpFrame(0x18, { text: `GET /file${k} HTTP/1.1\r\nHost: x\r\n\r\n` });
    const download = (n) => [tcpFrame(0x18, { back: true, text: `HTTP/1.1 200 OK\r\nContent-Length: ${n * 1448}\r\n\r\n` }), ...response(n - 1)];
    // 1-3 handshake, 4 a GET, 5-304 its download, 305 the next GET, 306-9305 its download, longer than the budget
    const keepAlive = fed([tcpFrame(0x02), tcpFrame(0x12, { back: true }), tcpFrame(ACK), get(1), ...download(300), get(2), ...download(9000)]);
    // Chunk 1-250, hi 320 past the first download's end: nothing comes along, and the chunk reads the same from now on
    assert.deepEqual(keepAlive.after(1, 250, 320, budget(1000)), { frames: new Int32Array(0), open: false });
    // hi 260 in the first download: its end, not the next one
    assert.deepEqual(keepAlive.after(1, 250, 260, budget(1000)), { frames: Int32Array.from(range(261, 304)), open: false });
    // The next GET is the chunk's last data: nothing of the download before or after it
    assert.deepEqual(keepAlive.after(1, 305, 305, budget(1000)), { frames: new Int32Array(0), open: false });
    // Over TLS: the next download starts with a new record
    const record = (back) => tcpFrame(0x18, { back, text: `\x17\x03\x03\x05\x00${"x".repeat(1443)}` });
    const secure = fed([tcpFrame(0x02), tcpFrame(0x12, { back: true }), tcpFrame(ACK), record(false), record(true), ...response(299), record(false), record(true), ...response(8999)]);
    assert.deepEqual(secure.after(1, 250, 320, budget(1000)), { frames: new Int32Array(0), open: false });
    // What doesn't start a new message after the other side's request may go on the one before: it comes along as the budget allows, and cutting it short leaves the chunk as it is
    const opaque = fed([tcpFrame(0x02), tcpFrame(0x12, { back: true }), tcpFrame(ACK), request(), ...response(300), request(), ...response(9000)]);
    const later = opaque.after(1, 250, 320, budget(1000));
    assert.equal(later.open, false);
    assert.ok(later.frames[0] === 321 && later.frames.length > 900, `${later.frames.length} frames from ${later.frames[0]}`);
  });

  await check("flows: a connection that ended (FIN, RST) or went quiet doesn't keep a chunk open", () => {
    // The response goes on until the connection closes
    const closed = [...exchange.slice(0, 104), ...close];
    assert.deepEqual(fed(closed).after(1, 40, 50, budget(1000)), { frames: Int32Array.from(range(51, 104)), open: false });
    assert.equal(fed([...exchange.slice(0, 104), tcpFrame(0x14)]).after(1, 40, 50, budget(1000)).open, false);
    // Only the client closed: the server may still send
    assert.equal(fed(closed.slice(0, 105)).after(1, 40, 50, budget(1000)).open, true);
    const quiet = new FlowIndex();
    [...exchange.slice(0, 104), g.udpFrame(0)].forEach((f, i) => quiet.feed(i + 1, "eth", f, i < 104 ? i / 1000 : 30));
    assert.equal(quiet.after(1, 40, 50, budget(1000)).open, false);
  });

  await check("flows: answers a non-TCP flow still owes come along from after the slice, and keep the chunk open until they came", () => {
    // Pings every 10 packets, each answered 35 packets later, a DNS query answered 100 packets later, among a one-way UDP stream
    const icmp = (back) => g.eth(0x0800, g.ip4(1, Buffer.alloc(16), back ? { src: [10, 0, 0, 2], dst: [10, 0, 0, 1] } : {}));
    const dns = (back) => g.eth(0x0800, g.ip4(17, g.udp(back ? 53 : 3333, back ? 3333 : 53, Buffer.alloc(30)), back ? { src: [10, 0, 0, 3], dst: [10, 0, 0, 4] } : { src: [10, 0, 0, 4], dst: [10, 0, 0, 3] }));
    const frames = Array.from({ length: 200 }, (_, n) => (n === 49 ? dns(false) : n === 149 ? dns(true) : n % 10 === 0 ? icmp(false) : n % 10 === 5 && n > 30 ? icmp(true) : g.udpFrame(n)));
    // Chunk 1-100, hi 120: the last ping's reply is 126, the query's answer 150
    assert.deepEqual(fed(frames).after(1, 100, 120, budget(1000)), { frames: Int32Array.of(126, 150), open: false });
    // Not in the file yet: they may still come
    assert.deepEqual(fed(frames.slice(0, 124)).after(1, 100, 120, budget(1000)), { frames: new Int32Array(0), open: true });
    // Unless the flows have been quiet for a while
    const quiet = new FlowIndex();
    [...frames.slice(0, 124), g.udpFrame(0, { sport: 999 })].forEach((f, i) => quiet.feed(i + 1, "eth", f, i < 124 ? i / 1000 : 30));
    assert.equal(quiet.after(1, 100, 120, budget(1000)).open, false);
    // A stream that only ever went one way owes nothing
    assert.deepEqual(fed(Array.from({ length: 100 }, (_, i) => g.udpFrame(i))).after(1, 40, 50, budget(1000)), { frames: new Int32Array(0), open: false });
  });

  await check("flows: a flow mostly one way, or a host that stopped answering, owes no answers; nor does one whose other side went quiet", () => {
    // As QUIC or a tunnel carries a download: ten packets from the server a packet from the client
    const quic = (back) => g.eth(0x0800, g.ip4(17, g.udp(back ? 443 : 40000, back ? 40000 : 443, Buffer.alloc(100)), back ? { src: [10, 0, 0, 2], dst: [10, 0, 0, 1] } : {}));
    assert.deepEqual(fed(Array.from({ length: 1200 }, (_, n) => quic(n % 11 !== 10))).after(1, 1000, 1100, budget(1000)), { frames: new Int32Array(0), open: false });
    // Pings every 10 packets, 0.05 s apart, among a one-way UDP stream; the host answers the first three, then no more
    const icmp = (back) => g.eth(0x0800, g.ip4(1, Buffer.alloc(16), back ? { src: [10, 0, 0, 2], dst: [10, 0, 0, 1] } : {}));
    const pings = (count) => {
      const flows = new FlowIndex();
      for (let n = 0; n < count; n++) flows.feed(n + 1, "eth", n % 10 === 0 ? icmp(false) : n % 10 === 2 && n < 30 ? icmp(true) : g.udpFrame(n), n * 0.05);
      return flows;
    };
    assert.deepEqual(pings(2000).after(1001, 1500, 1600, budget(1000)), { frames: new Int32Array(0), open: false });
    // The chunk it stopped answering in: open while an answer may come, not once it has been quiet for a while, however often it is asked
    assert.equal(pings(200).after(1, 50, 60, budget(1000)).open, true);
    assert.equal(pings(300).after(1, 50, 60, budget(1000)).open, false);
  });

  await check("flows: the flows whose rows what comes after hi may still change are named, and only those", () => {
    const openOf = (flows, lo, end, hi) => {
      const open = new Set();
      flows.after(lo, end, hi, budget(1000), open);
      return [...open];
    };
    // The response under way at hi, until it ended and the connection closed
    const growing = fed(exchange.slice(0, 80));
    assert.deepEqual(openOf(growing, 1, 40, 50), [growing.idOf(4)]);
    assert.deepEqual(openOf(fed(exchange), 1, 40, 50), []);
    // A request pipelined into the response is the flow's last packet up to hi: the response goes on after it
    const piped = fed([...exchange.slice(0, 105), ...response(20)]);
    assert.deepEqual(openOf(piped, 1, 100, 105), [piped.idOf(4)]);
    // Pings answered 35 packets later among a one-way UDP stream: the pings' flow, until their replies came
    const icmp = (back) => g.eth(0x0800, g.ip4(1, Buffer.alloc(16), back ? { src: [10, 0, 0, 2], dst: [10, 0, 0, 1] } : {}));
    const frames = Array.from({ length: 100 }, (_, n) => (n % 10 === 0 ? icmp(false) : n % 10 === 5 && n > 30 ? icmp(true) : g.udpFrame(n)));
    const asked = fed(frames.slice(0, 34));
    assert.deepEqual(openOf(asked, 1, 20, 30), [asked.idOf(1)]);
    assert.deepEqual(openOf(fed(frames), 1, 20, 30), []);
  });

  await check("flows: when there are too many, ended flows and those without a handshake are forgotten first", () => {
    const flows = new FlowIndex();
    // A connection that starts and goes quiet
    [tcpFrame(0x02), tcpFrame(0x12, { back: true }), tcpFrame(0x10), tcpFrame(0x18, { data: 80 })].forEach((f, i) => flows.feed(i + 1, "eth", f));
    // Then a quarter of a million single DNS-like packets
    const udp = g.udpFrame(0);
    const n = 250_000;
    for (let k = 0; k < n; k++) {
      udp.writeUInt16BE(1024 + (k % 60000), 34);
      udp[29] = Math.floor(k / 60000);
      flows.feed(5 + k, "eth", udp);
    }
    // The connection again: still known, from its handshake on
    flows.feed(n + 5, "eth", tcpFrame(0x18, { back: true, data: 100 }));
    assert.equal(flows.firstOf(n + 5), 1);
    assert.deepEqual([...flows.context(n + 5, n + 5, budget(1000))], range(1, 4));
  });

  await check("a slice of hundreds of long one-way downloads takes as long however long they run", async () => {
    // 400 downloads of one-byte segments after a request, every third packet an ACK: 5,000 packets each
    const K = 400;
    const seg = (k, flags, back, len) => {
      const t = g.tcp(back ? 80 : 20000 + k, back ? 20000 + k : 80, Buffer.alloc(len, 0x61));
      t[13] = flags;
      const a = [10, 1, k >> 8, k & 255];
      return g.eth(0x0800, g.ip4(6, t, back ? { src: [10, 9, 9, 9], dst: a } : { src: a, dst: [10, 9, 9, 9] }));
    };
    const file = join(out, "downloads.pcapng");
    const fd = openSync(file, "w", 0o600);
    let n = 0;
    let parts = [header()];
    const put = (f) => {
      parts.push(packet(n++, f, { pps: 50_000 }));
      if (parts.length < 50_000) return;
      writeSync(fd, Buffer.concat(parts));
      parts = [];
    };
    for (let k = 0; k < K; k++) [seg(k, 0x02, false, 0), seg(k, 0x12, true, 0), seg(k, 0x10, false, 0), seg(k, 0x18, false, 1)].forEach(put);
    const data = Array.from({ length: K }, (_, k) => seg(k, 0x18, true, 1));
    const acks = Array.from({ length: K }, (_, k) => seg(k, 0x10, false, 0));
    for (let i = 0; i < 5000; i++) for (let k = 0; k < K; k++) put(i % 3 === 2 ? acks[k] : data[k]);
    writeSync(fd, Buffer.concat(parts));
    closeSync(fd);
    const tail = new LiveTail({ file, dir: out, sharkd: newSharkd });
    try {
      await tail.update();
      const ms = [];
      for (let i = 0, lo = Math.floor((tail.count - 1) / CHUNK) * CHUNK + 1; i < 7; i++, lo -= CHUNK) {
        const t0 = performance.now();
        const s = tail.slice(lo);
        ms.push(performance.now() - t0);
        assert.ok(s.extras.length > 15_000, `${s.extras.length} frames from before`);
      }
      ms.sort((a, b) => a - b);
      report.push(`slices of ${K} downloads at ${tail.count} packets: ${ms[3].toFixed(1)} ms each`);
      // The bound leaves room for a busy machine
      assert.ok(ms[3] < 60, `a slice took ${ms[3].toFixed(1)} ms`);
    } finally {
      tail.close();
      rmSync(file, { force: true });
    }
  });

  /** A slice of chunk 20001-20003: frames 1, 7 and 900, then 18001-20005, then 20100 and 20300. */
  const s = { lo: 20001, end: 20003, hi: 20005, c0: 18001, extras: Int32Array.of(1, 7, 900), after: Int32Array.of(20100, 20300) };
  const tenfold = (n) => n * 10;

  await check("slices: local and file frame numbers; renumbered rows, Info and trees", () => {
    const frames = [...sliceFrames(s)];
    assert.equal(frames.length, 3 + 2005 + 2);
    assert.deepEqual(frames.slice(0, 4), [1, 7, 900, 18001]);
    assert.deepEqual(frames.slice(-3), [20005, 20100, 20300]);
    for (const [local, global] of [[1, 1], [3, 900], [4, 18001], [2008, 20005], [2009, 20100], [2010, 20300]]) {
      assert.equal(toGlobal(s, local), global);
      if (global >= s.c0 && global <= s.hi) assert.equal(toLocal(s, global), local);
    }
    assert.equal(toGlobal(s, 5000), 5000);
    const numbering = { frames: [0, 7], info: 6, blank: [8] };
    const row = { num: 2008, c: ["2008", "1.5", "a", "b", "TCP", "60", "[TCP Dup ACK 4#2] x [TCP PDU reassembled in 2007]", "3,2008", "7"], bg: "ff", fg: "00" };
    assert.deepEqual(renumberRow(row, s, numbering), {
      num: 20005,
      c: ["20005", "1.5", "a", "b", "TCP", "60", "[TCP Dup ACK 18001#2] x [TCP PDU reassembled in 20004]", "900,20005", ""],
      bg: "ff",
      fg: "00",
      p: true,
    });
    for (const [info, want] of [
      ["Fragmented IP protocol [Reassembled in #3]", "Fragmented IP protocol [Reassembled in #30]"],
      ["Echo (ping) request  id=0x5742, seq=1/256, ttl=64 (reply in 3)", "Echo (ping) request  id=0x5742, seq=1/256, ttl=64 (reply in 30)"],
      ["Echo (ping) reply    id=0x5742, seq=1/256, ttl=64 (request in 2)", "Echo (ping) reply    id=0x5742, seq=1/256, ttl=64 (request in 20)"],
      ["[MTP2 Reassembled in: 5]", "[MTP2 Reassembled in: 50]"],
      ["(Application Layer fragment 3, reassembled in packet 4)", "(Application Layer fragment 3, reassembled in packet 40)"],
      ["(N-PDU payload reassembled in packet 4)", "(N-PDU payload reassembled in packet 40)"],
      ["V3 GETATTR Reply (Call In 2) [RPC retransmission of #7]", "V3 GETATTR Reply (Call In 20) [RPC retransmission of #70]"],
      ["Request [DCE/RPC fragment, reas: #8]", "Request [DCE/RPC fragment, reas: #80]"],
      ["Standard query 0x1234 A host12.example.com", "Standard query 0x1234 A host12.example.com"],
    ]) {
      assert.equal(renumberInfo(info, tenfold), want);
    }
    const tree = renumberTree(
      [
        { l: "Frame 2008: 60 bytes on wire", fn: "frame", n: [{ l: "Frame Number: 2008", f: "frame.number == 2008", fn: "frame.number" }] },
        { l: "Transmission Control Protocol", fn: "tcp", n: [
          { l: "Stream index: 3", f: "tcp.stream == 3", fn: "tcp.stream" },
          { l: "[Reassembled PDU in frame: 2007]", f: "tcp.reassembled_in == 2007", fn: "tcp.reassembled_in", t: "framenum", fnum: 2007 },
          { l: "[2 Reassembled TCP Segments (2896 bytes): #4(1448), #2008(1448)]", fn: "tcp.segments" },
          { l: "[Frame: 4, payload: 0-4 (5 bytes)]", f: "tcp.segment == 4", fn: "tcp.segment", t: "framenum", fnum: 4 },
        ] },
      ],
      s,
    );
    assert.equal(tree[0].l, "Frame 20005: 60 bytes on wire");
    assert.deepEqual([tree[0].n[0].l, tree[0].n[0].f], ["Frame Number: 20005", "frame.number == 20005"]);
    const tcp = tree[1].n;
    assert.deepEqual([tcp[0].l, tcp[0].f], ["Stream index: unknown until read in full", undefined]);
    assert.deepEqual([tcp[1].l, tcp[1].f, tcp[1].fnum], ["[Reassembled PDU in frame: 20004]", "tcp.reassembled_in == 20004", 20004]);
    assert.equal(tcp[2].l, "[2 Reassembled TCP Segments (2896 bytes): #18001(1448), #20005(1448)]");
    assert.deepEqual([tcp[3].l, tcp[3].f, tcp[3].fnum], ["[Frame: 18001, payload: 0-4 (5 bytes)]", "tcp.segment == 18001", 18001]);
  });

  await check("Info: frame numbers in the forms dissectors write them; text a packet carries stays as it is", () => {
    for (const [info, want] of [
      ["Request [reply in 3]", "Request [reply in 30]"],
      ["Response [response to 2]", "Response [response to 20]"],
      ["V3 READ Call (Reply In 3) [RPC duplicate of #7]", "V3 READ Call (Reply In 30) [RPC duplicate of #70]"],
      ["PDV Fragment (reassembled in #3)", "PDV Fragment (reassembled in #30)"],
      ["Data [SCSI PDU Reassembled in #3] , [Reas: #4]", "Data [SCSI PDU Reassembled in #30] , [Reas: #40]"],
      ["(PPP MP reassembled in packet 4)", "(PPP MP reassembled in packet 40)"],
      ["Payload [Continuation to #5]", "Payload [Continuation to #50]"],
    ]) {
      assert.equal(renumberInfo(info, tenfold), want);
    }
    // As syslog, SIP or FTP show it
    for (const info of ["USER.INFO: upstream timeout, retrying request in 30 seconds", "duplicate of 12 queued jobs dropped", "response to 3 clients delayed", "SIP call in 5 minutes", "2 retransmission of 7 segments", "reassembled in 4 parts (reply in 3 days)", "Dup ACK 5#1"]) {
      assert.equal(renumberInfo(info, tenfold), info);
    }
  });

  await check("details: TCP's conversation completeness is unknown until read in full, like stream indices; a protocol's own streams (an HTTP/2 frame) keep their fields", () => {
    const [completeness] = renumberTree([{ l: "Conversation completeness: Incomplete, DATA (15)", f: "tcp.completeness == 15", fn: "tcp.completeness", n: [{ l: "...0 .... = FIN: Absent", f: "tcp.completeness.fin == False", fn: "tcp.completeness.fin" }] }], s);
    assert.deepEqual(completeness, { l: "Conversation completeness: unknown until read in full", fn: "tcp.completeness" });
    assert.equal(renumberTree([{ l: "[Stream index: 3]", fn: "udp.stream" }], s)[0].l, "[Stream index: unknown until read in full]");
    const [frame] = renumberTree([{ l: "Stream: HEADERS, Stream ID: 1, Length 1, 200 OK", fn: "http2.stream", n: [{ l: "Length: 1", f: "http2.length == 1", fn: "http2.length" }, { l: "Stream Identifier: 1", f: "http2.streamid == 1", fn: "http2.streamid" }, { l: "[Request in frame: 2008]", f: "http2.request_in == 2008", fn: "http2.request_in", t: "framenum", fnum: 2008 }] }], s);
    assert.deepEqual([frame.l, ...frame.n.map((n) => n.l)], ["Stream: HEADERS, Stream ID: 1, Length 1, 200 OK", "Length: 1", "Stream Identifier: 1", "[Request in frame: 20005]"]);
  });

  await check("details: frame numbers in expert info texts renumbered; lists of segments as long as with the file's numbers", () => {
    const [expert] = renumberTree([{ l: "Expert Info (Warning/Protocol): DNS query retransmission. Original request in frame 3", fn: "_ws.expert", n: [{ l: "DNS query retransmission. Original request in frame 3", fn: "dns.retransmit_request" }, { l: "Severity level: Warning", fn: "_ws.expert.severity" }] }], s);
    assert.deepEqual([expert.l, expert.n[0].l, expert.n[1].l], ["Expert Info (Warning/Protocol): DNS query retransmission. Original request in frame 900", "DNS query retransmission. Original request in frame 900", "Severity level: Warning"]);
    for (const [text, want] of [
      ["DNS response retransmission. Original response in frame 2", "DNS response retransmission. Original response in frame 7"],
      ["No response seen to ICMPv6 request in frame 3", "No response seen to ICMPv6 request in frame 900"],
      ["Duplicate IP address detected for 10.0.0.1 (02:00:00:00:00:01) - also in use by 02:00:00:00:00:02 (frame 4)", "Duplicate IP address detected for 10.0.0.1 (02:00:00:00:00:01) - also in use by 02:00:00:00:00:02 (frame 18001)"],
      ["This is a retransmission of frame 2008", "This is a retransmission of frame 20005"],
    ]) {
      assert.equal(renumberTree([{ l: `Expert Info (Note/Sequence): ${text}`, fn: "_ws.expert" }], s)[0].l, `Expert Info (Note/Sequence): ${want}`);
    }
    // sharkd shows 239 characters of a label at most: with the file's longer numbers, fewer segments fit
    const items = (map) => range(4, 43).map((n) => `#${map(n)}(1448)`);
    const fit = (list) => {
      const label = (k) => `40 Reassembled TCP Segments (57920 bytes): ${list.slice(0, k).join(", ")}`;
      let k = list.length;
      while (label(k).length > 239) k--;
      return label(k);
    };
    const [segments] = renumberTree([{ l: fit(items((n) => n)), fn: "tcp.segments" }], s);
    assert.equal(segments.l, fit(items((n) => toGlobal(s, n))));
    assert.ok(segments.l.endsWith("#18014(1448)"), segments.l);
  });

  await check("filters slices can't check: stream indices, conversation completeness, frame numbers, frame-number fields, references", async () => {
    const types = { "http.response_in": 35, "tcp.reassembled_in": 35, "ip.addr": 31, "http.request": 1 };
    const type = async (f) => types[f] ?? null;
    for (const f of ["tcp.stream eq 4", "udp.stream == 1 && dns", "tcp.stream.pnum > 3", "frame.number > 10", "http.response_in", "ip.addr == ${ip.src}", "sctp.assoc_index == 1", "quic.connection.number == 0", "tcp.completeness == 31", "tcp.completeness.fin == 1", "ip.stream == 2", "eth.stream == 0"]) {
      assert.ok(await heldReason(f, type), f);
    }
    for (const f of ["ip.addr == 10.0.0.1", "http.request", "tcp.analysis.flags", 'http.host contains "tcp.stream"', "http2.streamid == 3", "http2.stream", "http3.stream", "quic.stream.offset > 0"]) {
      assert.equal(await heldReason(f, type), null, f);
    }
    assert.ok(streamNumbered("tcp.stream") && streamNumbered("udp.stream.pnum") && streamNumbered("tcp.completeness.str") && streamNumbered("ipv6.stream"));
    for (const f of ["http2.streamid", "frame.number", "http2.stream", "http3.stream", "xmpp.stream", "quic.stream.stream_id", "amqp.stream.method"]) assert.ok(!streamNumbered(f), f);
  });

  await check("memory: another full read waits when sharkd would need more than is free", () => {
    const GB = 2 ** 30;
    // 1 GiB after reading 250,000 frames: about 3.6 KB a frame on top of what sharkd starts with
    const read = { activeBytes: GB, frames: 250_000 };
    assert.equal(memoryShort({ ...read, standbyBytes: GB, next: 300_000, available: 4 * GB }), false);
    // The standby's copy grows by what the new frames need
    assert.equal(memoryShort({ ...read, standbyBytes: GB, next: 1_000_000, available: 3.5 * GB }), false);
    assert.equal(memoryShort({ ...read, standbyBytes: GB, next: 1_000_000, available: 2 * GB }), true);
    assert.equal(memoryShort({ ...read, standbyBytes: 0, next: 1_000_000, available: 3.5 * GB }), true);
    assert.equal(memoryShort({ ...read, frames: 0, standbyBytes: 0, next: 1_000_000, available: 0 }), false);
  });

  // ------------------------------------------------- against the file cut at the same packet

  const big = join(out, "traffic.pcapng");
  const keylog = join(out, "traffic.keys");
  const total = 64000;
  writeTraffic(big, total, { keylog });
  const bigStore = new FrameStore(big);
  await bigStore.update();
  assert.equal(bigStore.count, total);
  const truth = newSharkd();
  /** The first `n` packets of the traffic, as a live file holds them after `n`. */
  const cutAt = async (n) => {
    const file = join(out, `cut-${n}.pcapng`);
    rmSync(file, { force: true });
    await bigStore.writeSlice(Int32Array.from({ length: n }, (_, i) => i + 1), file);
    return file;
  };
  const rowsOf = async (engine, from, to) => {
    const rows = [];
    for (let at = from; at <= to; at += 1000) rows.push(...(await engine.call("frames", { ...(at > 1 ? { skip: at - 1 } : {}), limit: Math.min(1000, to - at + 1) })));
    return rows;
  };
  /** Filters rows were read with. */
  const filtersRead = new Set();
  const view = {
    numbering: { frames: [0], info: 6, blank: [] },
    fetch: (engine, params) => {
      if (params.filter) filtersRead.add(params.filter);
      return engine.call("frames", params);
    },
    key: "",
  };
  const FILTERS = ["http", "http.request", "tls", "tcp.analysis.flags", "tcp.analysis.lost_segment", "tcp.analysis.duplicate_ack", "tcp.analysis.retransmission", "tcp.analysis.reused_ports", "dns", "icmp", "tcp.flags.syn == 1", "http.response.code == 404", "tcp.window_size > 60000", "tcp.len > 1000", 'http.request.method == "PUT"', "icmp.resp_not_found"];
  const same = (r, x) => r.num === x.num && r.c.join("\t") === x.c.join("\t") && (r.bg ?? "") === (x.bg ?? "") && (r.fg ?? "") === (x.fg ?? "") && r.p;

  await check("provisional rows, filter matches and filtered rows equal sharkd's reading of the file cut there, with and without TLS keys; final chunks' rows its reading of the whole file", async () => {
    const truthKeys = newSharkd(keylog);
    const whole = [newSharkd(), newSharkd(keylog)];
    for (const e of whole) assert.equal((await e.call("load", { file: big })).status, "OK");
    for (const keys of [null, keylog]) {
      const engine = keys ? truthKeys : truth;
      // Tails within a chunk and over several, whose complete chunks keep their rows; cuts inside and at the end of chunks
      for (const [cut, n] of [[21_500, 6000], [37_000, 24_000], [64_000, 24_000]]) {
        const file = await cutAt(cut);
        const base = cut - n;
        const load = await engine.call("load", { file, max_packets: cut });
        assert.equal(load.status, "OK");
        const exact = await rowsOf(engine, base + 1, cut);
        const byNum = new Map(exact.map((r) => [r.num, r]));
        const tail = new LiveTail({ file, dir: out, sharkd: () => newSharkd(keys) });
        const what = `cut ${cut}${keys ? " with keys" : ""}`;
        try {
          await tail.update();
          assert.equal(tail.count, cut);
          tail.rebase(base);
          tail.active = true;
          const t0 = performance.now();
          const rows = [];
          for (let i = 0; i < tail.listed(); i += 500) rows.push(...(await tail.rows(i, 500, view)));
          const ms = performance.now() - t0;
          assert.equal(rows.length, n);
          const differ = rows.filter((r, i) => !same(r, exact[i]));
          const examples = differ.slice(0, 3).map((r) => `${r.num}: ${byNum.get(r.num).c[6]} | ${r.c[6]}`);
          assert.equal(differ.length, 0, `${what}: ${differ.length} of ${n} rows differ, e.g.\n  ${examples.join("\n  ")}`);
          // Chunks whose rows read the same from now on, in the tail or before it, read as the whole file does
          let kept = 0;
          for (let f = 1; f <= cut; ) {
            const s = tail.slice(f);
            if (s.final) {
              const got = await tail.rowsOf(range(s.lo, s.end), view);
              const later = await rowsOf(whole[keys ? 1 : 0], s.lo, s.end);
              const wrong = got.filter((r, i) => !same(r, later[i]));
              assert.equal(wrong.length, 0, `${what}: ${wrong.length} rows of final chunk ${s.lo}-${s.end} differ from the whole file's, e.g. ${wrong[0]?.num}: ${wrong[0]?.c[6]}`);
              kept++;
            }
            f = s.end + 1;
          }
          let matches = 0;
          for (const f of keys ? ["http", "tls", "http.response.code == 200"] : FILTERS) {
            const want = [...(await matchingFrames(engine, f))].filter((m) => m > base);
            tail.setFilter(f, null);
            while (await tail.filterPass());
            const got = Array.from({ length: tail.listed() }, (_, i) => tail.frameAt(i));
            assert.deepEqual(got, want, `${what}, filter ${f}`);
            matches += want.length;
            // The filtered list's rows, its first and last pages
            const pages = got.length > 1000 ? [0, got.length - 500] : [0];
            for (const at of pages) {
              const listed = await tail.rows(at, 500, view);
              const wrong = listed.filter((r) => !same(r, byNum.get(r.num)));
              assert.equal(wrong.length, 0, `${what}, filter ${f}: ${wrong.length} rows differ, e.g. ${wrong[0]?.num}`);
            }
          }
          report.push(`${what}: ${n} rows identical in ${Math.round(ms)} ms; ${matches} filter matches and their rows identical; ${kept} final chunks as the whole file reads`);
        } finally {
          tail.close();
        }
      }
    }
    // Filtered rows come by the view's filter, which sharkd keeps, not by filters of their frame numbers
    assert.ok([...filtersRead].every((f) => FILTERS.includes(f) || f === "http.response.code == 200"), [...filtersRead].join(" | "));
  });

  await check("a naive slice (frame 1 and plain context) reads differently: the flows' starts matter", async () => {
    const cut = 50_000;
    const file = await cutAt(cut);
    await truth.call("load", { file, max_packets: cut });
    const exact = await rowsOf(truth, cut - 5999, cut);
    const naive = join(out, "naive.pcapng");
    const frames = [1, ...Array.from({ length: 6000 + CONTEXT }, (_, i) => cut - 6000 - CONTEXT + 1 + i)];
    await bigStore.writeSlice(frames, naive);
    const e = newSharkd();
    await e.call("load", { file: naive });
    const rows = (await e.call("frames", { skip: 1 + CONTEXT, limit: 6000 })).map((r) => ({ ...r, num: frames[r.num - 1] }));
    const info = rows.filter((r, i) => renumberInfo(r.c[6], (n) => frames[n - 1]) !== exact[i].c[6]).length;
    const proto = rows.filter((r, i) => r.c[4] !== exact[i].c[4]).length;
    report.push(`naive slice at ${cut}: ${info} of 6000 Info and ${proto} Protocol cells differ`);
    assert.ok(info > 300 && proto > 50, `${info} Info, ${proto} Protocol cells differ`);
  });

  await check("details of a provisional frame: renumbered, bytes exact", async () => {
    const cut = 37_000;
    const file = await cutAt(cut);
    await truth.call("load", { file, max_packets: cut });
    const tail = new LiveTail({ file, dir: out, sharkd: newSharkd });
    try {
      await tail.update();
      tail.rebase(cut - 3000);
      // A data segment reassembled later, one with a reassembled PDU, an ACK
      const picks = (await truth.call("frames", { filter: `frame.number > ${cut - 3000} && (tcp.reassembled_in || http.response || tcp.len == 0)`, limit: 200, column0: "frame.number:0" })).map((r) => r.num).filter((_, i) => i % 40 === 0);
      assert.ok(picks.length >= 4);
      // Coloring rules show once sharkd colored the frame for a row, which the truth's engine did
      const strip = (nodes) => nodes.filter((n) => !n.fn?.startsWith("frame.coloring_rule.")).map((n) => (streamNumbered(n.fn ?? "") ? { fn: n.fn } : { ...n, n: n.n && strip(n.n) }));
      for (const num of picks) {
        const want = await truth.call("frame", { frame: num, proto: true, bytes: true });
        const got = await tail.frame(num);
        assert.equal(got.bytes, want.bytes, `frame ${num} bytes`);
        assert.deepEqual(strip(got.tree), strip(want.tree), `frame ${num}`);
      }
      // Where the slices go: a private folder next to the capture, removed with the tail
      const folder = readdirSync(out).find((n) => n.startsWith(".wirebuddy-slices-"));
      assert.ok(folder, "a folder of slices");
      assert.equal(statSync(join(out, folder)).mode & 0o777, 0o700);
      for (const f of readdirSync(join(out, folder))) assert.equal(statSync(join(out, folder, f)).mode & 0o777, 0o600);
    } finally {
      tail.close();
    }
    assert.ok(!readdirSync(out).some((n) => n.startsWith(".wirebuddy-slices-")), "slices removed");
  });

  await check("a growing file: newer packets read from slices as they come", async () => {
    const file = await cutAt(CHUNK - 300);
    const tail = new LiveTail({ file, dir: out, sharkd: newSharkd });
    try {
      await tail.update();
      tail.rebase(CHUNK - 1000);
      assert.equal((await tail.rows(0, 1000, view)).at(-1).num, CHUNK - 300);
      // The file grows past a chunk's end
      const more = join(out, "more.pcapng");
      rmSync(more, { force: true });
      await bigStore.writeSlice(Int32Array.from({ length: 600 }, (_, i) => CHUNK - 300 + 1 + i), more);
      appendFileSync(file, readFileSync(more).subarray(header().length));
      await tail.update();
      assert.equal(tail.count, CHUNK + 300);
      const rows = await tail.rows(0, tail.listed(), view);
      assert.deepEqual([rows.length, rows[0].num, rows[999].num, rows.at(-1).num], [1300, CHUNK - 999, CHUNK, CHUNK + 300]);
      assert.equal(rows.at(-1).c[0], String(CHUNK + 300));
      assert.equal(tail.indexOf(CHUNK + 1), 1000);
      tail.rebase(CHUNK);
      assert.deepEqual([tail.frames, tail.frameAt(0), tail.indexOf(CHUNK)], [300, CHUNK + 1, -1]);
    } finally {
      tail.close();
    }
  });

  await check("a growing file: filter matches that later packets change (a late reply) are checked again as they come", async () => {
    const end = 40_000;
    const file = await cutAt(8000);
    const tail = new LiveTail({ file, dir: out, sharkd: newSharkd });
    try {
      await tail.update();
      tail.rebase(0);
      tail.setFilter("icmp.resp_not_found", null);
      const more = join(out, "more.pcapng");
      for (let count = 8000; count < end; count += 4000) {
        rmSync(more, { force: true });
        await bigStore.writeSlice(Int32Array.from({ length: 4000 }, (_, i) => count + 1 + i), more);
        appendFileSync(file, readFileSync(more).subarray(header().length));
        await tail.update();
        while (await tail.filterPass());
      }
      assert.equal(tail.count, end);
      assert.equal((await truth.call("load", { file })).status, "OK");
      const want = [...(await matchingFrames(truth, "icmp.resp_not_found"))];
      assert.deepEqual(Array.from({ length: tail.listed() }, (_, i) => tail.frameAt(i)), want);
      assert.ok(tail.revision > 0, "matches listed before changed");
    } finally {
      tail.close();
    }
  });

  await check("a full read that lands while a filter pass reads its newest rows: the matches it covers aren't listed again", async () => {
    const file = await cutAt(25_000);
    let landing = null;
    const racing = {
      ...view,
      fetch: async (engine, params) => {
        const rows = await view.fetch(engine, params);
        const land = landing;
        landing = null;
        land?.();
        return rows;
      },
    };
    const tail = new LiveTail({ file, dir: out, sharkd: newSharkd });
    try {
      await tail.update();
      tail.rebase(20_000);
      tail.setFilter("tcp", null);
      while (await tail.filterPass(racing, 500));
      const more = join(out, "more.pcapng");
      rmSync(more, { force: true });
      await bigStore.writeSlice(Int32Array.from({ length: 1000 }, (_, i) => 25_001 + i), more);
      appendFileSync(file, readFileSync(more).subarray(header().length));
      await tail.update();
      landing = () => tail.rebase(24_000);
      // The growing chunk is checked again after a pause as long as its last check took
      for (let i = 0; landing && i < 100; i++) {
        await tail.filterPass(racing, 500);
        if (landing) await sleep(100);
      }
      assert.equal(landing, null, "the full read landed while the pass read rows");
      const listed = Array.from({ length: tail.listed() }, (_, i) => tail.frameAt(i));
      assert.ok(listed.length > 0);
      assert.deepEqual(listed.filter((f) => f <= tail.base), []);
    } finally {
      tail.close();
    }
  });

  await check("rows kept while their chunk grew read as sharkd reads the file once it grew", async () => {
    const [cut, later, base] = [25_000, 31_000, 20_000];
    const file = await cutAt(cut);
    const tail = new LiveTail({ file, dir: out, sharkd: newSharkd });
    try {
      await tail.update();
      tail.rebase(base);
      for (let i = 0; i < cut - base; i += 500) await tail.rows(i, 500, view);
      const more = join(out, "more.pcapng");
      rmSync(more, { force: true });
      await bigStore.writeSlice(Int32Array.from({ length: later - cut }, (_, i) => cut + 1 + i), more);
      appendFileSync(file, readFileSync(more).subarray(header().length));
      await tail.update();
      const rows = [];
      for (let i = 0; i < cut - base; i += 500) rows.push(...(await tail.rows(i, 500, view)));
      await truth.call("load", { file: await cutAt(later), max_packets: later });
      const exact = await rowsOf(truth, base + 1, cut);
      const differ = rows.filter((r, i) => !same(r, exact[i]));
      assert.equal(differ.length, 0, `${differ.length} rows differ, e.g. ${differ.slice(0, 3).map((r) => `${r.num}: ${exact[r.num - base - 1].c[6]} | ${r.c[6]}`).join("; ")}`);
    } finally {
      tail.close();
    }
  });

  await check("rows read before their replies came read as sharkd reads the file once they came: pings and NFS calls answered thousands of packets later, a reply completed after the slice", async () => {
    const u32 = (...xs) => {
      const b = Buffer.alloc(4 * xs.length);
      xs.forEach((x, i) => b.writeUInt32BE(x >>> 0, 4 * i));
      return b;
    };
    // NFSv3 GETATTR; over TCP with a record mark
    const call = (xid) => u32(xid, 0, 2, 100003, 3, 1, 0, 0, 0, 0, 8, 1, 2);
    const reply = (xid, more = 0) => Buffer.concat([u32(xid, 1, 0, 0, 0, 0, 1), Buffer.alloc(more)]);
    const marked = (m) => Buffer.concat([u32(0x80000000 | m.length), m]);
    const echo = (type, seq) => {
      const b = Buffer.alloc(64);
      b[0] = type;
      b.writeUInt16BE(0x1234, 4);
      b.writeUInt16BE(seq, 6);
      let sum = 0;
      for (let i = 0; i < b.length; i += 2) sum += b.readUInt16BE(i);
      while (sum > 0xffff) sum = (sum & 0xffff) + (sum >>> 16);
      b.writeUInt16BE(~sum & 0xffff, 2);
      return b;
    };
    const [client, server] = [{ src: [10, 0, 0, 1], dst: [10, 0, 0, 2] }, { src: [10, 0, 0, 2], dst: [10, 0, 0, 1] }];
    /** A TCP connection from `port` to NFS; `from` 1: the server sends. */
    const nfsTcp = (port) => {
      const seq = [1000, 5000];
      return (from, flags, payload = Buffer.alloc(0)) => {
        const t = g.tcp(from ? 2049 : port, from ? port : 2049, payload);
        t.writeUInt32BE(seq[from] >>> 0, 4);
        t.writeUInt32BE(seq[1 - from] >>> 0, 8);
        t[13] = flags;
        seq[from] += payload.length + (flags & 0x02 ? 1 : 0);
        return g.eth(0x0800, g.ip4(6, t, from ? server : client));
      };
    };
    const [a, b] = [nfsTcp(800), nfsTcp(801)];
    const at = new Map([[1, () => a(0, 0x02)], [2, () => a(1, 0x12)], [3, () => a(0, 0x10)], [4, () => b(0, 0x02)], [5, () => b(1, 0x12)], [6, () => b(0, 0x10)]]);
    // Requests from 25000 on: the first answered at once, the others 3000 packets later
    for (let k = 0; k <= 30; k++) {
      const f = 25_000 + 100 * k;
      const r = k ? f + 3000 : f + 50;
      at.set(f, () => g.eth(0x0800, g.ip4(1, echo(8, k), { src: [10, 0, 0, 30], dst: [10, 9, 9, 9] })));
      at.set(r, () => g.eth(0x0800, g.ip4(1, echo(0, k), { src: [10, 9, 9, 9], dst: [10, 0, 0, 30] })));
      at.set(f + 2, () => g.eth(0x0800, g.ip4(17, g.udp(800, 2049, call(k)), client)));
      at.set(r + 2, () => g.eth(0x0800, g.ip4(17, g.udp(2049, 800, reply(k)), server)));
      at.set(f + 4, () => a(0, 0x18, marked(call(100 + k))));
      at.set(r + 4, () => a(1, 0x18, marked(reply(100 + k))));
    }
    // A call at the chunk's end whose reply of 2400 segments ends past its slice
    const long = marked(reply(1000, 2400 * 1448 - 32));
    at.set(29_990, () => b(0, 0x18, marked(call(1000))));
    for (let i = 0; i < 2400; i++) at.set(29_995 + 2 * i, () => b(1, 0x10, long.subarray(i * 1448, (i + 1) * 1448)));
    at.set(34_900, () => b(0, 0x18, marked(call(1001))));
    const frames = Array.from({ length: 40_000 }, (_, i) => at.get(i + 1)?.() ?? g.udpFrame(i + 1, { sport: 40_000 + (i % 50) }));
    const packets = (from, to) => Buffer.concat(frames.slice(from, to).map((f, i) => packet(from + i, f)));
    const file = join(out, "answers.pcapng");
    writeFileSync(file, Buffer.concat([header(), packets(0, 28_500)]));
    const tail = new LiveTail({ file, dir: out, sharkd: newSharkd });
    const base = 20_000;
    try {
      await tail.update();
      tail.rebase(base);
      // The chunk grows; then it is complete, the long reply still under way
      for (const [cut, more] of [[28_500, 32_200], [32_200, 40_000]]) {
        for (let i = 0; i < Math.min(cut, base + CHUNK) - base; i += 500) await tail.rows(i, 500, view);
        appendFileSync(file, packets(cut, more));
        await tail.update();
      }
      const rows = [];
      for (let i = 0; i < CHUNK; i += 500) rows.push(...(await tail.rows(i, 500, view)));
      const whole = newSharkd();
      await whole.call("load", { file });
      const exact = await rowsOf(whole, base + 1, base + CHUNK);
      const differ = rows.filter((r, i) => !same(r, exact[i]));
      assert.equal(differ.length, 0, `${differ.length} rows differ, e.g. ${differ.slice(0, 3).map((r) => `${r.num}: ${exact[r.num - base - 1].c[6]} | ${r.c[6]}`).join("; ")}`);
      assert.match(exact[29_990 - base - 1].c[6], /\(Reply In 34793\)/);
    } finally {
      tail.close();
      rmSync(file, { force: true });
    }
  });

  await check("rows of a chunk whose response goes on past a request pipelined into it read as sharkd reads the file once the response ended", async () => {
    const [client, server] = [{ src: [10, 0, 0, 1], dst: [10, 0, 0, 2] }, { src: [10, 0, 0, 2], dst: [10, 0, 0, 1] }];
    const seq = [1000, 50000];
    /** A segment of the connection; `from` 1: the server sends. */
    const seg = (from, flags, payload = Buffer.alloc(0)) => {
      const t = g.tcp(from ? 80 : 1000, from ? 1000 : 80, payload);
      t.writeUInt32BE(seq[from] >>> 0, 4);
      t.writeUInt32BE(seq[1 - from] >>> 0, 8);
      t[13] = flags;
      seq[from] += payload.length + (flags & 0x02 ? 1 : 0);
      return g.eth(0x0800, g.ip4(6, t, from ? server : client));
    };
    const body = Buffer.concat([Buffer.from("HTTP/1.1 200 OK\r\nContent-Length: 40000\r\n\r\n"), Buffer.alloc(40_000, 0x61)]);
    let sent = 0;
    const next = () => seg(1, 0x18, body.subarray(sent, (sent += 1000)));
    const frames = [seg(0, 0x02), seg(1, 0x12), seg(0, 0x10)];
    const fill = (to) => {
      while (frames.length < to) frames.push(g.udpFrame(frames.length));
    };
    // The response from 9981 on, past the chunk's end and hi; the client's next request right after hi, at 12001
    fill(9979);
    frames.push(seg(0, 0x18, Buffer.from("GET /big HTTP/1.1\r\nHost: x\r\n\r\n")));
    while (frames.length < CHUNK) frames.push(next());
    fill(CHUNK + CONTEXT - 10);
    frames.push(next());
    fill(CHUNK + CONTEXT);
    frames.push(seg(0, 0x18, Buffer.from("GET /next HTTP/1.1\r\nHost: x\r\n\r\n")));
    for (let i = 0; i < 5; i++) frames.push(next());
    const cut = frames.length;
    while (sent < body.length) frames.push(next());
    const file = join(out, "pipelined.pcapng");
    writeFileSync(file, Buffer.concat([header(), ...frames.slice(0, cut).map((f, i) => packet(i, f))]));
    const tail = new LiveTail({ file, dir: out, sharkd: newSharkd });
    try {
      await tail.update();
      tail.rebase(0);
      await tail.rows(9979, 22, view);
      appendFileSync(file, Buffer.concat(frames.slice(cut).map((f, i) => packet(cut + i, f))));
      await tail.update();
      const rows = await tail.rows(9979, 22, view);
      const whole = newSharkd();
      await whole.call("load", { file });
      const exact = await rowsOf(whole, 9980, 10_001);
      assert.match(exact[1].c[6], /reassembled in/);
      const differ = rows.filter((r, i) => !same(r, exact[i]));
      assert.equal(differ.length, 0, `${differ.length} rows differ, e.g. ${differ.slice(0, 2).map((r) => `${r.num}: ${exact[r.num - 9980].c[6]} | ${r.c[6]}`).join("; ")}`);
    } finally {
      tail.close();
      rmSync(file, { force: true });
    }
  });

  await check("big packets: chunks and slices keep to their byte budgets and read as the file does", async () => {
    // 64 KB packets, as bulk transfers on lo have them: 1100 of them take 70 MB
    const file = join(out, "jumbo.pcapng");
    const fd = openSync(file, "w", 0o600);
    writeSync(fd, header());
    const payload = Buffer.alloc(64000, 0x61);
    for (let n = 0; n < 1100; n++) {
      payload.writeUInt32BE(n, 0);
      writeSync(fd, packet(n, g.eth(0x0800, g.ip4(17, g.udp(40000, 9, payload)))));
    }
    closeSync(fd);
    const tail = new LiveTail({ file, dir: out, sharkd: newSharkd });
    try {
      await tail.update();
      const s = tail.slice(1100);
      assert.ok(s.lo > 1 && s.end - s.lo + 1 < CHUNK, `chunk ${s.lo}-${s.end}`);
      for (const f of [1, s.lo - 1, 1100]) {
        const bytes = sliceBytes(tail.store, [...sliceFrames(tail.slice(f))]);
        assert.ok(bytes <= 64 * 2 ** 20, `the slice of ${f} takes ${bytes} bytes`);
      }
      const e = newSharkd();
      await e.call("load", { file });
      const want = await e.call("frames", { skip: 1090, limit: 10 });
      const got = await tail.rows(1090, 10, view);
      assert.ok(got.length === 10 && got.every((r, i) => same(r, want[i])), JSON.stringify(got[0]));
    } finally {
      tail.close();
      rmSync(file, { force: true });
    }
  });

  await check("closing while a slice is written leaves no sharkd running", async () => {
    const file = await cutAt(37_000);
    const before = sharkdChildren();
    for (const ms of [0, 1, 2, 5, 10, 20, 40]) {
      const tail = new LiveTail({ file, dir: out, sharkd: newSharkd });
      await tail.update();
      tail.rebase(25_000);
      const rows = tail.rows(0, 100, view).catch((err) => err);
      await sleep(ms);
      tail.close();
      await rows;
    }
    for (const end = Date.now() + 5000; sharkdChildren() > before && Date.now() < end; ) await sleep(100);
    assert.equal(sharkdChildren(), before);
  });

  await check("rows asked for a list that changed since read no slice", async () => {
    const file = await cutAt(37_000);
    const before = sharkdChildren();
    const tail = new LiveTail({ file, dir: out, sharkd: newSharkd });
    try {
      await tail.update();
      tail.rebase(30_000);
      await assert.rejects(tail.rows(0, 100, view, () => false), Superseded);
      assert.equal(sharkdChildren(), before);
      assert.equal((await tail.rows(0, 100, view, () => true)).length, 100);
    } finally {
      tail.close();
    }
  });

  await check("rows read ahead come without reading a slice: the newest ones, and a filter pass's matches", async () => {
    const file = await cutAt(37_000);
    const tail = new LiveTail({ file, dir: out, sharkd: newSharkd });
    try {
      await tail.update();
      tail.rebase(30_000);
      await tail.warm(300, view);
      const newest = await tail.rows(tail.listed() - 300, 300, view, () => false);
      assert.deepEqual([newest.length, newest[0].num, newest.at(-1).num], [300, 36_701, 37_000]);
      assert.ok(newest.every((r) => r.p && r.c[0] === String(r.num)));
      tail.setFilter("dns", null);
      while (await tail.filterPass(view, 500));
      const dns = Array.from({ length: tail.listed() }, (_, i) => tail.frameAt(i));
      assert.ok(dns.length > 20, `${dns.length} matches`);
      // The filter's sharkd is busy with another filter meanwhile
      tail.setFilter("tcp", null);
      const busy = tail.filterPass(view, 500);
      const rows = await tail.rowsOf(dns, view, () => false);
      await busy;
      assert.ok(rows.length === dns.length && rows.every((r, i) => r.num === dns[i] && r.c[4] === "DNS"), JSON.stringify(rows[0]));
    } finally {
      tail.close();
    }
  });

  await check("slices go to a new folder when theirs was removed", async () => {
    const file = await cutAt(37_000);
    const tail = new LiveTail({ file, dir: out, sharkd: newSharkd });
    try {
      await tail.update();
      tail.rebase(15_000);
      await tail.rows(0, 10, view);
      const folder = readdirSync(out).find((n) => n.startsWith(".wirebuddy-slices-"));
      rmSync(join(out, folder), { recursive: true, force: true });
      // Another chunk: another slice
      const [row] = await tail.rows(20_000, 1, view);
      assert.deepEqual([row.num, row.c[0]], [35_001, "35001"]);
      assert.ok(readdirSync(out).some((n) => n.startsWith(".wirebuddy-slices-")));
    } finally {
      tail.close();
    }
  });
} finally {
  for (const e of engines) e.close();
  rmSync(out, { recursive: true, force: true });
}
for (const line of report) console.log(`     ${line}`);
console.log(failures ? `${failures} check(s) failed` : "all checks passed");
process.exit(failures ? 1 : 0);
