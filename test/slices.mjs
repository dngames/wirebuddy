// The live view's provisional tail: flows, slices, renumbering and the memory guard, and how
// close provisional rows and filter matches come to Wireshark's reading of the file cut at the
// same packet, with and without TLS keys.
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

/** A TCP packet between 10.0.0.1:1000 and 10.0.0.2:80 (`back`: the other way) with `flags`. */
const tcpFrame = (flags, { back = false, sport = 1000, data = 0 } = {}) => {
  const t = g.tcp(back ? 80 : sport, back ? sport : 80, Buffer.alloc(data, 0x61));
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
    assert.deepEqual([...fed(frames).context(39, 41, budget(1000))], [...heads, 34, 35, 36, 37, 38]);
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
    assert.deepEqual([...flows.context(500, 635, budget(20_000))], [...range(1, 16), ...range(35, 499)]);
    // Over the budget: the last packet each way
    assert.deepEqual([...flows.context(500, 635, budget(300))], [...range(1, 16), 497, 499]);
  });

  await check("flows: data under way at a chunk's end comes along from after the slice until the other side sends", () => {
    const ACK = 0x10;
    const response = (n) => Array.from({ length: n }, (_, i) => (i % 3 === 2 ? tcpFrame(ACK) : tcpFrame(0x18, { back: true, data: 1448 })));
    // 1-3 handshake, 4 request, 5-104 response, 105 the next request, 106 its answer
    const frames = [tcpFrame(0x02), tcpFrame(0x12, { back: true }), tcpFrame(ACK), tcpFrame(0x18, { data: 80 }), ...response(100), tcpFrame(0x18, { data: 80 }), tcpFrame(0x18, { back: true, data: 100 })];
    const flows = fed(frames);
    assert.deepEqual(flows.after(1, 40, 50, budget(1000)), { frames: Int32Array.from(range(51, 104)), open: false });
    assert.deepEqual(flows.after(1, 40, 50, budget(10)), { frames: Int32Array.from(range(51, 60)), open: false });
    assert.deepEqual(flows.after(1, 40, 50, budget(1000, 1000)), { frames: Int32Array.from(range(51, 60)), open: false });
    // The data ended before hi: nothing to complete
    assert.deepEqual(flows.after(1, 40, 105, budget(1000)), { frames: new Int32Array(0), open: false });
    // The file so far ends in the middle of the response: more may come
    const growing = fed(frames.slice(0, 80));
    assert.deepEqual(growing.after(1, 40, 50, budget(1000)), { frames: Int32Array.from(range(51, 80)), open: true });
    // Not TCP: nothing to complete
    const udp = fed(Array.from({ length: 100 }, (_, i) => g.udpFrame(i)));
    assert.deepEqual(udp.after(1, 40, 50, budget(1000)), { frames: new Int32Array(0), open: false });
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

  await check("slices: local and file frame numbers; renumbered rows, Info and trees", () => {
    const s = { lo: 20001, end: 20003, hi: 20005, c0: 18001, extras: Int32Array.of(1, 7, 900), after: Int32Array.of(20100, 20300) };
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
    const tenfold = (n) => n * 10;
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

  await check("filters slices can't check: stream indices, frame numbers, frame-number fields, references", async () => {
    const types = { "http.response_in": 35, "tcp.reassembled_in": 35, "ip.addr": 31, "http.request": 1 };
    const type = async (f) => types[f] ?? null;
    for (const f of ["tcp.stream eq 4", "udp.stream == 1 && dns", "tcp.stream.pnum > 3", "frame.number > 10", "http.response_in", "ip.addr == ${ip.src}", "sctp.assoc_index == 1", "quic.connection.number == 0"]) {
      assert.ok(await heldReason(f, type), f);
    }
    for (const f of ["ip.addr == 10.0.0.1", "http.request", "tcp.analysis.flags", 'http.host contains "tcp.stream"', "http2.streamid == 3"]) {
      assert.equal(await heldReason(f, type), null, f);
    }
    assert.ok(streamNumbered("tcp.stream") && streamNumbered("udp.stream.pnum") && !streamNumbered("http2.streamid") && !streamNumbered("frame.number"));
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
    for (let at = from; at <= to; at += 1000) rows.push(...(await engine.call("frames", { skip: at - 1, limit: Math.min(1000, to - at + 1) })));
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
  const FILTERS = ["http", "http.request", "tls", "tcp.analysis.flags", "tcp.analysis.lost_segment", "tcp.analysis.duplicate_ack", "tcp.analysis.retransmission", "tcp.analysis.reused_ports", "dns", "icmp", "tcp.flags.syn == 1", "http.response.code == 404", "tcp.window_size > 60000", "tcp.len > 1000"];
  const same = (r, x) => r.num === x.num && r.c.join("\t") === x.c.join("\t") && (r.bg ?? "") === (x.bg ?? "") && (r.fg ?? "") === (x.fg ?? "") && r.p;

  await check("provisional rows, filter matches and filtered rows equal sharkd's reading of the file cut there, with and without TLS keys", async () => {
    const truthKeys = newSharkd(keylog);
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
          report.push(`${what}: ${n} rows identical in ${Math.round(ms)} ms; ${matches} filter matches and their rows identical`);
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
