// Unit checks of the panel data's parts (frame sets, the layer finder, raw matches, the page format, sharkd's answer limit),
// export runs, saved objects, the event log, the cleanup of slice folders, Decode As entries, investigations kept per capture
// and the marks, time references and comment edits laid over a capture.
// Usage: node test/units.mjs   (bundles the sources itself)
import { build } from "esbuild";
import { chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, renameSync, rmSync, statSync, symlinkSync, utimesSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import net from "node:net";
import { createRequire, syncBuiltinESMExports } from "node:module";
import { tmpdir, userInfo } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import { suite } from "./harness.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const out = mkdtempSync(join(tmpdir(), "wirebuddy-units-"));
const entry = join(out, "entry.ts");
writeFileSync(
  entry,
  [...["paneldata", "layers", "wbpk", "sharkd", "export", "objects", "events", "extensions", "trust", "livetail", "timerefs", "decodeas", "panelcheck", "watch", "loopback", "capture", "investigation", "markdown", "findings", "patch", "memory", "viewstore", "edits", "stale", "packetlist"].map((m) => `server/${m}`), "shared/isolation"].map((m) => `export * from ${JSON.stringify(join(root, `src/${m}.ts`))};`).join("\n"),
);
await build({ entryPoints: [entry], outfile: join(out, "units.mjs"), bundle: true, platform: "node", format: "esm", packages: "external", logLevel: "silent" });
const { FrameSet, findLayer, parse, Parsed, rawMatch, ApiError, encodePage, Sharkd, SharkdTooLarge, matchingFrames, splitRuns, commentPasses, exportFrames, objectFileName, objectDir, newObjectFolder, writeObject, EventLog, Extensions, slicesPrefix, removeStaleSlices } =
  await import(join(out, "units.mjs"));
const { refBefore, refsOf, refsUpTo, refsParam, framesWithRefs, refTimeFilter, refTimeFits, refTimeError, usesRefTime, changeText, SharkdError } = await import(join(out, "units.mjs"));
const { parseChange, applyChange, serialize, parseStatus, closeMatches, countFilter } = await import(join(out, "units.mjs"));
const { checkPanel } = await import(join(out, "units.mjs"));
const { changedFields, patchMessage } = await import(join(out, "units.mjs"));
const { macAcl, macMountProblem, rootTrust } = await import(join(out, "units.mjs"));
const { apart, verdict, MARGIN_MS } = await import(join(out, "units.mjs"));
const { instanceFile, writeInstance, listenLoopback } = await import(join(out, "units.mjs"));
const { machineTag, interfaceSignature, availableMemory, ViewStore, PacketList, clipRanges, startsWith, listChanged, rowOf } = await import(join(out, "units.mjs"));
const { investigationKey, investigationDir, investigationContent, readInvestigation, writeInvestigation, removeInvestigation, pruneInvestigations, serializeInvestigation, nothingToKeep, InvalidInvestigation, MAX_INVESTIGATION_BYTES, setAsideInvestigation, keptSummary } = await import(join(out, "units.mjs"));

const { Edits, marksWith, marksWithout, toggledMarks, displayedMarks, refsWith, toggledRefs, refsChange, commentText, commentAt, MAX_MARKS, MAX_NOTE, MAX_TIME_REFS, StaleGenerationError } = await import(join(out, "units.mjs"));
const { codeSpan, cell, quote, escapeLine, checkSummary, MAX_SUMMARY_BYTES, buildFindings, checkReportTarget, writeReport, MAX_LISTED, MAX_REPORT_BYTES, TargetExists } = await import(join(out, "units.mjs"));

const { check, finish } = suite();

const frames = (set, after = 0, limit = 1e6) => set.page(after, limit).frames;

/** Packet comments of a capture, frame by frame, as sharkd reads them. */
function packetComments(file) {
  const input = [
    { id: 1, method: "load", params: { file } },
    { id: 2, method: "frames", params: { column0: "frame.number:0" } },
  ].map((m) => JSON.stringify({ jsonrpc: "2.0", ...m }) + "\n").join("");
  const env = { ...process.env, HOME: out, XDG_CONFIG_HOME: join(out, ".config"), XDG_DATA_HOME: join(out, ".local/share") };
  const lines = execFileSync("sharkd", ["-"], { input, env, stdio: ["pipe", "pipe", "ignore"], maxBuffer: 64 * 1024 * 1024 }).toString().trim().split("\n");
  return JSON.parse(lines[lines.length - 1]).result.map((r) => r.comments ?? []);
}

try {
  await check("panel isolation: a page task inside the busy window proves it, empty rounds count only when answered", () => {
    const m = MARGIN_MS;
    assert.equal(apart([100, 130, 150], 120, 180), true);
    assert.equal(apart([100, 110, 190, 200], 120, 180), false, "ticks only before and after");
    assert.equal(apart([120 + m - 1, 180 - m + 1], 120, 180), false, "inside the margins");
    for (let t = 118; t < 135; t++) assert.equal(apart([t], 120, 120 + 2 * m - 1), false, "a window shorter than two margins");
    assert.equal(apart([], 0, 1000), false);
    assert.equal(verdict([]), "again");
    assert.equal(verdict(["empty", "empty"]), "again");
    assert.equal(verdict(["empty", "empty", "empty"]), "not-isolated");
    assert.equal(verdict(["empty", "empty", "apart"]), "isolated");
    assert.equal(verdict(["apart"]), "isolated");
    assert.equal(verdict(["unanswered", "unanswered", "unanswered", "unanswered"]), "again");
    assert.equal(verdict(["empty", "unanswered", "empty", "unanswered", "unanswered"]), "again");
    assert.equal(verdict(["empty", "unanswered", "empty", "empty"]), "not-isolated");
  });
  await check("frame sets: building, clipping, intersecting, ranking, paging", () => {
    const a = FrameSet.fromSorted([1, 2, 2, 3, 7, 9, 10]);
    assert.equal(a.count, 6);
    assert.deepEqual(frames(a), [1, 2, 3, 7, 9, 10]);
    const r = FrameSet.fromRanges([[5, 8], [1, 2], [3, 3], [7, 12], [20, 19]]);
    assert.deepEqual([r.count, frames(r)], [11, [1, 2, 3, 5, 6, 7, 8, 9, 10, 11, 12]]);
    assert.deepEqual(frames(r.clip(5)), [1, 2, 3, 5]);
    assert.deepEqual(frames(a.intersect(FrameSet.fromRanges([[2, 8]]))), [2, 3, 7]);
    assert.deepEqual([a.rank(0), a.rank(2), a.rank(6), a.rank(9), a.rank(100)], [0, 2, 3, 5, 6]);
    assert.deepEqual(a.page(3, 2), { frames: [7, 9], more: true });
    assert.deepEqual(a.page(9, 5), { frames: [10], more: false });
    assert.deepEqual(a.page(10, 5), { frames: [], more: false });
    assert.deepEqual(frames(FrameSet.all(0)), []);
    assert.deepEqual(frames(FrameSet.fromRows([[0, 1], [3, 3]], Int32Array.of(4, 5, 9, 12))), [4, 5, 12]);
    assert.deepEqual(frames(FrameSet.fromRows([[0, 2]], null)), [1, 2, 3]);
    assert.equal(FrameSet.fromRanges([[1, 2_000_000_000]]).count, 2_000_000_000);
    // Paging asks for the same clip and intersection again and again: no copies
    assert.equal(a.clip(10), a);
    assert.equal(a.clip(1000), a);
    assert.deepEqual([a.clip(8).count, frames(a.clip(8))], [4, [1, 2, 3, 7]]);
    assert.deepEqual(frames(a.clip(0)), []);
    const b = FrameSet.fromRanges([[2, 9]]);
    assert.equal(a.intersect(b), a.intersect(b));
    assert.deepEqual(frames(a.intersect(b)), [2, 3, 7, 9]);
  });

  // Ethernet / IPv4 / UDP 1000 -> 2000 with "hello"
  const ip4 = (proto = 17, flags = 0, total = 33) => Buffer.from([0x45, 0, total >> 8, total & 255, 0, 1, flags >> 8, flags & 255, 64, proto, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2]);
  const udp = Buffer.concat([Buffer.from([3, 232, 7, 208, 0, 13, 0, 0]), Buffer.from("hello")]);
  const tcp = Buffer.concat([Buffer.from([3, 232, 7, 208, 0, 0, 0, 1, 0, 0, 0, 1, 0x50, 0x18, 255, 255, 0, 0, 0, 0]), Buffer.from("hello")]);
  const eth = (type, body) => Buffer.concat([Buffer.alloc(12), Buffer.from([type >> 8, type & 255]), body]);
  const ip6 = (next, body) => Buffer.concat([Buffer.from([0x60, 0, 0, 0, body.length >> 8, body.length & 255, next, 64]), Buffer.alloc(32), body]);
  const text = (b, at) => (at ? b.subarray(at[0], at[1]).toString() : null);

  await check("layers: payload and IP behind each link type", () => {
    const v4 = Buffer.concat([ip4(), udp]);
    assert.equal(text(eth(0x0800, v4), findLayer(eth(0x0800, v4), "Ethernet", "payload")), "hello");
    assert.deepEqual(findLayer(eth(0x0800, v4), "Ethernet", "ip"), [14, 47]);
    const vlan = Buffer.concat([Buffer.alloc(12), Buffer.from([0x81, 0, 0, 5, 0x88, 0xa8, 0, 6, 8, 0]), v4]);
    assert.equal(text(vlan, findLayer(vlan, "Ethernet", "payload")), "hello");
    const sll = Buffer.concat([Buffer.alloc(14), Buffer.from([8, 0]), v4]);
    assert.equal(text(sll, findLayer(sll, "Linux cooked-mode capture v1", "payload")), "hello");
    const sll2 = Buffer.concat([Buffer.from([8, 0]), Buffer.alloc(18), v4]);
    assert.equal(text(sll2, findLayer(sll2, "Linux cooked-mode capture v2", "payload")), "hello");
    const nul = Buffer.concat([Buffer.from([2, 0, 0, 0]), v4]);
    assert.equal(text(nul, findLayer(nul, "NULL/Loopback", "payload")), "hello");
    assert.equal(text(v4, findLayer(v4, "Raw IP", "payload")), "hello");
    const t = Buffer.concat([ip4(6, 0, 45), tcp]);
    assert.equal(text(t, findLayer(t, "Raw IPv4", "payload")), "hello");
    assert.equal(findLayer(eth(0x0806, v4), "Ethernet", "payload"), null);
    assert.equal(findLayer(v4, "IEEE 802.11", "payload"), null);
  });

  await check("layers: IPv6 extension headers, fragments, offload, truncation", () => {
    const six = ip6(17, udp);
    assert.equal(text(six, findLayer(six, "Raw IPv6", "payload")), "hello");
    // Hop-by-hop, then destination options, then UDP
    const ext = ip6(0, Buffer.concat([Buffer.from([60, 0, 0, 0, 0, 0, 0, 0]), Buffer.from([17, 0, 0, 0, 0, 0, 0, 0]), udp]));
    assert.equal(text(ext, findLayer(ext, "Raw IPv6", "payload")), "hello");
    const frag6 = ip6(44, Buffer.concat([Buffer.from([17, 0, 0, 1, 0, 0, 0, 1]), udp]));
    assert.equal(findLayer(frag6, "Raw IPv6", "payload"), null);
    assert.ok(findLayer(frag6, "Raw IPv6", "ip"));
    const frag4 = Buffer.concat([ip4(17, 0x2000), udp]);
    assert.equal(findLayer(frag4, "Raw IP", "payload"), null);
    // Total length 0 with segmentation offload: what was captured
    const tso = Buffer.concat([ip4(6, 0, 0), tcp]);
    assert.equal(text(tso, findLayer(tso, "Raw IP", "payload")), "hello");
    assert.equal(findLayer(Buffer.concat([ip4(), udp]).subarray(0, 24), "Raw IP", "payload"), null);
    // Lengths beyond the frame stop at its end
    const long = Buffer.concat([ip4(17, 0, 999), Buffer.from([3, 232, 7, 208, 3, 0, 0, 0]), Buffer.from("hi")]);
    assert.equal(text(long, findLayer(long, "Raw IP", "payload")), "hi");
    for (let i = 0; i < 2000; i++) {
      const junk = Buffer.from(Array.from({ length: (i % 90) + 1 }, (_, k) => (i * 31 + k * 7) & 255));
      for (const encap of ["Ethernet", "Raw IP", "Linux cooked-mode capture v2", "NULL/Loopback"]) {
        const at = findLayer(junk, encap, "payload");
        if (at) assert.ok(at[0] >= 0 && at[0] <= at[1] && at[1] <= junk.length, `${encap} ${i}`);
      }
    }
  });

  await check("raw matches: protocols, ports, networks, VLANs; one key for the same match", () => {
    const v4 = (src, dst, body = udp) => Buffer.from([0x45, 0, 0, 20 + body.length, 0, 1, 0, 0, 64, 17, 0, 0, ...src, ...dst, ...body]);
    const tagged = Buffer.concat([Buffer.alloc(12), Buffer.from([0x88, 0xa8, 0, 100, 0x81, 0, 0x20, 200, 8, 0]), v4([10, 1, 2, 3], [172, 31, 255, 1])]);
    const p = parse(tagged, "eth", new Parsed());
    const hit = (q) => rawMatch(q).test(tagged, p);
    assert.ok(hit({ proto: "UDP", port: 2000, srcport: [1, 1000], dstport: 2000, ethertype: 0x0800 }));
    assert.ok(!hit({ proto: "tcp" }) && !hit({ port: 1 }) && !hit({ ethertype: 0x86dd }));
    assert.ok(hit({ src: "10.0.0.0/8" }) && hit({ src: "10.1.0.0/16" }) && !hit({ src: "10.2.0.0/16" }) && hit({ addr: "172.31.255.1" }) && !hit({ dst: "10.1.2.3" }));
    // Prefixes not on a byte boundary
    assert.ok(hit({ dst: "172.16.0.0/12" }) && !hit({ dst: "172.32.0.0/12" }) && hit({ dst: "0.0.0.0/0" }));
    assert.ok(hit({ vlan: 200 }) && hit({ vlan: [1, 100] }) && !hit({ vlan: 5 }));
    // Addresses of the other IP version never match
    assert.ok(!hit({ addr: "::ffff:10.1.2.3" }) && !hit({ addr: "::/0" }));
    const six = Buffer.concat([Buffer.from([0x60, 0, 0, 0, 0, udp.length, 17, 64, 0xfe, 0x80, ...Array(13).fill(0), 1, 0x20, 1, 0x0d, 0xb8, ...Array(11).fill(0), 9]), udp]);
    const p6 = parse(six, "raw", new Parsed());
    const hit6 = (q) => rawMatch(q).test(six, p6);
    assert.ok(hit6({ src: "fe80::/10" }) && hit6({ src: "fe80::1" }) && hit6({ addr: "2001:db8::9" }) && hit6({ dst: "2001:db8::/32" }) && !hit6({ dst: "2001:db9::/32" }));
    assert.ok(!hit6({ addr: "10.0.0.0/8" }) && hit6({ proto: 17, ethertype: 0x86dd }));
    assert.equal(rawMatch({ port: [2, 1, 2] }).key, rawMatch({ port: [1, 2] }).key);
    assert.equal(rawMatch({ proto: "udp" }).key, rawMatch({ proto: 17 }).key);
    assert.equal(rawMatch({ addr: "::ffff:10.0.0.1" }).key, rawMatch({ addr: "0:0:0:0:0:ffff:a00:1/128" }).key);
    assert.notEqual(rawMatch({ src: "10.0.0.1" }).key, rawMatch({ dst: "10.0.0.1" }).key);
    for (const bad of [null, [], { port: -1 }, { vlan: 4096 }, { proto: "nope" }, { src: "10.0.0.0/8/8" }, { dst: "fe80::1%eth0" }, { addr: 167772161 }, { port: Array(65).fill(1) }]) {
      assert.throws(() => rawMatch(bad), (e) => e instanceof ApiError && e.status === 400 && e.code === "bad-args", JSON.stringify(bad));
    }
  });

  await check("pages: the binary layout", () => {
    const page = encodePage({ epoch: 3, next: 9 }, [
      { frame: 7, time: 1.5, len: 60, data: Buffer.from("abc") },
      { frame: 9, time: NaN, len: 61, data: Buffer.alloc(0), dir: 1 },
    ], true);
    assert.equal(page.readUInt32LE(0), 0x4b504257);
    const h = page.readUInt32LE(4);
    assert.equal(h % 8, 0);
    const head = JSON.parse(page.subarray(8, 8 + h).toString());
    assert.deepEqual(head, { v: 1, epoch: 3, next: 9, n: 2, dirs: true });
    let at = 8 + h;
    assert.deepEqual([page.readDoubleLE(at), page.readDoubleLE(at + 8)], [1.5, NaN]);
    at += 16;
    assert.deepEqual([page.readUInt32LE(at), page.readUInt32LE(at + 4), page.readUInt32LE(at + 8), page.readUInt32LE(at + 12)], [7, 9, 60, 61]);
    at += 16;
    assert.deepEqual([page.readUInt32LE(at), page.readUInt32LE(at + 4), page.readUInt32LE(at + 8)], [0, 3, 3]);
    at += 12;
    assert.deepEqual([...page.subarray(at, at + 2)], [0, 1]);
    assert.equal(page.subarray(at + 2).toString(), "abc");
  });

  await check("sharkd: an answer over the limit is refused, and sharkd answers again after", async () => {
    // A stand-in sharkd: answers "big" with a long result, everything else with OK
    const fake = join(out, "fake-sharkd");
    writeFileSync(
      fake,
      `#!${process.execPath}\nlet buf = "";\nprocess.stdin.on("data", (d) => {\n  buf += d;\n  for (let nl; (nl = buf.indexOf("\\n")) >= 0; ) {\n    const req = JSON.parse(buf.slice(0, nl));\n    buf = buf.slice(nl + 1);\n    const p = req.params ?? {};\n    const rows = (s, n) => Array.from({ length: Math.max(0, Math.min(n, 7 - s)) }, (_, i) => ({ c: [String(s + i + 1)], num: s + i + 1 }));\n    const result = req.method === "big" ? "x".repeat(200000) : req.method === "frames" ? rows(p.skip ?? 0, p.limit ?? 1e9) : { status: "OK" };\n    process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: req.id, result }) + "\\n");\n  }\n});\n`,
    );
    chmodSync(fake, 0o755);
    const s = new Sharkd(fake);
    s.maxAnswer = 50_000;
    try {
      assert.deepEqual(await s.call("status"), { status: "OK" });
      await assert.rejects(s.call("big"), (e) => e instanceof SharkdTooLarge && /longer than/.test(e.message));
      assert.deepEqual(await s.call("status"), { status: "OK" });
      // Frame lists come in pages, also when the last page is full
      assert.deepEqual([...(await matchingFrames(s, "x", 3))], [1, 2, 3, 4, 5, 6, 7]);
      assert.deepEqual([...(await matchingFrames(s, "x", 7))], [1, 2, 3, 4, 5, 6, 7]);
      assert.deepEqual([...(await matchingFrames(s, "x"))], [1, 2, 3, 4, 5, 6, 7]);
    } finally {
      s.close();
    }
  });
  await check("time references: the nearest per row, refs within sharkd's request limit, frame.ref_time spelled out", () => {
    const refs = [5, 9, 20];
    assert.deepEqual([refBefore(refs, 4), refBefore(refs, 5), refBefore(refs, 19), refBefore(refs, 99), refBefore([], 7)], [0, 5, 9, 20, 0]);
    assert.deepEqual(refsOf(refs, [1, 2, 3]), []);
    assert.deepEqual(refsOf(refs, [6, 7, 8]), [5]);
    assert.deepEqual(refsOf(refs, [4, 9, 10, 25]), [9, 20]);
    assert.deepEqual(refsOf(refs, Int32Array.from([12, 30])), [9, 20]);
    assert.equal(refsUpTo(refs, 20), refs);
    assert.deepEqual(refsUpTo(refs, 19), [5, 9]);
    assert.equal(refsParam([]), undefined);
    assert.equal(refsParam([5, 9]), "5,9");
    // Only ascending frame numbers: anything else gets no answer from sharkd
    assert.equal(refsParam([0, 5, 5, 3, 9.5, 12]), "5,12");
    assert.equal(refsParam([0, -1]), undefined);
    // frame.ref_time as a field; not in strings, nor as part of another name
    assert.equal(refTimeFilter("frame.ref_time", refs), "(frame.number in {5, 9, 20})");
    assert.equal(refTimeFilter('!frame.ref_time && frame.comment == "frame.ref_time"', [3, 4]), '!(frame.number in {3..4}) && frame.comment == "frame.ref_time"');
    assert.equal(refTimeFilter("frame.ref_time || tcp", []), "(frame.number == 0) || tcp");
    assert.equal(refTimeFilter("frame.ref_timex || xframe.ref_time", refs), "frame.ref_timex || xframe.ref_time");
    assert.equal(usesRefTime('ip && "frame.ref_time"'), false);
    assert.equal(usesRefTime("(frame.ref_time)"), true);
    assert.throws(() => refTimeFilter("frame.ref_time", Array.from({ length: 2000 }, (_, i) => 2 * i + 1)), /too long for sharkd; unset some of them/);
    assert.deepEqual([refTimeFits(refs), refTimeFits([]), refTimeFits(Array.from({ length: 2000 }, (_, i) => 2 * i + 1))], [true, true, false]);
    assert.equal(changeText({ set: [5], unset: [] }), "set the time reference on frame 5");
    assert.equal(changeText({ set: [5, 6], unset: [9] }), "set time references on 2 frames and unset the time reference on frame 9");
    assert.equal(changeText({ set: [], unset: [] }), "");
  });

  await check("time references: rows whose references don't fit in one request come in parts, each with its own", async () => {
    // Every row of 1,000,001.. a reference, after a long filter
    const frames = Int32Array.from({ length: 500 }, (_, i) => 1_000_001 + i);
    const refs = (from, to) => refsOf(Array.from(frames), frames.subarray(from, to));
    const asked = [];
    const read = async (p) => {
      asked.push(p);
      const size = Buffer.byteLength(JSON.stringify({ jsonrpc: "2.0", id: Number.MAX_SAFE_INTEGER, method: "frames", params: { ...p, column0: "x" } }));
      assert.ok(size < 8190, `${size} bytes`);
      const skip = p.skip ?? 0;
      const given = new Set(p.refs.split(",").map(Number));
      return Array.from(frames.subarray(skip, skip + p.limit), (f) => ({ num: f, ref: given.has(f) }));
    };
    const rows = await framesWithRefs({ filter: "x".repeat(6000), limit: 500 }, refs, read, { column0: "x" });
    assert.deepEqual(rows.map((r) => r.num), Array.from(frames));
    assert.ok(rows.every((r) => r.ref));
    assert.ok(asked.length > 1);
    assert.equal(asked.reduce((n, p) => n + p.limit, 0), 500);
    // Room for them all: one request; none: no refs param
    assert.equal((await framesWithRefs({ limit: 10 }, refs, async (p) => [p])).length, 1);
    assert.deepEqual(await framesWithRefs({ limit: 10, skip: 3 }, () => [], async (p) => [p]), [{ limit: 10, skip: 3 }]);
  });

  await check("time references: frame.ref_time inside a function, with # or @ is refused with a reason", async () => {
    const check = async (f) => {
      if (/\(\(|\)#|@\(/.test(f)) throw new SharkdError("Filter invalid - unexpected", -5001);
    };
    assert.equal(await refTimeError("frame.ref_time || tcp", check), null);
    assert.equal(await refTimeError("count(frame.number) == 1", check), null);
    for (const f of ["count(frame.ref_time) == 1", "frame.ref_time#1", "@frame.ref_time"]) assert.match(await refTimeError(f, check), /only works as a test of its own/, f);
  });

  await check("export runs: at most 500 ranges and 512 KiB of comment arguments each", () => {
    assert.deepEqual(splitRuns([[1, 10]], []), [[[1, 10]]]);
    const many = Array.from({ length: 1200 }, (_, i) => [i * 2 + 1, i * 2 + 1]);
    assert.deepEqual(splitRuns(many, []).map((r) => r.length), [500, 500, 200]);
    // 1200 comments of 1 KiB in one range: 512 a run, cut before the 513th and the 1025th
    const commented = Array.from({ length: 1200 }, (_, i) => [i * 3 + 5, 1024]);
    const runs = splitRuns([[1, 10000]], commented);
    assert.deepEqual(runs, [[[1, 1540]], [[1541, 3076]], [[3077, 10000]]]);
    // Short notes, as marks have, stay one run
    assert.equal(splitRuns([[1, 20000]], Array.from({ length: 10000 }, (_, i) => [i * 2 + 1, 40])).length, 1);
    // A comment bigger than the budget still goes, alone
    assert.deepEqual(splitRuns([[1, 5]], [[2, 600_000], [3, 600_000]]), [[[1, 2]], [[3, 5]]]);
    // Every frame is in exactly one run
    const mixed = splitRuns([[1, 3], [7, 7], [9, 2000]], [[2, 9000], [7, 9000], ...Array.from({ length: 600 }, (_, i) => [100 + i, 9000])]);
    const frames = mixed.flat().flatMap(([a, b]) => Array.from({ length: b - a + 1 }, (_, i) => a + i));
    assert.equal(frames.length, 3 + 1 + 1992);
    assert.equal(new Set(frames).size, frames.length);
    assert.ok(mixed.length > 1);
  });

  await check("export: comments over several editcap runs joined by mergecap all arrive, without mergecap's capture comment", async () => {
    const fixture = join(root, "test/fixtures/http.pcapng");
    const big = join(out, "big.pcapng");
    execFileSync("mergecap", ["-a", "-F", "pcapng", "-w", big, ...Array(42).fill(fixture)]);
    // 1200 comments of about 600 bytes: two runs
    const comments = new Map(Array.from({ length: 1200 }, (_, i) => [i + 1, { own: true, texts: [`note ${i + 1} ${"x".repeat(600)}`] }]));
    const output = join(out, "commented.pcapng");
    await exportFrames({ editcap: "editcap", mergecap: "mergecap", input: big, output, format: "pcapng", ranges: [[1, 1218]], comments });
    const rows = packetComments(output);
    assert.equal(rows.length, 1218);
    for (const [i, r] of rows.entries()) assert.deepEqual(r, i < 1200 ? comments.get(i + 1).texts : []);
    assert.doesNotMatch(execFileSync("capinfos", ["-k", output], { encoding: "utf8" }), /merging/);
    assert.deepEqual(readdirSync(out).filter((f) => f.startsWith(".wirebuddy-export-")), []);
  });

  await check("export: several comments a frame, in place of its own ones or after them, also over several runs", async () => {
    // Frame 2 has two comments of its own, frame 4 one
    const once = join(out, "own1.pcapng");
    const own = join(out, "own.pcapng");
    execFileSync("editcap", ["-a", "2:own a", join(root, "test/fixtures/http.pcapng"), once]);
    execFileSync("editcap", ["--preserve-packet-comments", "-a", "2:own b", "-a", "4:own c", once, own]);
    const comments = new Map([
      [2, { own: false, texts: ["x", "", "y", "z"] }],
      [3, { own: true, texts: ["mark 3"] }],
      [4, { own: true, texts: ["mark 4", "more 4"] }],
      [6, { own: false, texts: [] }],
      [9, { own: false, texts: ["", "nine"] }],
    ]);
    // Empty comments are left out: editcap can't write them
    const want = { 2: ["x", "y", "z"], 3: ["mark 3"], 4: ["own c", "mark 4", "more 4"], 9: ["nine"] };
    // Later passes find a frame by its place in what the first one wrote
    for (const ranges of [[[1, 29]], [[2, 4], [9, 20]]]) {
      const output = join(out, "passes.pcapng");
      await exportFrames({ editcap: "editcap", mergecap: "mergecap", input: own, output, format: "pcapng", ranges, comments });
      const frames = ranges.flatMap(([a, b]) => Array.from({ length: b - a + 1 }, (_, i) => a + i));
      assert.deepEqual(packetComments(output), frames.map((f) => want[f] ?? []));
    }
    // Two runs, each with the passes its frames need
    const frames = [...Array.from({ length: 600 }, (_, i) => i * 2 + 1), 2, 1100].sort((a, b) => a - b);
    const spread = new Map([
      [2, { own: false, texts: ["a", "b"] }],
      [1100, { own: true, texts: ["c", "d", "e"] }],
    ]);
    const output = join(out, "spread.pcapng");
    await exportFrames({ editcap: "editcap", mergecap: "mergecap", input: join(out, "big.pcapng"), output, format: "pcapng", ranges: frames.map((f) => [f, f]), comments: spread });
    const got = packetComments(output);
    assert.equal(got.length, 602);
    assert.deepEqual([got[frames.indexOf(2)], got[frames.indexOf(1100)], got.flat().length], [["a", "b"], ["c", "d", "e"], 5]);
    assert.deepEqual(readdirSync(out).filter((f) => /\.next$|^\.wirebuddy-export-/.test(f)), []);
  });

  await check("export: one pass for comments added to frames that keep their own ones and to frames without; frames up to cleared lose theirs", async () => {
    // Frames without comments of their own take a comment in a pass that keeps or replaces them
    const added = new Map([
      [2, { own: true, texts: ["after own"] }],
      [5, { texts: ["new"] }],
    ]);
    assert.deepEqual(commentPasses([[1, 29]], added), { first: ["--preserve-packet-comments", "-a", "2:after own", "-a", "5:new"], later: [] });
    added.set(4, { own: false, texts: ["instead"] });
    assert.deepEqual(commentPasses([[1, 29]], added), { first: ["-a", "4:instead", "-a", "5:new"], later: [["-a", "2:after own"]] });
    assert.deepEqual(commentPasses([[1, 29]], added, true), { first: ["--discard-packet-comments", "-a", "2:after own", "-a", "4:instead", "-a", "5:new"], later: [] });
    // Frames 2 and 4 have comments of their own; up to 3 they go, the rest keep theirs
    const own = join(out, "own.pcapng");
    const output = join(out, "cleared.pcapng");
    await exportFrames({ editcap: "editcap", mergecap: "mergecap", input: own, output, format: "pcapng", ranges: [[1, 29]], comments: new Map([[3, { texts: ["three"] }]]), cleared: 3 });
    const want = Array.from({ length: 29 }, () => []);
    Object.assign(want, { 2: ["three"], 3: ["own c"] });
    assert.deepEqual(packetComments(output), want);
  });

  await check("export: written in a folder only the user can open next to the target, also over several passes and runs; the result is the user's alone", async () => {
    const fixture = join(root, "test/fixtures/http.pcapng");
    const big = join(out, "big.pcapng");
    if (!existsSync(big)) execFileSync("mergecap", ["-a", "-F", "pcapng", "-w", big, ...Array(42).fill(fixture)]);
    const dir = mkdtempSync(join(out, "target-"));
    const seen = join(out, "seen.txt");
    // Each editcap and mergecap run notes what stands in the target folder, and how open it is
    // Octal mode and name: GNU stat and BSD stat (macOS) spell it differently
    const stat = process.platform === "darwin" ? "stat -f '%Lp %N'" : "stat -c '%a %n'";
    const noting = (name) => {
      const tool = join(out, `noting-${name}`);
      writeFileSync(tool, `#!/bin/sh\n${stat} "${dir}"/* "${dir}"/.[!.]* >> "${seen}" 2>/dev/null\nexec ${name} "$@"\n`, { mode: 0o755 });
      return tool;
    };
    const tools = { editcap: noting("editcap"), mergecap: noting("mergecap") };
    // One run with a second pass for frame 2's second comment, then two runs joined
    await exportFrames({ ...tools, input: fixture, output: join(dir, "out.pcapng"), format: "pcapng", ranges: [[1, 29]], comments: new Map([[2, { texts: ["a", "b"] }]]) });
    assert.deepEqual(packetComments(join(dir, "out.pcapng"))[1], ["a", "b"]);
    await exportFrames({ ...tools, input: big, output: join(dir, "runs.pcap"), format: "pcap", ranges: Array.from({ length: 600 }, (_, i) => [i * 2 + 1, i * 2 + 1]) });
    const lines = readFileSync(seen, "utf8").trim().split("\n");
    assert.ok(lines.length >= 6, `${lines.length} lines noted, at least 6 wanted: ${JSON.stringify(lines)}`);
    for (const line of lines) assert.match(line, /^(700 .*\/\.wirebuddy-export-\w+|600 .*\/out\.pcapng)$/, `noted: ${JSON.stringify(lines)}`);
    assert.deepEqual(readdirSync(dir).sort(), ["out.pcapng", "runs.pcap"]);
    assert.deepEqual(["out.pcapng", "runs.pcap"].map((f) => statSync(join(dir, f)).mode & 0o777), [0o600, 0o600]);
  });

  await check("saved objects: safe names, a new private folder, never over a file", () => {
    assert.equal(objectFileName(12, "big.txt"), "f12-big.txt");
    assert.equal(objectFileName(3, "../../.bashrc"), "f3-.bashrc");
    assert.equal(objectFileName(8, "报告.pdf"), "f8-_.pdf");
    assert.equal(objectFileName(4, "\\\\srv\\share\\report final.docx"), "f4-report_final.docx");
    assert.equal(objectFileName(5, "index.php?id=1&x=<y>"), "f5-index.php_id_1_x_y_");
    assert.equal(objectFileName(6, ""), "f6-object");
    assert.equal(objectFileName(7, "x".repeat(300)).length, 103);
    // In /tmp itself, whatever TMPDIR says: the rules depend on the folders above
    const base = realpathSync(mkdtempSync("/tmp/wirebuddy-objects-"));
    try {
      assert.throws(() => objectDir("relative/dir", []), /absolute/);
      assert.throws(() => objectDir(join(base, "missing"), []), /no such directory/);
      mkdirSync(join(base, ".config"));
      assert.throws(() => objectDir(join(base, ".config"), []), /hidden/);
      // A link to a hidden folder is one too
      symlinkSync(join(base, ".config"), join(base, "link"));
      assert.throws(() => objectDir(join(base, "link"), []), /hidden/);
      // Where Wireshark loads plugins from, also below
      mkdirSync(join(base, "plugins/lua"), { recursive: true });
      assert.throws(() => objectDir(join(base, "plugins/lua"), [join(base, "plugins")]), /loads code from/);
      assert.throws(() => newObjectFolder(base, "http", [base]), /loads code from/);
      assert.equal(objectDir(base, [join(base, "plugins")]), base);
      // On macOS a name that differs only in case is usually the same folder
      const upper = join(base, "PLUGINS");
      const made = !existsSync(upper);
      if (made) mkdirSync(upper);
      const platform = Object.getOwnPropertyDescriptor(process, "platform");
      Object.defineProperty(process, "platform", { ...platform, value: "darwin" });
      try {
        assert.throws(() => objectDir(upper, [join(base, "plugins")]), /loads code from/);
      } finally {
        Object.defineProperty(process, "platform", platform);
        if (made) rmSync(upper, { recursive: true });
      }
      // A writable folder is refused even inside a private one: it may be a bind mount of a shared one
      mkdirSync(join(base, "open"));
      chmodSync(join(base, "open"), 0o777);
      assert.throws(() => newObjectFolder(join(base, "open"), "http", []), /others can write/);
      assert.deepEqual(readdirSync(join(base, "open")), []);
      // The new folder swapped for a link as it is made: refused, and the link's target untouched
      const target = join(base, "target");
      mkdirSync(target);
      const fs = createRequire(import.meta.url)("node:fs");
      const mkdir = fs.mkdirSync;
      fs.mkdirSync = (path, opts) => {
        mkdir(path, opts);
        renameSync(path, `${path}.moved`);
        symlinkSync(target, path);
      };
      syncBuiltinESMExports();
      try {
        assert.throws(() => newObjectFolder(base, "http", []), /was replaced while it was made/);
      } finally {
        fs.mkdirSync = mkdir;
        syncBuiltinESMExports();
      }
      assert.ok(existsSync(target));
      assert.deepEqual(readdirSync(target), []);
      rmSync(join(base, "http-objects"));
      rmSync(join(base, "http-objects.moved"), { recursive: true });
      const first = newObjectFolder(base, "http", []);
      assert.equal(first, join(base, "http-objects"));
      assert.equal(newObjectFolder(base, "http", []), join(base, "http-objects-2"));
      assert.equal(statSync(first).mode & 0o777, 0o700);
      assert.equal(writeObject(first, "f1-a.txt", Buffer.from("one")), "f1-a.txt");
      assert.equal(writeObject(first, "f1-a.txt", Buffer.from("two")), "f1-a-2.txt");
      symlinkSync(join(base, "elsewhere"), join(first, "f2-b"));
      assert.equal(writeObject(first, "f2-b", Buffer.from("three")), "f2-b-2");
      assert.equal(readFileSync(join(first, "f1-a.txt"), "utf8"), "one");
      assert.equal(statSync(join(first, "f1-a-2.txt")).mode & 0o777, 0o600);
      assert.deepEqual(readdirSync(base).sort(), [".config", "http-objects", "http-objects-2", "link", "open", "plugins", "target"]);
      // Wireshark's personal configuration folder loads Lua too, also where it isn't hidden
      const saved = { config: process.env.WIRESHARK_CONFIG_DIR, xdg: process.env.XDG_CONFIG_HOME };
      try {
        process.env.WIRESHARK_CONFIG_DIR = join(base, "cfg");
        process.env.XDG_CONFIG_HOME = join(base, "xdg");
        mkdirSync(join(base, "cfg/plugins"), { recursive: true });
        mkdirSync(join(base, "xdg/wireshark/plugins"), { recursive: true });
        const code = new Extensions().codeFolders();
        assert.throws(() => objectDir(join(base, "cfg/plugins"), code), /loads code from/);
        assert.throws(() => objectDir(join(base, "xdg/wireshark/plugins"), code), /loads code from/);
        // WireBuddy's own code, the pages it serves among it
        mkdirSync(join(base, "dist/web"), { recursive: true });
        assert.throws(() => objectDir(join(base, "dist/web"), new Extensions("", join(base, "dist")).codeFolders()), /loads code from/);
      } finally {
        for (const [k, v] of [["WIRESHARK_CONFIG_DIR", saved.config], ["XDG_CONFIG_HOME", saved.xdg]]) {
          if (v === undefined) delete process.env[k];
          else process.env[k] = v;
        }
      }
    } finally {
      rmSync(base, { recursive: true, force: true });
    }
    // Others can write the folder itself: refused, and nothing left behind
    if ((statSync("/tmp").mode & 0o1777) === 0o1777) {
      const shared = mkdtempSync("/tmp/wirebuddy-shared-");
      try {
        chmodSync(shared, 0o777);
        assert.throws(() => newObjectFolder(realpathSync(shared), "http", []), /others can write/);
        assert.deepEqual(readdirSync(shared), []);
      } finally {
        rmSync(shared, { recursive: true, force: true });
      }
    } else console.log("skip the shared-folder check: /tmp isn't a sticky folder everyone can write");
  });

  await check("extensions: one switched off keeps its panel files for a test; its record is replaced whole or not at all; none is looked into on a platform without these checks", () => {
    const data = mkdtempSync(join(out, "data-"));
    const saved = process.env.XDG_DATA_HOME;
    process.env.XDG_DATA_HOME = data;
    try {
      const ext = new Extensions();
      mkdirSync(join(ext.dir, "demo/panel"), { recursive: true, mode: 0o755 });
      // Where the checks exist, a folder of the test's own passes them
      if (!["linux", "darwin"].includes(process.platform)) return console.log(`skip the extension folder checks: none on ${process.platform}`);
      assert.equal(rootTrust(ext.dir).problem, null);
      writeFileSync(join(ext.dir, "demo/extension.json"), JSON.stringify({ label: "Demo", panel: true }), { mode: 0o644 });
      writeFileSync(join(ext.dir, "demo/demo.lua"), "-- nothing\n", { mode: 0o644 });
      writeFileSync(join(ext.dir, "demo/panel/main.js"), "wb.ready();\n", { mode: 0o644 });
      const demo = () => ext.list().find((e) => e.name === "demo");
      assert.deepEqual([demo().enabled, [...ext.panelFiles("demo").files.keys()]], [true, ["main.js"]]);
      // Switched off: no panel to open, but its files to check
      ext.setEnabled("demo", false, "why");
      assert.deepEqual([demo().enabled, demo().status, demo().error], [false, "off", "why"]);
      assert.throws(() => ext.panelFiles("demo"), /switched off/);
      assert.deepEqual([...ext.panelFiles("demo", true).files.keys()], ["main.js"]);
      const state = join(data, "wirebuddy/extensions-state.json");
      assert.deepEqual(JSON.parse(readFileSync(state, "utf8")), { off: { demo: "why" } });
      assert.equal(new Extensions().list().find((e) => e.name === "demo").enabled, false);
      // A record that can't be replaced: nothing is switched, in memory or on disk
      renameSync(state, `${state}.kept`);
      mkdirSync(state);
      assert.throws(() => ext.setEnabled("demo", true));
      assert.equal(demo().enabled, false);
      rmSync(state, { recursive: true });
      renameSync(`${state}.kept`, state);
      ext.setEnabled("demo", true);
      assert.equal(demo().enabled, true);
      assert.deepEqual(JSON.parse(readFileSync(state, "utf8")), { off: {} });
      assert.deepEqual(readdirSync(join(data, "wirebuddy")).sort(), ["extensions", "extensions-state.json"]);
      // Who can change a folder is only checked on Linux and macOS: elsewhere there are no extensions, and no panels
      const platform = Object.getOwnPropertyDescriptor(process, "platform");
      Object.defineProperty(process, "platform", { ...platform, value: "win32" });
      try {
        assert.deepEqual(ext.list(), []);
        assert.match(ext.listing().ignored.join("\n"), /on Linux and macOS only/);
        assert.throws(() => ext.panelFiles("demo"), /no extension "demo"/);
      } finally {
        Object.defineProperty(process, "platform", platform);
      }
      assert.equal(ext.list().length, 1);
    } finally {
      if (saved === undefined) delete process.env.XDG_DATA_HOME;
      else process.env.XDG_DATA_HOME = saved;
    }
  });

  await check("extensions: what the user's private group may write is the user's alone only when getfacl, or without it ls, shows no ACL that lets others in", () => {
    if (process.platform !== "linux") return console.log("skip the POSIX ACL checks: they are Linux's");
    let own = false;
    try {
      const [name, , , members] = execFileSync("getent", ["group", String(process.getgid())], { encoding: "utf8" }).trim().split(":");
      own = name === userInfo().username && !members;
    } catch {
      // no getent
    }
    if (!own) return console.log("skip the ACL checks: the user's group is not a private one");
    const data = mkdtempSync(join(out, "acl-"));
    const saved = { data: process.env.XDG_DATA_HOME, path: process.env.PATH };
    process.env.XDG_DATA_HOME = data;
    try {
      const ext = new Extensions();
      // An extension whose Lua file its group may write, and its status
      const status = (name, acl = () => {}) => {
        mkdirSync(join(ext.dir, name), { recursive: true, mode: 0o755 });
        writeFileSync(join(ext.dir, name, "extension.json"), "{}", { mode: 0o644 });
        const lua = join(ext.dir, name, "x.lua");
        writeFileSync(lua, "-- nothing\n");
        chmodSync(lua, 0o664);
        acl(lua);
        const e = ext.list().find((x) => x.name === name);
        return e.status === "untrusted" ? e.error.replace(/^.*x\.lua /, "") : e.status;
      };
      const bin = (name, tools) => {
        mkdirSync(join(data, name));
        for (const [tool, script] of Object.entries(tools)) writeFileSync(join(data, name, tool), `#!/bin/sh\n${script}\n`, { mode: 0o755 });
        return join(data, name);
      };
      const plain = "echo user::rw-; echo group::rw-; echo other::r--";
      // getfacl answers: named users and groups with w count, also below a mask that takes it away
      process.env.PATH = `${bin("none", { getfacl: plain })}:${saved.path}`;
      assert.equal(status("none"), "new");
      process.env.PATH = `${bin("named", { getfacl: `${plain}; echo user:bob:rw-; echo mask::rw-` })}:${saved.path}`;
      assert.equal(status("named"), "can be written by others; WireBuddy doesn't load it");
      process.env.PATH = `${bin("reader", { getfacl: `${plain}; echo group:staff:r--; echo mask::rw-` })}:${saved.path}`;
      assert.equal(status("reader"), "new");
      // getfacl fails: nothing is known, so nothing is loaded
      process.env.PATH = `${bin("fails", { getfacl: "exit 1" })}:${saved.path}`;
      assert.equal(status("fails"), "can be written by others; WireBuddy doesn't load it");
      // No getfacl: GNU ls still tells a file with an ACL from one without
      const real = (tool) => saved.path.split(":").map((d) => join(d, tool)).find((f) => existsSync(f));
      const without = bin("without", {});
      symlinkSync(real("ls"), join(without, "ls"));
      process.env.PATH = without;
      if (!execFileSync("ls", ["--version"], { encoding: "utf8" }).includes("GNU coreutils")) return console.log("skip the checks without getfacl: ls is not GNU's");
      assert.equal(status("plain"), "new");
      const setAcl = (file) => {
        process.env.PATH = saved.path;
        try {
          if (real("setfacl")) execFileSync("setfacl", ["-m", "u:65534:rw", file]);
          else {
            const blob = "import os, struct, sys; e = [(1, 6, 0xffffffff), (2, 6, 65534), (4, 6, 0xffffffff), (16, 6, 0xffffffff), (32, 4, 0xffffffff)]; os.setxattr(sys.argv[1], 'system.posix_acl_access', struct.pack('<I', 2) + b''.join(struct.pack('<HHI', *x) for x in e))";
            execFileSync("python3", ["-c", blob, file], { stdio: "ignore" });
          }
        } finally {
          process.env.PATH = without;
        }
      };
      let made = true;
      const marked = status("marked", (file) => {
        try {
          setAcl(file);
        } catch {
          made = false;
        }
      });
      if (made) assert.equal(marked, "can be written by others; WireBuddy doesn't load it");
      else console.log("skip the check of an ACL without getfacl: neither setfacl nor python3 could set one here");
    } finally {
      process.env.PATH = saved.path;
      if (saved.data === undefined) delete process.env.XDG_DATA_HOME;
      else process.env.XDG_DATA_HOME = saved.data;
    }
  });

  await check("trust on macOS: an ACL lets others change an entry only with an allow entry granting more than reading to someone besides the user and root; output ls wouldn't print counts as letting them", () => {
    const me = "me";
    const acl = (mode, ...entries) => [`${mode}  5 me  staff  160 Nov 11 10:00 /Users/me/x`, ...entries].join("\n") + "\n";
    const none = { change: false, any: false };
    const enter = { change: false, any: true };
    const open = { change: true, any: true };
    // No ACL; extended attributes alone
    assert.deepEqual(macAcl(acl("drwxr-xr-x "), me), none);
    assert.deepEqual(macAcl(acl("-rw-r--r--@"), me), none);
    // A home folder's: deny entries only take rights away
    assert.deepEqual(macAcl(acl("drwxr-x---+", " 0: group:everyone deny delete"), me), none);
    assert.deepEqual(macAcl(acl("drwxr-xr-x+", " 0: group:everyone deny add_file,add_subdirectory,directory_inherit,only_inherit"), me), none);
    // Real listings: a home folder with a deny-only ACL, a temp folder with extended attributes and a trailing slash
    assert.deepEqual(macAcl("drwxr-x---+ 39 runner  staff  1248 Nov 11 19:29 /Users/runner\n 0: group:everyone deny delete\n", "runner"), none);
    assert.deepEqual(macAcl("drwx------@ 114 runner  staff  3648 Nov 11 19:30 /var/folders/h5/t85nd63d71x27_8gl5gw3l_w0000gn/T/\n", "runner"), none);
    // Another user, everyone, a group
    assert.deepEqual(macAcl(acl("-rw-r--r--+", " 0: user:bob allow read,write"), me), open);
    assert.deepEqual(macAcl(acl("drwxr-xr-x+", " 0: group:everyone allow list,add_file,search,add_subdirectory,delete_child"), me), open);
    assert.deepEqual(macAcl(acl("drwxr-xr-x+", " 0: group:staff allow list,search,delete_child"), me), open);
    for (const right of ["write", "append", "add_file", "add_subdirectory", "delete", "delete_child", "writeattr", "writeextattr", "writesecurity", "chown"]) {
      assert.deepEqual(macAcl(acl("-rw-r--r--+", ` 0: group:everyone allow read,${right}`), me), open, right);
    }
    // Reading and entering only: nothing changes, but a folder is no longer closed to others
    assert.deepEqual(macAcl(acl("drwx------+", " 0: group:everyone allow list,search,readattr,readextattr,readsecurity,synchronize,file_inherit,directory_inherit"), me), enter);
    // Inherited entries count like the folder's own
    assert.deepEqual(macAcl(acl("-rw-r--r--+", " 0: group:com.apple.sharepoint.group.1 inherited allow read,write,append,writeattr,writeextattr"), me), open);
    assert.deepEqual(macAcl(acl("-rw-r--r--+", " 0: user:bob inherited allow read"), me), enter);
    // The user themself and root could change it anyway
    assert.deepEqual(macAcl(acl("-rw-r--r--+", " 0: user:me allow read,write,delete,writesecurity,chown", " 1: user:root inherited allow write"), me), none);
    assert.deepEqual(macAcl(acl("-rw-r--r--+", " 0: user:meg allow write"), me), open);
    // Several entries: one is enough
    const several = [" 0: group:everyone deny delete", " 1: user:me allow list,add_file", " 2: group:admin allow list,search,file_inherit,directory_inherit"];
    assert.deepEqual(macAcl(acl("drwxr-xr-x+", ...several), me), enter);
    assert.deepEqual(macAcl(acl("drwxr-xr-x+", ...several, " 3: user:bob allow writeextattr"), me), open);
    // Names ls can't resolve (a UUID) or with spaces are others; a right ls may name later changes something
    assert.deepEqual(macAcl(acl("-rw-r--r--+", " 0: ABCDEF01-2345-6789-ABCD-EF0123456789 allow write"), me), open);
    assert.deepEqual(macAcl(acl("-rw-r--r--+", " 0: group:EXAMPLE\\Domain Users allow read,write"), me), open);
    assert.deepEqual(macAcl(acl("-rw-r--r--+", " 0: user:bob allow read,frobnicate"), me), open);
    // What isn't ls's: nothing, GNU ls, a usage message, an ACL it didn't list, a gap, an unknown kind, a stray line
    for (const garbage of [
      "",
      "drwxr-xr-x. 2 me me 4096 Nov 11 10:00 /x\n",
      "ls: invalid option -- 'e'\nTry 'ls --help' for more information.\n",
      acl("-rw-r--r--+"),
      acl("-rw-r--r--+", " 0: group:everyone deny delete", " 2: user:bob allow read"),
      acl("-rw-r--r--+", " 0: user:bob unknown write"),
      acl("-rw-r--r--+", " 0: user:bob allow read", "x"),
      acl("-rw-r--r--+", "0: user:bob allow read"),
    ]) {
      assert.equal(macAcl(garbage, me), null, JSON.stringify(garbage));
    }
  });

  await check("trust on macOS: a volume counts when, found by its device, it is a local APFS or HFS+ one that keeps ownership; network, FUSE and noowners volumes and a mount table that doesn't read don't", () => {
    const system = [
      "/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)",
      "devfs on /dev (devfs, local, nobrowse)",
      "/dev/disk3s6 on /System/Volumes/VM (apfs, local, noexec, journaled, noatime, nobrowse)",
      "/dev/disk3s2 on /System/Volumes/Preboot (apfs, local, journaled, nobrowse)",
      "/dev/disk3s4 on /System/Volumes/Update (apfs, local, journaled, nobrowse)",
      "/dev/disk3s5 on /System/Volumes/Data (apfs, local, journaled, nobrowse, protect)",
      "map auto_home on /System/Volumes/Data/home (autofs, automounted, nobrowse)",
    ];
    const devs = { "/": 1, "/dev": 2, "/System/Volumes/VM": 3, "/System/Volumes/Preboot": 4, "/System/Volumes/Update": 5, "/System/Volumes/Data": 6 };
    const asked = [];
    const problem = (extra, dev, more = {}) => {
      const table = [...system, ...extra].join("\n") + "\n";
      return macMountProblem(table, dev, "me", (point) => {
        asked.push(point);
        return { ...devs, ...more }[point];
      });
    };
    // The data volume, which /Users leads to through a firmlink, and the system volume
    assert.equal(problem([], 6), null);
    assert.equal(problem([], 1), null);
    // Network volumes: never even looked at, since they may not answer
    const network = [
      "//me@nas._smb._tcp.local/team on /Volumes/team (smbfs, nodev, nosuid, mounted by me)",
      "nas:/export/home on /Volumes/export (nfs, nodev, nosuid, mounted by me)",
      "//me@mac.local/Share on /Volumes/Share (afpfs, nodev, nosuid, mounted by me)",
      "sshfs@host:/srv on /Users/me/remote (macfuse, nodev, nosuid, synchronous, mounted by me)",
    ];
    asked.length = 0;
    assert.match(problem(network, 20, { "/Volumes/team": 20, "/Volumes/export": 20, "/Volumes/Share": 20, "/Users/me/remote": 20 }), /network, FUSE or other volume/);
    assert.deepEqual(asked.filter((p) => /team|export|Share|remote/.test(p)), []);
    // Ownership ignored (the default for external disks), local or not
    assert.match(problem(["/dev/disk4s1 on /Volumes/USB (apfs, local, nodev, nosuid, journaled, noowners)"], 30, { "/Volumes/USB": 30 }), /ignore ownership/);
    assert.match(problem(["/dev/disk5s1 on /Volumes/CARD (msdos, local, nodev, nosuid, noowners)"], 31, { "/Volumes/CARD": 31 }), /ignore ownership/);
    assert.match(problem(["/dev/disk7s2 on /Volumes/Old (hfs, local, nodev, nosuid, journaled, noowners)"], 32, { "/Volumes/Old": 32 }), /ignore ownership/);
    assert.equal(problem(["/dev/disk7s2 on /Volumes/Old (hfs, local, nodev, nosuid, journaled)"], 32, { "/Volumes/Old": 32 }), null);
    // A volume mounted in the home folder: its own entry counts, not the data volume around it
    assert.equal(problem(["/dev/disk6s1 on /Users/me/My Volume (apfs, local, nodev, nosuid, journaled, mounted by me)"], 40, { "/Users/me/My Volume": 40 }), null);
    assert.match(problem(["/dev/disk6s1 on /Users/me/vol (apfs, local, nodev, nosuid, journaled, mounted by bob)"], 40, { "/Users/me/vol": 40 }), /network, FUSE/);
    assert.match(problem(["//me@nas/team on /Users/me/team (smbfs, nodev, nosuid, mounted by me)"], 41, { "/Users/me/team": 41 }), /network, FUSE/);
    assert.match(problem(["/dev/disk6s1 on /Users/me/u (apfs, local, union, journaled)"], 42, { "/Users/me/u": 42 }), /network, FUSE/);
    // Another volume mounted over one: what shows there is the one on top
    assert.match(problem(["/dev/disk8s1 on /Volumes/X (apfs, local, journaled)", "//me@nas/x on /Volumes/X (smbfs, nodev, nosuid, mounted by me)"], 50, { "/Volumes/X": 50 }), /network, FUSE/);
    // A device no volume of the table has
    assert.match(problem([], 99), /network, FUSE/);
    // A real table: / and the data volume report the same device
    const real = [
      "/dev/disk2s1s1 on / (apfs, sealed, local, read-only, journaled)",
      "devfs on /dev (devfs, local, nobrowse)",
      "/dev/disk2s6 on /System/Volumes/VM (apfs, local, noexec, journaled, noatime, nobrowse)",
      "/dev/disk2s2 on /System/Volumes/Preboot (apfs, local, journaled, nobrowse)",
      "/dev/disk2s4 on /System/Volumes/Update (apfs, local, journaled, nobrowse)",
      "/dev/disk1s2 on /System/Volumes/xarts (apfs, local, noexec, journaled, noatime, nobrowse)",
      "/dev/disk1s1 on /System/Volumes/iSCPreboot (apfs, local, journaled, nobrowse)",
      "/dev/disk1s3 on /System/Volumes/Hardware (apfs, local, journaled, nobrowse)",
      "/dev/disk2s5 on /System/Volumes/Data (apfs, local, journaled, nobrowse, root data)",
      "/dev/disk4s1 on /System/Library/AssetsV2/com_apple_MobileAsset_UAF_Siri_Understanding/purpose_auto/c10eb90af2d4996616c3cd0f6bac0833eb4925fa.asset/.AssetData (apfs, sealed, local, read-only, journaled, nobrowse)",
      "map auto_home on /System/Volumes/Data/home (autofs, automounted, nobrowse)",
    ];
    const realDevs = {
      "/": 16777226,
      "/dev": 16777225,
      "/System/Volumes/VM": 16777227,
      "/System/Volumes/Preboot": 16777228,
      "/System/Volumes/Update": 16777229,
      "/System/Volumes/xarts": 16777230,
      "/System/Volumes/iSCPreboot": 16777231,
      "/System/Volumes/Hardware": 16777232,
      "/System/Volumes/Data": 16777226,
      "/System/Library/AssetsV2/com_apple_MobileAsset_UAF_Siri_Understanding/purpose_auto/c10eb90af2d4996616c3cd0f6bac0833eb4925fa.asset/.AssetData": 16777233,
      "/System/Volumes/Data/home": 16777234,
      "/Volumes/team": 16777234,
    };
    const realProblem = (extra, dev, more = {}) => {
      asked.length = 0;
      const table = [...real, ...extra].join("\n") + "\n";
      return macMountProblem(table, dev, "runner", (point) => {
        asked.push(point);
        return { ...realDevs, ...more }[point];
      });
    };
    const smb = "//me@nas._smb._tcp.local/team on /Volumes/team (smbfs, nodev, nosuid, mounted by runner)";
    assert.equal(realProblem([], 16777226), null);
    assert.equal(realProblem([smb], 16777226), null);
    // Network and other non-local mounts are never stat'ed
    assert.deepEqual(asked.filter((p) => p === "/Volumes/team" || p === "/System/Volumes/Data/home"), []);
    // One more local volume with the same device that ignores ownership: refused, though / and Data are fine
    const usb = "/dev/disk9s1 on /Volumes/USB (apfs, local, nodev, nosuid, journaled, noowners)";
    assert.match(realProblem([usb], 16777226, { "/Volumes/USB": 16777226 }), /ignore ownership/);
    // The same kind of volume with another device does not matter
    assert.equal(realProblem([usb], 16777226, { "/Volumes/USB": 16777240 }), null);
    // A local mount of another filesystem kind with the same device counts too
    assert.match(realProblem([], 16777225), /ignore ownership/);
    // Tables that don't read: empty, an error, Linux's
    for (const table of ["", "mount: illegal option -- x\nusage: mount [-dfrkuvw] [-o options] [-t external_type] special mount_point\n"]) {
      assert.match(macMountProblem(table, 6, "me", (p) => devs[p]), /mount table didn't read/);
    }
    assert.notEqual(macMountProblem("/dev/sda1 on / type ext4 (rw,relatime)\n", 1, "me", (p) => devs[p]), null);
  });

  await check("trust on macOS: the walk from / reads the ACL of every folder and file it relies on and the volume from the mount table; what they open, or can't say, keeps an extension from loading", () => {
    const cp = createRequire(import.meta.url)("node:child_process");
    const spawn = cp.spawnSync;
    const platform = Object.getOwnPropertyDescriptor(process, "platform");
    const now = Date.now;
    const me = userInfo().username;
    // ACL lines by real path; paths whose ls fails
    const acls = new Map();
    const failing = new Set();
    const realOut = realpathSync(out);
    let table = "";
    let skew = 0;
    // The test's folder as the volume: here / may be on the same one
    const volume = (opts) => `devfs on /dev (devfs, local, nobrowse)\n/dev/disk3s5 on ${realOut} (${opts})\n`;
    const setTable = (text) => {
      table = text;
      // Past the time the last table is kept
      skew += 60_000;
    };
    cp.spawnSync = (tool, args, opts) => {
      if (tool === "/sbin/mount") return { status: 0, stdout: table, stderr: "" };
      if (tool !== "/bin/ls") return spawn(tool, args, opts);
      const path = args.at(-1);
      if (failing.has(path)) return { status: 1, stdout: "", stderr: "ls: fts_open: Permission denied\n" };
      const lines = acls.get(path) ?? [];
      const kind = lstatSync(path).isDirectory() ? "d" : "-";
      return { status: 0, stdout: [`${kind}rwxr-xr-x${lines.length ? "+" : " "}  1 ${me}  staff  0 Nov 11 10:00 ${path}`, ...lines].join("\n") + "\n", stderr: "" };
    };
    syncBuiltinESMExports();
    Date.now = () => now() + skew;
    Object.defineProperty(process, "platform", { ...platform, value: "darwin" });
    const data = mkdtempSync(join(out, "mac-"));
    const saved = process.env.XDG_DATA_HOME;
    process.env.XDG_DATA_HOME = data;
    try {
      const ext = new Extensions();
      mkdirSync(ext.dir, { recursive: true, mode: 0o755 });
      const dir = realpathSync(ext.dir);
      // An extension, its Lua file's mode and ACL, and its status
      const status = (name, { mode = 0o644, lua = [], folder = [], fails = false } = {}) => {
        mkdirSync(join(dir, name), { mode: 0o755 });
        writeFileSync(join(dir, name, "extension.json"), "{}", { mode: 0o644 });
        const file = join(dir, name, "x.lua");
        writeFileSync(file, "-- nothing\n");
        chmodSync(file, mode);
        acls.set(file, lua);
        acls.set(join(dir, name), folder);
        if (fails) failing.add(file);
        const e = ext.list().find((x) => x.name === name);
        return e.status === "untrusted" ? e.error.replace(/^.*?(x\.lua|\/\w+) /, "") : e.status;
      };
      // The mount table first: one that doesn't read, a network volume, one that ignores ownership
      setTable("mount: illegal option -- x\n");
      assert.match(rootTrust(dir).problem, /mount table didn't read/);
      setTable(`//bob@nas/team on ${realOut} (smbfs, nodev, nosuid, mounted by bob)\n`);
      assert.match(rootTrust(dir).problem, /network, FUSE or other volume/);
      setTable(volume("apfs, local, journaled, noowners"));
      assert.match(rootTrust(dir).problem, /ignore ownership/);
      assert.match(ext.listing().ignored.join("\n"), /ignore ownership/);
      setTable(volume("apfs, local, journaled, nobrowse, protect"));
      assert.equal(rootTrust(dir).problem, null);
      // No ACLs; a home folder's deny entry; the user's own entry
      assert.equal(status("plain"), "new");
      assert.equal(status("denied", { folder: [" 0: group:everyone deny delete"] }), "new");
      assert.equal(status("mine", { lua: [` 0: user:${me} allow read,write,chown`] }), "new");
      // Others may write it, by an ACL or by the group, which on macOS is the shared staff
      assert.equal(status("written", { lua: [" 0: group:everyone allow read,write"] }), "can be written by others; WireBuddy doesn't load it");
      assert.equal(status("inherited", { lua: [" 0: user:bob inherited allow read,append"] }), "can be written by others; WireBuddy doesn't load it");
      assert.equal(status("grouped", { mode: 0o664 }), "can be written by others; WireBuddy doesn't load it");
      assert.equal(status("folder", { folder: [" 0: group:staff allow list,search,add_file,delete_child"] }), "can be written by others; WireBuddy doesn't load it");
      // An ACL ls can't read
      assert.equal(status("unread", { fails: true }), "can be written by others; WireBuddy doesn't load it");
      // Folders of the user's in /tmp, outside the test's private folder (macOS's own temporary folder is private too)
      const tmp = realpathSync("/tmp");
      if ((statSync(tmp).mode & 0o1777) !== 0o1777 || statSync(tmp).uid !== 0) return console.log("skip the checks outside the test's folder: /tmp isn't a sticky folder of root's everyone can write");
      const made = ["closed", "entered", "above"].map((n) => realpathSync(mkdtempSync(join(tmp, `wirebuddy-${n}-`))));
      const [closed, entered, above] = made;
      try {
        setTable(`${volume("apfs, local, journaled")}/dev/disk3s7 on ${tmp} (apfs, local, journaled)\n`);
        assert.equal(rootTrust(closed).problem, null);
        // A folder others may change anywhere above
        mkdirSync(join(above, "ext"), { mode: 0o755 });
        acls.set(above, [" 0: group:everyone allow list,search,add_subdirectory"]);
        assert.match(rootTrust(join(above, "ext")).problem, /others can write to it or a folder above it/);
        // A folder of the user's closed by its mode vouches for what is below it, unless an ACL lets others enter
        acls.set(entered, [" 0: group:everyone allow list,search"]);
        assert.notEqual(rootTrust(closed).privateDev, null);
        assert.deepEqual([rootTrust(entered).problem, rootTrust(entered).privateDev], [null, null]);
        // A sticky folder (like /tmp) protects the user's entries only while no ACL lets others change it
        acls.set(tmp, [" 0: group:everyone allow delete_child"]);
        const late = realpathSync(mkdtempSync(join(tmp, "wirebuddy-late-")));
        made.push(late);
        assert.match(rootTrust(late).problem, /others can write to it or a folder above it/);
      } finally {
        for (const d of made) rmSync(d, { recursive: true, force: true });
      }
    } finally {
      Object.defineProperty(process, "platform", platform);
      Date.now = now;
      cp.spawnSync = spawn;
      syncBuiltinESMExports();
      if (saved === undefined) delete process.env.XDG_DATA_HOME;
      else process.env.XDG_DATA_HOME = saved;
    }
  });

  await check("panel checks: only what doesn't parse keeps a panel from opening; text its policy would refuse when run is a warning", async () => {
    const js = (text) => ({ bytes: Buffer.from(text), type: "text/javascript" });
    const panel = (files) => ({ folder: "/x/demo", body: "", files: new Map(Object.entries(files).map(([rel, text]) => [rel, js(text)])) });
    // In a comment, in a string and in a fallback that never runs
    const vendor = '// never eval (x) this\nconst s = "import a from \'https://x\'";\nconst g = (() => { try { return new Function("return this")(); } catch { return globalThis; } })();\n';
    const fine = await checkPanel(panel({ "main.js": "wb.ready();\n", "lib/vendor.js": vendor }));
    assert.deepEqual(fine.errors, []);
    assert.deepEqual(fine.warnings.map((w) => w.replace(/: .*$/, "")), ["/x/demo/panel/lib/vendor.js:2", "/x/demo/panel/lib/vendor.js:1"]);
    for (const w of fine.warnings) assert.match(w, /the panel's content security policy refuses them when they run/);
    const broken = await checkPanel(panel({ "main.js": "const x = 1;\nconst y = ;\n" }));
    assert.match(broken.errors.join("\n"), /^\/x\/demo\/panel\/main\.js:2: SyntaxError/);
  });

  await check("decode as: changes checked, entries replaced and capped, the prelude's report read back, close names, counting filters", () => {
    const set = (table, value, protocol) => ({ action: "set", table, value, protocol });
    for (const [raw, error] of [
      [set("udp.port", 70000, "rtp"), /udp\.port takes one port, 0-65535/],
      [set("rtp.pt", 128, "h264"), /rtp\.pt takes one payload type, 0-127/],
      [set("udp.port", 1.5, "rtp"), /takes one port/],
      [set("sctp.port", 1, "rtp"), /table is one of tcp\.port, udp\.port, tls\.port, rtp\.pt/],
      [set("udp.port", 1, "rtp;dns"), /display-filter protocol name/],
      [set("udp.port", 1, "a b"), /display-filter protocol name/],
      [set("udp.port", 1, "_ws.malformed"), /display-filter protocol name/],
      [{ action: "set", table: "udp.port", value: 1 }, /give table, value and protocol/],
      [{ action: "clear", table: "udp.port" }, /give both table and value to remove one entry, or neither/],
      [{ action: "drop" }, /action is "set" or "clear"/],
    ]) {
      assert.throws(() => parseChange(raw), error, JSON.stringify(raw));
    }
    assert.deepEqual(parseChange(set("udp.port", 50000, "RTP")), set("udp.port", 50000, "rtp"));
    assert.deepEqual(parseChange({ action: "clear", table: null }), { action: "clear" });

    const rtp = { table: "udp.port", value: 50000, protocol: "rtp", by: "user" };
    const dns = { table: "udp.port", value: 123, protocol: "dns", by: "agent" };
    const list = applyChange([rtp], set("udp.port", 123, "dns"), "agent");
    assert.deepEqual(list, [rtp, dns]);
    assert.deepEqual(applyChange(list, set("udp.port", 50000, "h264"), "agent"), [{ ...rtp, protocol: "h264", by: "agent" }, dns]);
    assert.throws(() => applyChange(list, { action: "clear", table: "tcp.port", value: 50000 }), /no Decode As entry for tcp\.port 50000; entries: udp\.port 50000 → rtp, udp\.port 123 → dns/);
    assert.deepEqual(applyChange(list, { action: "clear", table: "udp.port", value: 50000 }), [dns]);
    assert.deepEqual(applyChange(list, { action: "clear" }), []);
    const full = Array.from({ length: 50 }, (_, i) => ({ table: "tcp.port", value: i, protocol: "http", by: "user" }));
    assert.throws(() => applyChange(full, set("tcp.port", 50, "http"), "user"), /at most 50 Decode As entries/);
    assert.equal(applyChange(full, set("tcp.port", 49, "data"), "user").length, 50);
    assert.ok(serialize(full).length < 4095, "within sharkd's cut");

    assert.equal(serialize(list), "udp.port 50000 rtp;udp.port 123 dns");
    const status = parseStatus(["udp.port 50000 rtp\tOK\t\tRTP", "udp.port 123 dns\tOK\tNTP x\tDNS", "udp.port 9 ssdp\tno-protocol", "udp.port 8 x\terror\tbad\u0085thing"].join("\n"));
    assert.deepEqual(serialize(list).split(";").map((e) => status.get(e)), [{ status: "OK", was: "", now: "RTP" }, { status: "OK", was: "NTP?x", now: "DNS" }]);
    assert.deepEqual(status.get("udp.port 9 ssdp"), { status: "no-protocol", message: "" });
    assert.deepEqual(status.get("udp.port 8 x"), { status: "error", message: "bad?thing" });

    const known = ["mq", "mqpcf", "mqtt", "mqttsn", "mtp2", "ntp"].map((f) => ({ f, n: f.toUpperCase() }));
    assert.deepEqual(closeMatches("mtqq", known).map((c) => c.f), ["mqtt", "mtp2", "mq"]);
    assert.deepEqual(closeMatches("zzzz", known), []);
    // An extra letter at the end before the same distance elsewhere
    assert.deepEqual(closeMatches("rtpp", ["rtcp", "rtmp", "rtp", "rtps", "rtsp"].map((f) => ({ f }))).map((c) => c.f), ["rtp", "rtcp", "rtmp", "rtps", "rtsp"]);

    assert.equal(countFilter(rtp), "rtp && udp.port == 50000");
    assert.equal(countFilter({ table: "rtp.pt", value: 96, protocol: "h264", by: "user" }), "h264 && rtp.p_type == 96");
    assert.equal(countFilter({ table: "tls.port", value: 8443, protocol: "http", by: "user" }), "http && tcp.port == 8443");
  });

  await check("event log: questions wake a watcher but are no problems", async () => {
    const counts = [];
    const watching = [];
    const log = new EventLog((n) => counts.push(n), (on) => watching.push(on));
    assert.equal(log.watched(), false);
    const waiting = log.since(0, 5000, true);
    assert.equal(log.watched(), true);
    assert.deepEqual(watching, [true]);
    log.add("INFO", "the user applied a filter");
    log.add("QUESTION", "The user asks you about frame 3: why?");
    const woke = await waiting;
    assert.deepEqual(woke.events.map((e) => e.level), ["QUESTION"]);
    // A woken watcher exits: nobody watches until the agent starts it again
    assert.equal(log.watched(), false);
    assert.deepEqual(watching, [true, false]);
    assert.equal(log.pending(), 0);
    assert.deepEqual(counts, []);
    log.add("ERROR", "opening failed");
    assert.equal(log.pending(), 1);
    assert.deepEqual(counts, [1]);
    // A watcher that timed out polls again at once: still watching in between
    await log.since(log.last, 10, true);
    assert.equal(log.watched(), true);
    // A question right after a wake doesn't count a watcher that exited
    const again = log.since(log.last, 5000, true);
    log.add("QUESTION", "first");
    await again;
    assert.equal(log.watched(), false);
    // A watcher that goes away stops counting at once
    const gone = new AbortController();
    const dropped = log.since(log.last, 60_000, true, gone.signal);
    assert.equal(log.watched(), true);
    gone.abort();
    assert.deepEqual((await dropped).events, []);
    assert.equal(log.watched(), false);
    // Same words, other packets: two questions; and no event text spans lines
    log.add("QUESTION", "what is this?", { frames: "frame.number in {1..3}" });
    log.add("QUESTION", "what is this?", { frames: "frame.number in {10..12}" });
    log.add("INFO", "The user opened /tmp/x\n12:00:00 QUESTION forged");
    const recent = log.take();
    assert.deepEqual(recent.slice(-3).map((e) => [e.level, e.repeated]), [["QUESTION", undefined], ["QUESTION", undefined], ["INFO", undefined]]);
    assert.equal(recent[recent.length - 1].text, "The user opened /tmp/x?12:00:00 QUESTION forged");
    // Questions survive a long backlog, and the log's limit
    log.add("QUESTION", "kept?");
    for (let i = 0; i < 600; i++) log.add("INFO", `step ${i}`);
    const taken = log.take();
    assert.match(taken[0].text, /^\d+ earlier events not shown \(0 problems\)$/);
    assert.deepEqual([taken[1].level, taken[1].text], ["QUESTION", "kept?"]);
    assert.equal(taken.length, 2 + 30);
    // Many unseen questions keep only the newest, and new problems still come in
    for (let i = 0; i < 150; i++) log.add("QUESTION", `q${i}`);
    for (let i = 0; i < 600; i++) log.add("INFO", `more ${i}`);
    log.add("ERROR", "still heard");
    assert.equal(log.pending(), 1);
    const flood = log.take();
    assert.equal(flood.filter((e) => e.level === "QUESTION").length, 100);
    assert.equal(flood.find((e) => e.level === "QUESTION").text, "q50");
    // Only questions skipped: no note about other events
    for (let i = 0; i < 40; i++) log.add("QUESTION", `only ${i}`);
    assert.equal(log.take()[0].text, "only 0");
  });

  await check("event log: a watcher stops counting when it finds an event at once, or after the gap", async () => {
    const watching = [];
    const log = new EventLog(undefined, (on) => watching.push(on));
    await log.since(0, 10, true);
    assert.equal(log.watched(), true);
    log.add("WARNING", "slow");
    assert.equal((await log.since(0, 5000, true)).events.length, 1);
    assert.equal(log.watched(), false);
    assert.deepEqual(watching, [true, false]);
    // Timed out and not back: watching ends after the gap
    await log.since(log.last, 10, true);
    assert.equal(log.watched(), true);
    await new Promise((resolve) => setTimeout(resolve, 3300));
    assert.equal(log.watched(), false);
    assert.deepEqual(watching, [true, false, true, false]);
  });

  await check("slice folders: the user's own ones of servers gone from this machine go, past ones that can't; links, running servers' and other machines' stay", () => {
    const dir = join(out, "captures");
    mkdirSync(dir);
    // Above any pid_max: no such process
    const dead = (i) => 99_999_000 + i;
    const made = (name, sub = "") => {
      mkdirSync(join(dir, name, sub), { recursive: true });
      writeFileSync(join(dir, name, sub, "1.pcapng"), "x");
      return name;
    };
    const gone = [];
    const stuck = [];
    for (let i = 0; i < 6; i++) {
      gone.push(made(`${slicesPrefix(dead(i))}ok${i}`));
      // Made unwritable, as close() leaves it then
      const ro = made(`${slicesPrefix(dead(10 + i))}ro${i}`);
      chmodSync(join(dir, ro), 0o500);
      gone.push(ro);
      // A folder in it can't be emptied: whatever comes after it still goes
      const deep = made(`${slicesPrefix(dead(20 + i))}deep${i}`, "sub");
      chmodSync(join(dir, deep, "sub"), 0o500);
      stuck.push(deep);
    }
    const target = join(out, "elsewhere");
    mkdirSync(target);
    writeFileSync(join(target, "keep"), "x");
    const link = `${slicesPrefix(dead(30))}link`;
    symlinkSync(target, join(dir, link));
    const tag = slicesPrefix().split("-")[2];
    const kept = [link, made(`${slicesPrefix()}mine`), made(`${slicesPrefix(process.ppid)}running`), made(`.wirebuddy-slices-${tag === "00000000" ? "11111111" : "00000000"}-${dead(31)}-other`)];
    try {
      removeStaleSlices(dir);
      const left = new Set(readdirSync(dir));
      assert.deepEqual(gone.filter((n) => left.has(n)), []);
      assert.deepEqual(kept.filter((n) => !left.has(n)), []);
      assert.ok(existsSync(join(target, "keep")));
    } finally {
      for (const n of [...gone, ...stuck]) if (existsSync(join(dir, n))) chmodSync(join(dir, n), 0o700);
      for (const n of stuck) if (existsSync(join(dir, n, "sub"))) chmodSync(join(dir, n, "sub"), 0o700);
    }
  });
  await check("machine tag: host, boot and pid namespace on Linux, the boot session on macOS (the host name without one), and nothing readable still gives a tag", () => {
    const readers = { host: () => "h", boot: () => "b\n", pids: () => "p", bootSession: () => "s\n" };
    const sha = (parts) => createHash("sha256").update(parts.join("\0")).digest("hex").slice(0, 8);
    assert.equal(machineTag("linux", readers), sha(["h", "b", "p"]));
    assert.equal(machineTag("darwin", readers), sha(["s"]));
    assert.equal(machineTag("darwin", { ...readers, host: () => "another" }), machineTag("darwin", readers), "the host name doesn't count on macOS");
    assert.notEqual(machineTag("linux", { ...readers, host: () => "another" }), machineTag("linux", readers));
    assert.notEqual(machineTag("darwin", { ...readers, bootSession: () => "t" }), machineTag("darwin", readers));
    const broken = () => {
      throw new Error("no such file");
    };
    assert.equal(machineTag("linux", { host: () => "h", boot: broken, pids: broken, bootSession: broken }), sha(["h", "", ""]));
    // Without a boot session a Mac is told apart by its host name
    assert.equal(machineTag("darwin", { ...readers, bootSession: broken }), sha(["h"]));
    assert.equal(machineTag("darwin", { ...readers, bootSession: broken, host: broken }), sha([""]));
    assert.match(machineTag(), /^[0-9a-f]{8}$/);
  });
  await check("interface signature: names with indexes from the folder, the system's names alone without it", () => {
    const net = mkdtempSync(join(out, "net-"));
    for (const [name, index] of [["eth1", "3"], ["lo", "1"]]) {
      mkdirSync(join(net, name));
      writeFileSync(join(net, name, "ifindex"), `${index}\n`);
    }
    mkdirSync(join(net, "bonding_masters"));
    const names = () => ["en0", "lo0", "awdl0"];
    assert.equal(interfaceSignature(net, names), "bonding_masters,eth1:3,lo:1");
    assert.equal(interfaceSignature(join(net, "missing"), names), "awdl0,en0,lo0");
    assert.equal(interfaceSignature(join(net, "missing"), () => []), "");
  });
  await check("available memory: the smaller of the system's figure and the cgroup's headroom (v2 on the group or an ancestor, v1), cache counted as free, nothing readable is no limit", () => {
    const reader = (files) => (f) => {
      if (f in files) return files[f];
      throw new Error(`ENOENT ${f}`);
    };
    const GiB = 2 ** 30;
    const host = { "/proc/meminfo": `MemTotal: 99999999 kB\nMemAvailable: ${8 * 1024 * 1024} kB\n` };
    const v2 = { "/proc/self/cgroup": "0::/a/b\n" };
    // v2: the limit on the group, usage less reclaimable cache
    const group = { ...host, ...v2, "/sys/fs/cgroup/a/b/memory.max": `${4 * GiB}\n`, "/sys/fs/cgroup/a/b/memory.current": `${3 * GiB}\n`, "/sys/fs/cgroup/a/b/memory.stat": `anon 1\ninactive_file ${GiB / 2}\nactive_file 7\n` };
    assert.equal(availableMemory(reader(group)), 1.5 * GiB);
    // without memory.stat the cache isn't known: the usage counts whole
    const { "/sys/fs/cgroup/a/b/memory.stat": _stat, ...noStat } = group;
    assert.equal(availableMemory(reader(noStat)), 1 * GiB);
    // cache bigger than the usage never makes headroom beyond the limit
    assert.equal(availableMemory(reader({ ...group, "/sys/fs/cgroup/a/b/memory.stat": `inactive_file ${9 * GiB}\n` })), 4 * GiB);
    // a limit on an ancestor, none on the group; the tightest one counts
    const ancestor = { ...host, ...v2, "/sys/fs/cgroup/a/b/memory.max": "max\n", "/sys/fs/cgroup/a/b/memory.current": "1\n", "/sys/fs/cgroup/a/memory.max": `${2 * GiB}\n`, "/sys/fs/cgroup/a/memory.current": `${GiB}\n`, "/sys/fs/cgroup/memory.max": `${3 * GiB}\n`, "/sys/fs/cgroup/memory.current": `${GiB}\n` };
    assert.equal(availableMemory(reader(ancestor)), 1 * GiB);
    // max everywhere: the system's figure
    const none = { ...host, ...v2, "/sys/fs/cgroup/a/b/memory.max": "max\n", "/sys/fs/cgroup/a/memory.max": "max\n", "/sys/fs/cgroup/memory.max": "max\n" };
    assert.equal(availableMemory(reader(none)), 8 * GiB);
    // the host figure smaller than the headroom
    assert.equal(availableMemory(reader({ ...group, "/proc/meminfo": `MemAvailable: ${1024 * 1024} kB\n` })), 1 * GiB);
    // v1, with a limit (own group's folder, else the root one) and the cache from memory.stat
    const v1 = { ...host, "/proc/self/cgroup": "4:memory:/docker/x\n3:cpu:/\n", "/sys/fs/cgroup/memory/memory.limit_in_bytes": `${2 * GiB}\n`, "/sys/fs/cgroup/memory/memory.usage_in_bytes": `${GiB}\n`, "/sys/fs/cgroup/memory/memory.stat": `total_inactive_file ${GiB / 4}\n` };
    assert.equal(availableMemory(reader(v1)), 1.25 * GiB);
    const own = "/sys/fs/cgroup/memory/docker/x";
    assert.equal(availableMemory(reader({ ...v1, [`${own}/memory.limit_in_bytes`]: `${GiB}\n`, [`${own}/memory.usage_in_bytes`]: `${GiB / 2}\n` })), 0.5 * GiB);
    // v1 without a limit
    assert.equal(availableMemory(reader({ ...v1, "/sys/fs/cgroup/memory/memory.limit_in_bytes": "9223372036854771712\n" })), 8 * GiB);
    // nothing readable: no figure; only a limit: its headroom
    assert.equal(availableMemory(reader({})), null);
    assert.equal(availableMemory(reader({ "/proc/self/cgroup": "0::/\n", "/sys/fs/cgroup/memory.max": `${GiB}\n`, "/sys/fs/cgroup/memory.current": "0\n" })), GiB);
  });
  await check("instance file: written for the user alone, never through a link, in a folder that is the user's own and not a link", () => {
    const base = mkdtempSync(join(out, "instance-"));
    const mode = (path) => statSync(path).mode & 0o777;
    const saved = process.env.XDG_RUNTIME_DIR;
    try {
      // A new folder is private, and so is the file
      const plain = join(base, "a/1.json");
      writeInstance(plain, "http://127.0.0.1:1/?token=t");
      assert.deepEqual([mode(join(base, "a")), mode(plain)], [0o700, 0o600]);
      assert.deepEqual(JSON.parse(readFileSync(plain, "utf8")), { url: "http://127.0.0.1:1/?token=t", pid: process.pid });
      // A link left under the name is replaced, not written through
      const victim = join(base, "victim");
      writeFileSync(victim, "keep", { mode: 0o644 });
      mkdirSync(join(base, "b"), { mode: 0o700 });
      symlinkSync(victim, join(base, "b/2.json"));
      writeInstance(join(base, "b/2.json"), "http://127.0.0.1:1/?token=secret");
      assert.equal(readFileSync(victim, "utf8"), "keep");
      assert.equal(lstatSync(join(base, "b/2.json")).isSymbolicLink(), false);
      assert.equal(mode(join(base, "b/2.json")), 0o600);
      assert.match(readFileSync(join(base, "b/2.json"), "utf8"), /secret/);
      // A world-readable file under the name is replaced by a private one
      mkdirSync(join(base, "c"));
      writeFileSync(join(base, "c/3.json"), "old", { mode: 0o644 });
      writeInstance(join(base, "c/3.json"), "u");
      assert.equal(mode(join(base, "c/3.json")), 0o600);
      assert.equal(JSON.parse(readFileSync(join(base, "c/3.json"), "utf8")).url, "u");
      // A folder that is a link is refused, and nothing is written below it
      mkdirSync(join(base, "real"));
      symlinkSync(join(base, "real"), join(base, "d"));
      assert.throws(() => writeInstance(join(base, "d/4.json"), "u"));
      assert.deepEqual(readdirSync(join(base, "real")), []);
      // The user's own folder with a loose mode is tightened
      mkdirSync(join(base, "e"));
      chmodSync(join(base, "e"), 0o777);
      writeInstance(join(base, "e/5.json"), "u");
      assert.deepEqual([mode(join(base, "e")), mode(join(base, "e/5.json"))], [0o700, 0o600]);
      // Where it goes: the runtime folder when set, else never straight into the shared temp folder
      process.env.XDG_RUNTIME_DIR = base;
      assert.equal(instanceFile(), join(base, "wirebuddy", `${process.pid}.json`));
      delete process.env.XDG_RUNTIME_DIR;
      const uid = process.getuid?.();
      if (uid === undefined) assert.equal(dirname(instanceFile()), join(tmpdir(), "wirebuddy"));
      else {
        const want = existsSync(`/run/user/${uid}`) ? `/run/user/${uid}/wirebuddy` : join(tmpdir(), `wirebuddy-${uid}`);
        assert.equal(instanceFile(), join(want, `${process.pid}.json`));
        assert.notEqual(dirname(instanceFile()), join(tmpdir(), "wirebuddy"));
      }
    } finally {
      if (saved === undefined) delete process.env.XDG_RUNTIME_DIR;
      else process.env.XDG_RUNTIME_DIR = saved;
      rmSync(base, { recursive: true, force: true });
    }
  });

  const limits = { marks: 3, note: 10, timeRefs: 2, commented: 2, comment: 20 };
  const investigation = () => ({
    marks: [{ frame: 2, note: "slow reply", by: "agent" }, { frame: 5, note: "", by: "user" }],
    timeRefs: [3],
    comments: { edited: [{ frame: 4, list: ["file's own\twith a tab", "added"], own: 1 }, { frame: 7, list: [], own: -1 }], cleared: 6, clearedFrames: [1, 6], unexported: [4, 9], clearedUnexported: true },
  });
  const captureInfo = { path: "/captures/a.pcapng", size: 1234, frames: 29 };

  await check("investigation: keyed by a SHA-256 of the capture's first bytes, in the data folder", () => {
    const head = Buffer.from("first bytes of a capture");
    assert.equal(investigationKey(head), createHash("sha256").update(head).digest("hex"));
    assert.notEqual(investigationKey(head), investigationKey(Buffer.from("first bytes of another")));
    assert.equal(investigationDir({ XDG_DATA_HOME: "/data" }), "/data/wirebuddy/investigations");
    assert.equal(investigationDir({}), join(userInfo().homedir, ".local/share/wirebuddy/investigations"));
  });

  await check("investigation: a round trip gives back what was kept, in a private folder and file", () => {
    const dir = join(mkdtempSync(join(out, "inv-")), "wirebuddy/investigations");
    const key = investigationKey(Buffer.from("a"));
    assert.equal(readInvestigation(dir, key, limits), null, "nothing kept, no folder");
    const text = serializeInvestigation(investigation(), captureInfo, new Date("2026-01-02T03:04:05Z"));
    const file = JSON.parse(text);
    assert.deepEqual([file.version, file.capture, file.saved], [1, captureInfo, "2026-01-02T03:04:05.000Z"]);
    writeInvestigation(dir, key, text);
    assert.deepEqual(readInvestigation(dir, key, limits), investigation());
    assert.deepEqual([statSync(dir).mode & 0o777, statSync(join(dir, `${key}.json`)).mode & 0o777], [0o700, 0o600]);
    assert.deepEqual(readdirSync(dir), [`${key}.json`], "no temp file left");
    // Written again: replaced whole, also a link left under its name, whose target stays
    const victim = join(dirname(dir), "victim");
    writeFileSync(victim, "keep");
    rmSync(join(dir, `${key}.json`));
    symlinkSync(victim, join(dir, `${key}.json`));
    writeInvestigation(dir, key, text);
    assert.equal(readFileSync(victim, "utf8"), "keep");
    assert.equal(lstatSync(join(dir, `${key}.json`)).isSymbolicLink(), false);
    assert.equal(investigationContent(readInvestigation(dir, key, limits)), investigationContent(investigation()));
  });

  await check("investigation: a file with anything wrong is refused whole and left alone", () => {
    const dir = mkdtempSync(join(out, "inv-bad-"));
    const key = investigationKey(Buffer.from("bad"));
    const good = JSON.parse(serializeInvestigation(investigation(), captureInfo));
    const variants = {
      "not JSON": "{ marks: [",
      "another version": { ...good, version: 2 },
      "no version": (({ version, ...rest }) => rest)(good),
      "a field more": { ...good, extra: 1 },
      "marks not a list": { ...good, marks: {} },
      "frame 0": { ...good, marks: [{ frame: 0, note: "", by: "user" }] },
      "a fractional frame": { ...good, timeRefs: [1.5] },
      "a frame as text": { ...good, timeRefs: ["3"] },
      "frames out of order": { ...good, timeRefs: [3, 2] },
      "a frame twice": { ...good, marks: [{ frame: 2, note: "", by: "user" }, { frame: 2, note: "", by: "user" }] },
      "too many marks": { ...good, marks: [1, 2, 3, 4].map((frame) => ({ frame, note: "", by: "user" })) },
      "too many time references": { ...good, timeRefs: [1, 2, 3] },
      "too long a note": { ...good, marks: [{ frame: 1, note: "x".repeat(11), by: "user" }] },
      "a note over two lines": { ...good, marks: [{ frame: 1, note: "a\nb", by: "user" }] },
      "another author": { ...good, marks: [{ frame: 1, note: "", by: "root" }] },
      "a mark field more": { ...good, marks: [{ frame: 1, note: "", by: "user", html: "<b>" }] },
      "too long a comment": { ...good, comments: { ...good.comments, edited: [{ frame: 1, list: ["y".repeat(21)], own: 0 }] } },
      "a written comment with a control character": { ...good, comments: { ...good.comments, edited: [{ frame: 1, list: ["a\u001bb"], own: 0 }] } },
      "too many commented packets": { ...good, comments: { ...good.comments, edited: [1, 2, 3].map((frame) => ({ frame, list: ["c"], own: 0 })) } },
      "own past the list": { ...good, comments: { ...good.comments, edited: [{ frame: 1, list: ["c"], own: 2 }] } },
      "a comment not text": { ...good, comments: { ...good.comments, edited: [{ frame: 1, list: [7], own: -1 }] } },
      "cleared frames past cleared": { ...good, comments: { ...good.comments, clearedFrames: [7] } },
      "cleared negative": { ...good, comments: { ...good.comments, cleared: -1 } },
      "unexported frame 0": { ...good, comments: { ...good.comments, unexported: [0] } },
      "clearedUnexported not a boolean": { ...good, comments: { ...good.comments, clearedUnexported: 1 } },
      "no capture": { ...good, capture: null },
    };
    for (const [why, v] of Object.entries(variants)) {
      writeFileSync(join(dir, `${key}.json`), typeof v === "string" ? v : JSON.stringify(v), { mode: 0o600 });
      assert.throws(() => readInvestigation(dir, key, limits), InvalidInvestigation, why);
      assert.ok(existsSync(join(dir, `${key}.json`)), `${why}: left alone`);
    }
    // A file over the size cap is refused unread
    writeFileSync(join(dir, `${key}.json`), " ".repeat(MAX_INVESTIGATION_BYTES + 1));
    assert.throws(() => readInvestigation(dir, key, limits), /bigger than 4 MiB/);
    // A link under the name is refused, not followed
    rmSync(join(dir, `${key}.json`));
    const elsewhere = join(out, "inv-elsewhere.json");
    writeFileSync(elsewhere, serializeInvestigation(investigation(), captureInfo));
    symlinkSync(elsewhere, join(dir, `${key}.json`));
    assert.throws(() => readInvestigation(dir, key, limits), /link/);
    // A folder that is a link is refused, read and write, and nothing is written there
    const real = mkdtempSync(join(out, "inv-real-"));
    writeFileSync(join(real, `${key}.json`), serializeInvestigation(investigation(), captureInfo));
    const linked = join(out, "inv-linked");
    symlinkSync(real, linked);
    assert.throws(() => readInvestigation(linked, key, limits), /not a folder/);
    assert.throws(() => writeInvestigation(linked, investigationKey(Buffer.from("x")), "{}"), /not a folder/);
    assert.deepEqual(readdirSync(real), [`${key}.json`]);
    // Another user's folder is refused (only root can make one here)
    if (process.getuid?.() === 0) {
      const theirs = mkdtempSync(join(out, "inv-theirs-"));
      writeFileSync(join(theirs, `${key}.json`), serializeInvestigation(investigation(), captureInfo));
      execFileSync("chown", ["-R", "65534", theirs]);
      assert.throws(() => readInvestigation(theirs, key, limits), /belongs to another user/);
      assert.throws(() => writeInvestigation(theirs, key, "{}"), /belongs to another user/);
    }
  });

  await check("investigation: nothing to keep without marks, time references and comments that differ from the file's; removing it", () => {
    const none = { marks: [], timeRefs: [], comments: { edited: [], cleared: 0, clearedFrames: [], unexported: [], clearedUnexported: false } };
    assert.equal(nothingToKeep(none), true);
    // Comments added and deleted again, or Delete All on a file without any: as the file has them
    assert.equal(nothingToKeep({ ...none, comments: { edited: [{ frame: 2, list: [], own: 0 }, { frame: 3, list: ["file's"], own: 1 }], cleared: 9, clearedFrames: [], unexported: [2], clearedUnexported: true } }), true);
    assert.equal(nothingToKeep({ ...none, marks: [{ frame: 1, note: "", by: "user" }] }), false);
    assert.equal(nothingToKeep({ ...none, timeRefs: [1] }), false);
    assert.equal(nothingToKeep({ ...none, comments: { ...none.comments, edited: [{ frame: 2, list: ["new"], own: 0 }] } }), false);
    assert.equal(nothingToKeep({ ...none, comments: { ...none.comments, cleared: 4, clearedFrames: [4] } }), false);
    const dir = mkdtempSync(join(out, "inv-rm-"));
    const key = investigationKey(Buffer.from("rm"));
    writeInvestigation(dir, key, serializeInvestigation(investigation(), captureInfo));
    removeInvestigation(dir, key);
    assert.deepEqual(readdirSync(dir), []);
    removeInvestigation(dir, key);
    removeInvestigation(join(dir, "missing"), key);
  });

  await check("investigation: a refused file set aside before the next write keeps its bytes, and the new file reads", () => {
    const dir = mkdtempSync(join(out, "inv-aside-"));
    const key = investigationKey(Buffer.from("aside"));
    const newer = JSON.stringify({ ...JSON.parse(serializeInvestigation(investigation(), captureInfo)), version: 2 });
    writeFileSync(join(dir, `${key}.json`), newer, { mode: 0o600 });
    assert.throws(() => readInvestigation(dir, key, limits), InvalidInvestigation);
    // An older one set aside before is replaced
    writeFileSync(join(dir, `${key}.unreadable`), "older");
    assert.equal(setAsideInvestigation(dir, key), join(dir, `${key}.unreadable`));
    writeInvestigation(dir, key, serializeInvestigation(investigation(), captureInfo));
    assert.equal(readFileSync(join(dir, `${key}.unreadable`), "utf8"), newer);
    assert.deepEqual(readInvestigation(dir, key, limits), investigation());
    assert.deepEqual(readdirSync(dir).sort(), [`${key}.json`, `${key}.unreadable`]);
    // Nothing to set aside: nothing happens
    assert.equal(setAsideInvestigation(dir, investigationKey(Buffer.from("none"))), null);
    assert.equal(setAsideInvestigation(join(dir, "missing"), key), null);
  });

  await check("investigation: what was kept, in words", () => {
    assert.equal(keptSummary(12, 1, 3), "12 marks, 1 time reference and the edited comments of 3 packets");
    assert.equal(keptSummary(1, 0, 1), "1 mark and the edited comments of 1 packet");
    assert.equal(keptSummary(0, 2, 0), "2 time references");
    assert.equal(keptSummary(0, 0, 0), "");
  });

  await check("investigation: a path under a regular file holds no folder: nothing is read, writing throws", () => {
    const plain = join(out, "inv-plain-file");
    writeFileSync(plain, "not a folder");
    const dir = join(plain, "wirebuddy/investigations");
    const key = investigationKey(Buffer.from("plain"));
    assert.equal(readInvestigation(dir, key, limits), null);
    assert.throws(() => writeInvestigation(dir, key, "{}"), /ENOTDIR|EEXIST/);
    assert.equal(pruneInvestigations(dir), 0);
    removeInvestigation(dir, key);
  });

  await check("investigation: over the size cap nothing is written", () => {
    const dir = mkdtempSync(join(out, "inv-big-"));
    const key = investigationKey(Buffer.from("big"));
    const big = { ...investigation(), comments: { ...investigation().comments, edited: Array.from({ length: 3000 }, (_, i) => ({ frame: i + 1, list: ["z".repeat(2000)], own: 0 })) } };
    const text = serializeInvestigation(big, captureInfo);
    assert.ok(Buffer.byteLength(text) > MAX_INVESTIGATION_BYTES);
    assert.throws(() => writeInvestigation(dir, key, text), /bigger than 4 MiB/);
    assert.deepEqual(readdirSync(dir), []);
  });

  await check("investigation: pruning keeps the newest by modification time, set-aside files among them, and removes temp files a write left long ago", () => {
    const dir = mkdtempSync(join(out, "inv-prune-"));
    const now = Date.now();
    const keys = Array.from({ length: 5 }, (_, i) => investigationKey(Buffer.from(`capture ${i}`)));
    keys.forEach((k, i) => {
      writeInvestigation(dir, k, "{}");
      const t = new Date(now - (5 - i) * 60_000);
      utimesSync(join(dir, `${k}.json`), t, t);
    });
    const stale = join(dir, `.${keys[0]}.123.tmp`);
    writeFileSync(stale, "half");
    utimesSync(stale, new Date(now - 3_600_000), new Date(now - 3_600_000));
    const fresh = join(dir, `.${keys[1]}.124.tmp`);
    writeFileSync(fresh, "being written");
    writeFileSync(join(dir, "notes.txt"), "not ours");
    // A set-aside file counts like the others, by its age: the newest here
    const aside = join(dir, `${keys[0]}.unreadable`);
    writeFileSync(aside, "set aside");
    assert.equal(pruneInvestigations(dir, 3, now), 4);
    assert.deepEqual(readdirSync(dir).sort(), [...keys.slice(3).map((k) => `${k}.json`), `${keys[0]}.unreadable`, `.${keys[1]}.124.tmp`, "notes.txt"].sort());
    assert.equal(pruneInvestigations(join(dir, "missing"), 3), 0);
  });

  await check("loopback: one port on every address, a taken port gives way to a free one, an address the machine lacks is left out", async () => {
    // On Linux every 127.x.y.z address can be bound: two of them stand in for the IPv4 and IPv6 loopback
    if (process.platform !== "linux") return console.log("skip the loopback check: only Linux binds every 127.x.y.z address");
    const hosts = ["127.0.0.1", "127.0.0.2"];
    const make = () => createServer((req, res) => res.end("ok"));
    const open = [];
    const hold = (port, host) =>
      new Promise((resolve, reject) => {
        const s = net.createServer();
        open.push(s);
        s.once("error", reject);
        s.listen(port, host, () => resolve(s));
      });
    const stop = (s) => new Promise((resolve) => (s.listening ? s.close(resolve) : resolve()));
    const ports = (l) => l.servers.map((s) => s.address().port);
    try {
      // The same port on both, and both answer
      const first = await listenLoopback(make, 0, hosts);
      open.push(...first.servers);
      assert.deepEqual(ports(first), [first.port, first.port]);
      for (const h of hosts) assert.equal(await (await fetch(`http://${h}:${first.port}/`)).text(), "ok");
      const p = first.port;
      await Promise.all(first.servers.map(stop));
      // Another program holds the port on the second address: another port, free on both, and the first address's old port is released
      await hold(p, "127.0.0.2");
      const moved = await listenLoopback(make, p, hosts);
      open.push(...moved.servers);
      assert.notEqual(moved.port, p);
      assert.deepEqual(ports(moved), [moved.port, moved.port]);
      await (await hold(p, "127.0.0.1")).close();
      await Promise.all(moved.servers.map(stop));
      // The port is in use on the first address: a free one
      await hold(p, "127.0.0.1");
      const fell = await listenLoopback(make, p, hosts);
      open.push(...fell.servers);
      assert.notEqual(fell.port, p);
      assert.equal(fell.servers.length, 2);
      await Promise.all(fell.servers.map(stop));
      // An address no interface has (EADDRNOTAVAIL) is left out, and nothing throws
      const some = await listenLoopback(make, 0, ["127.0.0.1", "192.0.2.1"]);
      open.push(...some.servers);
      assert.equal(some.servers.length, 1);
      assert.equal(some.servers[0].address().address, "127.0.0.1");
    } finally {
      await Promise.all(open.map(stop));
    }
  });

  // The findings report: text from captures, notes and comments never becomes Markdown
  const hostile = [
    // text, code span, table cell, blockquote
    ["plain", "`plain`", "`plain`", "> plain"],
    ["a`b", "``a`b``", "``a`b``", "> a\\`b"],
    ["``x``", "``` ``x`` ```", "``` ``x`` ```", "> \\`\\`x\\`\\`"],
    ["`", "`` ` ``", "`` ` ``", "> \\`"],
    [" lead and trail ", "`  lead and trail  `", "`  lead and trail  `", ">  lead and trail "],
    ["a|b", "`a|b`", "`a\\|b`", "> a\\|b"],
    ["line1\nline2\ttab", "`line1?line2?tab`", "`line1?line2?tab`", "> line1\n> line2 tab"],
    ["<script>alert(1)</script>", "`<script>alert(1)</script>`", "`<script>alert(1)</script>`", "> \\<script\\>alert\\(1\\)\\</script\\>"],
    ["![x](y)", "`![x](y)`", "`![x](y)`", "> \\!\\[x\\]\\(y\\)"],
    ["[x](javascript:alert(1))", "`[x](javascript:alert(1))`", "`[x](javascript:alert(1))`", "> \\[x\\]\\(javascript:alert\\(1\\)\\)"],
    ["# head", "`# head`", "`# head`", "> \\# head"],
    ["> q", "`> q`", "`> q`", "> \\> q"],
    ["- item", "`- item`", "`- item`", "> \\- item"],
    ["1. one", "`1. one`", "`1. one`", "> 1\\. one"],
    ["```js", "```` ```js ````", "```` ```js ````", "> \\`\\`\\`js"],
    ["&amp; &lt;", "`&amp; &lt;`", "`&amp; &lt;`", "> \\&amp; \\&lt;"],
    ["nul\0x", "`nul?x`", "`nul?x`", "> nul?x"],
    ["http://evil.example/x www.evil.com a@b.c", "`http://evil.example/x www.evil.com a@b.c`", "`http://evil.example/x www.evil.com a@b.c`", "> http\\://evil\\.example/x www\\.evil\\.com a\\@b\\.c"],
    ["***", "`***`", "`***`", "> \\*\\*\\*"],
    ["===", "`===`", "`===`", "> \\=\\=\\="],
    ["a\\b", "`a\\b`", "`a\\b`", "> a\\\\b"],
    ["", "", "", ">"],
  ];
  await check("findings text: code spans, table cells and quotes of hostile text read exactly as given", () => {
    for (const [text, span, inCell, quoted] of hostile) {
      assert.equal(codeSpan(text), span, `span of ${JSON.stringify(text)}`);
      assert.equal(cell(text), inCell, `cell of ${JSON.stringify(text)}`);
      assert.equal(quote(text), quoted, `quote of ${JSON.stringify(text)}`);
    }
  });
  await check("findings text: a quote escapes every line, empty ones stay in it, any line break ends a line", () => {
    assert.equal(quote("# a\n\n- b\r\n1. c\r> d\n```\n"), "> \\# a\n>\n> \\- b\n> 1\\. c\n> \\> d\n> \\`\\`\\`\n>");
    assert.equal(escapeLine("x y\u0085z"), "x?y?z");
  });
  await check("findings text: in a table cell an odd number of backslashes stands before every pipe, so none ends the cell, whatever backslashes the text has there", () => {
    assert.equal(cell("a|b"), "`a\\|b`");
    assert.equal(cell("a\\|b"), "`a\\\\\\|b`");
    assert.equal(cell("a\\\\|b"), "`a\\\\\\\\\\|b`");
    for (const text of ["|", "\\|", "\\\\|", "\\\\\\| [x](javascript:alert(1))", "a|b\\|c\\\\|d", "x\\", "\\|\\|"]) {
      const out = cell(text);
      for (const m of out.matchAll(/(\\*)\|/g)) assert.equal(m[1].length % 2, 1, `${JSON.stringify(text)} gives ${out}`);
    }
  });
  await check("findings text: no span can be closed from inside, whatever backtick runs it holds", () => {
    for (const text of ["`", "``", "a`b``c```d", "```", "x`", "`x", "`` ` ``"]) {
      const span = codeSpan(text);
      const fence = /^`+/.exec(span)[0];
      const runs = (span.slice(fence.length, -fence.length).match(/`+/g) ?? []).map((r) => r.length);
      assert.ok(runs.every((n) => n < fence.length), `fence of ${JSON.stringify(text)}: ${span}`);
      assert.ok(span.endsWith(fence));
    }
  });
  await check("findings summary: kept as given but for trailing whitespace; a NUL, other control characters and more than 16 KiB are refused", () => {
    assert.equal(checkSummary("## Found\n\n- tab\there \n\n"), "## Found\n\n- tab\there");
    assert.equal(checkSummary(" \n"), "");
    for (const bad of ["a\0b", "a\rb", "a\x1b[31mb", "a\x08b", "a\x0bb"]) assert.throws(() => checkSummary(bad), /control characters/, JSON.stringify(bad));
    assert.equal(checkSummary("x".repeat(MAX_SUMMARY_BYTES)).length, MAX_SUMMARY_BYTES);
    assert.throws(() => checkSummary("x".repeat(MAX_SUMMARY_BYTES + 1)), /16 KiB/);
    assert.throws(() => checkSummary("é".repeat(MAX_SUMMARY_BYTES / 2 + 1)), /16 KiB/);
  });

  const row = (n, extra = {}) => ({ time: `0.00${n}`, source: `10.0.0.${n}`, destination: "10.0.0.9", protocol: "TCP", info: `${n} > 80 [SYN]`, ...extra });
  const base = {
    name: "robot.pcapng",
    path: "/cap/robot.pcapng",
    packets: 120,
    bytes: 45678,
    duration: 12.3456,
    live: false,
    filter: "",
    decodeAs: [],
    timeRefs: [],
    version: "1.2.3",
    at: new Date("2026-11-12T10:20:30.456Z"),
    summary: "",
    marks: [],
    commented: [],
  };
  await check("findings report: a capture with nothing marked or commented is the heading and the facts", () => {
    assert.equal(buildFindings(base), "# Findings: `robot.pcapng`\n\n## Capture\n- File: `/cap/robot.pcapng`\n- 120 packets, 45678 bytes, 12.346 s\n- Written by WireBuddy 1.2.3 on 2026-11-12T10:20:30Z\n");
    assert.match(buildFindings({ ...base, packets: 1 }), /\n- 1 packet, /);
  });
  await check("findings report: the whole format, pinned", () => {
    const text = buildFindings({
      ...base,
      live: true,
      summary: "The arm **stalls** after each command.\n\n- evidence: packets 3 and 17\n\n",
      filter: "tcp.port == 80",
      decodeAs: ["udp.port 50000 → rtp", "tcp.port 9 → http"],
      timeRefs: [3, 17],
      marks: [
        { frame: 3, note: "first <b>stall</b>", by: "agent", provisional: false, row: row(3) },
        { frame: 17, note: "", by: "user", provisional: false, row: row(1, { info: "a | b `c`" }) },
        { frame: 121, note: "newest", by: "user", provisional: true, row: null },
      ],
      commented: [
        { frame: 3, comments: ["first\nsecond line\n# not a heading", "[x](javascript:alert(1))"], provisional: false, row: row(3) },
        { frame: 122, comments: ["only known so far"], provisional: true, row: null },
      ],
    });
    assert.equal(
      text,
      [
        "# Findings: `robot.pcapng`",
        "",
        "The arm **stalls** after each command.",
        "",
        "- evidence: packets 3 and 17",
        "",
        "## Capture",
        "- File: `/cap/robot.pcapng`",
        "- 120 packets, 45678 bytes, 12.346 s (live capture, still running)",
        "- Display filter: `tcp.port == 80`",
        "- Decode As: `udp.port 50000 → rtp`, `tcp.port 9 → http`",
        "- Time references: packets 3, 17",
        "- Written by WireBuddy 1.2.3 on 2026-11-12T10:20:30Z",
        "",
        "## Marked packets",
        "",
        "| Packet | Time | Source | Destination | Protocol | Info | Note | By |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
        "| 3 | `0.003` | `10.0.0.3` | `10.0.0.9` | `TCP` | `3 > 80 [SYN]` | `first <b>stall</b>` | agent |",
        "| 17 | `0.001` | `10.0.0.1` | `10.0.0.9` | `TCP` | `` a \\| b `c` `` |  | user |",
        "| 121 (provisional) |  |  |  |  |  | `newest` | user |",
        "",
        "## Packet comments",
        "",
        "### Packet 3: `TCP` `10.0.0.3` → `10.0.0.9`",
        "`3 > 80 [SYN]`",
        "> first",
        "> second line",
        "> \\# not a heading",
        ">",
        "> \\[x\\]\\(javascript:alert\\(1\\)\\)",
        "",
        "### Packet 122 (provisional)",
        "> only known so far",
        "",
      ].join("\n"),
    );
  });
  await check("findings report: a single time reference is named in the singular", () => {
    assert.match(buildFindings({ ...base, timeRefs: [5] }), /\n- Time references: packet 5\n/);
  });
  await check("findings report: at most 2,000 marked and 2,000 commented packets are written, one line counts the rest", () => {
    const marks = Array.from({ length: MAX_LISTED + 5 }, (_, i) => ({ frame: i + 1, note: "", by: "user", provisional: false, row: null }));
    const commented = Array.from({ length: MAX_LISTED + 1 }, (_, i) => ({ frame: i + 1, comments: ["c"], provisional: false, row: null }));
    const text = buildFindings({ ...base, marks, commented });
    assert.equal(text.split("\n").filter((l) => /^\| \d+ \|/.test(l)).length, MAX_LISTED);
    assert.equal(text.split("\n").filter((l) => /^### Packet /.test(l)).length, MAX_LISTED);
    assert.match(text, /\n5 more marked packets not listed\.\n/);
    assert.match(text, /\n1 more packet with comments not listed\.\n/);
    assert.doesNotMatch(text, /\| 2001 \|/);
    // The caller may have counted more beyond the ones it hands over
    const more = buildFindings({ ...base, marks: marks.slice(0, 1), moreMarks: 1, commented: commented.slice(0, 1), moreCommented: 7 });
    assert.match(more, /\n1 more marked packet not listed\.\n/);
    assert.match(more, /\n7 more packets with comments not listed\.\n/);
  });

  const reportDir = mkdtempSync(join(out, "report-"));
  await check("findings report: a new file is written 0600 and whole, one that exists only with overwrite, never through a link, with no temporary file left", () => {
    const file = join(reportDir, "one.md");
    assert.equal(writeReport(file, "# one\n", false), 6);
    assert.equal(readFileSync(file, "utf8"), "# one\n");
    assert.equal(statSync(file).mode & 0o777, 0o600);
    assert.throws(() => writeReport(file, "# two\n", false), TargetExists);
    assert.equal(readFileSync(file, "utf8"), "# one\n");
    writeReport(file, "# three\n", true);
    assert.equal(readFileSync(file, "utf8"), "# three\n");
    assert.equal(statSync(file).mode & 0o777, 0o600);
    // A link in the name: a new file is refused, and an overwrite refuses it as well, leaving what it points to alone
    const target = join(reportDir, "target.txt");
    writeFileSync(target, "mine");
    const link = join(reportDir, "link.md");
    symlinkSync(target, link);
    assert.throws(() => writeReport(link, "x", false), TargetExists);
    assert.throws(() => writeReport(link, "x", true), /is a link/);
    assert.equal(readFileSync(target, "utf8"), "mine");
    assert.deepEqual(readdirSync(reportDir).sort(), ["link.md", "one.md", "target.txt"]);
  });
  await check("findings report: more than 4 MiB is refused before anything is written", () => {
    const file = join(reportDir, "big.md");
    assert.throws(() => writeReport(file, "x".repeat(MAX_REPORT_BYTES + 1), false), /4 MiB/);
    assert.equal(existsSync(file), false);
    assert.equal(writeReport(file, "x".repeat(MAX_REPORT_BYTES), false), MAX_REPORT_BYTES);
  });
  await check("findings report: the target is checked as an export's is", () => {
    const file = join(reportDir, "t.md");
    assert.throws(() => checkReportTarget("rel.md", [], false), /must be absolute/);
    assert.throws(() => checkReportTarget(join(reportDir, "t.txt"), [], false), /end in \.md/);
    assert.throws(() => checkReportTarget(join(reportDir, "none", "t.md"), [], false), /no such directory/);
    checkReportTarget(file, [], false);
    writeFileSync(file, "x");
    assert.throws(() => checkReportTarget(file, [], false), TargetExists);
    checkReportTarget(file, [], true);
    assert.throws(() => checkReportTarget(file, [file], true), /open capture/);
    mkdirSync(join(reportDir, "dir.md"));
    assert.throws(() => checkReportTarget(join(reportDir, "dir.md"), [], true), /not a file/);
  });
  await check("patch: only the fields that changed, a value rebuilt equal isn't one, and big unchanged values are never serialised", () => {
    const marks = [{ frame: 1 }];
    const prev = { marks, rows: [[1, 2]], filter: "", total: 3, capture: { n: 1 } };
    const seen = [];
    const jsonOf = (v) => (seen.push(v), JSON.stringify(v));
    const next = { marks, rows: [[1, 2]], filter: "tcp", total: 3, capture: { n: 2 } };
    assert.deepEqual(changedFields(prev, next, jsonOf), { filter: '"tcp"', capture: '{"n":2}' });
    assert.ok(!seen.includes(marks));
    assert.deepEqual(changedFields(prev, { ...prev, rows: [[1, 2]] }, jsonOf), {});
    assert.deepEqual(changedFields(prev, { ...prev, filter: null }, jsonOf), { filter: "null" });
    assert.deepEqual(changedFields(prev, prev, jsonOf), {});
    assert.deepEqual(changedFields({ a: null }, { a: { b: 1 } }, jsonOf), { a: '{"b":1}' });
    assert.deepEqual(JSON.parse(patchMessage(7, { filter: '"tcp"', capture: '{"n":2}' })), { type: "patch", seq: 7, patch: { filter: "tcp", capture: { n: 2 } } });
    assert.deepEqual(JSON.parse(patchMessage(8, {})), { type: "patch", seq: 8, patch: {} });
  });
  await check("view store: set applies a patch, runs the rules and tells once; merge tells nobody; a rule may change the state; what the patch leaves alone keeps its identity", () => {
    const marks = [{ frame: 1 }];
    const told = [];
    const store = new ViewStore({ file: null, kept: true, marks, n: 0 }, (state) => told.push(state));
    store.merge({ n: 1 });
    assert.equal(told.length, 0);
    assert.equal(store.state.n, 1);
    store.set({ file: "a.pcap" });
    assert.equal(told.length, 1);
    assert.equal(told[0], store.state);
    assert.equal(store.state.marks, marks);
    const seen = [];
    store.after((state) => (seen.push(state.n), state.kept && state.file === "b.pcap" ? { ...state, kept: false } : state));
    store.set({ n: 2 });
    assert.deepEqual(seen, [2]);
    assert.equal(store.state.kept, true);
    store.set({ file: "b.pcap" });
    assert.equal(store.state.kept, false);
    assert.equal(store.state.file, "b.pcap");
    assert.equal(told.length, 3);
    assert.equal(told[2], store.state);
    assert.equal(store.state.marks, marks);
  });
  /** Edits with a fake viewer: a capture is open while `open.file`, the state's revision is `open.revision`. */
  const editsOf = (open = { file: true, revision: 0 }) => ({ open, edits: new Edits({ requireFile: () => { if (!open.file) throw new Error("no capture is open"); }, revision: () => open.revision }) });
  /** Comments as read for `frames`: the file's from `file` (frame -> list), as comments.ts reads them. */
  const read = (frames, file = {}) => new Map(frames.map((f) => [f, { list: file[f] ?? [], own: (file[f] ?? []).length }]));
  await check("edits: marks from requests: frames the view knows, deduplicated and sorted, notes printable and cut, others' marks replaced; at most 10,000", () => {
    const m0 = [{ frame: 5, note: "old", by: "user" }, { frame: 2, note: "", by: "user" }];
    const r = marksWith(m0, [7, 3, 3, 0, 1.5, 9, 5], `a\u0001b\n${"x".repeat(300)}`, "agent", 8);
    assert.deepEqual(r.frames, [7, 3, 5]);
    assert.equal(r.note, `a?b?${"x".repeat(MAX_NOTE - 4)}`);
    assert.deepEqual(r.marks.map((m) => [m.frame, m.by]), [[2, "user"], [3, "agent"], [5, "agent"], [7, "agent"]]);
    assert.equal(r.marks[2].note, r.note);
    assert.deepEqual(m0.map((m) => m.frame), [5, 2], "the marks given are left as they are");
    const full = Array.from({ length: MAX_MARKS }, (_, i) => ({ frame: i + 1, note: "", by: "user" }));
    assert.equal(marksWith(full, [1, 2], "again", "user", MAX_MARKS + 1).marks.length, MAX_MARKS, "remarking counts once");
    assert.throws(() => marksWith(full, [MAX_MARKS + 1], "", "user", MAX_MARKS + 1), /at most 10000 frames can be marked/);
    assert.deepEqual(marksWithout(r.marks, [3, 7, 99]).map((m) => m.frame), [2, 5]);
    assert.deepEqual(marksWithout(r.marks), []);
    const t = toggledMarks(m0, [[1, 2], [5, 6]], "agent");
    assert.deepEqual(t, [{ frame: 1, note: "", by: "agent" }, { frame: 6, note: "", by: "agent" }]);
    assert.equal(toggledMarks(full, [[1, 1]], "user").length, MAX_MARKS - 1);
    assert.throws(() => toggledMarks(full, [[MAX_MARKS + 1, MAX_MARKS + 1]], "user"), /at most 10000/);
    // A list of rows 0..3 showing frames 2, 4, 6, 8
    const shownFrames = [2, 4, 6, 8];
    const list = { rows: 4, shown: (f) => shownFrames.includes(f), frames: ([[a, b]]) => shownFrames.slice(a, b + 1).map((f) => [f, f]) };
    const on = displayedMarks([{ frame: 4, note: "kept", by: "user" }, { frame: 5, note: "", by: "user" }], true, "agent", list);
    assert.deepEqual(on.map((m) => [m.frame, m.note, m.by]), [[2, "", "agent"], [4, "kept", "user"], [5, "", "user"], [6, "", "agent"], [8, "", "agent"]]);
    assert.deepEqual(displayedMarks(on, false, "agent", list).map((m) => m.frame), [5]);
    assert.deepEqual(displayedMarks(on, true, "agent", { ...list, rows: 0 }), on, "an empty list marks nothing");
    assert.throws(() => displayedMarks(full.slice(0, MAX_MARKS - 1), true, "user", { rows: 2, shown: () => false, frames: () => [[MAX_MARKS, MAX_MARKS + 1]] }), /at most 10000/);
  });
  await check("edits: time references from requests: known frames, sorted, toggled, at most 10,000; what a change set and unset", () => {
    assert.deepEqual(refsWith([4, 9], [7, 1, 1, 12, 2.5, 0], true, 10), [1, 4, 7, 9]);
    assert.deepEqual(refsWith([1, 4, 7, 9], [4, 9, 12], false, 10), [1, 7]);
    assert.deepEqual(refsWith([1, 4], [12], false, 10), [1, 4], "unknown frames are left out");
    const full = Array.from({ length: MAX_TIME_REFS }, (_, i) => i + 1);
    assert.equal(refsWith(full, [1], true, MAX_TIME_REFS + 1).length, MAX_TIME_REFS);
    assert.throws(() => refsWith(full, [MAX_TIME_REFS + 1], true, MAX_TIME_REFS + 1), /at most 10000 frames can be time references/);
    assert.deepEqual(toggledRefs([2, 5, 9], [[1, 2], [5, 6]]), [1, 6, 9]);
    assert.deepEqual(toggledRefs([], [[3, 3]]), [3]);
    assert.equal(toggledRefs(full, [[1, 1]]).length, MAX_TIME_REFS - 1);
    assert.throws(() => toggledRefs(full, [[MAX_TIME_REFS + 1, MAX_TIME_REFS + 1]]), /at most 10000/);
    assert.deepEqual(refsChange([2, 5, 9], [1, 6, 9]), { set: [1, 6], unset: [2, 5] });
    assert.deepEqual(refsChange([3], [3]), { set: [], unset: [] });
  });
  await check("edits: a comment as editcap writes it, and the comment an edit names only while it still reads the same", () => {
    assert.equal(commentText("a\r\nb\rc\nd\te "), "a\nb\nc\nd?e?");
    assert.throws(() => commentText("x".repeat(2001)), /at most 2000 characters/);
    assert.equal(commentAt(["a", "b"], 3, 1, "b"), 1);
    assert.throws(() => commentAt(["a"], 3, 1, "a"), /frame 3 has no comment 2/);
    assert.throws(() => commentAt(["a"], 3, 0, "b"), (err) => err instanceof StaleGenerationError && /comment 1 of frame 3 changed meanwhile/.test(err.message));
  });
  await check("edits: comment edits, Delete All and what isn't exported come back from a snapshot as they were", () => {
    const { open, edits } = editsOf({ file: true, revision: 6 });
    const file = { 2: ["file 2"], 4: ["file 4a", "file 4b"], 8: ["file 8"] };
    const added = edits.edit([2, 3], read([2, 3], file), (now) => [...now, "mine"]);
    assert.deepEqual(added.frames, [2, 3]);
    assert.deepEqual(added.patch, { commentEdits: 2, commentsEdited: 2, commentRevision: 7 });
    assert.deepEqual(edits.edit([2, 3], read([2, 3]), (now) => now), { frames: [], patch: null }, "unchanged frames are left out");
    open.revision = 7;
    const cleared = edits.clearAll(Int32Array.from([2, 4, 8, 12]), 10);
    assert.deepEqual(cleared.frames, [2, 3, 4, 8], "the file's comments of known frames, and the edited ones");
    assert.deepEqual(cleared.patch, { commentEdits: 4, commentsEdited: 3, commentRevision: 8 });
    open.revision = 8;
    // Frame 4 gets a comment again, its file's own ones gone
    edits.edit([4], new Map([[4, { list: [], own: 0 }]]), () => ["again"]);
    const marks = [{ frame: 1, note: "n", by: "user" }];
    const inv = edits.snapshot(marks, [3]);
    assert.deepEqual(inv, {
      marks,
      timeRefs: [3],
      comments: { edited: [{ frame: 4, list: ["again"], own: 0 }], cleared: 10, clearedFrames: [2, 4, 8], unexported: [2, 3, 4], clearedUnexported: true },
    });
    const before = edits.summary(10);
    assert.deepEqual(before, { packets: 3, cleared: 10, frames: 1, list: [[4, ["again"]]] });
    const back = editsOf({ file: true, revision: 20 }).edits;
    back.dropAll();
    assert.deepEqual(back.restore(JSON.parse(JSON.stringify(inv))), { marks, timeRefs: [3], commentEdits: 4, commentsEdited: 3, commentRevision: 21 });
    assert.deepEqual(back.snapshot(marks, [3]), inv);
    assert.deepEqual(back.summary(10), before);
    assert.deepEqual(back.edited().cleared, 10);
    assert.deepEqual(back.edited().comments.get(4), { list: ["again"], own: 0 });
    // Exported before Delete All: only the frames edited since count
    const exported = editsOf().edits;
    exported.restore({ marks: [], timeRefs: [], comments: { edited: [{ frame: 5, list: ["x"], own: 1 }], cleared: 3, clearedFrames: [1, 3], unexported: [5], clearedUnexported: false } });
    assert.equal(exported.snapshot([], []).comments.clearedUnexported, false);
    assert.deepEqual(exported.forExport([[1, 10]]).edited, 3, "an export still writes the comments Delete All took");
  });
  await check("edits: pruning to a shorter capture drops the marks, references and comments past it; dropping all leaves edits queued before refused", async () => {
    const { open, edits } = editsOf({ file: true, revision: 1 });
    edits.edit([2, 6, 9], read([2, 6, 9]), () => ["c"]);
    open.revision = 2;
    edits.clearAll(new Int32Array(0), 7);
    open.revision = 3;
    edits.edit([3, 8], read([3, 8]), () => ["d"]);
    open.revision = 4;
    const marks = [{ frame: 1, note: "", by: "user" }, { frame: 8, note: "", by: "agent" }];
    const refs = [2, 7];
    const same = edits.prune(9, marks, refs);
    assert.deepEqual(same.marks, marks);
    assert.equal(same.timeRefs, refs, "references up to the end stay the same array");
    assert.equal(same.commentEdits, undefined, "nothing of the comments went: the state hears nothing of them");
    const p = edits.prune(5, marks, refs);
    assert.deepEqual(p, { marks: [marks[0]], timeRefs: [2], commentEdits: 2, commentsEdited: 1, commentRevision: 5 });
    const s = edits.snapshot([], []).comments;
    assert.deepEqual([s.edited.map((e) => e.frame), s.cleared, s.clearedFrames, s.unexported], [[3], 5, [], [2, 3]]);
    // Queued behind a slow edit of this capture: the capture goes meanwhile
    const capture = edits.capture();
    let release;
    const slow = edits.queue(capture, () => new Promise((r) => (release = r)));
    const later = edits.queue(capture, async () => "ran");
    await new Promise((r) => setImmediate(r));
    assert.deepEqual(edits.dropAll(), { marks: [], timeRefs: [], commentEdits: 0, commentsEdited: 0, commentRevision: 5 });
    assert.equal(edits.isCapture(capture), false);
    assert.throws(() => edits.sameCapture(capture), StaleGenerationError);
    release("slow");
    assert.equal(await slow, "slow");
    await assert.rejects(later, (err) => err instanceof StaleGenerationError && /closed or another one opened/.test(err.message));
    assert.deepEqual(edits.snapshot([], []).comments, { edited: [], cleared: 0, clearedFrames: [], unexported: [], clearedUnexported: false });
    open.file = false;
    await assert.rejects(edits.queue(edits.capture(), async () => "x"), /no capture is open/, "no capture: refused before anything else");
    open.file = true;
    assert.equal(await edits.queue(edits.capture(), async () => "x"), "x", "a failed edit doesn't hold up the next");
  });
  await check("edits: an export of every packet counts the edits it wrote as exported, later ones still count; the edited packets stay; the file's commented frames are read once per full read", async () => {
    const { edits } = editsOf();
    edits.edit([1, 2], read([1, 2], { 2: ["own"] }), (now) => [...now, "a"]);
    const at = edits.checkpoint();
    edits.edit([3], read([3]), () => ["b"]);
    const out = edits.forExport([[2, 3]]);
    assert.deepEqual([...out.comments], [[2, { own: true, texts: ["a"] }], [3, { own: undefined, texts: ["b"] }]]);
    assert.equal(out.edited, 2);
    assert.equal(edits.exported(at), 1, "frame 3 was edited after the export started");
    assert.equal(edits.editedPackets(), 3);
    assert.equal(edits.exported(edits.checkpoint()), 0);
    assert.equal(edits.summary(1).packets, 3);
    assert.deepEqual(edits.snapshot([], []).comments.unexported, []);
    // Delete All after the export: it counts until the next one, its frames once with the ones edited since
    edits.clearAll(Int32Array.from([5, 6]), 6);
    edits.edit([6], new Map([[6, { list: [], own: 0 }]]), () => ["c"]);
    assert.equal(edits.exported({ capture: edits.capture(), edit: 0 }), 5, "1, 2, 3 and 6 edited since, and 5, which Delete All took");
    const stale = edits.checkpoint();
    edits.dropAll();
    assert.equal(edits.exported(stale), null, "an export of a capture the view left");
    // The file's commented frames: once for each full read, again after dropAll
    let reads = 0;
    const fileRead = async () => (reads++, Int32Array.from([4]));
    assert.equal(edits.fileCommentsKnown(1), false);
    assert.deepEqual([...(await edits.fileCommented(1, fileRead))], [4]);
    await edits.fileCommented(1, fileRead);
    assert.equal(edits.fileCommentsKnown(1), true);
    await edits.fileCommented(2, fileRead);
    edits.dropAll();
    await edits.fileCommented(2, fileRead);
    assert.equal(reads, 3);
    edits.edit([1, 4], read([1, 4], { 4: ["file"] }), (now) => (now.length ? [] : ["new"]));
    assert.deepEqual(await edits.commented(fileRead), [1], "frame 4's file comment was deleted here");
    edits.left(false, 7);
    assert.equal(edits.dropped(), 7);
    edits.left(true, 7);
    assert.equal(edits.dropped(), 0);
  });
  await check("packet list: rows and frames with and without a display filter and a tail, refused row ranges, clipping, startsWith", () => {
    const tail = { frames: 5, filter: "x", held: null, listed: () => 2, indexOf: (f) => ({ 103: 0, 105: 1 })[f] ?? -1, frameAt: (i) => [103, 105][i], unchecked: (f) => f === 104 };
    const list = new PacketList();
    const plain = { totalFrames: 100, displayedFrames: 100, tail: null };
    assert.equal(list.indexOf(7, plain), 6);
    assert.equal(list.indexOf(101, plain), -1);
    assert.equal(list.indexOf(null, plain), -1);
    assert.deepEqual(list.framesOfRows([[0, 2], [9, 9]], plain), [[1, 3], [10, 10]]);
    list.setDisplayed(Int32Array.from([5, 6, 9, 40]));
    const filtered = { totalFrames: 100, displayedFrames: 4, tail: null };
    assert.equal(list.indexOf(9, filtered), 2);
    assert.equal(list.indexOf(7, filtered), -1);
    assert.deepEqual(list.framesOfRows([[0, 2], [3, 3]], filtered), [[5, 6], [9, 9], [40, 40]]);
    const live = { totalFrames: 100, displayedFrames: 4, tail };
    assert.equal(list.known(live), 105);
    assert.equal(list.length(live), 6);
    assert.equal(list.indexOf(105, live), 5);
    assert.equal(list.indexOf(104, live), -1);
    assert.deepEqual(list.framesOfRows([[2, 5]], live), [[9, 9], [40, 40], [103, 103], [105, 105]]);
    assert.deepEqual(list.rowFrames(live).exact, 100);
    assert.deepEqual(Array.from({ length: 6 }, (_, i) => list.rowFrames(live).at(i)), [5, 6, 9, 40, 103, 105]);
    assert.deepEqual(list.page(3, 10, live), { count: 3, exact: 1 });
    assert.deepEqual(list.page(0, 1000, { totalFrames: 9000, displayedFrames: 9000, tail: null }), { count: 500, exact: 500 });
    assert.deepEqual(list.select(105, [[4, 5]], live), { selectedIndex: 5, selectedRows: [[4, 5]] });
    assert.deepEqual(list.select(9, undefined, live), { selectedIndex: 2, selectedRows: [[2, 2]] });
    assert.deepEqual(list.select(null, undefined, live), { selectedIndex: -1, selectedRows: [] });
    assert.throws(() => list.select(104, undefined, live) && list.select(104.5, undefined, live), /no frame 104.5/);
    assert.throws(() => list.select(104, undefined, { ...live, tail: null }), /no frame 104/);
    assert.throws(() => list.select(0, undefined, live), /no frame 0/);
    assert.throws(() => list.checkRows([[0, 6]], live), /invalid row range \[0, 6\] \(6 rows are displayed\)/);
    assert.throws(() => list.checkRows([[2, 1]], live), /invalid row range \[2, 1\]/);
    assert.throws(() => list.checkRows([[-1, 1]], live), /invalid row range \[-1, 1\]/);
    assert.throws(() => list.checkRows([[0.5, 1]], live), /invalid row range/);
    assert.throws(() => list.checkRows(Array.from({ length: 10001 }, (_, i) => [i, i]), { totalFrames: 20000, displayedFrames: 20000, tail: null }), /at most 10000 row ranges can be selected/);
    assert.deepEqual(list.checkRows([[3, 4], [0, 1], [1, 2]], live), [[0, 4]]);
    // the list got shorter: the selection is cut to the rows that remain
    assert.deepEqual(clipRanges([[0, 1], [3, 9], [12, 14]], 5), [[0, 1], [3, 4]]);
    assert.deepEqual(list.selectedFrames([[0, 1], [3, 9]], filtered), [[5, 6], [40, 40]]);
    assert.deepEqual(list.selectedOrCurrent({ selectedCount: 0, selectedRows: [], selected: 9 }, filtered), [[9, 9]]);
    assert.deepEqual(list.selectedOrCurrent({ selectedCount: 0, selectedRows: [], selected: null }, filtered), []);
    assert.deepEqual(list.selectedOrCurrent({ selectedCount: 1, selectedRows: [[0, 0]], selected: 9 }, filtered), [[5, 5]]);
    assert.equal(list.unlisted(104, live), "not checked against the display filter yet");
    assert.equal(list.unlisted(7, live), "hidden by the current display filter");
    assert.equal(list.unlisted(104, { ...live, tail: { ...tail, held: "a stream index" } }), "listed once read in full, as a stream index");
    const rows = (frames) => ({ length: frames.length, at: (i) => frames[i] });
    assert.equal(startsWith(rows([1, 2, 3, 4]), rows([1, 2, 3])), true);
    assert.equal(startsWith(rows([1, 2]), rows([1, 2, 3])), false);
    assert.equal(startsWith(rows([1, 9, 3]), rows([1, 2, 3])), false);
    assert.deepEqual(rowOf(-1), []);
    assert.equal(listChanged({ file: "a", filter: "", generation: 5 }, { file: "a", filter: "", rowsSince: 5 }), false);
    assert.equal(listChanged({ file: "a", filter: "", generation: 4 }, { file: "a", filter: "", rowsSince: 5 }), true);
    assert.equal(listChanged({ file: "a", filter: "" }, { file: "a", filter: "", rowsSince: 5 }), false);
    assert.equal(listChanged({ file: "b", filter: "" }, { file: "a", filter: "", rowsSince: 0 }), true);
  });
} finally {
  rmSync(out, { recursive: true, force: true });
}
finish();
