// Unit checks of the panel data's parts (frame sets, the layer finder, raw matches, the page format, sharkd's answer limit),
// export runs, saved objects, the event log and the cleanup of slice folders.
// Usage: node test/units.mjs   (bundles the sources itself)
import { build } from "esbuild";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, renameSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { createRequire, syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const out = mkdtempSync(join(tmpdir(), "wirebuddy-units-"));
const entry = join(out, "entry.ts");
writeFileSync(
  entry,
  ["paneldata", "layers", "wbpk", "sharkd", "export", "objects", "events", "extensions", "livetail", "timerefs"].map((m) => `export * from ${JSON.stringify(join(root, `src/server/${m}.ts`))};`).join("\n"),
);
await build({ entryPoints: [entry], outfile: join(out, "units.mjs"), bundle: true, platform: "node", format: "esm", packages: "external", logLevel: "silent" });
const { FrameSet, findLayer, parse, Parsed, rawMatch, ApiError, encodePage, Sharkd, SharkdTooLarge, matchingFrames, splitRuns, commentPasses, exportFrames, objectFileName, objectDir, newObjectFolder, writeObject, EventLog, Extensions, slicesPrefix, removeStaleSlices } =
  await import(join(out, "units.mjs"));
const { refBefore, refsOf, refsUpTo, refsParam, framesWithRefs, refTimeFilter, refTimeFits, refTimeError, usesRefTime, changeText, SharkdError } = await import(join(out, "units.mjs"));

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
} finally {
  rmSync(out, { recursive: true, force: true });
}
console.log(failures ? `${failures} check(s) failed` : "all checks passed");
process.exit(failures ? 1 : 0);
