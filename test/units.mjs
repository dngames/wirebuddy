// Unit checks of the panel data's parts: frame sets, the layer finder, raw matches, the page format, sharkd's answer limit.
// Usage: node test/units.mjs   (bundles the sources itself)
import { build } from "esbuild";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const out = mkdtempSync(join(tmpdir(), "wirebuddy-units-"));
const entry = join(out, "entry.ts");
writeFileSync(
  entry,
  ["paneldata", "layers", "wbpk", "sharkd"].map((m) => `export * from ${JSON.stringify(join(root, `src/server/${m}.ts`))};`).join("\n"),
);
await build({ entryPoints: [entry], outfile: join(out, "units.mjs"), bundle: true, platform: "node", format: "esm", packages: "external", logLevel: "silent" });
const { FrameSet, findLayer, parse, Parsed, rawMatch, ApiError, encodePage, Sharkd, SharkdTooLarge, matchingFrames } = await import(join(out, "units.mjs"));

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
} finally {
  rmSync(out, { recursive: true, force: true });
}
console.log(failures ? `${failures} check(s) failed` : "all checks passed");
process.exit(failures ? 1 : 0);
