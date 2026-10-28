// FrameStore and the layer parser: pcap and pcapng read straight from the file, checked against sharkd.
// Usage: node test/framestore.mjs   (bundles the sources itself; needs sharkd)
import { build } from "esbuild";
import { appendFileSync, closeSync, mkdirSync, mkdtempSync, openSync, readFileSync, renameSync, rmSync, statSync, truncateSync, writeFileSync, writeSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";
import assert from "node:assert/strict";
import * as g from "./capgen.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const out = mkdtempSync(join(tmpdir(), "wirebuddy-framestore-"));
const entry = join(out, "entry.ts");
writeFileSync(entry, ["framestore", "layers", "sharkd"].map((m) => `export * from ${JSON.stringify(join(root, `src/server/${m}.ts`))};`).join("\n"));
await build({ entryPoints: [entry], outfile: join(out, "framestore.mjs"), bundle: true, platform: "node", format: "esm", packages: "external", logLevel: "silent" });
const { FrameStore, MAX_RECORD, parse, Parsed, linkOfType, linkOfEncap, Sharkd } = await import(join(out, "framestore.mjs"));

// sharkd with an empty home, so the user's Wireshark settings don't count
const home = join(out, "home");
mkdirSync(home);
const env = { ...process.env, HOME: home, XDG_CONFIG_HOME: join(home, ".config"), XDG_DATA_HOME: join(home, ".local/share"), WIREBUDDY_EXTENSIONS: "" };
const sharkd = new Sharkd("sharkd", undefined, () => env);

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

let fileNo = 0;
/** Every store made, closed at the end. */
const stores = [];
const write = (bytes, name = `f${++fileNo}`) => {
  const path = join(out, name);
  writeFileSync(path, bytes);
  return path;
};
const storeOf = (path) => {
  const store = new FrameStore(path);
  stores.push(store);
  return store;
};
async function indexed(path) {
  const store = storeOf(path);
  await store.update();
  return store;
}
async function records(store, frames) {
  const recs = [];
  const each = (frame, time, len, link, data) => recs.push({ frame, time, len, link, data: Buffer.from(data) });
  if (frames) await store.readFrames(frames, each);
  else await store.readRange(1, store.count, each);
  return recs;
}
/** What sharkd reads of the file: count, and per frame time, length, captured length. */
async function sharkdView(path) {
  const load = await sharkd.call("load", { file: path });
  assert.ok(load.status === "OK" || load.err === -12, JSON.stringify(load));
  const { frames } = await sharkd.call("status");
  const rows = frames ? await sharkd.call("frames", { column0: "frame.time_epoch:0", column1: "frame.len:0", column2: "frame.cap_len:0" }) : [];
  return { frames, rows: rows.map((r) => ({ time: r.c[0] === "" ? NaN : Number(r.c[0]), len: Number(r.c[1]), cap: Number(r.c[2]) })) };
}
/** FrameStore and sharkd agree on the packets of `path`. */
async function sameAsSharkd(path, store) {
  const view = await sharkdView(path);
  assert.equal(store.count, view.frames, `${path}: ${store.count} packets, sharkd ${view.frames}`);
  const recs = await records(store);
  recs.forEach((r, i) => {
    const s = view.rows[i];
    assert.ok(Number.isNaN(s.time) ? Number.isNaN(r.time) : Math.abs(r.time - s.time) < 1e-6, `frame ${i + 1}: time ${r.time} vs ${s.time}`);
    assert.deepEqual([r.len, r.data.length], [s.len, s.cap], `frame ${i + 1}`);
  });
}

/** A seeded random number generator: the same fuzz on every run. */
function random(seed) {
  return () => {
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

try {
  await check("pcap: µs and ns times, both byte orders", async () => {
    for (const little of [true, false]) {
      for (const nano of [false, true]) {
        const recs = Array.from({ length: 6 }, (_, i) => ({ sec: 1700000000 + i, frac: nano ? 123456789 - i : 654321 - i, data: g.udpFrame(i, { size: 10 + i * 7 }) }));
        const file = write(Buffer.concat([g.pcapHeader({ little, nano }), ...recs.map((r, i) => g.pcapRecord(r.sec, r.frac, r.data, { little, orig: r.data.length + (i === 5 ? 100 : 0) }))]));
        const store = await indexed(file);
        assert.equal(store.off, null);
        const got = await records(store);
        assert.equal(got.length, 6);
        got.forEach((r, i) => {
          assert.equal(r.time, recs[i].sec + recs[i].frac / (nano ? 1e9 : 1e6));
          assert.equal(r.len, recs[i].data.length + (i === 5 ? 100 : 0));
          assert.ok(r.data.equals(recs[i].data) && r.link === "eth", `${little} ${nano} ${i}`);
        });
        await sameAsSharkd(file, store);
        store.close();
      }
    }
  });

  await check("pcapng: sections in both byte orders, if_tsresol 10^-9 and 2^-20, if_tsoffset, EPB, OPB, SPB; other blocks skipped", async () => {
    const t9 = 1700000000123456789n;
    const raw = g.ip4(17, g.udp(1, 2, Buffer.from("raw")));
    const file = write(
      Buffer.concat([
        g.shb(true), g.idb(1, { tsresol: 9 }), g.idb(101, { tsresol: 0x94, tsoffset: 1000 }), g.nrb(),
        g.epb(0, t9, g.udpFrame(1)), g.epb(1, 1700000000n * 1048576n + 524288n, raw), g.isb(0),
        g.opb(0, t9 + 1000n, g.udpFrame(3)),
        g.shb(false), g.idb(1, { little: false, snaplen: 40 }), g.epb(0, 1700000001000000n, g.udpFrame(4), { little: false }),
        g.spb(g.udpFrame(5).subarray(0, 40), { little: false, orig: 74 }), g.block(0x80000001, Buffer.alloc(8), false),
      ]),
    );
    const store = await indexed(file);
    const got = await records(store);
    assert.deepEqual(got.map((r) => r.link), ["eth", "raw", "eth", "eth", "eth"]);
    assert.deepEqual(got.map((r) => r.len), [74, 31, 74, 74, 74]);
    assert.deepEqual(got.map((r) => r.data.length), [74, 31, 74, 74, 40]);
    assert.ok(got[1].data.equals(raw) && got[3].data.equals(g.udpFrame(4)));
    assert.ok(Math.abs(got[0].time - 1700000000.123456789) < 1e-7 && got[1].time === 1700001000.5 && got[3].time === 1700000001, JSON.stringify(got.map((r) => r.time)));
    assert.ok(Number.isNaN(got[4].time));
    await sameAsSharkd(file, store);
  });

  await check("truncated tails: a half-written record or block is indexed once it is complete", async () => {
    const recs = [1, 2, 3, 4].map((i) => g.pcapRecord(1700000000, i, g.udpFrame(i)));
    const whole = Buffer.concat([g.pcapHeader(), ...recs]);
    // Grown a few bytes at a time: header, record headers and data cut anywhere
    const file = write(Buffer.alloc(0));
    const store = storeOf(file);
    for (let at = 0; at < whole.length; ) {
      const next = Math.min(whole.length, at + 13);
      appendFileSync(file, whole.subarray(at, next));
      at = next;
      await store.update();
      const complete = recs.filter((_, i) => 24 + recs.slice(0, i + 1).reduce((a, r) => a + r.length, 0) <= at).length;
      assert.equal(store.count, complete, `at ${at}`);
    }
    assert.equal(store.count, 4);
    assert.equal(store.off, null);
    assert.ok((await records(store)).every((r, i) => r.data.equals(g.udpFrame(i + 1))));
    // pcapng: a block whose start, or end, isn't there yet
    const blocks = [g.shb(), g.idb(1), g.epb(0, 1n, g.udpFrame(1)), g.epb(0, 2n, g.udpFrame(2)), g.epb(0, 3n, g.udpFrame(3))];
    const ng = Buffer.concat(blocks);
    const ngFile = write(ng.subarray(0, 6));
    const ngStore = storeOf(ngFile);
    for (const at of [6, 40, ng.length - blocks[4].length + 7, ng.length - 4, ng.length]) {
      writeFileSync(ngFile, ng.subarray(0, at));
      await ngStore.update();
      assert.equal(ngStore.count, at === ng.length ? 3 : at > 40 ? 2 : 0, `at ${at}`);
    }
    await sameAsSharkd(ngFile, ngStore);
  });

  await check("broken blocks stop indexing, also once the file grew; compressed and other files are refused", async () => {
    const good = [g.shb(), g.idb(1), g.epb(0, 1n, g.udpFrame(1))];
    const odd = Buffer.from(g.epb(0, 2n, g.udpFrame(2)));
    odd.writeUInt32LE(odd.length - 2, 4);
    const trailer = Buffer.from(g.epb(0, 2n, g.udpFrame(2)));
    trailer.writeUInt32LE(4, trailer.length - 4);
    const caplen = Buffer.from(g.epb(0, 2n, g.udpFrame(2)));
    caplen.writeUInt32LE(9999, 20);
    for (const [why, bad] of [["odd length", odd], ["trailer", trailer], ["caplen", caplen], ["no interface", g.epb(7, 2n, g.udpFrame(2))], ["no section", null]]) {
      const file = write(bad ? Buffer.concat([...good, bad]) : Buffer.concat([g.idb(1), g.epb(0, 1n, g.udpFrame(1))]));
      const store = await indexed(file);
      appendFileSync(file, g.epb(0, 3n, g.udpFrame(3)));
      await store.update();
      assert.equal(store.count, bad ? 1 : 0, why);
    }
    // Space a writer zeroed first is looked at again once the file grew
    const second = g.epb(0, 2n, g.udpFrame(2));
    const zeroed = write(Buffer.concat([...good, Buffer.alloc(second.length)]));
    const zeroedStore = await indexed(zeroed);
    assert.equal(zeroedStore.count, 1);
    const fd = openSync(zeroed, "r+");
    writeSync(fd, second, 0, second.length, Buffer.concat(good).length);
    closeSync(fd);
    await zeroedStore.update();
    assert.equal(zeroedStore.count, 1);
    appendFileSync(zeroed, g.epb(0, 3n, g.udpFrame(3)));
    await zeroedStore.update();
    assert.equal(zeroedStore.count, 3);
    const big = write(Buffer.concat([g.pcapHeader(), g.pcapRecord(1, 0, g.udpFrame(1)), Buffer.from([0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1])]));
    assert.equal((await indexed(big)).count, 1);
    const gz = await indexed(write(gzipSync(readFileSync(join(root, "test/fixtures/http.pcapng")))));
    assert.match(gz.off, /compressed/);
    assert.equal(gz.count, 0);
    assert.match((await indexed(write(Buffer.from("not a capture at all")))).off, /not a pcap or pcapng/);
    // Not there yet: no verdict
    assert.equal((await indexed(write(Buffer.alloc(0)))).off, null);
  });

  await check("records of up to 16 MiB; frames read apart and together", async () => {
    const max = Buffer.alloc(MAX_RECORD, 7);
    const file = write(Buffer.concat([g.pcapHeader(), g.pcapRecord(1, 0, g.udpFrame(1)), g.pcapRecord(2, 0, max), g.pcapRecord(3, 0, g.udpFrame(3))]));
    const store = await indexed(file);
    assert.equal(store.count, 3);
    const got = await records(store, [1, 3]);
    assert.deepEqual(got.map((r) => r.frame), [1, 3]);
    assert.ok(got[0].data.equals(g.udpFrame(1)) && got[1].data.equals(g.udpFrame(3)));
    assert.equal((await records(store, [2]))[0].data.length, MAX_RECORD);
    const over = write(Buffer.concat([g.pcapHeader(), g.pcapRecord(1, 0, g.udpFrame(1)), g.pcapRecord(2, 0, Buffer.alloc(MAX_RECORD + 1))]));
    assert.equal((await indexed(over)).count, 1);
    // Many packets in two sections, read sparsely
    const n = 20000;
    const blocks = [g.shb(), g.idb(1)];
    for (let i = 1; i <= n; i++) {
      if (i === n / 2 + 1) blocks.push(g.shb(false), g.idb(1, { little: false }));
      blocks.push(g.epb(0, 1700000000000000n + BigInt(i), g.udpFrame(i, { size: 20 + (i % 50) }), { little: i <= n / 2 }));
    }
    const many = write(Buffer.concat(blocks));
    const manyStore = await indexed(many);
    const pick = [1, 2, 500, 9999, 10000, 10001, 15000, 19999, 20000];
    const sparse = await records(manyStore, pick);
    assert.deepEqual(sparse.map((r) => r.data.readUInt32BE(42)), pick);
    assert.deepEqual(sparse.map((r) => Math.round((r.time - 1700000000) * 1e6)), pick);
    assert.equal(manyStore.count, (await sharkdView(many)).frames);
  });

  await check("review cases: variants, short blocks, blocks between records", async () => {
    // pcap 2.2 is AIX's to Wireshark; implausible first records another variant's
    const v22 = g.pcapHeader();
    v22.writeUInt16LE(2, 6);
    const aix = await indexed(write(Buffer.concat([v22, g.pcapRecord(1, 0, g.udpFrame(1))])));
    assert.match(aix.off ?? "", /pcap variant/);
    const odd = await indexed(write(Buffer.concat([g.pcapHeader(), g.pcapRecord(1, 2_000_000, g.udpFrame(1))])));
    assert.match(odd.off ?? "", /another pcap variant/);
    // A packet block too short to hold its fields, at the end of the file: stuck, not a throw
    for (const len of [12, 16, 20]) {
      const body = Buffer.alloc(len - 12);
      const store = await indexed(write(Buffer.concat([g.shb(), g.idb(1), g.epb(0, 1n, g.udpFrame(1)), g.block(6, body)])));
      assert.equal(store.count, 1);
      await store.update();
    }
    // Blocks between two packets are not read with the first one
    const filler = g.block(0x0bad, Buffer.alloc(4 * 1024 * 1024));
    const gap = await indexed(write(Buffer.concat([g.shb(), g.idb(1), g.epb(0, 1n, g.udpFrame(1)), filler, filler, g.epb(0, 2n, g.udpFrame(2))])));
    let largest = 0;
    const alloc = Buffer.allocUnsafe;
    Buffer.allocUnsafe = (n) => ((largest = Math.max(largest, n)), alloc(n));
    try {
      assert.deepEqual((await records(gap, [1])).map((r) => r.data.readUInt32BE(42)), [1]);
    } finally {
      Buffer.allocUnsafe = alloc;
    }
    assert.ok(largest < 64 * 1024, `read ${largest} bytes for one small packet`);
  });

  await check("slices: header and chosen records, as sharkd reads them; heads; what can't be sliced", async () => {
    const recsOf = async (store) => (await records(store)).map((r) => ({ time: r.time, len: r.len, data: r.data.toString("hex") }));
    const pick = (all, frames) => frames.map((f) => all[f - 1]);
    const ng = (n, extra = () => []) => {
      const blocks = [g.shb(), g.idb(1, { tsresol: 9 }), g.nrb()];
      for (let i = 1; i <= n; i++) blocks.push(g.epb(0, 1700000000000000000n + BigInt(i) * 1000n, g.udpFrame(i, { size: 20 + (i % 9) })), ...extra(i));
      return Buffer.concat(blocks);
    };
    const pc = Buffer.concat([g.pcapHeader({ nano: true }), ...Array.from({ length: 50 }, (_, i) => g.pcapRecord(1700000000, i, g.udpFrame(i + 1)))]);
    // Interface statistics between records don't stop slicing
    for (const [name, bytes] of [["pcapng", ng(50, (i) => (i % 7 ? [] : [g.isb(0)]))], ["pcap", pc]]) {
      const file = write(bytes);
      const store = await indexed(file);
      assert.equal(store.sliceable(), null, name);
      const all = await recsOf(store);
      for (const frames of [[1, ...Array.from({ length: 11 }, (_, i) => 20 + i)], [1, 2, 3, 9, 30, 31, 50], [50]]) {
        const slice = join(out, `slice-${++fileNo}.${name}`);
        await store.writeSlice(frames, slice);
        assert.equal(statSync(slice).mode & 0o777, 0o600, name);
        const sliced = await indexed(slice);
        assert.deepEqual(await recsOf(sliced), pick(all, frames), `${name} ${frames}`);
        assert.equal((await sharkdView(slice)).frames, frames.length);
        // Never over an existing file
        await assert.rejects(store.writeSlice(frames, slice), /EEXIST/);
      }
      await assert.rejects(store.writeSlice([51], join(out, `slice-${++fileNo}`)), /no such frames/);
      const heads = [];
      await store.readHeads(3, 5, 16, (frame, time, len, link, data) => heads.push([frame, len, data.length, link]));
      assert.deepEqual(heads, [3, 4, 5].map((f) => [f, g.udpFrame(f, { size: name === "pcap" ? 32 : 20 + (f % 9) }).length, 16, "eth"]));
    }
    // A file that grows: new records slice too
    const growing = write(ng(10));
    const store = await indexed(growing);
    appendFileSync(growing, Buffer.concat([11, 12].map((i) => g.epb(0, BigInt(i), g.udpFrame(i)))));
    await store.update();
    const grownSlice = join(out, `slice-${++fileNo}`);
    await store.writeSlice([1, 12], grownSlice);
    assert.deepEqual((await records(await indexed(grownSlice))).map((r) => r.data.readUInt32BE(42)), [1, 12]);
    // Several sections, or interfaces after the first packet: no slices
    const twoSections = await indexed(write(Buffer.concat([g.shb(), g.idb(1), g.epb(0, 1n, g.udpFrame(1)), g.shb(), g.idb(1), g.epb(0, 2n, g.udpFrame(2))])));
    assert.match(twoSections.sliceable(), /sections/);
    const lateIdb = await indexed(write(Buffer.concat([g.shb(), g.idb(1), g.epb(0, 1n, g.udpFrame(1)), g.idb(101), g.epb(1, 2n, g.ip4(17, g.udp(1, 2, Buffer.from("raw"))))])));
    assert.match(lateIdb.sliceable(), /after its first packet/);
    assert.match((await indexed(write(gzipSync(pc)))).sliceable(), /compressed/);
  });

  await check("a replaced or cut file is noticed", async () => {
    const file = write(Buffer.concat([g.pcapHeader(), ...[1, 2, 3].map((i) => g.pcapRecord(1, i, g.udpFrame(i)))]));
    const store = await indexed(file);
    assert.ok(store.same());
    appendFileSync(file, g.pcapRecord(1, 4, g.udpFrame(4)));
    assert.ok(store.same());
    await store.update();
    assert.equal(store.count, 4);
    truncateSync(file, 100);
    await store.update();
    assert.ok(store.changed && !store.same());
    const other = await indexed(file);
    writeFileSync(`${file}.new`, readFileSync(file));
    renameSync(`${file}.new`, file);
    assert.ok(!other.same());
    await other.update();
    assert.ok(other.changed);
  });

  await check("the count equals sharkd's status frames (fixture and generated files)", async () => {
    const fixture = join(root, "test/fixtures/http.pcapng");
    const store = await indexed(fixture);
    await sameAsSharkd(fixture, store);
    // And the bytes are sharkd's
    for (const r of await records(store)) {
      const f = await sharkd.call("frame", { frame: r.frame, bytes: true });
      assert.ok(Buffer.from(f.bytes, "base64").equals(r.data), `frame ${r.frame}`);
    }
    // A systemd journal entry is a frame to Wireshark, not to FrameStore: the count check catches that
    const journal = write(Buffer.concat([g.shb(), g.idb(1), g.epb(0, 1n, g.udpFrame(1)), g.block(9, Buffer.from("__REALTIME_TIMESTAMP=1700000000000000\nMESSAGE=hi\n")), g.epb(0, 2n, g.udpFrame(2))]));
    assert.deepEqual([(await indexed(journal)).count, (await sharkdView(journal)).frames], [2, 3]);
  });

  // Ethernet / IPv4 / UDP 1000 -> 2000 with "hello"
  const hello = Buffer.from("hello");
  const v4 = g.ip4(17, g.udp(1000, 2000, hello));
  const v6 = g.ip6(17, g.udp(1000, 2000, hello));
  const parsed = new Parsed();
  const view = (b, link) => {
    const p = parse(b, link, parsed);
    const payload = p.range("payload");
    return { ethertype: p.ethertype, vlans: [...p.vlans], ip: p.ip, proto: p.proto, ports: [p.srcport, p.dstport], fragment: p.fragment, payload: payload && b.subarray(...payload).toString(), src: p.src, dst: p.dst };
  };
  const udpV4 = (src, extra = {}) => ({ ethertype: 0x0800, vlans: [], ip: 4, proto: 17, ports: [1000, 2000], fragment: false, payload: "hello", src, dst: src + 4, ...extra });

  await check("layers: Ethernet, 802.1Q, QinQ, SLL, SLL2, raw IPv4 and IPv6, NULL and loopback", () => {
    assert.deepEqual(view(g.eth(0x0800, v4), "eth"), udpV4(26));
    assert.deepEqual(view(g.eth(0x0800, v4, [[0x8100, 5]]), "eth"), udpV4(30, { vlans: [5] }));
    assert.deepEqual(view(g.eth(0x0800, v4, [[0x88a8, 0x2064], [0x8100, 0x00c8]]), "eth"), udpV4(34, { vlans: [100, 200] }));
    assert.deepEqual(view(Buffer.concat([Buffer.alloc(14), Buffer.from([8, 0]), v4]), "sll"), udpV4(28));
    assert.deepEqual(view(Buffer.concat([Buffer.from([8, 0]), Buffer.alloc(18), v4]), "sll2"), udpV4(32));
    assert.deepEqual(view(v4, "raw"), udpV4(12));
    assert.deepEqual(view(v6, "raw"), udpV4(8, { ethertype: 0x86dd, ip: 6, dst: 24 }));
    assert.deepEqual(view(Buffer.concat([Buffer.from([2, 0, 0, 0]), v4]), "null"), udpV4(16));
    // BSD's AF_INET6 in either byte order
    assert.deepEqual(view(Buffer.concat([Buffer.from([0, 0, 0, 30]), v6]), "null"), udpV4(12, { ethertype: 0x86dd, ip: 6, dst: 28 }));
    const arp = view(g.eth(0x0806, Buffer.alloc(28)), "eth");
    assert.deepEqual([arp.ethertype, arp.ip, arp.payload], [0x0806, 0, null]);
    assert.equal(view(Buffer.concat([Buffer.alloc(12), Buffer.from([0, 40]), Buffer.alloc(40)]), "eth").ethertype, -1);
    assert.equal(view(v4, null).ip, 0);
    const t = view(g.eth(0x0800, g.ip4(6, g.tcp(80, 5000, hello))), "eth");
    assert.deepEqual([t.proto, t.ports, t.payload], [6, [80, 5000], "hello"]);
    assert.deepEqual([1, 113, 276, 0, 108, 101, 228, 229, 105].map(linkOfType), ["eth", "sll", "sll2", "null", "null", "raw", "raw", "raw", null]);
    assert.deepEqual(["Ethernet", "Raw IPv6", "IEEE 802.11"].map(linkOfEncap), ["eth", "raw", null]);
  });

  await check("layers: IPv6 extension headers, IPv4 and IPv6 fragments", () => {
    // Hop-by-hop, routing, destination options, then TCP
    const ext = g.ip6(0, Buffer.concat([Buffer.from([43, 0, 0, 0, 0, 0, 0, 0]), Buffer.from([60, 0, 0, 0, 0, 0, 0, 0]), Buffer.from([6, 0, 0, 0, 0, 0, 0, 0]), g.tcp(80, 5000, hello)]));
    assert.deepEqual(view(ext, "raw"), udpV4(8, { ethertype: 0x86dd, ip: 6, dst: 24, proto: 6, ports: [80, 5000] }));
    // First fragment: ports, but no payload; a later one: neither
    const first6 = view(g.ip6(44, Buffer.concat([Buffer.from([17, 0, 0, 1, 0, 0, 0, 1]), g.udp(1000, 2000, hello)])), "raw");
    assert.deepEqual([first6.fragment, first6.ports, first6.payload, first6.proto], [true, [1000, 2000], null, 17]);
    const later6 = view(g.ip6(44, Buffer.concat([Buffer.from([17, 0, 0, 0x10, 0, 0, 0, 1]), hello])), "raw");
    assert.deepEqual([later6.fragment, later6.ports, later6.payload], [true, [-1, -1], null]);
    const first4 = view(g.ip4(17, g.udp(1000, 2000, hello), { flags: 0x2000 }), "raw");
    assert.deepEqual([first4.fragment, first4.ports, first4.payload], [true, [1000, 2000], null]);
    const later4 = view(g.ip4(17, hello, { flags: 185 }), "raw");
    assert.deepEqual([later4.fragment, later4.ports, later4.payload, later4.proto], [true, [-1, -1], null, 17]);
    // Don't fragment is no fragment
    assert.equal(view(g.ip4(17, g.udp(1000, 2000, hello), { flags: 0x4000 }), "raw").payload, "hello");
  });

  await check("fuzz: 10000 random frames parse without a throw, inside their bytes", () => {
    const rnd = random(42);
    const links = ["eth", "sll", "sll2", "null", "raw", null];
    const templates = [g.eth(0x0800, v4, [[0x8100, 1]]), g.eth(0x86dd, v6), v4, v6, g.ip6(0, Buffer.concat([Buffer.from([44, 0, 0, 0, 0, 0, 0, 0]), Buffer.from([17, 0, 0, 1, 0, 0, 0, 1]), g.udp(1, 2, hello)]))];
    for (let i = 0; i < 10000; i++) {
      // Random bytes, or a real frame with some of them changed or cut
      let b;
      if (i % 2) b = Buffer.from(Array.from({ length: Math.floor(rnd() * 160) }, () => Math.floor(rnd() * 256)));
      else {
        b = Buffer.from(templates[i % templates.length]);
        for (let k = Math.floor(rnd() * 6); k >= 0; k--) b[Math.floor(rnd() * b.length)] = Math.floor(rnd() * 256);
        b = b.subarray(0, Math.floor(rnd() * (b.length + 1)));
      }
      const link = links[i % links.length];
      const p = parse(b, link, parsed);
      for (const layer of ["ip", "payload"]) {
        const at = p.range(layer);
        if (at) assert.ok(at[0] >= 0 && at[0] <= at[1] && at[1] <= b.length, `${i} ${link} ${layer} ${at}`);
      }
      for (const at of [p.src, p.dst]) if (at >= 0) assert.ok(at + (p.ip === 4 ? 4 : 16) <= b.length, `${i} address`);
      assert.ok(p.srcport >= -1 && p.srcport <= 65535 && p.vlans.length <= 4);
    }
  });

  await check("fuzz: 300 damaged capture files index and read without a throw", async () => {
    const rnd = random(7);
    const ng = Buffer.concat([g.shb(), g.idb(1, { tsresol: 9, tsoffset: 5 }), g.epb(0, 1n, g.udpFrame(1)), g.spb(g.udpFrame(2)), g.opb(0, 3n, g.udpFrame(3)), g.shb(false), g.idb(101, { little: false }), g.epb(0, 4n, v4, { little: false })]);
    const pc = Buffer.concat([g.pcapHeader({ nano: true }), g.pcapRecord(1, 2, g.udpFrame(1)), g.pcapRecord(3, 4, g.udpFrame(2))]);
    for (let i = 0; i < 300; i++) {
      const b = Buffer.from(i % 2 ? ng : pc);
      for (let k = Math.floor(rnd() * 4); k >= 0; k--) b[4 + Math.floor(rnd() * (b.length - 4))] = Math.floor(rnd() * 256);
      const file = write(b.subarray(0, Math.floor(b.length * (0.5 + rnd() / 2))), "fuzz");
      const store = await indexed(file);
      for (const r of await records(store)) assert.ok(r.data.length <= MAX_RECORD && r.data.length <= b.length);
      store.close();
    }
  });
} finally {
  for (const store of stores) store.close();
  sharkd.close();
  rmSync(out, { recursive: true, force: true });
}
console.log(failures ? `${failures} check(s) failed` : "all checks passed");
process.exit(failures ? 1 : 0);
