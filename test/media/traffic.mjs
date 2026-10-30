// Busy traffic for the live view's tests, the same on every run: long-lived HTTP keep-alive
// connections with window scaling, TLS 1.3 connections, short HTTP connections on ports used again
// and again, big downloads over HTTP and over TLS 1.2 (decryptable with the key log it writes),
// requests pipelined into a big response, uploads after a 100 Continue on connections used before,
// DNS, pings and pings answered thousands of packets later, with segments lost before the capture
// saw them (dup ACKs and retransmissions follow).
// Usage: node test/media/traffic.mjs <out.pcapng> <packets> [packets per second] [key log]
import { createCipheriv, createHmac } from "node:crypto";
import { closeSync, openSync, writeFileSync, writeSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { epb, idb, shb } from "../capgen.mjs";

const MSS = 1448;
/** Window scale shift the connections agree on: the field says 512, the window is 65536. */
const SHIFT = 7;

/** A seeded random number generator (mulberry32). */
export function random(seed) {
  return () => {
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const EMPTY = Buffer.alloc(0);
const u16 = (v) => Buffer.from([v >> 8, v & 255]);
const u24 = (v) => Buffer.from([v >> 16, (v >> 8) & 255, v & 255]);

/** Ethernet and IPv4 around a transport segment. */
function ip(src, dst, proto, l4, id) {
  const h = Buffer.alloc(34);
  h[0] = h[6] = 2;
  h[5] = dst[3];
  h[11] = src[3];
  h.writeUInt16BE(0x0800, 12);
  h[14] = 0x45;
  h.writeUInt16BE(20 + l4.length, 16);
  h.writeUInt16BE(id & 0xffff, 18);
  h[20] = 0x40;
  h[22] = 64;
  h[23] = proto;
  h.set(src, 26);
  h.set(dst, 30);
  let sum = 0;
  for (let i = 14; i < 34; i += 2) sum += h.readUInt16BE(i);
  while (sum > 0xffff) sum = (sum & 0xffff) + (sum >>> 16);
  h.writeUInt16BE(~sum & 0xffff, 24);
  return Buffer.concat([h, l4]);
}

/** One TCP connection; `seg` returns the frame of a segment and moves the sender's sequence number. */
class Tcp {
  constructor(rnd, client, cport, server, sport) {
    this.side = [
      { ip: client, port: cport, seq: Math.floor(rnd() * 2 ** 32), id: Math.floor(rnd() * 65536) },
      { ip: server, port: sport, seq: Math.floor(rnd() * 2 ** 32), id: Math.floor(rnd() * 65536) },
    ];
  }

  /** `from` 0: the client sends, 1: the server. flags: 0x02 SYN, 0x10 ACK, 0x18 PSH+ACK, 0x11 FIN+ACK. */
  seg(from, flags, payload = EMPTY, { seq, ack } = {}) {
    const a = this.side[from];
    const b = this.side[1 - from];
    const syn = flags & 0x02;
    // SYNs: MSS, SACK permitted, window scale
    const opts = syn ? Buffer.from([2, 4, MSS >> 8, MSS & 255, 4, 2, 1, 3, 3, SHIFT, 1, 1]) : EMPTY;
    const h = Buffer.alloc(20 + opts.length);
    h.writeUInt16BE(a.port, 0);
    h.writeUInt16BE(b.port, 2);
    h.writeUInt32BE((seq ?? a.seq) >>> 0, 4);
    h.writeUInt32BE(flags & 0x10 ? (ack ?? b.seq) >>> 0 : 0, 8);
    h[12] = (h.length / 4) << 4;
    h[13] = flags;
    h.writeUInt16BE(syn ? 64240 : 512, 14);
    opts.copy(h, 20);
    if (seq === undefined) a.seq = (a.seq + payload.length + (syn || flags & 0x01 ? 1 : 0)) >>> 0;
    return ip(a.ip, b.ip, 6, Buffer.concat([h, payload]), a.id++);
  }

  *handshake() {
    yield this.seg(0, 0x02);
    yield this.seg(1, 0x12);
    yield this.seg(0, 0x10);
  }

  /** Sends `data` from `from` in segments, some lost and sent again after the receiver's dup ACKs. */
  *send(rnd, from, data, lossRate) {
    const lost = [];
    let unacked = 0;
    for (let at = 0; at < data.length; at += MSS) {
      const part = data.subarray(at, at + MSS);
      const seq = this.side[from].seq;
      if (at > 0 && rnd() < lossRate) {
        // Lost before the capture: the sequence number moves on all the same
        lost.push({ seq, part });
        this.side[from].seq = (seq + part.length) >>> 0;
      } else yield this.seg(from, 0x18, part);
      if (++unacked === 2 || at + MSS >= data.length) {
        unacked = 0;
        yield this.seg(1 - from, 0x10, EMPTY, { ack: lost.length ? lost[0].seq : undefined });
      }
    }
    if (!lost.length) return;
    for (let k = 0; k < 2; k++) yield this.seg(1 - from, 0x10, EMPTY, { ack: lost[0].seq });
    for (const l of lost) yield this.seg(from, 0x18, l.part, { seq: l.seq });
    yield this.seg(1 - from, 0x10);
  }

  *close() {
    yield this.seg(0, 0x11);
    yield this.seg(1, 0x11);
    yield this.seg(0, 0x10);
  }
}

const SIZES = [200, 800, 3000, 12000, 40000];

function body(rnd, n) {
  const b = Buffer.alloc(n);
  for (let i = 0; i < n; i++) b[i] = 97 + Math.floor(rnd() * 26);
  return b;
}

function bytes(rnd, n) {
  const b = Buffer.alloc(n);
  for (let i = 0; i < n; i++) b[i] = Math.floor(rnd() * 256);
  return b;
}

/** An HTTP connection: `requests` exchanges (Infinity: keep-alive for good) of `size` bytes or random ones, then the close. */
function* http(rnd, client, cport, requests, lossRate, size) {
  const c = new Tcp(rnd, client, cport, [10, 0, 1, 1], 80);
  yield* c.handshake();
  for (let k = 0; k < requests; k++) {
    const n = size ?? SIZES[Math.floor(rnd() * SIZES.length)];
    yield c.seg(0, 0x18, Buffer.from(`GET /data?n=${n}&k=${k} HTTP/1.1\r\nHost: 10.0.1.1\r\nConnection: keep-alive\r\n\r\n`));
    const head = Buffer.from(`HTTP/1.1 ${rnd() < 0.05 ? "404 Not Found" : "200 OK"}\r\nContent-Type: text/plain\r\nContent-Length: ${n}\r\n\r\n`);
    yield* c.send(rnd, 1, Buffer.concat([head, body(rnd, n)]), lossRate);
  }
  yield* c.close();
}

/** A response of `n` bytes with its headers. */
const response = (rnd, n, status = "200 OK") => Buffer.concat([Buffer.from(`HTTP/1.1 ${status}\r\nContent-Type: text/plain\r\nContent-Length: ${n}\r\n\r\n`), body(rnd, n)]);

/** A keep-alive HTTP connection: a few requests, then a big response the next three requests are pipelined into while it is under way. */
function* pipelined(rnd, client, cport) {
  const c = new Tcp(rnd, client, cport, [10, 0, 1, 1], 80);
  yield* c.handshake();
  for (let k = 0; k < 6; k++) {
    yield c.seg(0, 0x18, Buffer.from(`GET /small?k=${k} HTTP/1.1\r\nHost: 10.0.1.1\r\n\r\n`));
    yield* c.send(rnd, 1, response(rnd, 300), 0);
  }
  yield c.seg(0, 0x18, Buffer.from("GET /big HTTP/1.1\r\nHost: 10.0.1.1\r\n\r\n"));
  const big = response(rnd, 600_000);
  let at = 0;
  for (let k = 0; k < 3; k++) {
    const to = Math.floor((big.length * (k + 1)) / 4 / MSS) * MSS;
    yield* c.send(rnd, 1, big.subarray(at, to), 1 / 600);
    at = to;
    yield c.seg(0, 0x18, Buffer.from(`GET /next?k=${k} HTTP/1.1\r\nHost: 10.0.1.1\r\n\r\n`));
  }
  yield* c.send(rnd, 1, big.subarray(at), 1 / 600);
  for (let k = 0; k < 3; k++) yield* c.send(rnd, 1, response(rnd, 500 + k * 1000), 0);
  yield* c.close();
}

/** A keep-alive HTTP connection: a few requests, then an upload with Expect: 100-continue. */
function* upload(rnd, client, cport) {
  const c = new Tcp(rnd, client, cport, [10, 0, 1, 1], 80);
  yield* c.handshake();
  for (let k = 0; k < 8; k++) {
    yield c.seg(0, 0x18, Buffer.from(`GET /small?k=${k} HTTP/1.1\r\nHost: 10.0.1.1\r\n\r\n`));
    yield* c.send(rnd, 1, response(rnd, 400), 0);
  }
  const size = 500_000;
  yield c.seg(0, 0x18, Buffer.from(`PUT /up HTTP/1.1\r\nHost: 10.0.1.1\r\nContent-Type: application/octet-stream\r\nContent-Length: ${size}\r\nExpect: 100-continue\r\n\r\n`));
  yield c.seg(1, 0x18, Buffer.from("HTTP/1.1 100 Continue\r\n\r\n"));
  yield* c.send(rnd, 0, body(rnd, size), 1 / 600);
  yield* c.send(rnd, 1, response(rnd, 20, "201 Created"), 0);
  yield* c.close();
}

/** A TLS record of `type` (22 handshake, 20 change cipher spec, 23 application data). */
const record = (type, payload, version = 0x0303) => Buffer.concat([Buffer.from([type]), u16(version), u16(payload.length), payload]);
const ext = (type, data) => Buffer.concat([u16(type), u16(data.length), data]);
const handshake = (type, b) => Buffer.concat([Buffer.from([type]), u24(b.length), b]);

/** A TLS 1.3 connection that exchanges application data for good. */
function* tls(rnd, client, cport, lossRate) {
  const c = new Tcp(rnd, client, cport, [10, 0, 1, 2], 443);
  yield* c.handshake();
  const sid = body(rnd, 32);
  const share = Buffer.concat([u16(0x001d), u16(32), body(rnd, 32)]);
  const name = Buffer.from("tls.example");
  const hello = Buffer.concat([
    u16(0x0303), body(rnd, 32), Buffer.from([32]), sid, u16(2), u16(0x1301), Buffer.from([1, 0]),
    u16(0), // extensions follow
  ]);
  const extensions = Buffer.concat([
    ext(0x0000, Buffer.concat([u16(name.length + 3), Buffer.from([0]), u16(name.length), name])),
    ext(0x000a, Buffer.concat([u16(2), u16(0x001d)])),
    ext(0x000d, Buffer.concat([u16(2), u16(0x0804)])),
    ext(0x002b, Buffer.from([2, 3, 4])),
    ext(0x0033, Buffer.concat([u16(share.length), share])),
  ]);
  hello.writeUInt16BE(extensions.length, hello.length - 2);
  yield c.seg(0, 0x18, record(22, handshake(1, Buffer.concat([hello, extensions])), 0x0301));
  const server = Buffer.concat([
    u16(0x0303), body(rnd, 32), Buffer.from([32]), sid, u16(0x1301), Buffer.from([0]),
    u16(4 + 2 + 4 + share.length), ext(0x002b, u16(0x0304)), ext(0x0033, share),
  ]);
  yield c.seg(1, 0x18, Buffer.concat([record(22, handshake(2, server)), record(20, Buffer.from([1])), record(23, body(rnd, 900))]));
  yield c.seg(0, 0x18, Buffer.concat([record(20, Buffer.from([1])), record(23, body(rnd, 53))]));
  for (;;) {
    yield c.seg(0, 0x18, record(23, body(rnd, 100 + Math.floor(rnd() * 300))));
    yield* c.send(rnd, 1, record(23, body(rnd, 500 + Math.floor(rnd() * 6000))), lossRate);
  }
}

/** TLS 1.2's PRF (P_SHA256). */
function prf(secret, label, seed, n) {
  const s = Buffer.concat([Buffer.from(label), seed]);
  const out = [];
  for (let a = s, len = 0; len < n; ) {
    a = createHmac("sha256", secret).update(a).digest();
    out.push(createHmac("sha256", secret).update(Buffer.concat([a, s])).digest());
    len += 32;
  }
  return Buffer.concat(out).subarray(0, n);
}

/**
 * A TLS 1.2 connection (AES-128-GCM) that downloads one file of `size` bytes and closes; `key`
 * gets its key log line, with which Wireshark decrypts it.
 */
function* tls12(rnd, client, cport, size, lossRate, key) {
  const c = new Tcp(rnd, client, cport, [10, 0, 1, 3], 443);
  yield* c.handshake();
  const clientRandom = bytes(rnd, 32);
  const serverRandom = bytes(rnd, 32);
  const master = bytes(rnd, 48);
  key(`CLIENT_RANDOM ${clientRandom.toString("hex")} ${master.toString("hex")}`);
  const block = prf(master, "key expansion", Buffer.concat([serverRandom, clientRandom]), 40);
  const sides = [
    { key: block.subarray(0, 16), iv: block.subarray(32, 36), seq: 0n },
    { key: block.subarray(16, 32), iv: block.subarray(36, 40), seq: 0n },
  ];
  /** A record of `type` with `plain` encrypted by side `from`. */
  const sealed = (from, type, plain) => {
    const side = sides[from];
    const explicit = Buffer.alloc(8);
    explicit.writeBigUInt64BE(side.seq++);
    const cipher = createCipheriv("aes-128-gcm", side.key, Buffer.concat([side.iv, explicit]));
    cipher.setAAD(Buffer.concat([explicit, Buffer.from([type]), u16(0x0303), u16(plain.length)]));
    return record(type, Buffer.concat([explicit, cipher.update(plain), cipher.final(), cipher.getAuthTag()]));
  };
  const suite = u16(0x009c);
  yield c.seg(0, 0x18, record(22, handshake(1, Buffer.concat([u16(0x0303), clientRandom, Buffer.from([0]), u16(2), suite, Buffer.from([1, 0])]))));
  yield c.seg(1, 0x18, record(22, Buffer.concat([handshake(2, Buffer.concat([u16(0x0303), serverRandom, Buffer.from([0]), suite, Buffer.from([0])])), handshake(14, EMPTY)])));
  yield c.seg(0, 0x18, Buffer.concat([record(22, handshake(16, Buffer.concat([u16(256), bytes(rnd, 256)]))), record(20, Buffer.from([1])), sealed(0, 22, handshake(20, bytes(rnd, 12)))]));
  yield c.seg(1, 0x18, Buffer.concat([record(20, Buffer.from([1])), sealed(1, 22, handshake(20, bytes(rnd, 12)))]));
  yield c.seg(0, 0x18, sealed(0, 23, Buffer.from(`GET /file?n=${size} HTTP/1.1\r\nHost: tls12.example\r\n\r\n`)));
  const response = Buffer.concat([Buffer.from(`HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: ${size}\r\n\r\n`), body(rnd, size)]);
  const records = [];
  for (let at = 0; at < response.length; at += 16000) records.push(sealed(1, 23, response.subarray(at, at + 16000)));
  yield* c.send(rnd, 1, Buffer.concat(records), lossRate);
  yield* c.close();
}

/** A ping (ICMP echo request) and its reply, `wait` turns of its actor later, between 10.0.0.(30 + host) and 10.0.1.(30 + host). */
function* ping(seq, host = 0, wait = 0) {
  const icmp = (type) => {
    const b = Buffer.alloc(64);
    b[0] = type;
    b.writeUInt16BE(0x5742, 4);
    b.writeUInt16BE(seq & 0xffff, 6);
    for (let i = 8; i < b.length; i++) b[i] = i;
    let sum = 0;
    for (let i = 0; i < b.length; i += 2) sum += b.readUInt16BE(i);
    while (sum > 0xffff) sum = (sum & 0xffff) + (sum >>> 16);
    b.writeUInt16BE(~sum & 0xffff, 2);
    return b;
  };
  yield ip([10, 0, 0, 30 + host], [10, 0, 1, 30 + host], 1, icmp(8), seq);
  // A late reply: the actor waits turns of its own
  for (let i = 0; i < wait; i++) yield null;
  yield ip([10, 0, 1, 30 + host], [10, 0, 0, 30 + host], 1, icmp(0), seq);
}

/** A DNS query and its answer. */
function* dns(rnd, k) {
  const id = Math.floor(rnd() * 65536);
  const port = 20000 + Math.floor(rnd() * 40000);
  const qname = Buffer.concat([...`host${k}.example.com`.split(".").map((l) => Buffer.concat([Buffer.from([l.length]), Buffer.from(l)])), Buffer.from([0])]);
  const question = Buffer.concat([qname, u16(1), u16(1)]);
  const udp = (sport, dport, payload) => Buffer.concat([u16(sport), u16(dport), u16(8 + payload.length), u16(0), payload]);
  const query = Buffer.concat([u16(id), u16(0x0100), u16(1), u16(0), u16(0), u16(0), question]);
  yield ip([10, 0, 0, 53], [10, 0, 1, 53], 17, udp(port, 53, query), k);
  const answer = Buffer.concat([u16(0xc00c), u16(1), u16(1), Buffer.from([0, 0, 0, 60]), u16(4), Buffer.from([10, 1, k >> 8 & 255, k & 255])]);
  yield ip([10, 0, 1, 53], [10, 0, 0, 53], 17, udp(53, port, Buffer.concat([u16(id), u16(0x8180), u16(1), u16(1), u16(0), u16(0), question, answer])), k);
}

/** Ethernet frames of the traffic, endlessly; `key` gets the key log lines of the TLS 1.2 connections. */
export function* traffic(seed = 1, key = () => {}) {
  const rnd = random(seed);
  const actors = [];
  for (let i = 0; i < 12; i++) actors.push(http(rnd, [10, 0, 0, 1 + i], 40000 + i, Infinity, 1 / 600));
  for (let i = 0; i < 6; i++) actors.push(tls(rnd, [10, 0, 0, 20 + i], 41000 + i, 1 / 600));
  let short = 0;
  let big = 0;
  let secure = 0;
  let piped = 0;
  let uploads = 0;
  for (let n = 0; ; n++) {
    if (n % 350 === 0) actors.push(http(rnd, [10, 0, 0, 100], 50000 + (short++ % 24), 1 + Math.floor(rnd() * 3), 0));
    if (n % 90 === 0) actors.push(dns(rnd, n));
    if (n % 120 === 60) actors.push(ping(n / 120));
    // Pings answered about 4,000 packets later, after the slice of the chunk they are in
    if (n % 2000 === 1250) actors.push(ping(Math.floor(n / 2000), 1, 150));
    // Downloads of hundreds of segments, which chunks of slices cut in the middle
    if (n % 7000 === 3500) actors.push(http(rnd, [10, 0, 0, 101], 51000 + (big++ % 24), 1, 1 / 600, 600_000));
    if (n % 9000 === 6000) actors.push(tls12(rnd, [10, 0, 0, 40], 42000 + (secure++ % 24), [150_000, 400_000, 900_000][secure % 3], 1 / 600, key));
    // The other side sends while a message is under way: pipelined requests, a 100 Continue
    if (n % 16000 === 1000) actors.push(pipelined(rnd, [10, 0, 0, 102], 52000 + (piped++ % 24)));
    if (n % 16000 === 9000) actors.push(upload(rnd, [10, 0, 0, 103], 53000 + (uploads++ % 24)));
    for (;;) {
      const i = Math.floor(rnd() * actors.length);
      const next = actors[i].next();
      if (next.done) {
        actors.splice(i, 1);
        continue;
      }
      // Waiting: another actor sends
      if (next.value === null) continue;
      yield next.value;
      break;
    }
  }
}

/** What dumpcap writes first: a section and one Ethernet interface (microseconds). */
export function header() {
  return Buffer.concat([shb(), idb(1, { snaplen: 262144 })]);
}

/** Packet `n` (0-based) at `pps` packets a second from `start` (epoch seconds). */
export function packet(n, frame, { pps = 10000, start = 1700000000 } = {}) {
  return epb(0, BigInt(Math.round(start * 1e6)) + BigInt(Math.round((n * 1e6) / pps)), frame);
}

/** Writes the first `count` packets of the traffic to `path` as pcapng, and with `keylog` its TLS 1.2 keys. */
export function writeTraffic(path, count, { pps = 10000, seed = 1, keylog } = {}) {
  const fd = openSync(path, "w", 0o600);
  const keys = [];
  try {
    writeSync(fd, header());
    const gen = traffic(seed, (line) => keys.push(line));
    let parts = [];
    let size = 0;
    for (let n = 0; n < count; n++) {
      const b = packet(n, gen.next().value, { pps });
      parts.push(b);
      size += b.length;
      if (size > 8 << 20 || n === count - 1) {
        writeSync(fd, Buffer.concat(parts));
        parts = [];
        size = 0;
      }
    }
  } finally {
    closeSync(fd);
  }
  if (keylog) writeFileSync(keylog, keys.map((k) => k + "\n").join(""), { mode: 0o600 });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [out, count, pps, keylog] = process.argv.slice(2);
  if (!out || !count) {
    console.error("usage: node test/media/traffic.mjs <out.pcapng> <packets> [packets per second] [key log]");
    process.exit(2);
  }
  writeTraffic(out, Number(count), { pps: Number(pps) || 10000, keylog });
}
