// Packets and capture files written by hand, for the FrameStore and panel tests:
// pcap in both byte orders with µs or ns times, pcapng with several sections.

/** IPv4 header (20 bytes, no checksum) around `body`. */
export function ip4(proto, body, { src = [10, 0, 0, 1], dst = [10, 0, 0, 2], flags = 0, total = 20 + body.length } = {}) {
  return Buffer.concat([Buffer.from([0x45, 0, total >> 8, total & 255, 0, 1, flags >> 8, flags & 255, 64, proto, 0, 0, ...src, ...dst]), body]);
}

/** IPv6 header around `body`; `src`/`dst` are 16 bytes. */
export function ip6(next, body, { src = [0xfe, 0x80, ...Array(13).fill(0), 1], dst = [0xfe, 0x80, ...Array(13).fill(0), 2] } = {}) {
  return Buffer.concat([Buffer.from([0x60, 0, 0, 0, body.length >> 8, body.length & 255, next, 64, ...src, ...dst]), body]);
}

export function udp(sport, dport, payload) {
  const h = Buffer.alloc(8);
  h.writeUInt16BE(sport, 0);
  h.writeUInt16BE(dport, 2);
  h.writeUInt16BE(8 + payload.length, 4);
  return Buffer.concat([h, payload]);
}

export function tcp(sport, dport, payload) {
  const h = Buffer.alloc(20);
  h.writeUInt16BE(sport, 0);
  h.writeUInt16BE(dport, 2);
  h[12] = 0x50;
  h[13] = 0x18;
  h.writeUInt16BE(65535, 14);
  return Buffer.concat([h, payload]);
}

/** Ethernet II with optional VLAN tags [[tpid, id], ...] around a packet of `type`. */
export function eth(type, body, tags = []) {
  const head = [...Array(12).fill(0)];
  for (const [tpid, id] of tags) head.push(tpid >> 8, tpid & 255, id >> 8, id & 255);
  head.push(type >> 8, type & 255);
  return Buffer.concat([Buffer.from(head), body]);
}

/** A UDP packet over Ethernet and IPv4, numbered by `seq` in its payload. */
export function udpFrame(seq, { sport = 40000, dport = 7502, size = 32 } = {}) {
  const payload = Buffer.alloc(size);
  payload.writeUInt32BE(seq, 0);
  return eth(0x0800, ip4(17, udp(sport, dport, payload)));
}

const u16 = (v, le) => {
  const b = Buffer.alloc(2);
  le ? b.writeUInt16LE(v) : b.writeUInt16BE(v);
  return b;
};
const u32 = (v, le) => {
  const b = Buffer.alloc(4);
  le ? b.writeUInt32LE(v >>> 0) : b.writeUInt32BE(v >>> 0);
  return b;
};
const pad4 = (b) => Buffer.concat([b, Buffer.alloc((4 - (b.length % 4)) % 4)]);

/** pcap file header. */
export function pcapHeader({ little = true, nano = false, link = 1, snaplen = 262144 } = {}) {
  const magic = nano ? 0xa1b23c4d : 0xa1b2c3d4;
  return Buffer.concat([u32(magic, little), u16(2, little), u16(4, little), u32(0, little), u32(0, little), u32(snaplen, little), u32(link, little)]);
}

/** A pcap record: `sec`, `frac` (µs or ns), the bytes, the length on the wire. */
export function pcapRecord(sec, frac, data, { little = true, orig = data.length } = {}) {
  return Buffer.concat([u32(sec, little), u32(frac, little), u32(data.length, little), u32(orig, little), data]);
}

/** A pcapng block of `type` around `body`. */
export function block(type, body, little = true) {
  const b = pad4(body);
  return Buffer.concat([u32(type, little), u32(12 + b.length, little), b, u32(12 + b.length, little)]);
}

/** Section header; its section length is "unknown". */
export function shb(little = true) {
  return block(0x0a0d0d0a, Buffer.concat([u32(0x1a2b3c4d, little), u16(1, little), u16(0, little), Buffer.alloc(8, 0xff)]), little);
}

/** Interface description: `tsresol` is the if_tsresol byte, `tsoffset` seconds. */
export function idb(link, { little = true, snaplen = 0, tsresol, tsoffset } = {}) {
  const opts = [];
  if (tsresol !== undefined) opts.push(u16(9, little), u16(1, little), pad4(Buffer.from([tsresol])));
  if (tsoffset !== undefined) {
    const v = Buffer.alloc(8);
    little ? v.writeBigInt64LE(BigInt(tsoffset)) : v.writeBigInt64BE(BigInt(tsoffset));
    opts.push(u16(14, little), u16(8, little), v);
  }
  if (opts.length) opts.push(u16(0, little), u16(0, little));
  return block(1, Buffer.concat([u16(link, little), u16(0, little), u32(snaplen, little), ...opts]), little);
}

/** Enhanced packet block; `ts` is a bigint in the interface's units. */
export function epb(iface, ts, data, { little = true, orig = data.length } = {}) {
  return block(6, Buffer.concat([u32(iface, little), u32(Number(ts >> 32n), little), u32(Number(ts & 0xffffffffn), little), u32(data.length, little), u32(orig, little), data]), little);
}

/** Obsolete packet block. */
export function opb(iface, ts, data, { little = true } = {}) {
  return block(2, Buffer.concat([u16(iface, little), u16(0, little), u32(Number(ts >> 32n), little), u32(Number(ts & 0xffffffffn), little), u32(data.length, little), u32(data.length, little), data]), little);
}

/** Simple packet block: `data` is what was captured of `orig` bytes. */
export function spb(data, { little = true, orig = data.length } = {}) {
  return block(3, Buffer.concat([u32(orig, little), data]), little);
}

/** Interface statistics and name resolution blocks: not packets. */
export function isb(iface, little = true) {
  return block(5, Buffer.concat([u32(iface, little), u32(0, little), u32(0, little)]), little);
}

export function nrb(little = true) {
  return block(4, Buffer.concat([u16(0, little), u16(0, little)]), little);
}
