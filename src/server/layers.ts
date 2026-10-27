/**
 * Finds the IP packet, or the UDP/TCP payload, in a frame's bytes, for panels
 * that parse their protocol themselves, and what raw matches look at (link
 * type, VLAN ids, addresses, protocol, ports). Per packet, without reassembly:
 * IP fragments and link types it doesn't know have no layer.
 */

export type Layer = "ip" | "payload";

/** Link layers the parser knows; null for any other. */
export type Link = "eth" | "sll" | "sll2" | "null" | "raw" | null;

const ETH_VLAN = new Set([0x8100, 0x88a8, 0x9100]);
const IPV4 = 0x0800;
const IPV6 = 0x86dd;
/** VLAN tags read in a row (QinQ and more). */
const MAX_VLAN_TAGS = 4;
/** IPv6 extension headers skipped on the way to UDP or TCP. */
const MAX_EXTENSION_HEADERS = 8;
/** IP protocols with source and destination ports in their first 4 bytes: TCP, UDP, DCCP, SCTP, UDP-Lite. */
const WITH_PORTS = new Set([6, 17, 33, 132, 136]);

/** Wireshark's encapsulation names (frame.encap_type). */
const BY_ENCAP: Record<string, Link> = {
  Ethernet: "eth",
  "Linux cooked-mode capture v1": "sll",
  "Linux cooked-mode capture v2": "sll2",
  "NULL/Loopback": "null",
  "OpenBSD loopback": "null",
  "Raw IP": "raw",
  "Raw IPv4": "raw",
  "Raw IPv6": "raw",
};

/** pcap and pcapng link types (LINKTYPE_*). */
const BY_TYPE: Record<number, Link> = { 1: "eth", 113: "sll", 276: "sll2", 0: "null", 108: "null", 101: "raw", 12: "raw", 14: "raw", 228: "raw", 229: "raw" };

export function linkOfEncap(encap: string): Link {
  return BY_ENCAP[encap] ?? null;
}

export function linkOfType(type: number): Link {
  return BY_TYPE[type] ?? null;
}

/** What one parse of a frame found; one object is filled again for each frame. -1: not there. */
export class Parsed {
  /** Of the network layer, behind any VLAN tags; for raw and loopback links, from the IP version. */
  ethertype = -1;
  /** VLAN ids, outer first. */
  readonly vlans: number[] = [];
  /** IP version, 0 without IP. */
  ip = 0;
  ipStart = -1;
  ipEnd = -1;
  /** Where the source and destination addresses start (4 or 16 bytes). */
  src = -1;
  dst = -1;
  /** IP protocol of the transport layer, behind IPv6 extension headers. */
  proto = -1;
  fragment = false;
  /** Of TCP, UDP, DCCP, SCTP and UDP-Lite; also in a first fragment. */
  srcport = -1;
  dstport = -1;
  /** UDP or TCP payload, not in fragments. */
  payloadStart = -1;
  payloadEnd = -1;

  /** The byte range of `layer`, or null. */
  range(layer: Layer): [number, number] | null {
    if (layer === "ip") return this.ip ? [this.ipStart, this.ipEnd] : null;
    return this.payloadStart >= 0 ? [this.payloadStart, this.payloadEnd] : null;
  }
}

/** Byte range [start, end) of `layer` in a frame of Wireshark's encapsulation `encap` (frame.encap_type), or null. */
export function findLayer(b: Uint8Array, encap: string, layer: Layer): [number, number] | null {
  return parse(b, linkOfEncap(encap), new Parsed()).range(layer);
}

/** Parses `b`, a frame of `link`, into `out`. */
export function parse(b: Uint8Array, link: Link, out: Parsed): Parsed {
  out.ip = 0;
  out.ethertype = out.ipStart = out.ipEnd = out.src = out.dst = out.proto = out.srcport = out.dstport = out.payloadStart = out.payloadEnd = -1;
  out.vlans.length = 0;
  out.fragment = false;
  const at = ipStart(b, link, out);
  if (at === null || at >= b.length) return out;
  const version = b[at] >> 4;
  // Behind a link without a type, the IP version tells
  if (link === "null" || link === "raw") out.ethertype = version === 4 ? IPV4 : version === 6 ? IPV6 : -1;
  if (version === 4) ipv4(b, at, out);
  else if (version === 6) ipv6(b, at, out);
  return out;
}

/** Where the IP header starts behind the link layer, or null; sets the ethertype and VLAN ids on the way. */
function ipStart(b: Uint8Array, link: Link, out: Parsed): number | null {
  const u16 = (i: number): number => (i + 2 <= b.length ? (b[i] << 8) | b[i + 1] : -1);
  const byType = (type: number, at: number): number | null => {
    out.ethertype = type;
    return type === IPV4 || type === IPV6 ? at : null;
  };
  switch (link) {
    case "eth": {
      let at = 14;
      let type = u16(12);
      for (let tags = 0; ETH_VLAN.has(type) && tags < MAX_VLAN_TAGS; tags++) {
        const tci = u16(at);
        if (tci >= 0) out.vlans.push(tci & 0xfff);
        type = u16(at + 2);
        at += 4;
      }
      // Up to 1500 it is an 802.3 length
      return byType(type >= 0x600 ? type : -1, at);
    }
    case "sll":
      return byType(u16(14), 16);
    case "sll2":
      return byType(u16(0), 20);
    case "null":
      // The address family's byte order varies: the IP version nibble tells
      return 4;
    case "raw":
      return 0;
    default:
      return null;
  }
}

function ipv4(b: Uint8Array, at: number, out: Parsed): void {
  if (at + 20 > b.length) return;
  const ihl = (b[at] & 15) * 4;
  // 0 with segmentation offload: the packet is what was captured, as Wireshark reads it
  const total = ((b[at + 2] << 8) | b[at + 3]) || b.length - at;
  if (ihl < 20 || total < ihl) return;
  const flags = (b[at + 6] << 8) | b[at + 7];
  const end = Math.min(at + total, b.length);
  [out.ip, out.ipStart, out.ipEnd, out.src, out.dst, out.proto] = [4, at, end, at + 12, at + 16, b[at + 9]];
  out.fragment = (flags & 0x3fff) !== 0;
  transport(b, at + ihl, end, (flags & 0x1fff) === 0, out);
}

function ipv6(b: Uint8Array, at: number, out: Parsed): void {
  if (at + 40 > b.length) return;
  const payload = (b[at + 4] << 8) | b[at + 5];
  // 0: a jumbogram, sized by its hop-by-hop option
  const end = payload ? Math.min(at + 40 + payload, b.length) : b.length;
  let next = b[at + 6];
  let p = at + 40;
  let fragment = false;
  let first = true;
  for (let i = 0; i < MAX_EXTENSION_HEADERS; i++) {
    if (next === 0 || next === 43 || next === 60) {
      if (p + 2 > end) return;
      [next, p] = [b[p], p + (b[p + 1] + 1) * 8];
    } else if (next === 44) {
      if (p + 8 > end) return;
      const offset = (b[p + 2] << 8) | b[p + 3];
      if ((offset & 0xfff9) !== 0) fragment = true;
      if ((offset & 0xfff8) !== 0) first = false;
      [next, p] = [b[p], p + 8];
    } else if (next === 51) {
      if (p + 2 > end) return;
      [next, p] = [b[p], p + (b[p + 1] + 2) * 4];
    } else break;
  }
  if (p > end) return;
  [out.ip, out.ipStart, out.ipEnd, out.src, out.dst, out.proto, out.fragment] = [6, at, end, at + 8, at + 24, next, fragment];
  transport(b, p, end, first, out);
}

/** Ports (in a first fragment too) and the UDP or TCP payload (not in fragments). */
function transport(b: Uint8Array, l4: number, end: number, first: boolean, out: Parsed): void {
  const proto = out.proto;
  if (first && WITH_PORTS.has(proto) && l4 + 4 <= end) {
    out.srcport = (b[l4] << 8) | b[l4 + 1];
    out.dstport = (b[l4 + 2] << 8) | b[l4 + 3];
  }
  if (out.fragment) return;
  if (proto === 17) {
    if (l4 + 8 > end) return;
    const len = (b[l4 + 4] << 8) | b[l4 + 5];
    [out.payloadStart, out.payloadEnd] = [l4 + 8, len >= 8 ? Math.min(l4 + len, end) : end];
  } else if (proto === 6) {
    if (l4 + 20 > end) return;
    const header = (b[l4 + 12] >> 4) * 4;
    if (header >= 20 && l4 + header <= end) [out.payloadStart, out.payloadEnd] = [l4 + header, end];
  }
}
