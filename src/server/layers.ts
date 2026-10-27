/**
 * Finds the IP packet, or the UDP/TCP payload, in a frame's bytes, for panels
 * that parse their protocol themselves. Per packet, without reassembly: IP
 * fragments and link types it doesn't know have no layer.
 */

export type Layer = "ip" | "payload";

const ETH_VLAN = new Set([0x8100, 0x88a8, 0x9100]);
const IPV4 = 0x0800;
const IPV6 = 0x86dd;
/** IPv6 extension headers skipped on the way to UDP or TCP. */
const MAX_EXTENSION_HEADERS = 8;

/** Byte range [start, end) of `layer` in a frame of Wireshark's encapsulation `encap` (frame.encap_type), or null. */
export function findLayer(b: Uint8Array, encap: string, layer: Layer): [number, number] | null {
  const at = ipStart(b, encap);
  if (at === null || at >= b.length) return null;
  const version = b[at] >> 4;
  const ip = version === 4 ? ipv4(b, at) : version === 6 ? ipv6(b, at) : null;
  if (!ip) return null;
  if (layer === "ip") return [at, ip.end];
  if (ip.fragment) return null;
  return transportPayload(b, ip.proto, ip.l4, ip.end);
}

/** Where the IP header starts behind the link layer, or null. */
function ipStart(b: Uint8Array, encap: string): number | null {
  const u16 = (i: number): number => (i + 2 <= b.length ? (b[i] << 8) | b[i + 1] : -1);
  const byType = (type: number, at: number): number | null => (type === IPV4 || type === IPV6 ? at : null);
  switch (encap) {
    case "Ethernet": {
      let at = 14;
      let type = u16(12);
      for (let tags = 0; ETH_VLAN.has(type) && tags < 4; tags++) {
        type = u16(at + 2);
        at += 4;
      }
      return byType(type, at);
    }
    case "Linux cooked-mode capture v1":
      return byType(u16(14), 16);
    case "Linux cooked-mode capture v2":
      return byType(u16(0), 20);
    case "NULL/Loopback":
    case "OpenBSD loopback":
      // The address family's byte order varies: the IP version nibble tells
      return 4;
    case "Raw IP":
    case "Raw IPv4":
    case "Raw IPv6":
      return 0;
    default:
      return null;
  }
}

function ipv4(b: Uint8Array, at: number): { proto: number; l4: number; end: number; fragment: boolean } | null {
  if (at + 20 > b.length) return null;
  const ihl = (b[at] & 15) * 4;
  // 0 with segmentation offload: the packet is what was captured, as Wireshark reads it
  const total = ((b[at + 2] << 8) | b[at + 3]) || b.length - at;
  if (ihl < 20 || total < ihl) return null;
  const flags = (b[at + 6] << 8) | b[at + 7];
  return { proto: b[at + 9], l4: at + ihl, end: Math.min(at + total, b.length), fragment: (flags & 0x3fff) !== 0 };
}

function ipv6(b: Uint8Array, at: number): { proto: number; l4: number; end: number; fragment: boolean } | null {
  if (at + 40 > b.length) return null;
  const payload = (b[at + 4] << 8) | b[at + 5];
  // 0: a jumbogram, sized by its hop-by-hop option
  const end = payload ? Math.min(at + 40 + payload, b.length) : b.length;
  let next = b[at + 6];
  let p = at + 40;
  let fragment = false;
  for (let i = 0; i < MAX_EXTENSION_HEADERS; i++) {
    if (next === 0 || next === 43 || next === 60) {
      if (p + 2 > end) return null;
      [next, p] = [b[p], p + (b[p + 1] + 1) * 8];
    } else if (next === 44) {
      if (p + 8 > end) return null;
      if ((((b[p + 2] << 8) | b[p + 3]) & 0xfff9) !== 0) fragment = true;
      [next, p] = [b[p], p + 8];
    } else if (next === 51) {
      if (p + 2 > end) return null;
      [next, p] = [b[p], p + (b[p + 1] + 2) * 4];
    } else break;
  }
  return p <= end ? { proto: next, l4: p, end, fragment } : null;
}

function transportPayload(b: Uint8Array, proto: number, l4: number, end: number): [number, number] | null {
  if (proto === 17) {
    if (l4 + 8 > end) return null;
    const len = (b[l4 + 4] << 8) | b[l4 + 5];
    return [l4 + 8, len >= 8 ? Math.min(l4 + len, end) : end];
  }
  if (proto === 6) {
    if (l4 + 20 > end) return null;
    const header = (b[l4 + 12] >> 4) * 4;
    return header >= 20 && l4 + header <= end ? [l4 + header, end] : null;
  }
  return null;
}
