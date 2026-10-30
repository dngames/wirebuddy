/** Helpers over FrameDetail: data sources, tree walking, filters. */

import type { ExpertSeverity, FrameDetail, TreeNode } from "../shared/api.ts";
import { b64ToBytes } from "./util.ts";

export interface Source {
  name: string;
  bytes: Uint8Array;
}

interface Info {
  /** [frame bytes, ...ds]; a node's source is `sources[node.ds ?? 0]`. */
  sources: Source[];
  parent: Map<TreeNode, TreeNode | null>;
  depth: Map<TreeNode, number>;
}

const cache = new WeakMap<FrameDetail, Info>();

export function frameInfo(fd: FrameDetail): Info {
  let info = cache.get(fd);
  if (info) return info;
  const frameBytes = b64ToBytes(fd.bytes);
  const sources: Source[] = [{ name: `Frame (${frameBytes.length} bytes)`, bytes: frameBytes }];
  for (const d of fd.ds ?? []) sources.push({ name: d.name, bytes: b64ToBytes(d.bytes) });
  const parent = new Map<TreeNode, TreeNode | null>();
  const depth = new Map<TreeNode, number>();
  walk(fd.tree, (n, d, p) => {
    parent.set(n, p);
    depth.set(n, d);
  });
  info = { sources, parent, depth };
  cache.set(fd, info);
  return info;
}

/** Index into frameInfo().sources for a node's byte range. */
export function srcIndex(fd: FrameDetail, n: TreeNode): number {
  const k = n.ds ?? 0;
  return k >= 0 && k <= (fd.ds?.length ?? 0) ? k : 0;
}

export function walk(nodes: TreeNode[] | undefined, fn: (n: TreeNode, depth: number, parent: TreeNode | null) => void | boolean, depth = 0, parent: TreeNode | null = null): void {
  if (!nodes) return;
  for (const n of nodes) {
    if (fn(n, depth, parent) === false) continue;
    walk(n.n, fn, depth + 1, n);
  }
}

/** Label as Wireshark shows it: generated fields in [brackets]. */
export function nodeLabel(n: TreeNode): string {
  if (n.g && !n.l.startsWith("[")) return `[${n.l}]`;
  return n.l;
}

/** Field display name from the label: "Source Address: 1.2.3.4" gives "Source Address". */
export function fieldName(n: TreeNode): string {
  let s = n.l.replace(/^\[|\]$/g, "");
  if (n.t === "proto") {
    const k = s.indexOf(", ");
    if (k > 0) s = s.slice(0, k);
  } else {
    const k = s.indexOf(": ");
    if (k > 0) s = s.slice(0, k);
  }
  return s;
}

/** Value part of a field: text after ": " in the label, else after "==" in the filter. */
export function fieldValue(n: TreeNode): string {
  const l = n.l.replace(/^\[|\]$/g, "");
  const k = l.indexOf(": ");
  if (k > 0) return l.slice(k + 2);
  if (n.f) {
    const e = n.f.indexOf("==");
    if (e > 0) return n.f.slice(e + 2).trim();
  }
  return l;
}

/** Status bar text: "Source Address (ip.src), 4 bytes". */
export function fieldInfoText(n: TreeNode): string {
  let s = fieldName(n);
  if (n.fn) s += ` (${n.fn})`;
  if (n.h && n.h[1] > 0) s += `, ${n.h[1]} byte${n.h[1] === 1 ? "" : "s"}`;
  return s;
}

const SEV_RANK: Record<ExpertSeverity, number> = { Comment: 1, Chat: 2, Note: 3, Warning: 4, Warn: 4, Error: 5 };

/** 1 (Comment) … 5 (Error); 0 for unknown values. */
export function sevRank(s: ExpertSeverity | string | null | undefined): number {
  return (s && SEV_RANK[s as ExpertSeverity]) || 0;
}

export function sevClass(s: ExpertSeverity | undefined): string {
  switch (s) {
    case "Comment":
      return "sev-comment";
    case "Chat":
      return "sev-chat";
    case "Note":
      return "sev-note";
    case "Warning":
    case "Warn":
      return "sev-warn";
    case "Error":
      return "sev-error";
    default:
      return "";
  }
}

export function maxSeverity(fd: FrameDetail | null): ExpertSeverity | null {
  if (!fd) return null;
  let best: ExpertSeverity | null = null;
  walk(fd.tree, (n) => {
    if (n.s && (!best || SEV_RANK[n.s] > SEV_RANK[best])) best = n.s;
  });
  return best;
}

/** First value of each field name in `nodes`, taken from `fn == value` filters. */
function firstValues(nodes: TreeNode[], names: Set<string>): Map<string, string> {
  const out = new Map<string, string>();
  walk(nodes, (n) => {
    if (n.fn && names.has(n.fn) && !out.has(n.fn) && n.f && n.f.length < 300) {
      const e = n.f.indexOf("==");
      if (e > 0) out.set(n.fn, n.f.slice(e + 2).trim());
    }
  });
  return out;
}

/** Conversation filters (Ethernet, IPv4, IPv6, TCP, UDP) for a frame, like Wireshark's. */
export function conversationFilters(fd: FrameDetail): { label: string; filter: string }[] {
  const v = firstValues(
    fd.tree,
    new Set(["eth.src", "eth.dst", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst", "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport"]),
  );
  const out: { label: string; filter: string }[] = [];
  const pair = (field: string, a?: string, b?: string): string | null => (a && b ? `${field} == ${a} && ${field} == ${b}` : null);
  const eth = pair("eth.addr", v.get("eth.src"), v.get("eth.dst"));
  const ip4 = pair("ip.addr", v.get("ip.src"), v.get("ip.dst"));
  const ip6 = pair("ipv6.addr", v.get("ipv6.src"), v.get("ipv6.dst"));
  const ip = ip4 ?? ip6;
  if (eth) out.push({ label: "Ethernet", filter: eth });
  if (ip4) out.push({ label: "IPv4", filter: ip4 });
  if (ip6) out.push({ label: "IPv6", filter: ip6 });
  for (const proto of ["tcp", "udp"]) {
    const ports = pair(`${proto}.port`, v.get(`${proto}.srcport`), v.get(`${proto}.dstport`));
    if (ports) out.push({ label: proto.toUpperCase(), filter: ip ? `(${ip}) && (${ports})` : ports });
  }
  return out;
}

/**
 * The ports Decode As can take of a frame: those of its last top-level TCP
 * or UDP layer (the inner one of tunneled traffic), with the protocol that
 * decodes its payload now (null: none in this packet, as for a TCP segment
 * reassembled in another) and whether it has payload at all.
 */
export function decodeAsPorts(fd: FrameDetail): { transport: "tcp" | "udp"; src: number; dst: number; now: string | null; payload: boolean } | null {
  const at = fd.tree.findLastIndex((n) => n.fn === "tcp" || n.fn === "udp");
  if (at < 0) return null;
  const transport = fd.tree[at].fn as "tcp" | "udp";
  const v = firstValues([fd.tree[at]], new Set([`${transport}.srcport`, `${transport}.dstport`, "tcp.len"]));
  const [src, dst] = [v.get(`${transport}.srcport`), v.get(`${transport}.dstport`)].map(Number);
  if (!Number.isInteger(src) || !Number.isInteger(dst)) return null;
  // Past nodes that aren't protocols (reassembled TCP segments)
  const next = fd.tree.slice(at + 1).find((n) => n.t === "proto");
  return { transport, src, dst, now: next ? next.l.split(" (")[0] : null, payload: !!next || Number(v.get("tcp.len")) > 0 };
}

/** Deepest node whose byte range in source `src` covers `off`. */
export function nodeAtOffset(fd: FrameDetail, src: number, off: number): TreeNode | null {
  let best: TreeNode | null = null;
  let bestDepth = -1;
  let bestLen = Infinity;
  walk(fd.tree, (n, d) => {
    if (!n.h || n.h[1] <= 0 || srcIndex(fd, n) !== src) return;
    if (off < n.h[0] || off >= n.h[0] + n.h[1]) return;
    if (d > bestDepth || (d === bestDepth && n.h[1] < bestLen)) {
      best = n;
      bestDepth = d;
      bestLen = n.h[1];
    }
  });
  return best;
}
