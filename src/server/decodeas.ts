/**
 * Decode As, like Wireshark's: entries that make a port (or an RTP payload
 * type) dissect as a protocol Wireshark knows. WireBuddy's prelude applies
 * them in every sharkd from the preference wirebuddy.decode_as, as
 * "<table> <value> <protocol>" joined by ";", and reports how each went in
 * wirebuddy.decode_as_status.
 */

import type { DecodeAsChange, DecodeAsEntry, DecodeAsTable } from "../shared/api.ts";
import { entryText } from "../shared/decodeas.ts";
import { ReportedError } from "./events.ts";
import { printable } from "./text.ts";

/** Per table: its largest value, and the field its packets are counted by. */
export const TABLES: Record<DecodeAsTable, { max: number; field: string }> = {
  "tcp.port": { max: 65535, field: "tcp.port" },
  "udp.port": { max: 65535, field: "udp.port" },
  "tls.port": { max: 65535, field: "tcp.port" },
  "rtp.pt": { max: 127, field: "rtp.p_type" },
};
/** About 3.3 KB serialized: sharkd cuts preference values at 4095 characters. */
export const MAX_ENTRIES = 50;
/** A display-filter protocol name: no dots, spaces or ";". */
const PROTOCOL = /^[a-z0-9][a-z0-9_-]{0,47}$/;

/** How the prelude applied an entry: what decoded its value before and now (dissector names, "" for none), or why not. */
export type EntryStatus = { status: "OK"; was: string; now: string } | { status: "no-table" | "no-protocol" | "error"; message: string };

/** A change as the agent or the UI sent it, checked; throws ReportedError. */
export function parseChange(raw: unknown): DecodeAsChange {
  const r = (raw && typeof raw === "object" ? raw : {}) as Record<string, unknown>;
  const has = (key: string): boolean => r[key] !== undefined && r[key] !== null;
  if (r.action === "clear") {
    if (has("table") !== has("value")) throw new ReportedError("give both table and value to remove one entry, or neither to remove all");
    if (!has("table")) return { action: "clear" };
    const table = tableOf(r.table);
    return { action: "clear", table, value: valueOf(table, r.value) };
  }
  if (r.action !== "set") throw new ReportedError('action is "set" or "clear"');
  if (!has("table") || !has("value") || !has("protocol")) throw new ReportedError("give table, value and protocol to set an entry");
  const table = tableOf(r.table);
  const value = valueOf(table, r.value);
  const protocol = typeof r.protocol === "string" ? r.protocol.toLowerCase() : "";
  if (!PROTOCOL.test(protocol)) throw new ReportedError("protocol is a display-filter protocol name such as rtp or mqtt");
  return { action: "set", table, value, protocol };
}

function tableOf(v: unknown): DecodeAsTable {
  if (typeof v !== "string" || !Object.hasOwn(TABLES, v)) throw new ReportedError(`table is one of ${Object.keys(TABLES).join(", ")}`);
  return v as DecodeAsTable;
}

function valueOf(table: DecodeAsTable, v: unknown): number {
  const { max } = TABLES[table];
  if (!Number.isInteger(v) || (v as number) < 0 || (v as number) > max) throw new ReportedError(`${table} takes one ${table === "rtp.pt" ? "payload type" : "port"}, 0-${max}`);
  return v as number;
}

/** The entries after `change`; setting one for a table and value that has one replaces it. Throws ReportedError. */
export function applyChange(list: readonly DecodeAsEntry[], change: DecodeAsChange, by: "user" | "agent"): DecodeAsEntry[] {
  if (change.action === "clear" && change.table === undefined) return [];
  const i = list.findIndex((e) => e.table === change.table && e.value === change.value);
  if (change.action === "clear") {
    if (i < 0) throw new ReportedError(`no Decode As entry for ${change.table} ${change.value}; entries: ${list.map(entryText).join(", ") || "none"}`);
    return list.filter((_, j) => j !== i);
  }
  const entry: DecodeAsEntry = { table: change.table, value: change.value, protocol: change.protocol, by };
  if (i >= 0) return list.map((e, j) => (j === i ? entry : e));
  if (list.length >= MAX_ENTRIES) throw new ReportedError(`at most ${MAX_ENTRIES} Decode As entries; remove some first`);
  return [...list, entry];
}

/** The entries as the prelude reads them. */
export function serialize(list: readonly DecodeAsEntry[]): string {
  return list.map((e) => `${e.table} ${e.value} ${e.protocol}`).join(";");
}

/** The prelude's report, by entry as serialize() writes it. */
export function parseStatus(text: string): Map<string, EntryStatus> {
  const out = new Map<string, EntryStatus>();
  for (const line of text.split("\n")) {
    const [entry, status, ...rest] = line.split("\t").map(printable);
    if (!entry) continue;
    if (status === "OK") out.set(entry, { status, was: rest[0] ?? "", now: rest[1] ?? "" });
    else out.set(entry, { status: status === "no-table" || status === "no-protocol" ? status : "error", message: rest.join(" ") });
  }
  return out;
}

/** Up to `n` of `candidates` within 2 edits of `name` (a swap of neighbours is one), closest first, then a letter more or less at the end. */
export function closeMatches<T extends { f: string }>(name: string, candidates: readonly T[], n = 5): T[] {
  return candidates
    .map((c) => ({ c, d: distance(name, c.f) }))
    .filter((x) => x.d <= 2)
    .sort((x, y) => x.d - y.d || Number(prefixed(name, y.c.f)) - Number(prefixed(name, x.c.f)) || Math.abs(x.c.f.length - name.length) - Math.abs(y.c.f.length - name.length) || (x.c.f < y.c.f ? -1 : 1))
    .slice(0, n)
    .map((x) => x.c);
}

function prefixed(a: string, b: string): boolean {
  return a.startsWith(b) || b.startsWith(a);
}

/** Damerau–Levenshtein distance (optimal string alignment). */
function distance(a: string, b: string): number {
  const d = Array.from({ length: a.length + 1 }, (_, i) => Array.from({ length: b.length + 1 }, (_, j) => (i ? (j ? 0 : i) : j)));
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
    }
  }
  return d[a.length][b.length];
}

/** The display filter of the packets an entry decodes. */
export function countFilter(e: DecodeAsEntry): string {
  return `${e.protocol} && ${TABLES[e.table].field} == ${e.value}`;
}
