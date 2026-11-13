/**
 * What the statistics dialogs and Find Packet ask sharkd, and the shape of
 * its answers: protocol hierarchy, conversations, endpoints, expert info, I/O
 * graphs, the frame at a time and the next frame matching a filter. Each
 * reads the view through the few members of StatsView.
 */

import { matchingFrames, page, type Sharkd } from "./sharkd.ts";
import { StaleGenerationError } from "./stale.ts";
import { printable } from "./text.ts";
import type { SharkdPhs } from "./viewer.ts";
import type { ConvRow, EndpointRow, ExpertItem, ExpertSeverity, FilterCheck, FindResult, IoGraphResult, IoGraphSpec, PhsNode, ViewState } from "../shared/api.ts";

const CONV_TAPS = { eth: "Ethernet", ipv4: "IPv4", ipv6: "IPv6", tcp: "TCP", udp: "UDP" } as const;
export type ConvType = keyof typeof CONV_TAPS;
export const CONV_TYPES = Object.keys(CONV_TAPS) as ConvType[];
const MAX_IO_BUCKETS = 4000;
/** sharkd computes the interval in 32-bit microseconds; larger intervals overflow. */
const MAX_IO_INTERVAL = 2_000_000;
const MAX_IO_BUCKETS_HARD = 100_000;
const MAX_IO_GRAPHS = 4;

/** What the questions need of the viewer. */
export interface StatsView {
  /** The sharkd the view reads from now. */
  engine(): Sharkd;
  state(): Pick<ViewState, "file" | "filter" | "duration">;
  requireFile(): void;
  checkFilter(filter: string): Promise<FilterCheck>;
  sharkdFilter(filter: string): string;
  indexOf(frame: number | null): number;
}

/** sharkd tap parameters, limited to `filter` when given. */
async function tapParams(v: StatsView, tap: string, filter?: string): Promise<Record<string, unknown>> {
  v.requireFile();
  if (!filter?.trim()) return { tap0: tap };
  const check = await v.checkFilter(filter);
  if (!check.ok) throw new Error(`invalid display filter: ${check.error}`);
  return { tap0: tap, filter: v.sharkdFilter(filter.trim()) };
}

export async function phs(v: StatsView, filter?: string): Promise<PhsNode[]> {
  const r = await v.engine().call<{ taps: { protos: SharkdPhs[] }[] }>("tap", await tapParams(v, "phs", filter));
  const map = (p: SharkdPhs): PhsNode => ({
    proto: p.proto,
    frames: p.frames,
    bytes: p.bytes,
    children: (p.protos ?? []).map(map),
  });
  return (r.taps[0]?.protos ?? []).map(map);
}

export async function conversations(v: StatsView, type: ConvType, filter?: string): Promise<ConvRow[]> {
  const r = await v.engine().call<{ taps: { convs?: Record<string, never>[] }[] }>("tap", await tapParams(v, `conv:${CONV_TAPS[type]}`, filter));
  return (r.taps[0]?.convs ?? []).map((c: Record<string, any>) => ({
    addrA: c.saddr,
    portA: c.sport,
    addrB: c.daddr,
    portB: c.dport,
    framesAB: c.txf,
    bytesAB: c.txb,
    framesBA: c.rxf,
    bytesBA: c.rxb,
    start: c.start,
    duration: c.stop - c.start,
    filter: c.filter,
  }));
}

export async function endpoints(v: StatsView, type: ConvType, filter?: string): Promise<EndpointRow[]> {
  const r = await v.engine().call<{ taps: { hosts?: Record<string, never>[] }[] }>("tap", await tapParams(v, `endpt:${CONV_TAPS[type]}`, filter));
  return (r.taps[0]?.hosts ?? []).map((h: Record<string, any>) => ({
    addr: h.host,
    port: h.port,
    framesTx: h.txf,
    bytesTx: h.txb,
    framesRx: h.rxf,
    bytesRx: h.rxb,
    filter: h.filter,
  }));
}

export async function expert(v: StatsView, filter?: string): Promise<ExpertItem[]> {
  const r = await v.engine().call<{ taps: { details?: { f: number; s: string; g: string; p: string; m: string }[] }[] }>(
    "tap",
    await tapParams(v, "expert", filter),
  );
  return (r.taps[0]?.details ?? [])
    // Lua dissectors can put packet bytes into messages
    .map((d) => ({ frame: d.f, severity: d.s as ExpertSeverity, group: printable(d.g), protocol: printable(d.p), message: printable(d.m) }))
    .sort((a, b) => a.frame - b.frame);
}

/**
 * Packets, bytes or bits per interval for up to four filters. The interval
 * grows when the capture would need more than MAX_IO_BUCKETS buckets.
 */
export async function ioGraph(v: StatsView, specs: IoGraphSpec[], intervalMs: number): Promise<IoGraphResult> {
  v.requireFile();
  if (!specs.length || specs.length > MAX_IO_GRAPHS) throw new Error(`give 1 to ${MAX_IO_GRAPHS} graphs`);
  if (!Number.isFinite(intervalMs) || intervalMs < 1) throw new Error("the interval must be at least 1 ms");
  const params: Record<string, unknown> = {};
  for (const [i, g] of specs.entries()) {
    if (g.metric !== "packets" && g.metric !== "bytes" && g.metric !== "bits") throw new Error(`unknown metric "${g.metric}"`);
    params[`graph${i}`] = g.metric;
    const filter = (g.filter ?? "").trim();
    if (filter) {
      const check = await v.checkFilter(filter);
      if (!check.ok) throw new Error(`invalid display filter "${filter}": ${check.error}`);
      params[`filter${i}`] = v.sharkdFilter(filter);
    }
  }
  const spanUs = Math.max(Math.round(v.state().duration * 1e6), 1);
  const interval = Math.min(niceInterval(Math.max(Math.round(intervalMs), Math.ceil(spanUs / 1000 / MAX_IO_BUCKETS))), MAX_IO_INTERVAL);
  const buckets = Math.floor(spanUs / (interval * 1000)) + 1;
  if (buckets > MAX_IO_BUCKETS_HARD) throw new Error("the capture spans too much time for an I/O graph (check for packets with bogus timestamps)");
  const r = await v.engine().call<{ iograph: { items?: (number | string)[] }[] }>("iograph", { interval, ...params });
  return {
    interval,
    series: specs.map((g, i) => ({ metric: g.metric, filter: (g.filter ?? "").trim(), values: denseItems(r.iograph[i]?.items ?? [], buckets) })),
  };
}

/** First frame at or after `seconds` since the first frame (and before `until`, if given), within the display filter. */
export async function frameAt(v: StatsView, seconds: number, until?: number): Promise<number | null> {
  v.requireFile();
  if (!Number.isFinite(seconds) || seconds < 0) throw new Error("time must be a non-negative number of seconds");
  if (until !== undefined && !(Number.isFinite(until) && until > seconds)) throw new Error("until must be a time after t");
  const at = `frame.time_relative >= ${seconds.toFixed(9)}${until === undefined ? "" : ` && frame.time_relative < ${until.toFixed(9)}`}`;
  return firstMatching(v.engine(), v.state().filter ? `(${v.sharkdFilter(v.state().filter)}) && ${at}` : at);
}

/**
 * Find Packet: the first displayed frame after `from` (dir 1) or the last
 * one before it (dir -1) matching `filter`, else the first (last) one
 * overall. `from` 0 searches the whole list without wrapping.
 */
export async function find(v: StatsView, filter: string, from: number, dir: number): Promise<FindResult> {
  v.requireFile();
  if (dir !== 1 && dir !== -1) throw new Error("dir must be 1 or -1");
  if (!Number.isInteger(from) || from < 0) throw new Error("from must be a frame number, or 0 for none");
  filter = filter.trim();
  if (!filter) throw new Error("no display filter to find");
  const check = await v.checkFilter(filter);
  if (!check.ok) throw new Error(`invalid display filter: ${check.error}`);
  const engine = v.engine();
  const { file, filter: view } = v.state();
  const match = v.sharkdFilter(view ? `(${view}) && (${filter})` : `(${filter})`);
  let frame: number | null;
  let wrapped = false;
  if (dir === 1) {
    frame = await firstMatching(engine, from ? `${match} && frame.number > ${from}` : match);
    if (frame === null && from) {
      frame = await firstMatching(engine, match);
      wrapped = frame !== null;
    }
  } else {
    const frames = await matchingFrames(engine, match);
    const last = frames.length ? frames[frames.length - 1] : null;
    const before = from ? (frames.findLast((f) => f < from) ?? null) : last;
    frame = before ?? last;
    wrapped = before === null && last !== null;
  }
  // Live reloads keep frame numbers; another file or filter does not
  if (v.state().file !== file || v.state().filter !== view) throw new StaleGenerationError("the view changed during the search");
  return { frame, index: v.indexOf(frame), wrapped };
}

async function firstMatching(engine: Sharkd, filter: string): Promise<number | null> {
  const rows = await engine.call<{ num: number }[]>("frames", { filter, ...page(0, 1), column0: "frame.number:0" });
  return rows[0]?.num ?? null;
}

/** Rounds up to 1, 2 or 5 times a power of ten milliseconds. */
function niceInterval(ms: number): number {
  const p = 10 ** Math.floor(Math.log10(ms));
  for (const m of [1, 2, 5, 10]) if (m * p >= ms) return m * p;
  return 10 * p;
}

/** sharkd skips empty buckets: a string item is the next bucket's index in hex. */
function denseItems(items: (number | string)[], buckets: number): number[] {
  const values = new Array<number>(buckets).fill(0);
  let i = 0;
  for (const item of items) {
    if (typeof item === "string") i = parseInt(item, 16);
    else {
      // Rounding of the capture duration can leave sharkd one bucket ahead of us
      while (values.length <= i) values.push(0);
      values[i] = item;
      i++;
    }
  }
  return values;
}
