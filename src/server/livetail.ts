/**
 * LiveTail: the packets of a live capture that arrived after the last full
 * read of the file, dissected provisionally. The full read stays the only
 * exact source; until it covers them, newer packets are read from small
 * slices of the file by sharkd processes of their own.
 *
 * The file is cut into chunks of CHUNK frames, fewer when they would take
 * more than CHUNK_BYTES. A chunk's slice holds the chunk, the CONTEXT frames
 * before and after it (later packets complete reassembled PDUs), and what
 * FlowIndex finds the chunk's flows need from further away: frame 1 (the time
 * reference), their first packets, their messages under way before the slice,
 * their data under way after it and the answers they still owe. Every part
 * has a byte budget too, so a slice takes about 64 MiB at most whatever the
 * packet sizes. A chunk's rows always come from a slice of its own, so they
 * read the same every time once nothing that comes later can change them. A
 * complete chunk's row is kept once its slice reaches as far past the chunk
 * as it ever will and the row's flow takes nothing more from after that;
 * others while their chunk's slice stays the same. sharkd numbers a slice's
 * frames from 1: rows and details are renumbered to the file's frame numbers.
 */

import { createHash } from "node:crypto";
import { chmodSync, existsSync, lstatSync, mkdtempSync, readdirSync, readFileSync, readlinkSync, rmSync } from "node:fs";
import { unlink } from "node:fs/promises";
import { hostname } from "node:os";
import { join } from "node:path";
import { FrameStore } from "./framestore.ts";
import { FlowIndex, HEAD_BYTES } from "./flows.ts";
import { matchingFrames, type Sharkd } from "./sharkd.ts";
import type { PacketRow, TreeNode } from "../shared/api.ts";

const MiB = 2 ** 20;
/** Frames per chunk, and the bytes they may take. */
export const CHUNK = 10_000;
const CHUNK_BYTES = 32 * MiB;
/** Frames before and after a chunk its slice holds, and the bytes they may take on each side. */
export const CONTEXT = 2_000;
const CONTEXT_BYTES = 4 * MiB;
/** What a slice brings along for its flows from before the chunk's context, and from after it. */
const BEFORE = { frames: 20_000, bytes: 16 * MiB };
const AFTER = { frames: 10_000, bytes: 8 * MiB };
/** Rows kept that read so from now on. */
const MAX_CACHED_ROWS = 100_000;
/** Rows kept that later packets may still change, while their chunk's slice stays the same. */
const MAX_RECENT_ROWS = 5_000;
/** A page of a chunk brings the chunk's other filter matches along when there are no more than this. */
const READ_BATCH = 500;
/** Slices worked out, kept by chunk. */
const MAX_SLICES = 16;
/** Chunks whose slice wasn't final when checked against the filter that a pass looks at again. */
const UNSETTLED_LOOKS = 2;
/** Folders of slices start with this, then the machine's tag (see machineTag) and the server's process id. */
const DIR_PREFIX = ".wirebuddy-slices-";
/** sharkd's ftype of frame-number fields (FT_FRAMENUM). */
export const FT_FRAMENUM = 35;
/**
 * Fields counted over all sharkd read of a conversation (stream and
 * conversation indices, TCP's conversation completeness): a slice counts them
 * differently. Not the fields of a protocol's own streams (http2.stream,
 * quic.stream.offset).
 */
const STREAM_NUMBERED = /^(?:eth|ip|ipv6|ilnp|tcp|udp|dccp|mptcp|tls|dtls|bt-utp|wg|mp2t|usbcom\.data|irdma\.ep)\.stream(\.|$)|^sctp\.assoc_index$|^quic\.connection\.number$|^dect_nr\.conv_index$|^tcp\.completeness(\.|$)/;
/** Fields of frame numbers and displayed frames that filters on slices get wrong. */
const FRAME_FIELDS = /^frame\.(number|time_delta_displayed|ref_time)$/;
/** Frame numbers dissectors put into Info, in the forms they write them (text a packet carries is left alone). */
const INFO_FRAMES = [
  /([([](?:reply|request) in )(\d+)(?=[)\]])/g,
  /(\((?:Call|Reply) In )(\d+)(?=\))/g,
  /(\[response to )(\d+)(?=\])/g,
  /(\[TCP PDU reassembled in )(\d+)(?=\])/g,
  /(\b[Rr]eassembled in #)(\d+)\b/g,
  /(\[MTP2 Reassembled in: )(\d+)(?=\])/g,
  /(\([^()]*\breassembled in packet )(\d+)(?=\))/g,
  /(\[Reas: #|\breas: #)(\d+)(?=\])/g,
  /(\[RPC (?:retransmission|duplicate) of #)(\d+)(?=\])/g,
  /(\[Continuation to #)(\d+)(?=\])/g,
  /(\[(?:TCP )?Dup ACK )(\d+)(?=#\d+\])/g,
];
/** Frame numbers in expert info texts: "Original request in frame 12", "(frame 12)", "a retransmission of frame 12". */
const EXPERT_FRAMES = /(\b(?:in|of|to|from|at|using) frame:? |\(frame:? |\bin packet:? )(\d+)\b/g;
/** Longest label sharkd shows: lists of frames that would make it longer stop before. */
const MAX_LABEL = 239;

/** The list changed since rows were asked for, or the tail closed: they are asked for again. */
export class Superseded extends Error {}

/** Whether a field is counted over what sharkd read, so slices can't tell its value. */
export function streamNumbered(field: string): boolean {
  return STREAM_NUMBERED.test(field);
}

/** The slice of chunk lo..end: frames `extras` (all before c0), c0..hi, then frames `after` (all after hi). */
export interface Slice {
  lo: number;
  end: number;
  hi: number;
  c0: number;
  extras: Int32Array;
  after: Int32Array;
  /** The chunk won't grow. */
  complete: boolean;
  /** Nothing more comes before hi: the chunk's slices differ only in `after` from now on. */
  settled: boolean;
  /** Its rows read the same from now on: what comes later can't change them. */
  final: boolean;
}

/** The slice's frames in its own order. */
export function sliceFrames(s: Slice): Int32Array {
  const n = s.hi - s.c0 + 1;
  const out = new Int32Array(s.extras.length + n + s.after.length);
  out.set(s.extras);
  for (let i = 0; i < n; i++) out[s.extras.length + i] = s.c0 + i;
  out.set(s.after, s.extras.length + n);
  return out;
}

/** The file's frame number of the slice's frame `local`, or `local` itself when there is none. */
export function toGlobal(s: Slice, local: number): number {
  const k = s.extras.length;
  const n = s.hi - s.c0 + 1;
  if (local >= 1 && local <= k) return s.extras[local - 1];
  if (local > k && local <= k + n) return s.c0 + local - k - 1;
  if (local > k + n && local <= k + n + s.after.length) return s.after[local - k - n - 1];
  return local;
}

/** The slice's frame number of the file's frame `frame` (c0..hi). */
export function toLocal(s: Slice, frame: number): number {
  return s.extras.length + frame - s.c0 + 1;
}

/** Which columns of a row show frame numbers, and which are numbered or counted within a slice. */
export interface Numbering {
  /** No. and frame-number fields (frame.number, tcp.reassembled_in, ...). */
  frames: number[];
  /** The Info column, or -1. */
  info: number;
  /** Fields numbered within a slice (stream indices): left empty. */
  blank: number[];
  /** Cumulative Bytes (%B): the bytes of the file's packets up to the row's. */
  bytes?: number[];
}

/** Renumbers a row read from slice `s` and marks it provisional; `bytes` gives a frame's Cumulative Bytes. */
export function renumberRow(row: PacketRow, s: Slice, n: Numbering, bytes?: (frame: number) => number): PacketRow {
  const g = (m: string): string => String(toGlobal(s, Number(m)));
  const num = toGlobal(s, row.num);
  const c = row.c.slice();
  for (const j of n.frames) if (c[j]) c[j] = c[j].replace(/\d+/g, g);
  if (n.info >= 0 && c[n.info]) c[n.info] = renumberInfo(c[n.info], (m) => toGlobal(s, m));
  for (const j of n.blank) if (j < c.length) c[j] = "";
  for (const j of n.bytes ?? []) if (j < c.length) c[j] = bytes ? String(bytes(num)) : "";
  return { num, c, bg: row.bg, fg: row.fg, p: true };
}

/**
 * Frame numbers dissectors put into Info: "[TCP PDU reassembled in 12]",
 * "[Reassembled in #12]", "(reply in 12)", "(request in 12)", "[RPC
 * retransmission of #12]", "[TCP Dup ACK 12#1]" and the like.
 */
export function renumberInfo(info: string, map: (frame: number) => number): string {
  for (const re of INFO_FRAMES) info = info.replace(re, (_, words: string, d: string) => words + map(Number(d)));
  return info;
}

/**
 * Renumbers a details tree read from slice `s`; fields counted within the
 * slice lose their value. `expert`: the nodes are an expert info's.
 */
export function renumberTree(nodes: TreeNode[], s: Slice, expert = false): TreeNode[] {
  const g = (n: number): number => toGlobal(s, n);
  const word = (text: string, from: number, to: number): string => text.replace(new RegExp(`\\b${from}\\b`), String(to));
  return nodes.map((n) => {
    const out: TreeNode = { ...n };
    const inExpert = expert || n.fn === "_ws.expert";
    if (n.t === "framenum" && n.fnum) {
      out.fnum = g(n.fnum);
      out.l = word(n.l, n.fnum, out.fnum);
      if (n.f) out.f = word(n.f, n.fnum, out.fnum);
    } else if (n.fn === "frame") out.l = n.l.replace(/^Frame (\d+):/, (_, d: string) => `Frame ${g(Number(d))}:`);
    else if (n.fn === "frame.number") {
      out.l = n.l.replace(/\d+$/, (d) => String(g(Number(d))));
      if (n.f) out.f = n.f.replace(/\d+$/, (d) => String(g(Number(d))));
    } else if (n.fn && STREAM_NUMBERED.test(n.fn)) {
      // Its parts (TCP's completeness flags) are just as unknown
      out.l = n.l.replace(/:.*?(\]?)$/, ": unknown until read in full$1");
      delete out.f;
      delete out.n;
      return out;
    } else if (inExpert) out.l = n.l.replace(EXPERT_FRAMES, (_, words: string, d: string) => words + g(Number(d)));
    // Lists of the frames a PDU was reassembled from, "#12(1448), #14(552)", as long as the file's numbers let them be
    if (/#\d+\(/.test(out.l)) {
      out.l = out.l.replace(/#(\d+)\(/g, (_, d: string) => `#${g(Number(d))}(`);
      while (out.l.length > MAX_LABEL && /, #\d+\(\d+\)(?=[^#]*$)/.test(out.l)) out.l = out.l.replace(/, #\d+\(\d+\)(?=[^#]*$)/, "");
    }
    if (n.n) out.n = renumberTree(n.n, s, inExpert);
    return out;
  });
}

/**
 * Why a display filter can't be checked on slices, or null: it uses a field
 * counted over what sharkd read (stream indices, TCP's conversation
 * completeness, frame numbers), or a field reference or macro ("$"). `type`
 * gives a field's sharkd ftype.
 */
export async function heldReason(filter: string, type: (field: string) => Promise<number | null>): Promise<string | null> {
  if (filter.includes("$")) return "the filter uses a field reference or macro";
  for (const token of new Set(filter.replace(/"(\\.|[^"\\])*"/g, " ").match(/[A-Za-z_][A-Za-z0-9_.-]*/g) ?? [])) {
    if (STREAM_NUMBERED.test(token) || FRAME_FIELDS.test(token)) return `the filter uses ${token}`;
    if (token.includes(".") && (await type(token)) === FT_FRAMENUM) return `the filter uses the frame number field ${token}`;
  }
  return null;
}

/** How the view's rows read. */
export interface RowView {
  numbering: Numbering;
  /** Reads rows from a sharkd like the view's packet list does (its columns, custom ones too). */
  fetch: (engine: Sharkd, params: Record<string, unknown>) => Promise<PacketRow[]>;
  /** Changes whenever rows would read differently (columns, extensions, TLS keys). */
  key: string;
}

/** A sharkd for slices, with the slice it holds; work on it runs one at a time. */
class Engine {
  /** The slice it holds, and its file. */
  slice: Slice | null = null;
  file = "";
  /** The held slice's frames a filter matches, once asked for (sharkd keeps that filter's result too). */
  matches: { filter: string; local: Int32Array } | null = null;
  private pending = 0;
  private queue: Promise<unknown> = Promise.resolve();

  constructor(readonly sharkd: Sharkd) {}

  /** Nothing queued or running on it. */
  get idle(): boolean {
    return this.pending === 0;
  }

  run<T>(fn: () => Promise<T>): Promise<T> {
    this.pending++;
    const next = this.queue.then(fn, fn).finally(() => this.pending--);
    this.queue = next.catch(() => {});
    return next;
  }

  /** Whether frames of `s`'s chunk up to `last` can be read from the slice it holds: `s` itself, or while the chunk grows an earlier one. */
  serves(s: Slice, last: number): boolean {
    const held = this.slice;
    if (!held || held.lo !== s.lo || last > held.end || this.sharkd.outdated()) return false;
    return !s.complete || sliceKey(held) === sliceKey(s);
  }
}

export interface TailOptions {
  /** The live capture file. */
  file: string;
  /** Where the folder of slices goes: the capture's folder. */
  dir: string;
  /** A sharkd set up like the view's (profile, extensions, TLS keys). */
  sharkd: () => Sharkd;
}

export class LiveTail {
  readonly file: string;
  readonly store: FrameStore;
  private readonly flows = new FlowIndex();
  /** Per frame: the bytes of frames 1..it, as Wireshark counts Cumulative Bytes (32 bits). */
  private cumBytes = new Uint32Array(4096);
  /** First frames of the chunks so far; the last chunk may still grow. */
  private readonly starts: number[] = [1];
  /** Frames 1..base are read in full; the tail is base+1..count. */
  base = 0;
  /** Shown in the view: full reads have become slow. */
  active = false;
  filter = "";
  /** Why newer packets wait for a full read with this filter, or null. */
  held: string | null = null;
  /** Provisional matches of the filter, ascending, after base. */
  private matches: number[] = [];
  /** Frames up to here were checked against the filter. */
  private checked = 0;
  /** When the newest chunk may be checked again. */
  private growingAt = 0;
  /** Chunks checked before their slice was final, by first frame: the slice checked, the count of frames then and when last looked at. */
  private readonly unsettled = new Map<number, { key: string; checked: number; looked: number }>();
  /** Changes when a check changed provisional matches listed before. */
  revision = 0;
  /** Changes with the filter and on close: passes started before are dropped. */
  private seq = 0;
  private folder: string | null = null;
  private files = 0;
  private rowsEngine: Engine | null = null;
  private filterEngine: Engine | null = null;
  private indexing: Promise<void> = Promise.resolve();
  /** Slices worked out, by chunk, with the count they are for. */
  private readonly slices = new Map<number, { count: number; slice: Slice }>();
  /** Rows that read so from now on, by chunk, the one used last at the end; for RowView.key. */
  private readonly cache = new Map<number, Map<number, PacketRow>>();
  private cachedRows = 0;
  private cacheKey = "";
  /** Other rows, by chunk, with the slice they were read from: kept while it is the chunk's slice. */
  private readonly recent = new Map<number, { key: string; rows: Map<number, PacketRow> }>();
  private recentRows = 0;
  private closed = false;

  constructor(private readonly opts: TailOptions) {
    this.file = opts.file;
    this.store = new FrameStore(opts.file);
  }

  /** Packets indexed: frames 1..count. */
  get count(): number {
    return this.flows.count;
  }

  /** Packets after the full read. */
  get frames(): number {
    return Math.max(0, this.count - this.base);
  }

  /** Why the tail can't go on, or null. */
  broken(): string | null {
    return this.store.sliceable();
  }

  /** Indexes what the file gained. */
  update(): Promise<void> {
    const index = async (): Promise<void> => {
      await this.store.update();
      if (this.store.count > this.flows.count) {
        await this.store.readHeads(this.flows.count + 1, this.store.count, HEAD_BYTES, (frame, time, len, link, data) => {
          this.flows.feed(frame, link, data, time);
          this.addBytes(frame, len);
        });
        this.cut();
      }
    };
    this.indexing = this.indexing.then(index, index);
    return this.indexing;
  }

  private addBytes(frame: number, len: number): void {
    if (frame > this.cumBytes.length) {
      const grown = new Uint32Array(this.cumBytes.length * 2);
      grown.set(this.cumBytes);
      this.cumBytes = grown;
    }
    this.cumBytes[frame - 1] = (frame > 1 ? this.cumBytes[frame - 2] : 0) + len;
  }

  /** A full read covers frames 1..frames now. */
  rebase(frames: number): void {
    // Back to fewer (a read failed): all of them are checked against the filter again
    if (frames < this.base) {
      this.base = frames;
      this.setFilter(this.filter, this.held);
    }
    this.base = frames;
    let i = 0;
    while (i < this.matches.length && this.matches[i] <= frames) i++;
    if (i) this.matches = this.matches.slice(i);
    this.checked = Math.max(this.checked, frames);
    for (const [lo, rows] of this.cache) {
      for (const f of rows.keys()) {
        if (f > frames) continue;
        rows.delete(f);
        this.cachedRows--;
      }
      if (!rows.size) this.cache.delete(lo);
    }
  }

  setFilter(filter: string, held: string | null): void {
    this.filter = filter;
    this.held = filter ? held : null;
    this.matches = [];
    this.checked = this.base;
    this.growingAt = 0;
    this.unsettled.clear();
    this.seq++;
  }

  /** Rows the tail adds to the view's list. */
  listed(): number {
    if (!this.filter) return this.frames;
    return this.held ? 0 : this.matches.length;
  }

  /** Newer packets the filter wasn't checked against yet. */
  unfiltered(): number {
    return this.filter && !this.held ? Math.max(0, this.count - Math.max(this.checked, this.base)) : 0;
  }

  /** Whether the tail's `frame` wasn't checked against the filter yet. */
  unchecked(frame: number): boolean {
    return !!this.filter && !this.held && frame > Math.max(this.checked, this.base);
  }

  /** Frame of the tail's row `i`. */
  frameAt(i: number): number {
    return this.filter ? this.matches[i] : this.base + 1 + i;
  }

  /** The tail's row of `frame`, or -1. */
  indexOf(frame: number): number {
    if (frame <= this.base || frame > this.count) return -1;
    if (!this.filter) return frame - this.base - 1;
    let lo = 0;
    let hi = this.matches.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      if (this.matches[mid] === frame) return mid;
      if (this.matches[mid] < frame) lo = mid + 1;
      else hi = mid - 1;
    }
    return -1;
  }

  /** The slice of the chunk that holds `frame`, as far as the file is indexed. */
  slice(frame: number): Slice {
    const { lo, end, complete } = this.chunk(frame);
    const hit = this.slices.get(lo);
    if (hit?.count === this.count) return hit.slice;
    const size = (f: number): number => this.store.size(f);
    const c0 = this.fitBack(Math.max(1, lo - CONTEXT), lo - 1, CONTEXT_BYTES);
    const hi = this.fit(end + 1, Math.min(end + CONTEXT, this.count), CONTEXT_BYTES);
    // Nothing more comes before hi once it holds CONTEXT frames, or stopped short of the newest one
    const settled = complete && (hi === end + CONTEXT || hi < this.count);
    const after = settled ? this.flows.after(lo, end, hi, { ...AFTER, size }) : { frames: new Int32Array(0), open: true };
    const extras = this.flows.context(c0, end, { ...BEFORE, size });
    const s: Slice = { lo, end, hi, c0, extras, after: after.frames, complete, settled, final: settled && !after.open };
    this.slices.delete(lo);
    this.slices.set(lo, { count: this.count, slice: s });
    if (this.slices.size > MAX_SLICES) this.slices.delete(this.slices.keys().next().value!);
    return s;
  }

  /** Rows i0..i0+n-1 of the tail, renumbered; slices are read only while `wanted` says so. */
  rows(i0: number, n: number, view: RowView, wanted?: () => boolean): Promise<PacketRow[]> {
    const frames: number[] = [];
    for (let i = i0; i < i0 + n && i < this.listed(); i++) frames.push(this.frameAt(i));
    return this.rowsOf(frames, view, wanted);
  }

  /** Rows of the given tail frames (ascending), whatever the filter; slices are read only while `wanted` says so. */
  async rowsOf(frames: number[], view: RowView, wanted: () => boolean = () => true): Promise<PacketRow[]> {
    this.useView(view);
    const got = new Map<number, PacketRow>();
    for (let i = 0; i < frames.length; ) {
      const { lo, end, complete } = this.chunk(frames[i]);
      let j = i;
      while (j + 1 < frames.length && frames[j + 1] <= end) j++;
      const cached = this.cache.get(lo);
      if (cached) {
        this.cache.delete(lo);
        this.cache.set(lo, cached);
      }
      const take = (rows: Map<number, PacketRow> | undefined) => (f: number): boolean => {
        const r = rows?.get(f);
        if (r) got.set(f, r);
        return !r;
      };
      let part = frames.slice(i, j + 1).filter(take(cached));
      const recent = part.length ? this.recentOf(lo) : undefined;
      if (recent) part = part.filter(take(recent));
      // A filter's matches are sparse: pages around these ask for the chunk's others next, when they are few
      if (part.length && complete && this.filter && !this.held) {
        const more = this.matchesIn(lo, end).filter((f) => !cached?.has(f) && !recent?.has(f));
        if (more.length <= READ_BATCH) part = [...new Set([...part, ...more])].sort((a, b) => a - b);
      }
      if (part.length) {
        const { rows, slice } = await this.readChunk(part, view, wanted);
        this.keepAll(slice, part, rows, got);
      }
      i = j + 1;
    }
    return frames.map((f) => got.get(f)!);
  }

  /** Rows kept are of `view`: none once rows read differently. */
  private useView(view: RowView): void {
    if (view.key === this.cacheKey) return;
    this.cache.clear();
    this.cachedRows = 0;
    this.recent.clear();
    this.recentRows = 0;
    this.cacheKey = view.key;
  }

  /** Rows read from slice `s` of `frames` into `got`, kept while they read so. */
  private keepAll(s: Slice, frames: number[], rows: Map<number, PacketRow>, got?: Map<number, PacketRow>): void {
    for (const f of frames) {
      const row = rows.get(f);
      got?.set(f, row ?? { num: f, c: [], p: true });
      if (!row) continue;
      if (this.settled(s, f)) this.keep(s.lo, f, row);
      else this.remember(s, f, row);
    }
  }

  /** Reads the newest `n` rows of the tail, so a list that shows them next gets them at once. */
  async warm(n: number, view: RowView): Promise<void> {
    const listed = this.listed();
    if (listed) await this.rows(Math.max(0, listed - n), Math.min(n, listed), view);
  }

  /** Rows kept of chunk `lo` that read so now. */
  private recentOf(lo: number): Map<number, PacketRow> | undefined {
    const r = this.recent.get(lo);
    if (!r) return undefined;
    this.recent.delete(lo);
    if (this.current(lo, r.key)) {
      this.recent.set(lo, r);
      return r.rows;
    }
    this.recentRows -= r.rows.size;
    return undefined;
  }

  /** Whether rows read from slice `key` still read so for chunk `lo`: it is the chunk's slice now. */
  private current(lo: number, key: string): boolean {
    return key === sliceKey(this.slice(lo));
  }

  /**
   * Whether a row read from slice `s` reads so until a full read covers it:
   * its chunk is final, or settled and its flow takes nothing more from
   * after hi. A growing chunk's rows may still change: a reply that comes
   * later than its slice holds names its request (ping, NFS).
   */
  private settled(s: Slice, frame: number): boolean {
    return s.final || (s.settled && !this.flows.pending(frame, s.hi));
  }

  /** Keeps a row read from slice `s` while that is its chunk's slice; the chunks used longest ago go first. */
  private remember(s: Slice, frame: number, row: PacketRow): void {
    const key = sliceKey(s);
    if (!this.current(s.lo, key)) return;
    let r = this.recent.get(s.lo);
    if (r?.key !== key) {
      if (r) this.recentRows -= r.rows.size;
      r = { key, rows: new Map() };
    }
    this.recent.delete(s.lo);
    this.recent.set(s.lo, r);
    if (!r.rows.has(frame)) this.recentRows++;
    r.rows.set(frame, row);
    for (const [old, x] of this.recent) {
      if (this.recentRows <= MAX_RECENT_ROWS || old === s.lo) break;
      this.recent.delete(old);
      this.recentRows -= x.rows.size;
    }
  }

  /** Rows of `frames` (ascending, of one chunk) from a slice of their chunk, `slice`. */
  private async readChunk(frames: number[], view: RowView, wanted: () => boolean): Promise<{ rows: Map<number, PacketRow>; slice: Slice }> {
    const last = frames[frames.length - 1];
    // The filter's sharkd may hold the slice (the newest chunk, just checked), when it has nothing else to do
    const filter = this.filterEngine;
    if (filter?.idle && filter.serves(this.slice(last), last)) {
      const got = await filter.run(async () => (filter.serves(this.slice(last), last) ? this.read(filter, frames, view) : null));
      if (got) return got;
    }
    const engine = (this.rowsEngine ??= this.newEngine());
    return engine.run(async () => {
      // Asked for again since, for a list that grew: that request reads them
      if (!wanted()) throw new Superseded("the list changed since");
      const s = this.slice(last);
      if (!engine.serves(s, last)) await this.load(engine, s);
      return this.read(engine, frames, view);
    });
  }

  /** Rows of `frames` (ascending, of the chunk) from the slice `engine` holds, renumbered. */
  private async read(engine: Engine, frames: number[], view: RowView): Promise<{ rows: Map<number, PacketRow>; slice: Slice }> {
    const s = engine.slice!;
    const filter = this.filter && !this.held ? this.filter : "";
    const matched = filter ? await this.matchesOf(engine, filter) : null;
    // A match by its place among the slice's, which sharkd keeps (no pass over the slice again); other frames by number
    const byMatch: number[] = [];
    const byFrame: number[] = [];
    for (const f of frames) {
      const local = toLocal(s, f);
      const i = matched ? indexIn(matched, local) : -1;
      if (i >= 0) byMatch.push(i);
      else byFrame.push(local);
    }
    const rows = new Map<number, PacketRow>();
    const fetch = async (params: Record<string, unknown>): Promise<void> => {
      for (const r of await view.fetch(engine.sharkd, params)) rows.set(toGlobal(s, r.num), renumberRow(r, s, view.numbering, (f) => this.cumBytes[f - 1]));
    };
    for (const [first, n] of runs(byMatch)) await fetch({ filter, ...(first ? { skip: first } : {}), limit: n });
    for (const [first, n] of runs(byFrame)) await fetch({ ...(first > 1 ? { skip: first - 1 } : {}), limit: n });
    return { rows, slice: s };
  }

  /** The frames of the slice `engine` holds that `filter` matches, by their numbers there. */
  private async matchesOf(engine: Engine, filter: string): Promise<Int32Array> {
    const known = engine.matches;
    if (known?.filter === filter) return known.local;
    const local = await matchingFrames(engine.sharkd, filter);
    engine.matches = { filter, local };
    return local;
  }

  /** The filter's provisional matches in lo..hi. */
  private matchesIn(lo: number, hi: number): number[] {
    return this.matches.slice(this.matchAt(lo), this.matchAt(hi + 1));
  }

  /** Where the first of the filter's provisional matches from `frame` on is. */
  private matchAt(frame: number): number {
    let a = 0;
    let b = this.matches.length;
    while (a < b) {
      const mid = (a + b) >> 1;
      if (this.matches[mid] < frame) a = mid + 1;
      else b = mid;
    }
    return a;
  }

  /** Keeps a row that reads so from now on (see settled); the chunks used longest ago go first. */
  private keep(lo: number, frame: number, row: PacketRow): void {
    let rows = this.cache.get(lo);
    if (!rows) this.cache.set(lo, (rows = new Map()));
    if (!rows.has(frame)) this.cachedRows++;
    rows.set(frame, row);
    for (const [old, r] of this.cache) {
      if (this.cachedRows <= MAX_CACHED_ROWS || old === lo) break;
      this.cache.delete(old);
      this.cachedRows -= r.size;
    }
  }

  /** Details of a tail frame from a slice of its chunk, renumbered. */
  frame(num: number): Promise<{ tree: TreeNode[]; bytes: string; ds: { name: string; bytes: string }[]; first: number | null }> {
    const engine = (this.rowsEngine ??= this.newEngine());
    return engine.run(async () => {
      const s = this.slice(num);
      if (!engine.serves(s, num)) await this.load(engine, s);
      const held = engine.slice!;
      const f = await engine.sharkd.call<{ tree: TreeNode[]; bytes?: string; ds?: { name: string; bytes: string }[] }>("frame", { frame: toLocal(held, num), proto: true, bytes: true });
      return { tree: renumberTree(f.tree, held), bytes: f.bytes ?? "", ds: f.ds ?? [], first: this.flows.firstOf(num) };
    });
  }

  /**
   * Checks the next chunk of newer packets against the filter, else again
   * one whose slice wasn't final then and changed since (a reply that came
   * may change its matches): once it is final, or else once the chunk is
   * twice as old as then (CONTEXT packets at least). True when more wait:
   * the newest chunk, still growing, is checked again once more packets
   * came, and after a pause as long as the last check took (sharkd reads the
   * whole slice for each).
   * With `view`, the newest `rows` matches of the newest chunk it checked
   * are read too, while sharkd holds the slice, so a list that shows them
   * next gets them at once.
   */
  async filterPass(view?: RowView, rows = 0): Promise<boolean> {
    const { seq, filter } = this;
    if (!filter || this.held || this.closed) return false;
    const from = Math.max(this.checked, this.base) + 1;
    const next = from <= this.count && (this.chunk(from).complete || Date.now() >= this.growingAt) ? from : this.recheck();
    if (!next) return false;
    const engine = (this.filterEngine ??= this.newEngine());
    return engine.run(async () => {
      const started = Date.now();
      const s = this.slice(next);
      await this.load(engine, s);
      const found = await this.matchesOf(engine, filter);
      if (seq !== this.seq) return false;
      const lo = Math.max(s.lo, this.base + 1);
      const first = s.extras.length + 1;
      const last = s.extras.length + s.hi - s.c0 + 1;
      const now: number[] = [];
      for (const local of found) {
        const f = toGlobal(s, local);
        if (local >= first && local <= last && f >= lo && f <= s.end) now.push(f);
      }
      if (view && rows > 0 && next === from && now.length) {
        this.useView(view);
        const newest = now.slice(-rows);
        this.keepAll(s, newest, (await this.read(engine, newest, view)).rows);
        if (seq !== this.seq) return false;
      }
      this.place(lo, s.end, now);
      this.checked = Math.max(this.checked, s.end);
      if (!s.complete) this.growingAt = 2 * Date.now() - started;
      this.unsettled.delete(s.lo);
      if (s.complete && !s.final) this.unsettled.set(s.lo, { key: sliceKey(s), checked: this.count, looked: this.count });
      return (s.complete && this.checked < this.count) || this.recheck() > 0;
    });
  }

  /** Puts the filter's matches in lo..end in place of those found before; a change to ones listed before is a new revision. */
  private place(lo: number, end: number, found: number[]): void {
    const a = this.matchAt(lo);
    const b = this.matchAt(end + 1);
    const listed = (fs: number[]): string => fs.filter((f) => f <= this.checked).join();
    if (listed(this.matches.slice(a, b)) !== listed(found)) this.revision++;
    this.matches.splice(a, b - a, ...found);
  }

  /**
   * The first frame of a chunk to check again (see filterPass()), or 0. A
   * few others are looked at a pass, each again after the others once more
   * packets came.
   */
  private recheck(): number {
    let looks = UNSETTLED_LOOKS;
    for (const [lo, was] of this.unsettled) {
      const { end } = this.chunk(lo);
      if (end <= this.base) {
        this.unsettled.delete(lo);
        continue;
      }
      if (was.looked === this.count) continue;
      const s = this.slice(lo);
      const changed = sliceKey(s) !== was.key;
      if (changed && (s.final || this.count - end >= Math.max(CONTEXT, 2 * (was.checked - end)))) return lo;
      // Final as it was checked: its matches stand
      this.unsettled.delete(lo);
      if (!s.final) this.unsettled.set(lo, { ...was, looked: this.count });
      if (!--looks) break;
    }
    return 0;
  }

  /** Slices must be read with the TLS keys now in use. */
  setTlsKeylog(path: string | null): void {
    for (const e of [this.rowsEngine, this.filterEngine]) {
      if (!e) continue;
      e.slice = null;
      e.matches = null;
      e.sharkd.setPref("tls.keylog_file", path ?? "").catch(() => {});
    }
  }

  close(): void {
    this.closed = true;
    this.seq++;
    // Work under way can't start them again
    for (const e of [this.rowsEngine, this.filterEngine]) e?.sharkd.dispose();
    this.rowsEngine = this.filterEngine = null;
    this.store.close();
    try {
      if (this.folder) rmSync(this.folder, { recursive: true, force: true });
    } catch {
      // made unwritable meanwhile: a later server on this machine removes it
    }
    this.folder = null;
  }

  private newEngine(): Engine {
    // Closed: nobody would close its sharkd
    if (this.closed) throw new Superseded("the live view moved on");
    return new Engine(this.opts.sharkd());
  }

  /** Writes slice `s` and loads it into `engine`, unless it holds it already. */
  private async load(engine: Engine, s: Slice): Promise<void> {
    if (this.closed) throw new Superseded("the live view moved on");
    // New extensions: a new process, which has no slice yet
    if (engine.sharkd.outdated()) {
      engine.sharkd.restart();
      engine.slice = null;
    }
    if (engine.slice && sliceKey(engine.slice) === sliceKey(s)) return;
    engine.slice = null;
    engine.matches = null;
    const frames = sliceFrames(s);
    const path = join(this.dir(), `${++this.files}.pcapng`);
    try {
      await this.store.writeSlice(frames, path);
      if (this.closed) throw new Superseded("the live view moved on");
      const r = await engine.sharkd.call<{ status: string; err?: number }>("load", { file: path });
      if (r.status !== "OK") throw new Error(`sharkd could not read a slice: ${r.status}`);
      const status = await engine.sharkd.call<{ frames: number }>("status");
      if (status.frames !== frames.length) throw new Error(`sharkd read ${status.frames} of a slice's ${frames.length} packets`);
    } catch (err) {
      unlink(path).catch(() => {});
      throw err;
    }
    // sharkd closed the slice it held before
    if (engine.file) unlink(engine.file).catch(() => {});
    Object.assign(engine, { slice: s, file: path });
  }

  /** The folder of slices, only the user's, next to the capture; again if it was removed. */
  private dir(): string {
    if (this.folder && !existsSync(this.folder)) this.folder = null;
    if (!this.folder) {
      removeStaleSlices(this.opts.dir);
      this.folder = mkdtempSync(join(this.opts.dir, slicesPrefix()));
    }
    return this.folder;
  }

  /** The chunk lo..end that holds `frame` (1..count). */
  private chunk(frame: number): { lo: number; end: number; complete: boolean } {
    let a = 0;
    let b = this.starts.length - 1;
    while (a < b) {
      const mid = (a + b + 1) >> 1;
      if (this.starts[mid] <= frame) a = mid;
      else b = mid - 1;
    }
    const next = this.starts[a + 1];
    return next === undefined ? { lo: this.starts[a], end: this.count, complete: false } : { lo: this.starts[a], end: next - 1, complete: true };
  }

  /** Cuts newly indexed frames into chunks: CHUNK frames, or fewer when the next one would take them past CHUNK_BYTES. */
  private cut(): void {
    for (;;) {
      const lo = this.starts[this.starts.length - 1];
      const end = this.fit(lo, Math.min(lo + CHUNK - 1, this.count), CHUNK_BYTES);
      if (end < lo + CHUNK - 1 && end >= this.count) return;
      this.starts.push(end + 1);
    }
  }

  /** The last frame of lo..hi such that lo up to it take at most `bytes` (lo at least). */
  private fit(lo: number, hi: number, bytes: number): number {
    if (hi <= lo || this.store.bytes(lo, hi) <= bytes) return hi;
    let a = lo;
    let b = hi;
    while (b - a > 1) {
      const mid = (a + b) >> 1;
      if (this.store.bytes(lo, mid) <= bytes) a = mid;
      else b = mid;
    }
    return a;
  }

  /** The first frame of lo..hi such that it up to hi take at most `bytes` (hi at least). */
  private fitBack(lo: number, hi: number, bytes: number): number {
    if (hi <= lo || this.store.bytes(lo, hi) <= bytes) return lo;
    let a = lo;
    let b = hi;
    while (b - a > 1) {
      const mid = (a + b) >> 1;
      if (this.store.bytes(mid, hi) <= bytes) b = mid;
      else a = mid;
    }
    return b;
  }
}

/** Which slice an engine holds. */
function sliceKey(s: Slice): string {
  return `${s.lo}-${s.end}-${s.hi}-${s.extras.length}-${s.after.length}`;
}

/** Where `v` is in the ascending `a`, or -1. */
function indexIn(a: Int32Array, v: number): number {
  let lo = 0;
  let hi = a.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (a[mid] === v) return mid;
    if (a[mid] < v) lo = mid + 1;
    else hi = mid - 1;
  }
  return -1;
}

/** Runs of consecutive numbers in the ascending `xs`, as [first, length]. */
function runs(xs: number[]): [number, number][] {
  const out: [number, number][] = [];
  for (let i = 0; i < xs.length; ) {
    let j = i;
    while (j + 1 < xs.length && xs[j + 1] === xs[j] + 1) j++;
    out.push([xs[i], j - i + 1]);
    i = j + 1;
  }
  return out;
}

/**
 * Tells the processes a pid can be checked against: the same host, boot and
 * pid namespace. Another container, or another host sharing the folder, has
 * pids of its own.
 */
function machineTag(): string {
  const read = (get: () => string): string => {
    try {
      return get().trim();
    } catch {
      return "";
    }
  };
  const boot = read(() => readFileSync("/proc/sys/kernel/random/boot_id", "utf8"));
  const pids = read(() => readlinkSync("/proc/self/ns/pid"));
  return createHash("sha256").update([hostname(), boot, pids].join("\0")).digest("hex").slice(0, 8);
}
const MACHINE = machineTag();

/** How the name of a folder of slices of the server `pid` on this machine starts. */
export function slicesPrefix(pid = process.pid): string {
  return `${DIR_PREFIX}${MACHINE}-${pid}-`;
}

/**
 * Removes the folders of slices the user's servers on this machine left
 * behind (killed, or the folder was made unwritable): ones whose server is
 * gone. Links, others' folders and folders of servers elsewhere stay.
 */
export function removeStaleSlices(dir: string): void {
  let names: string[];
  try {
    names = readdirSync(dir);
  } catch {
    return;
  }
  for (const name of names) {
    const m = /^\.wirebuddy-slices-([0-9a-f]{8})-(\d+)-/.exec(name);
    const pid = Number(m?.[2]);
    if (!m || m[1] !== MACHINE || !pid || pid === process.pid || alive(pid)) continue;
    const path = join(dir, name);
    try {
      const st = lstatSync(path);
      if (!st.isDirectory() || st.uid !== process.getuid?.()) continue;
      if ((st.mode & 0o700) !== 0o700) chmodSync(path, 0o700);
      rmSync(path, { recursive: true, force: true });
    } catch {
      // the others still go
    }
  }
}

function alive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === "EPERM";
  }
}
