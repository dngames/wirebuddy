/**
 * Capture data for panels, read by a sharkd of their own: the view's engines
 * answer strictly in order, so a panel's queries there would stall the packet
 * list. The panel engine starts on the first request, reads the view's file
 * again when it changes (a growing live file at most once a second), lets the
 * open panels take turns, and stops a minute after the last panel closed.
 *
 * Raw packets need no sharkd: when the file is uncompressed pcap or pcapng,
 * FrameStore reads times, lengths, frame/IP/payload bytes and raw matches
 * straight from it, also ahead of the view while the file grows. Such pages
 * are never `pending` (each request reads the file's end); a "packets" event
 * says when it grew. Pages that need the engine are `pending` while it has
 * read fewer packets than the view or FrameStore know of.
 */

import { closeSync, openSync, readSync, statSync } from "node:fs";
import { isIPv4, isIPv6 } from "node:net";
import { basename } from "node:path";
import type { PanelView } from "../shared/api.ts";
import type { Ranges } from "../shared/ranges.ts";
import type { EventLog } from "./events.ts";
import { FrameStore } from "./framestore.ts";
import { findLayer, parse, Parsed, type Layer } from "./layers.ts";
import { matchingFrames, Sharkd, SharkdError, SharkdTooLarge } from "./sharkd.ts";
import { printable } from "./text.ts";
import { framesWithRefs, refBefore, refsOf, refTimeError, refTimeFilter } from "./timerefs.ts";
import { encodePage, type PageRow } from "./wbpk.ts";

/** One sharkd call (a load: LOAD_BUDGET_MS) may take this long; then the engine restarts. */
const CALL_BUDGET_MS = 30_000;
const LOAD_BUDGET_MS = 5 * 60_000;
const IDLE_STOP_MS = 60_000;
/** A growing live file is read again at most this often. */
const LIVE_LOAD_MS = 1000;
const CRASHES_PER_MINUTE = 3;
/** Longest sharkd answer the panel engine reads (a followed stream, a frame with its reassembled data), in characters. */
const MAX_ANSWER = 96 * 1024 * 1024;
/** Per load: filter checks and export object listings, and frame sets of filters. */
const MAX_CACHED = 256;
const MAX_CACHED_SETS = 8;
const MAX_FIELDS = 16;
const MAX_FILTER = 4096;
const MAX_RANGES = 10_000;
const DEFAULT_LIMIT = 1000;
/** Packets per page: without fields (bytes from FrameStore), with fields, with bytes from sharkd (one call per packet). */
const MAX_LIMIT = { plain: 50_000, fields: 5_000, bytes: 2_000 };
/** Packets read from FrameStore at once: for a page, and while matching. */
const RAW_BATCH = 2048;
const SCAN_BATCH = 65_536;
/** Values a match key may list. */
const MAX_MATCH_VALUES = 64;
/** IP protocols by name, for match.proto. */
const PROTOS: Record<string, number> = { icmp: 1, igmp: 2, tcp: 6, udp: 17, dccp: 33, gre: 47, esp: 50, ah: 51, icmpv6: 58, ospf: 89, pim: 103, vrrp: 112, sctp: 132, udplite: 136 };
const DEFAULT_MAX_BYTES = 4 * 1024 * 1024;
const MAX_BYTES = 16 * 1024 * 1024;
const MAX_OBJECT = 64 * 1024 * 1024;
const MAX_OBJECTS = 10_000;
/** Packets whose bytes one turn at the engine asks for. */
const BYTES_BATCH = 32;
/** Characters of field values one sharkd answer may hold (about 2 KB a value at most), and the frame numbers of a filter per answer. */
const COLUMN_CHARS = MAX_ANSWER / 2;
const MATCH_PAGE = 500_000;
const FIELD_NAME = /^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$/;
/** sharkd's mark for a value it cut (about 2 KB). */
const CLIPPED = "[…] ";
const EO_KINDS = new Set(["http", "imf", "smb", "tftp", "dicom", "ftp-data"]);
const CONV = { eth: "Ethernet", ipv4: "IPv4", ipv6: "IPv6", tcp: "TCP", udp: "UDP" };
const TAPS: Record<string, string> = {
  phs: "phs",
  expert: "expert",
  "rtp-streams": "rtp-streams",
  ...Object.fromEntries(Object.entries(CONV).flatMap(([k, v]) => [[`conv:${k}`, `conv:${v}`], [`endpt:${k}`, `endpt:${v}`]])),
};
/** Follow protocols whose streams are numbered by TCP's or UDP's stream index. */
const STREAM_OF: Record<string, string> = { TCP: "tcp", TLS: "tcp", HTTP: "tcp", UDP: "udp" };
const LUA_HINT = 'is the extension\'s Lua loaded? extensions action "reload"';
/** The turn label of offer checks; panel labels are base32. */
const OFFERS = "_offers";

/** A failed panel request: HTTP status, a code the bridge acts on, and help for the agent. */
export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly extra: { hint?: string; retryMs?: number; epoch?: number } = {},
  ) {
    super(message);
  }
}

/** What panels see of the view, and the frame lists they can ask for. */
export interface PanelSource {
  view(): PanelView;
  /** Changes whenever packets already seen may read differently. */
  epoch(): number;
  /** Why it changed last: file, closed, rewritten, extensions, tls or decode-as. */
  resetWhy(): string;
  file(): string | null;
  /** The view follows a capture that is running. */
  live(): boolean;
  totalFrames(): number;
  /** The frames the view shows, and its display filter as sharkd matches it. */
  displayed(): { set: FrameSet; filter: string };
  /** The packets the user selected, else the selected one. */
  selected(): FrameSet;
  marked(): FrameSet;
  /** Time references, ascending: what frame.ref_time matches and time fields count from. */
  timeRefs(): readonly number[];
  /** The dissection preferences WireBuddy set (TLS key log, Decode As), for every sharkd. */
  prefs(): ReadonlyMap<string, string>;
  /** Inode and first bytes of the file as the view read it. */
  fileId(): { ino: number; head: Buffer };
}

export type Answer = { kind: "json"; body: unknown } | { kind: "page"; body: Buffer } | { kind: "object"; body: Buffer; type: string; filename: string };

/** A request after its load: the panel and the file it reads. */
interface Ctx {
  label: string;
  loaded: Loaded;
}

interface Loaded {
  file: string;
  epoch: number;
  frames: number;
  /** Counts loads: caches belong to one. */
  seq: number;
  at: number;
}

interface TreeNode {
  fn?: string;
  h?: [number, number];
  ds?: number;
  n?: TreeNode[];
}

interface EoObject {
  pkt: number;
  hostname?: string;
  type?: string;
  filename?: string;
  _download: string;
  len: number;
  sha1?: string;
}

export class PanelData {
  private engine: Sharkd | null = null;
  private loaded: Loaded | null = null;
  private seq = 0;
  /** Panels waiting for their turn, in turn order; each turn is one sharkd call (or a batch). */
  private readonly waiting = new Map<string, { go: () => void; fail: (e: Error) => void }[]>();
  private busy = false;
  /** Labels of the open panels: only they get turns. */
  private readonly open = new Set<string>();
  private crashes: number[] = [];
  private idleTimer: NodeJS.Timeout | null = null;
  /** Of the current load: filter checks and export object listings; frame sets by filter. */
  private readonly cache = new Map<string, unknown>();
  private readonly sets = new Map<string, unknown>();
  /** The last stream followed, decoded. */
  private lastFollow: { seq: number; key: string; result: FollowData } | null = null;
  /** The view's file as FrameStore reads it; kept over epochs that leave the file as it was. */
  private store: { store: FrameStore; epoch: number; checked: boolean } | null = null;
  /** Frames of raw matches in the store's file, by match. */
  private readonly matchSets = new Map<string, MatchScan>();
  /** Panels that read from FrameStore: they hear when the file grows. */
  private readonly tailers = new Set<string>();
  /** While the view reads with other extensions or keys: requests wait. */
  private holding = false;
  /** Offer checks running: they take turns like a panel. */
  private offerChecks = 0;
  /** Frames whose sharkd answer is too long to read, per file and epoch; then bytes are asked for one frame at a time. */
  private oversized = { key: "", frames: new Set<number>(), single: false };

  constructor(
    private readonly opts: {
      bin: string;
      profile?: string;
      env: () => NodeJS.ProcessEnv;
      generation: () => number;
      source: PanelSource;
      events: EventLog;
    },
  ) {}

  /** A panel opened: its page may ask for data. */
  opened(label: string): void {
    this.open.add(label);
    this.idle();
  }

  /** A panel closed: its waiting requests end, and the engine stops a while after the last one. */
  closed(label: string): void {
    this.open.delete(label);
    this.tailers.delete(label);
    for (const w of this.waiting.get(label) ?? []) w.fail(new ApiError(404, "gone", "the panel was closed"));
    this.waiting.delete(label);
    this.idle();
  }

  /** Whether the panel reads from FrameStore, so a growing file is worth watching for it. */
  tailing(label: string): boolean {
    return this.tailers.has(label);
  }

  /** Indexes what the view's file gained: how many packets FrameStore knows now, or null without it. */
  async tail(): Promise<number | null> {
    const epoch = this.opts.source.epoch();
    const store = this.storeOf(epoch, false);
    if (!store || store.off || store.changed) return null;
    try {
      await store.update();
    } catch {
      return null;
    }
    // Another file meanwhile: this count is not of it
    if (this.store?.store !== store || this.opts.source.epoch() !== epoch) return null;
    return store.off || store.changed ? null : store.count;
  }

  /** Stops the engine IDLE_STOP_MS after no panel is open. */
  private idle(): void {
    if (this.idleTimer) clearTimeout(this.idleTimer);
    this.idleTimer = null;
    if (this.open.size || (!this.engine && !this.store)) return;
    this.idleTimer = setTimeout(() => this.close(), IDLE_STOP_MS);
    this.idleTimer.unref();
  }

  /**
   * Which of `filters` match a packet of the view's file, read by the panel
   * engine so the view's own sharkd never waits for it, and how many packets
   * it read. `release`: the next checks of a live capture won't need the file
   * read. Throws ApiError when the file changed meanwhile.
   */
  async anyMatch(filters: string[], release = false): Promise<{ matches: Map<string, boolean>; frames: number }> {
    this.offerChecks++;
    this.open.add(OFFERS);
    try {
      const loaded = await this.load(OFFERS, this.opts.source.epoch());
      const matches = new Map<string, boolean>();
      for (const filter of filters) {
        const rows = await this.run(OFFERS, (e) => e.call<{ num: number }[]>("frames", { filter, limit: 1, column0: "frame.number:0" }), CALL_BUDGET_MS, loaded).catch((err) => {
          if (err instanceof SharkdError) return [];
          throw err;
        });
        matches.set(filter, rows.length > 0);
      }
      return { matches, frames: loaded.frames };
    } finally {
      if (--this.offerChecks === 0) {
        this.open.delete(OFFERS);
        if (release && !this.open.size && this.opts.source.live()) this.close();
        else this.idle();
      }
    }
  }

  /** The view is about to read with other extensions, TLS keys or Decode As (true) or has (false): until then, requests wait. */
  hold(on: boolean): void {
    this.holding = on;
  }

  /** A dissection preference the view now reads with; an engine started later gets it from prefs(). */
  setPref(name: string, value: string): void {
    this.engine?.setPref(name, value).catch(() => {});
  }

  close(): void {
    this.engine?.close();
    this.engine = null;
    this.loaded = null;
    this.cache.clear();
    this.sets.clear();
    this.lastFollow = null;
    this.dropStore();
  }

  private dropStore(): void {
    this.store?.store.close();
    this.store = null;
    this.matchSets.clear();
  }

  /**
   * FrameStore of the view's file for `epoch`: the one in use while the file is
   * the same, else a new one (with `create`); null without a file.
   */
  private storeOf(epoch: number, create = true): FrameStore | null {
    const file = this.opts.source.file();
    const s = this.store;
    if (s && (s.store.file !== file || (s.epoch !== epoch && !s.store.same()))) this.dropStore();
    if (!file || (!this.store && !create)) return null;
    this.store ??= { store: new FrameStore(file), epoch, checked: false };
    this.store.epoch = epoch;
    return this.store.store;
  }

  /** FrameStore indexed up to the file's end, or null when it can't read the file (see noStore). */
  private async frameStore(epoch: number): Promise<FrameStore | null> {
    const source = this.opts.source;
    const store = this.storeOf(epoch);
    if (!store) throw new ApiError(409, "no-capture", "no capture is open");
    try {
      await store.update();
    } catch (err) {
      throw new ApiError(500, "internal", `reading the capture failed: ${printable((err as Error).message)}`, { retryMs: 1000 });
    }
    if (source.epoch() !== epoch) throw stale(source.epoch());
    if (store.changed) throw new ApiError(409, "stale", "the capture file was replaced or cut: start over once WireBuddy read it again", { epoch, retryMs: 2000 });
    const s = this.store;
    // A file still growing (more than the view read) is checked once the view caught up
    if (s?.store === store && !s.checked && !store.off && (source.live() || store.count <= source.totalFrames())) {
      s.checked = true;
      // A live file grows meanwhile; a finished one must have Wireshark's packets, numbered alike
      if (!source.live() && store.count !== source.totalFrames()) {
        store.off = `WireBuddy's own reading found ${store.count} packets, Wireshark ${source.totalFrames()}`;
        this.opts.events.add("WARNING", `Panels read ${basename(store.file)} through sharkd only (slower, no match): ${store.off}`);
      }
    }
    return store.off ? null : store;
  }

  /** Why a match can't be answered for the view's file. */
  private noStore(): string {
    const store = this.store?.store;
    return `match reads the capture file itself, and it can't read ${basename(store?.file ?? "")}: ${store?.off ?? "no file"}. Use a display filter instead`;
  }

  /** The frames of `m` in the store's file, scanning what was added since last time. */
  private async matchSet(store: FrameStore, m: Match): Promise<FrameSet> {
    let s = this.matchSets.get(m.key);
    if (s) this.matchSets.delete(m.key);
    else s = { test: m.test, ranges: new Int32Array(64), used: 0, count: 0, scanned: 0, snap: null, scanning: null };
    this.matchSets.set(m.key, s);
    if (this.matchSets.size > MAX_CACHED_SETS) this.matchSets.delete(this.matchSets.keys().next().value!);
    const scan = s;
    while (scan.scanned < store.count) {
      scan.scanning ??= this.scan(store, scan).finally(() => (scan.scanning = null));
      await scan.scanning;
    }
    if (scan.snap?.count !== scan.count) scan.snap = FrameSet.ofRanges(scan.ranges.slice(0, scan.used), scan.count);
    return scan.snap;
  }

  private async scan(store: FrameStore, s: MatchScan): Promise<void> {
    const parsed = new Parsed();
    const to = store.count;
    for (let from = s.scanned + 1; from <= to; from += SCAN_BATCH) {
      const last = Math.min(to, from + SCAN_BATCH - 1);
      await store.readRange(from, last, (frame, _time, _len, link, data) => {
        if (!s.test(data, parse(data, link, parsed))) return;
        const u = s.used;
        if (u && s.ranges[u - 1] === frame - 1) s.ranges[u - 1] = frame;
        else {
          if (u + 2 > s.ranges.length) {
            const grown = new Int32Array(s.ranges.length * 2);
            grown.set(s.ranges);
            s.ranges = grown;
          }
          s.ranges[u] = s.ranges[u + 1] = frame;
          s.used += 2;
        }
        s.count++;
      });
      s.scanned = last;
    }
  }

  /** Answers a panel's data request; `label` is the panel's instance. */
  async handle(label: string, method: string, body: Record<string, unknown>): Promise<Answer> {
    if (!this.open.has(label)) throw new ApiError(404, "gone", "the panel was closed");
    switch (method) {
      case "packets":
        return { kind: "page", body: await this.packets(label, body) };
      case "frame":
        return { kind: "json", body: await this.frame(label, body) };
      case "follow":
        return { kind: "page", body: await this.follow(label, body) };
      case "objects":
        return { kind: "json", body: await this.objects(label, body) };
      case "object":
        return { kind: "object", ...(await this.object(label, body)) };
      case "tap":
        return { kind: "json", body: await this.tap(label, body) };
      case "check":
        return { kind: "json", body: await this.check(label, body) };
      default:
        throw new ApiError(404, "bad-args", `no method "${printable(method).slice(0, 40)}"`);
    }
  }

  // --- the engine and its turns

  private engineNow(): Sharkd {
    if (this.engine) return this.engine;
    const { bin, profile, env, generation, source, events } = this.opts;
    const engine = new Sharkd(bin, profile, env, generation);
    engine.maxAnswer = MAX_ANSWER;
    engine.onFailure = (message) => {
      // load() reads the file again; a respawn needn't
      engine.forgetFile();
      this.loaded = null;
      const now = Date.now();
      this.crashes = [...this.crashes.filter((t) => now - t < 60_000), now];
      if (this.crashes.length <= CRASHES_PER_MINUTE) events.add("WARNING", `Panel engine: ${printable(message)}`);
    };
    for (const [name, value] of source.prefs()) engine.setPref(name, value).catch(() => {});
    this.engine = engine;
    return engine;
  }

  /**
   * Runs `fn` on the engine in this panel's turn, within a time budget; with
   * `on`, only while the engine still has the file that request started from.
   */
  private async run<T>(label: string, fn: (engine: Sharkd) => Promise<T>, budgetMs = CALL_BUDGET_MS, on?: Loaded): Promise<T> {
    await new Promise<void>((go, fail) => {
      if (!this.open.has(label)) return fail(new ApiError(404, "gone", "the panel was closed"));
      const q = this.waiting.get(label) ?? [];
      q.push({ go, fail });
      this.waiting.set(label, q);
      this.pump();
    });
    try {
      if (!this.open.has(label)) throw new ApiError(404, "gone", "the panel was closed");
      if (this.holding) throw new ApiError(429, "busy", "WireBuddy is reading the capture with other extensions or keys", { retryMs: 500 });
      const now = Date.now();
      this.crashes = this.crashes.filter((t) => now - t < 60_000);
      if (this.crashes.length >= CRASHES_PER_MINUTE) {
        throw new ApiError(500, "internal", 'the panel engine keeps crashing on this capture; an extension may crash it (extensions action "test")', { retryMs: 60_000 - (now - this.crashes[0]) });
      }
      const engine = this.engineNow();
      // Nothing else of ours is in flight: an engine with outdated extensions restarts right away
      if (engine.outdated()) this.restart(engine);
      if (on) {
        // Another panel's request may have read another file meanwhile; a grown one is fine
        const now = this.loaded;
        if (!now) throw new ApiError(429, "busy", "the panel engine restarted", { retryMs: 500 });
        if (now.file !== on.file || now.epoch !== on.epoch) throw stale(this.opts.source.epoch());
      }
      return await this.budget(engine, fn(engine), budgetMs);
    } finally {
      this.busy = false;
      this.pump();
    }
  }

  /** Gives the engine to the next panel in turn. */
  private pump(): void {
    if (this.busy) return;
    const next = this.waiting.entries().next();
    if (next.done) return;
    const [label, q] = next.value;
    this.waiting.delete(label);
    const { go } = q.shift()!;
    // Back at the end: every other waiting panel goes first
    if (q.length) this.waiting.set(label, q);
    this.busy = true;
    go();
  }

  /** Stops the engine; the next call starts it, and load() reads the file into it. */
  private restart(engine: Sharkd): void {
    engine.forgetFile();
    engine.restart();
    this.loaded = null;
  }

  private budget<T>(engine: Sharkd, work: Promise<T>, ms: number): Promise<T> {
    let timer: NodeJS.Timeout | undefined;
    const over = new Promise<never>((_, fail) => {
      timer = setTimeout(() => {
        this.restart(engine);
        fail(new ApiError(504, "too-slow", `the panel engine needed over ${ms / 1000} s and was restarted: ask for less (a narrower filter, fewer packets)`));
      }, ms);
    });
    const failed = (err: unknown): never => {
      // A refused answer stopped sharkd: load() reads the file again, within its own budget
      if (err instanceof SharkdTooLarge) this.restart(engine);
      return engineFailure(err);
    };
    return Promise.race([work.catch(failed), over]).finally(() => clearTimeout(timer));
  }

  /** The epoch a request is for: the current one; a panel that knows an older one starts over. */
  private epochOf(body: Record<string, unknown>): number {
    const epoch = this.opts.source.epoch();
    if (body.epoch !== undefined && body.epoch !== epoch) throw stale(epoch);
    return epoch;
  }

  /** Reads the view's file when it is another one, or when the view read more of it (at most every LIVE_LOAD_MS). */
  private load(label: string, epoch: number): Promise<Loaded> {
    return this.run(
      label,
      async (engine) => {
        const source = this.opts.source;
        const file = source.file();
        if (!file) throw new ApiError(409, "no-capture", "no capture is open");
        if (source.epoch() !== epoch) throw stale(source.epoch());
        const was = this.loaded;
        // FrameStore may know of packets the view hasn't read yet
        const known = Math.max(source.totalFrames(), source.live() ? this.storeCount() : 0);
        if (was && was.file === file && was.epoch === epoch && (known <= was.frames || Date.now() - was.at < LIVE_LOAD_MS)) return was;
        if (!sameFile(file, source.fileId())) throw new ApiError(409, "stale", "the capture file changed on disk since WireBuddy read it: View › Reload reads it again", { epoch, retryMs: 2000 });
        const r = await engine.call<{ status: string; err?: number }>("load", { file });
        // A file still being written ends mid-packet; sharkd keeps what it read
        if (r.status !== "OK" && r.err !== -12) throw new ApiError(500, "internal", `the panel engine could not read the capture: ${printable(r.status)}`);
        const status = await engine.call<{ frames: number }>("status");
        this.cache.clear();
        this.sets.clear();
        this.lastFollow = null;
        this.loaded = { file, epoch, frames: status.frames, seq: ++this.seq, at: Date.now() };
        return this.loaded;
      },
      LOAD_BUDGET_MS,
    );
  }

  /** Packets FrameStore knows of in the view's file, 0 without it. */
  private storeCount(): number {
    const s = this.store;
    return s && !s.store.off && !s.store.changed && s.store.file === this.opts.source.file() ? s.store.count : 0;
  }

  /** `make()`'s value, kept for the current load in `map` (the most recently used `max` of them). */
  private async cached<T>(key: string, make: () => Promise<T>, map = this.cache, max = MAX_CACHED): Promise<T> {
    const seq = this.loaded?.seq;
    if (map.has(key)) {
      const value = map.get(key) as T;
      map.delete(key);
      map.set(key, value);
      return value;
    }
    const value = await make();
    // Not for a load that came in between
    if (this.loaded?.seq === seq) {
      map.set(key, value);
      if (map.size > max) map.delete(map.keys().next().value!);
    }
    return value;
  }

  /** Throws a filter error with sharkd's own explanation. */
  private async checkFilter(ctx: Ctx, filter: string, what = "display filter"): Promise<void> {
    const error = await this.cached(`check:${filter}`, async () => {
      try {
        const check = (f: string) => this.run(ctx.label, (e) => e.call("check", { filter: f }), CALL_BUDGET_MS, ctx.loaded);
        await check(filter);
        return (await refTimeError(filter, check)) ?? "";
      } catch (err) {
        if (err instanceof SharkdError) return err.message.replace(/^Filter invalid - /, "");
        throw err;
      }
    });
    if (!error) return;
    const unknown = /not a valid protocol or protocol field|neither a field nor/.test(error);
    if (what === "field") throw new ApiError(400, "bad-args", `unknown field "${filter}": ${printable(error)}`, unknown ? { hint: LUA_HINT } : {});
    throw new ApiError(400, "filter", `invalid display filter "${printable(filter).slice(0, 200)}": ${printable(error)}`, unknown ? { hint: LUA_HINT } : {});
  }

  /** The frames a display filter matches in the loaded file, and the filter as sharkd matched it (frame.ref_time spelled out). */
  private async matching(ctx: Ctx, filter: string): Promise<{ set: FrameSet; sharkd: string }> {
    await this.checkFilter(ctx, filter);
    let sharkd: string;
    try {
      sharkd = refTimeFilter(filter, this.opts.source.timeRefs());
    } catch (err) {
      throw new ApiError(400, "filter", `invalid display filter "${printable(filter).slice(0, 200)}": ${(err as Error).message}`);
    }
    const set = await this.cached(
      sharkd,
      async () => {
        return FrameSet.fromSorted(await this.run(ctx.label, (e) => matchingFrames(e, sharkd, MATCH_PAGE), CALL_BUDGET_MS, ctx.loaded));
      },
      this.sets,
      MAX_CACHED_SETS,
    );
    return { set, sharkd };
  }

  // --- methods

  private async packets(label: string, q: Record<string, unknown>): Promise<Buffer> {
    const epoch = this.epochOf(q);
    const fields = [...new Set(list(q.fields, "fields", MAX_FIELDS).map((f) => fieldName(f, "fields")))];
    const bytes = q.bytes === undefined ? "none" : str(q.bytes, "bytes", 128);
    const layer = bytes === "none" || bytes === "frame" || bytes === "ip" || bytes === "payload" ? bytes : fieldName(bytes, "bytes");
    const filter = q.filter === undefined ? "" : str(q.filter, "filter", MAX_FILTER).trim();
    const match = q.match === undefined ? null : rawMatch(q.match);
    const after = int(q.after, "after", 0, 0);
    const requested = int(q.limit, "limit", DEFAULT_LIMIT, 1);
    const maxBytes = int(q.maxBytes, "maxBytes", DEFAULT_MAX_BYTES, 1);
    if (maxBytes > MAX_BYTES) throw new ApiError(413, "too-large", `maxBytes is at most ${MAX_BYTES} (16 MiB)`);
    const which = frameChoice(q.frames);
    const fieldBytes = layer !== "none" && layer !== "frame" && layer !== "ip" && layer !== "payload";

    // Times, lengths, frame/ip/payload bytes and matches from the file itself when FrameStore reads it;
    // the panel engine for filters, fields, field bytes, and files FrameStore can't read
    const source = this.opts.source;
    const [store, early] = await Promise.all([
      fieldBytes && !match ? null : this.frameStore(epoch),
      fields.length || filter || fieldBytes ? this.load(label, epoch) : null,
    ]);
    if (match && !store) throw new ApiError(400, "bad-args", this.noStore());
    if (match && store?.unknownLinks()) throw new ApiError(400, "bad-args", "match reads the packets' headers itself, and this capture has a link type it doesn't know. Use a display filter instead");
    const raw = store !== null && !fieldBytes;
    if (raw) this.tailers.add(label);
    const cap = fields.length ? MAX_LIMIT.fields : fieldBytes || (layer !== "none" && !raw) ? MAX_LIMIT.bytes : MAX_LIMIT.plain;
    const limit = Math.min(requested, cap);
    const loaded = early ?? (raw ? null : await this.load(label, epoch));
    const ctx = loaded ? { label, loaded } : null;
    for (const f of fields) await this.checkFilter(ctx!, f, "field");
    if (fieldBytes) await this.checkFilter(ctx!, layer, "field");
    // As far as every source of this page has read
    const known = Math.min(loaded ? loaded.frames : Infinity, raw ? store.count : Infinity);

    // The set of frames, and the filter whose matches it is exactly (sharkd pages those by position)
    let set: FrameSet;
    let byFilter = "";
    if (which === "displayed") {
      const d = source.displayed();
      set = d.set;
      byFilter = d.filter;
    } else if (which === "selected") set = source.selected();
    else if (which === "marked") set = source.marked();
    else if (which) set = FrameSet.fromRanges(which);
    else set = FrameSet.all(known);
    // The view's lists are of the file the engine read only while the epoch is the same
    if (source.epoch() !== epoch) throw stale(source.epoch());
    set = set.clip(known);
    if (match) {
      set = set.intersect(await this.matchSet(store!, match));
      byFilter = "";
      if (source.epoch() !== epoch) throw stale(source.epoch());
    }
    if (filter) {
      const { set: m, sharkd } = await this.matching(ctx!, filter);
      set = which || match ? set.intersect(m) : m.clip(known);
      byFilter = which || match ? "" : sharkd;
    }

    const { frames, more } = set.page(after, limit);
    // Third: what the layer is found by, the link type or the field's value
    const columns = raw ? fields : ["frame.time_epoch", "frame.len", ...(layer === "ip" || layer === "payload" ? ["frame.encap_type"] : fieldBytes ? [layer] : []), ...fields];
    // Long field values for many packets would be too long for one sharkd answer, and may be cut by maxBytes anyway
    const perCall = fields.length ? Math.max(32, Math.floor(COLUMN_CHARS / (fields.length * 2200 + 200))) : MAX_LIMIT.plain;
    const step = raw ? Math.min(RAW_BATCH, perCall) : layer === "none" ? perCall : BYTES_BATCH;
    const rows: PageRow[] = [];
    const fieldValues: Record<string, string[]> = Object.fromEntries(fields.map((f) => [f, []]));
    const clipped: [number, string][] = [];
    const first = columns.length - fields.length;
    let dropped = 0;
    let size = 0;
    let cut = false;
    for (let i = 0; i < frames.length && !cut; i += step) {
      const chunk = frames.slice(i, i + step);
      const values = ctx && columns.length ? await this.columns(ctx, chunk, columns, byFilter, set) : null;
      const batch = values ? chunk.filter((f) => values.has(f)) : chunk;
      const got = raw ? await this.fromStore(store, batch, layer) : await this.fromEngine(ctx!, batch, layer, values!);
      for (const [k, frame] of batch.entries()) {
        const c = values?.get(frame) ?? [];
        const { time, len, data: d } = got[k] ?? { time: NaN, len: 0, data: null };
        const bytesHere = d ?? EMPTY;
        let rowSize = bytesHere.length;
        for (let j = first; j < c.length; j++) rowSize += Buffer.byteLength(c[j]);
        // At least one packet, however large
        if (rows.length && size + rowSize > maxBytes) {
          cut = true;
          break;
        }
        if (d === null && fieldBytes && c[2]) {
          throw new ApiError(400, "bad-args", `"${layer}" has a value but no bytes in the packet (a hidden or generated field): ask for a field the packet details show with bytes, e.g. ip.src instead of ip.addr`);
        }
        if (d == null) dropped++;
        size += rowSize;
        for (const [j, f] of fields.entries()) {
          const v = c[first + j] ?? "";
          if (v.startsWith(CLIPPED)) clipped.push([rows.length, f]);
          fieldValues[f].push(v);
        }
        rows.push({ frame, time, len, data: bytesHere });
      }
    }
    if (source.epoch() !== epoch) throw stale(source.epoch());
    const last = rows.length ? rows[rows.length - 1].frame : null;
    return encodePage(
      {
        epoch,
        total: set.count,
        next: last,
        done: !cut && !more,
        live: source.live(),
        layer,
        fields: fieldValues,
        clipped,
        dropped,
        // FrameStore reads to the file's end on every request: only the engine can be behind
        pending: loaded ? loaded.frames < Math.max(source.totalFrames(), this.storeCount()) : false,
      },
      rows,
    );
  }

  /** Time, length and the bytes of `layer` per frame, from the file (null: no such layer). */
  private async fromStore(store: FrameStore, frames: number[], layer: string): Promise<RowData[]> {
    const out: RowData[] = [];
    const parsed = new Parsed();
    await store.readFrames(frames, (_frame, time, len, link, data) => {
      let d: Uint8Array | null = layer === "none" ? EMPTY : data;
      if (layer === "ip" || layer === "payload") {
        const at = parse(data, link, parsed).range(layer as Layer);
        d = at ? data.subarray(at[0], at[1]) : null;
      }
      out.push({ time, len, data: d });
    });
    return out;
  }

  /** The same from the engine's columns and frames. */
  private async fromEngine(ctx: Ctx, frames: number[], layer: string, values: Map<number, string[]>): Promise<RowData[]> {
    const data = layer === "none" ? null : await this.bytesOf(ctx, frames, layer, values);
    return frames.map((frame, k) => {
      const c = values.get(frame)!;
      return { time: c[0] ? Number(c[0]) : NaN, len: Number(c[1]) || 0, data: data ? data[k] : EMPTY };
    });
  }

  /** Column values per frame: one sharkd call per page of a filter, else per stretch of nearby frames; times count from the view's time references. */
  private async columns(ctx: Ctx, frames: number[], columns: string[], byFilter: string, set: FrameSet): Promise<Map<number, string[]>> {
    const out = new Map<number, string[]>();
    if (!frames.length) return out;
    const params = Object.fromEntries(columns.map((f, i) => [`column${i}`, `${f}:0`]));
    const timeRefs = this.opts.source.timeRefs();
    if (byFilter) {
      const skip = set.rank(frames[0] - 1);
      const refs = (from: number, to: number) => refsOf(timeRefs, frames.slice(from, to));
      const rows = await this.run(ctx.label, (e) => framesWithRefs({ filter: byFilter, ...page(skip, frames.length), ...params }, refs, (p) => e.call<{ num: number; c: string[] }[]>("frames", p)), CALL_BUDGET_MS, ctx.loaded).catch((err) => {
        // The view's filter, read differently by the panel engine: by stretches below
        if (err instanceof SharkdError) return [];
        throw err;
      });
      if (rows.length === frames.length && rows.every((r, i) => r.num === frames[i])) {
        for (const r of rows) out.set(r.num, r.c);
        return out;
      }
    }
    // Sparse frames: a stretch read whole is cheaper than a call per frame, up to about twice the frames
    for (let i = 0; i < frames.length; ) {
      let j = i;
      while (j + 1 < frames.length && frames[j + 1] - frames[i] + 1 <= 2 * (j + 2 - i) + 64) j++;
      const [a, b] = [frames[i], frames[j]];
      const stretch = Int32Array.from({ length: b - a + 1 }, (_, k) => a + k);
      const refs = (from: number, to: number) => refsOf(timeRefs, stretch.subarray(from, to));
      const rows = await this.run(ctx.label, (e) => framesWithRefs({ ...page(a - 1, b - a + 1), ...params }, refs, (p) => e.call<{ num: number; c: string[] }[]>("frames", p)), CALL_BUDGET_MS, ctx.loaded);
      for (const r of rows) out.set(r.num, r.c);
      i = j + 1;
    }
    return out;
  }

  /**
   * The bytes of `layer` per frame; null where the frame has no such layer,
   * undefined where sharkd's answer (with all reassembled data) is too long to read.
   */
  private async bytesOf(ctx: Ctx, frames: number[], layer: string, values: Map<number, string[]>): Promise<(Uint8Array | null | undefined)[]> {
    const tree = layer !== "frame" && layer !== "ip" && layer !== "payload";
    const key = `${ctx.loaded.file}\n${ctx.loaded.epoch}`;
    if (this.oversized.key !== key) this.oversized = { key, frames: new Set(), single: false };
    const big = this.oversized;
    const ask = frames.filter((f) => !big.frames.has(f));
    const answers = new Map<number, { bytes?: string; tree?: TreeNode[]; ds?: { bytes?: string }[] }>();
    for (const group of big.single ? ask.map((f) => [f]) : [ask]) {
      try {
        const got = await this.run(
          ctx.label,
          (e) => Promise.all(group.map((frame) => e.call<{ bytes?: string; tree?: TreeNode[]; ds?: { bytes?: string }[] }>("frame", { frame, bytes: true, ...(tree ? { proto: true, hidden: true } : {}) }))),
          CALL_BUDGET_MS,
          ctx.loaded,
        );
        group.forEach((f, i) => answers.set(f, got[i]));
      } catch (err) {
        if (!(err instanceof ApiError) || err.code !== "too-large") throw err;
        // Which packet it was: one at a time from now on, and the one that fails alone is left out
        if (group.length === 1) big.frames.add(group[0]);
        else big.single = true;
        throw new ApiError(429, "busy", "a packet's answer was too long to read; reading on without it", { retryMs: 200 });
      }
    }
    return frames.map((frame) => {
      const r = answers.get(frame);
      if (!r) return undefined;
      if (tree) return fieldBytes(r, layer);
      const b = Buffer.from(r.bytes ?? "", "base64");
      if (layer === "frame") return b;
      const at = findLayer(b, values.get(frame)?.[2] ?? "", layer as "ip" | "payload");
      return at ? b.subarray(at[0], at[1]) : null;
    });
  }

  private async frame(label: string, q: Record<string, unknown>): Promise<unknown> {
    const epoch = this.epochOf(q);
    const frame = int(q.frame, "frame", undefined, 1);
    const tree = q.tree === undefined ? true : bool(q.tree, "tree");
    const bytes = q.bytes === undefined ? true : bool(q.bytes, "bytes");
    const loaded = await this.load(label, epoch);
    if (frame > loaded.frames && this.opts.source.live() && frame <= this.storeCount()) {
      throw new ApiError(429, "busy", `the panel engine has not read frame ${frame} of the live file yet`, { retryMs: LIVE_LOAD_MS });
    }
    if (frame > loaded.frames) throw new ApiError(404, "gone", `no frame ${frame}: the capture has ${loaded.frames}`);
    const ref = refBefore(this.opts.source.timeRefs(), frame);
    const r = await this.run(
      label,
      (e) =>
        e.call<{ tree?: TreeNode[]; bytes?: string; ds?: { name: string; bytes: string }[]; followers?: { protocol: string; filter: string }[] }>("frame", {
          frame,
          ...(tree ? { proto: true } : {}),
          ...(bytes ? { bytes: true } : {}),
          ...(ref ? { ref_frame: ref } : {}),
        }),
      CALL_BUDGET_MS,
      loaded,
    ).catch((err) => {
      if (err instanceof ApiError && err.code === "too-large") throw new ApiError(413, "too-large", `frame ${frame} with its reassembled data is too long to read: ask with {bytes: false}, or for a field's bytes with wb.packets`);
      throw err;
    });
    return {
      frame,
      tree: r.tree ?? null,
      bytes: r.bytes ?? "",
      sources: (r.ds ?? []).map((d) => ({ name: d.name, bytes: d.bytes ?? "" })),
      followers: (r.followers ?? []).filter((f) => f.filter).map((f) => [f.protocol, f.filter]),
    };
  }

  private async follow(label: string, q: Record<string, unknown>): Promise<Buffer> {
    const epoch = this.epochOf(q);
    const offset = int(q.offset, "offset", 0, 0);
    const maxBytes = int(q.maxBytes, "maxBytes", DEFAULT_MAX_BYTES, 1);
    if (maxBytes > MAX_BYTES) throw new ApiError(413, "too-large", `maxBytes is at most ${MAX_BYTES} (16 MiB)`);
    const loaded = await this.load(label, epoch);
    const ctx = { label, loaded };
    let protocol: string;
    let filter: string;
    if (q.frame !== undefined) {
      const frame = int(q.frame, "frame", undefined, 1);
      if (frame > loaded.frames) throw new ApiError(404, "gone", `no frame ${frame}: the capture has ${loaded.frames}`);
      const r = await this.run(label, (e) => e.call<{ followers?: { protocol: string; filter: string }[] }>("frame", { frame }), CALL_BUDGET_MS, loaded);
      const followers = (r.followers ?? []).filter((f) => f.filter);
      const want = q.protocol === undefined ? null : str(q.protocol, "protocol", 16).toUpperCase();
      const pick = want ? followers.find((f) => f.protocol.toUpperCase() === want) : (followers.find((f) => f.protocol === "TCP") ?? followers.find((f) => f.protocol === "UDP") ?? followers[0]);
      if (!pick) throw new ApiError(404, "gone", `frame ${frame} belongs to no ${want ?? ""}${want ? " " : ""}stream`);
      [protocol, filter] = [pick.protocol, pick.filter];
    } else {
      protocol = str(q.protocol, "protocol", 16).toUpperCase();
      if (!/^[A-Z0-9_-]+$/.test(protocol)) throw new ApiError(400, "bad-args", `"${printable(protocol)}" is not a protocol`);
      if (q.stream !== undefined) {
        const of = STREAM_OF[protocol];
        if (!of) throw new ApiError(400, "bad-args", `streams of ${protocol} are chosen by a filter: give filter instead of stream`);
        filter = `${of}.stream eq ${int(q.stream, "stream", undefined, 0)}`;
      } else filter = str(q.filter, "filter", MAX_FILTER);
    }
    const key = `${protocol}\n${filter}`;
    let data = this.lastFollow?.seq === loaded.seq && this.lastFollow.key === key ? this.lastFollow.result : null;
    if (!data) {
      await this.checkFilter(ctx, filter);
      const r = await this.run(
        label,
        (e) =>
          e.call<{ shost: string; sport: string; chost: string; cport: string; payloads?: { n: number; d: string; s?: number }[] }>("follow", { follow: protocol, filter }).catch((err) => {
            if (err instanceof SharkdError) throw new ApiError(400, "bad-args", `can't follow ${protocol}: ${printable(err.message)}`);
            throw err;
          }),
        CALL_BUDGET_MS,
        loaded,
      ).catch((err) => {
        if (err instanceof ApiError && err.code === "too-large") {
          throw new ApiError(413, "too-large", `the stream is too long to follow at once: read its packets instead, wb.packets({filter: ${JSON.stringify(filter)}, bytes: "payload"})`);
        }
        throw err;
      });
      if (r.shost === "NONE" && r.chost === "NONE" && !r.payloads?.length) throw new ApiError(404, "gone", `no ${protocol} stream matches ${filter}`);
      const chunks = (r.payloads ?? []).map((p) => ({ frame: p.n, dir: p.s ? 1 : 0, data: Buffer.from(p.d, "base64") }));
      const sum = (dir: number) => chunks.reduce((a, c) => a + (c.dir === dir ? c.data.length : 0), 0);
      data = {
        chunks,
        total: sum(0) + sum(1),
        client: { host: r.chost, port: r.cport, bytes: sum(0) },
        server: { host: r.shost, port: r.sport, bytes: sum(1) },
      };
      this.lastFollow = { seq: loaded.seq, key, result: data };
    }
    const rows: PageRow[] = [];
    let at = 0;
    let end = offset;
    for (const c of data.chunks) {
      const from = Math.max(0, offset - at);
      at += c.data.length;
      if (from >= c.data.length) continue;
      const room = offset + maxBytes - end;
      if (room <= 0) break;
      const part = c.data.subarray(from, from + room);
      rows.push({ frame: c.frame, time: NaN, len: part.length, data: part, dir: c.dir });
      end += part.length;
    }
    const more = end < data.total;
    return encodePage(
      {
        epoch,
        total: data.total,
        next: more ? end : null,
        done: !more,
        live: this.opts.source.live(),
        layer: "follow",
        follow: { protocol, filter, client: data.client, server: data.server, truncated: more },
      },
      rows,
      true,
    );
  }

  private async objectList(ctx: Ctx, kind: string): Promise<EoObject[]> {
    return this.cached(`eo:${kind}`, async () => {
      const r = await this.run(ctx.label, (e) => e.call<{ taps?: { objects?: EoObject[] }[] }>("tap", { tap0: `eo:${kind}` }), CALL_BUDGET_MS, ctx.loaded);
      return r.taps?.[0]?.objects ?? [];
    });
  }

  private async objects(label: string, q: Record<string, unknown>): Promise<unknown> {
    const epoch = this.epochOf(q);
    const kind = eoKind(q.kind);
    const all = await this.objectList({ label, loaded: await this.load(label, epoch) }, kind);
    return {
      objects: all.slice(0, MAX_OBJECTS).map((o) => ({
        id: objectId(kind, o),
        frame: o.pkt,
        host: o.hostname ?? "",
        type: o.type ?? "",
        filename: o.filename ?? "",
        size: o.len,
        sha1: o.sha1 ?? "",
      })),
      truncated: all.length > MAX_OBJECTS,
    };
  }

  private async object(label: string, q: Record<string, unknown>): Promise<{ body: Buffer; type: string; filename: string }> {
    const epoch = this.epochOf(q);
    const m = /^([a-z-]+):(\d+):([0-9a-f]{16})$/.exec(str(q.id, "id", 80));
    if (!m) throw new ApiError(400, "bad-args", "not an object id from wb.objects()");
    const kind = eoKind(m[1]);
    const loaded = await this.load(label, epoch);
    const o = (await this.objectList({ label, loaded }, kind)).find((x) => objectId(kind, x) === m[0]);
    if (!o) throw new ApiError(404, "gone", "no such object in the capture (it changed?): list them again with wb.objects()");
    if (o.len > MAX_OBJECT) throw new ApiError(413, "too-large", `the object has ${o.len} bytes; at most ${MAX_OBJECT} (64 MiB) can be read`);
    const r = await this.run(label, (e) => e.call<{ file?: string; mime?: string; data?: string }>("download", { token: o._download }), CALL_BUDGET_MS, loaded);
    if (r.data === undefined) throw new ApiError(404, "gone", "sharkd could not export the object");
    return { body: Buffer.from(r.data, "base64"), type: o.type || r.mime || "application/octet-stream", filename: o.filename || r.file || "object" };
  }

  private async tap(label: string, q: Record<string, unknown>): Promise<unknown> {
    const epoch = this.epochOf(q);
    const name = str(q.name, "name", 32);
    const tap0 = TAPS[name];
    if (!tap0) throw new ApiError(400, "bad-args", `no tap "${printable(name)}": ${Object.keys(TAPS).join(", ")}`);
    const filter = q.filter === undefined ? "" : str(q.filter, "filter", MAX_FILTER).trim();
    const loaded = await this.load(label, epoch);
    if (filter) await this.checkFilter({ label, loaded }, filter);
    const r = await this.run(label, (e) => e.call<{ taps?: unknown[] }>("tap", { tap0, ...(filter ? { filter } : {}) }), CALL_BUDGET_MS, loaded);
    return r.taps?.[0] ?? null;
  }

  private async check(label: string, q: Record<string, unknown>): Promise<unknown> {
    const filter = str(q.filter, "filter", MAX_FILTER).trim();
    if (!filter) return { ok: true };
    try {
      const r = await this.run(label, (e) => e.call<{ warning?: string }>("check", { filter }));
      return r?.warning ? { ok: true, warning: r.warning } : { ok: true };
    } catch (err) {
      if (err instanceof SharkdError) return { ok: false, error: err.message.replace(/^Filter invalid - /, "") };
      throw err;
    }
  }
}

interface FollowData {
  chunks: { frame: number; dir: number; data: Buffer }[];
  total: number;
  client: { host: string; port: string; bytes: number };
  server: { host: string; port: string; bytes: number };
}

/** A packet of a page: data null when it has no such layer. */
interface RowData {
  time: number;
  len: number;
  /** null: no such layer; undefined: too long to read. */
  data: Uint8Array | null | undefined;
}

/** A raw match: its cache key and its test on a parsed frame. */
interface Match {
  key: string;
  test: (b: Uint8Array, p: Parsed) => boolean;
}

/** The frames a match found so far, as ranges [a0, b0, a1, b1, ...] in ranges[0, used). */
interface MatchScan {
  test: Match["test"];
  ranges: Int32Array;
  used: number;
  count: number;
  /** Frames 1..scanned are looked at. */
  scanned: number;
  snap: FrameSet | null;
  scanning: Promise<void> | null;
}

/** An address or a network: its bytes and how many leading bits count. */
interface Prefix {
  bytes: Uint8Array;
  bits: number;
}

const MATCH_KEYS = ["proto", "port", "srcport", "dstport", "addr", "src", "dst", "ethertype", "vlan"];

/** Checks and compiles q.match: every key must hold (each a value, or a list of which one must). */
export function rawMatch(v: unknown): Match {
  if (!v || typeof v !== "object" || Array.isArray(v)) throw new ApiError(400, "bad-args", `match is an object with any of ${MATCH_KEYS.join(", ")}`);
  const m = v as Record<string, unknown>;
  for (const k of Object.keys(m)) if (!MATCH_KEYS.includes(k)) throw new ApiError(400, "bad-args", `match has no key "${printable(k).slice(0, 40)}": ${MATCH_KEYS.join(", ")}`);
  const values = (k: string): unknown[] | null => {
    if (m[k] === undefined) return null;
    const list = Array.isArray(m[k]) ? (m[k] as unknown[]) : [m[k]];
    if (!list.length || list.length > MAX_MATCH_VALUES) throw new ApiError(400, "bad-args", `match.${k} is a value or a list of 1 to ${MAX_MATCH_VALUES}`);
    return list;
  };
  const numbers = (k: string, max: number, names: Record<string, number> = {}): Set<number> | null => {
    const list = values(k);
    if (!list) return null;
    return new Set(
      list.map((x) => {
        const n = typeof x === "string" ? names[x.toLowerCase()] : x;
        if (typeof n !== "number" || !Number.isInteger(n) || n < 0 || n > max) {
          const named = Object.keys(names).length ? ` or one of ${Object.keys(names).join(", ")}` : "";
          throw new ApiError(400, "bad-args", `match.${k}: ${printable(JSON.stringify(x) ?? "").slice(0, 40)} is not a number from 0 to ${max}${named}`);
        }
        return n;
      }),
    );
  };
  const prefixes = (k: string): Prefix[] | null => values(k)?.map((x) => prefix(k, x)) ?? null;
  const proto = numbers("proto", 255, PROTOS);
  const [port, srcport, dstport] = [numbers("port", 65535), numbers("srcport", 65535), numbers("dstport", 65535)];
  const [ethertype, vlan] = [numbers("ethertype", 65535), numbers("vlan", 4095)];
  const [addr, src, dst] = [prefixes("addr"), prefixes("src"), prefixes("dst")];
  const canon = (x: Set<number> | Prefix[] | null) => (x instanceof Set ? [...x].sort((a, b) => a - b) : x?.map((p) => `${[...p.bytes].join(".")}/${p.bits}`).sort());
  const key = JSON.stringify(MATCH_KEYS.map((k, i) => [k, canon([proto, port, srcport, dstport, addr, src, dst, ethertype, vlan][i])]));
  return {
    key,
    test: (b, p) =>
      (!proto || proto.has(p.proto)) &&
      (!port || port.has(p.srcport) || port.has(p.dstport)) &&
      (!srcport || srcport.has(p.srcport)) &&
      (!dstport || dstport.has(p.dstport)) &&
      (!ethertype || ethertype.has(p.ethertype)) &&
      (!vlan || p.vlans.some((id) => vlan.has(id))) &&
      (!addr || within(addr, b, p.src, p.ip) || within(addr, b, p.dst, p.ip)) &&
      (!src || within(src, b, p.src, p.ip)) &&
      (!dst || within(dst, b, p.dst, p.ip)),
  };
}

/** "10.0.0.1", "10.0.0.0/8", "fe80::1", "2001:db8::/32". */
function prefix(k: string, x: unknown): Prefix {
  const bad = (): never => {
    throw new ApiError(400, "bad-args", `match.${k}: ${printable(JSON.stringify(x) ?? "").slice(0, 60)} is not an IPv4 or IPv6 address (or network, "10.0.0.0/8")`);
  };
  if (typeof x !== "string" || x.length > 64) return bad();
  const [ip, len, ...rest] = x.split("/");
  const bytes = ipBytes(ip);
  if (!bytes || rest.length) return bad();
  const bits = len === undefined ? bytes.length * 8 : /^\d{1,3}$/.test(len) ? Number(len) : -1;
  if (bits < 0 || bits > bytes.length * 8) return bad();
  return { bytes, bits };
}

function ipBytes(s: string): Uint8Array | null {
  if (isIPv4(s)) return Uint8Array.from(s.split(".").map(Number));
  if (!isIPv6(s) || s.includes("%")) return null;
  const groups = (part: string): number[] =>
    part
      ? part.split(":").flatMap((g) => {
          if (!g.includes(".")) return [parseInt(g, 16)];
          const [a, b, c, d] = g.split(".").map(Number);
          return [(a << 8) | b, (c << 8) | d];
        })
      : [];
  const [head, tail] = s.includes("::") ? s.split("::") : [s, ""];
  const h = groups(head);
  const t = groups(tail);
  const all = [...h, ...new Array<number>(8 - h.length - t.length).fill(0), ...t];
  return Uint8Array.from(all.flatMap((g) => [g >> 8, g & 255]));
}

/** Whether the IPv`ip` address at `at` in `b` lies in one of the prefixes. */
function within(prefixes: Prefix[], b: Uint8Array, at: number, ip: number): boolean {
  if (at < 0) return false;
  return prefixes.some(({ bytes, bits }) => {
    if (bytes.length !== (ip === 4 ? 4 : 16) || at + bytes.length > b.length) return false;
    let i = 0;
    for (; i < bits >> 3; i++) if (b[at + i] !== bytes[i]) return false;
    const rest = bits & 7;
    return !rest || ((b[at + i] ^ bytes[i]) & (0xff00 >> rest) & 0xff) === 0;
  });
}

const EMPTY = new Uint8Array(0);

/** Ascending frame numbers as inclusive ranges, flat: [a0, b0, a1, b1, ...]. */
export class FrameSet {
  /** Frames before each range, for rank(). */
  private before: Float64Array | null = null;
  /** Intersections with other sets, as paging asks for the same one again and again. */
  private readonly meets = new WeakMap<FrameSet, FrameSet>();

  private constructor(
    private readonly r: Int32Array,
    readonly count: number,
  ) {}

  static all(n: number): FrameSet {
    return n > 0 ? new FrameSet(Int32Array.of(1, n), n) : new FrameSet(new Int32Array(0), 0);
  }

  /** Of ranges already ascending, apart and merged, holding `count` frames. */
  static ofRanges(r: Int32Array, count: number): FrameSet {
    return new FrameSet(r, count);
  }

  /** From ascending frame numbers (duplicates allowed). */
  static fromSorted(frames: ArrayLike<number>): FrameSet {
    return FrameSet.build((add) => {
      for (let i = 0; i < frames.length; i++) add(frames[i]);
    });
  }

  /** The frames at row ranges of a displayed list; without one, row i is frame i + 1. */
  static fromRows(rows: Ranges, displayed: Int32Array | null): FrameSet {
    if (!displayed) return FrameSet.fromRanges(rows.map(([a, b]): [number, number] => [a + 1, b + 1]));
    return FrameSet.build((add) => {
      for (const [a, b] of rows) for (let i = Math.max(0, a); i <= b && i < displayed.length; i++) add(displayed[i]);
    });
  }

  /** From frames `each` adds in ascending order. */
  private static build(each: (add: (frame: number) => void) => void): FrameSet {
    const out: number[] = [];
    let count = 0;
    each((f) => {
      const last = out.length - 1;
      if (last > 0 && f <= out[last]) return;
      if (last > 0 && f === out[last] + 1) out[last] = f;
      else out.push(f, f);
      count++;
    });
    return new FrameSet(Int32Array.from(out), count);
  }

  /** From merged, ascending inclusive ranges. */
  static fromRanges(ranges: Ranges): FrameSet {
    const sorted = [...ranges].filter(([a, b]) => b >= a && b >= 1).map(([a, b]): [number, number] => [Math.max(1, a), b]).sort((x, y) => x[0] - y[0]);
    const out: number[] = [];
    let count = 0;
    for (const [a, b] of sorted) {
      const last = out.length - 1;
      if (last > 0 && a <= out[last] + 1) {
        if (b > out[last]) {
          count += b - out[last];
          out[last] = b;
        }
      } else {
        out.push(a, b);
        count += b - a + 1;
      }
    }
    return new FrameSet(Int32Array.from(out), count);
  }

  /** Only frames up to `max`. */
  clip(max: number): FrameSet {
    const count = this.rank(max);
    if (count === this.count) return this;
    const k = this.rangeAtOrBefore(max);
    const r = this.r.slice(0, 2 * (k + 1));
    if (k >= 0) r[2 * k + 1] = Math.min(r[2 * k + 1], max);
    return new FrameSet(r, count);
  }

  intersect(o: FrameSet): FrameSet {
    let met = this.meets.get(o);
    if (!met) {
      met = this.meet(o);
      this.meets.set(o, met);
    }
    return met;
  }

  private meet(o: FrameSet): FrameSet {
    const out: number[] = [];
    let count = 0;
    let i = 0;
    let j = 0;
    while (i < this.r.length && j < o.r.length) {
      const a = Math.max(this.r[i], o.r[j]);
      const b = Math.min(this.r[i + 1], o.r[j + 1]);
      if (a <= b) {
        out.push(a, b);
        count += b - a + 1;
      }
      if (this.r[i + 1] < o.r[j + 1]) i += 2;
      else j += 2;
    }
    return new FrameSet(Int32Array.from(out), count);
  }

  /** How many frames are at most `x`. */
  rank(x: number): number {
    if (!this.before) {
      this.before = new Float64Array(this.r.length / 2);
      let n = 0;
      for (let i = 0; i < this.r.length; i += 2) {
        this.before[i / 2] = n;
        n += this.r[i + 1] - this.r[i] + 1;
      }
    }
    const k = this.rangeAtOrBefore(x);
    return k < 0 ? 0 : this.before[k] + Math.min(this.r[2 * k + 1], x) - this.r[2 * k] + 1;
  }

  /** Up to `limit` frames after `after`, and whether more follow. */
  page(after: number, limit: number): { frames: number[]; more: boolean } {
    const frames: number[] = [];
    for (let k = Math.max(0, this.rangeAtOrBefore(after)); k < this.r.length / 2; k++) {
      for (let f = Math.max(this.r[2 * k], after + 1); f <= this.r[2 * k + 1]; f++) {
        if (frames.length === limit) return { frames, more: true };
        frames.push(f);
      }
    }
    return { frames, more: false };
  }

  /** Index of the last range starting at or before `x`, or -1. */
  private rangeAtOrBefore(x: number): number {
    let lo = 0;
    let hi = this.r.length / 2 - 1;
    let found = -1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      if (this.r[2 * mid] <= x) {
        found = mid;
        lo = mid + 1;
      } else hi = mid - 1;
    }
    return found;
  }
}

/** The bytes of the first tree item for `field`, from the data source it is in. */
function fieldBytes(r: { bytes?: string; tree?: TreeNode[]; ds?: { bytes?: string }[] }, field: string): Uint8Array | null {
  const find = (nodes: TreeNode[] | undefined): TreeNode | null => {
    for (const n of nodes ?? []) {
      if (n.fn === field && n.h) return n;
      const deeper = find(n.n);
      if (deeper) return deeper;
    }
    return null;
  };
  const node = find(r.tree);
  if (!node?.h) return null;
  const src = node.ds ? r.ds?.[node.ds - 1]?.bytes : r.bytes;
  if (src === undefined) return null;
  return Buffer.from(src, "base64").subarray(node.h[0], node.h[0] + node.h[1]);
}

function objectId(kind: string, o: EoObject): string {
  return `${kind}:${o.pkt}:${(o.sha1 ?? "").slice(0, 16).padEnd(16, "0")}`;
}

function eoKind(v: unknown): string {
  const kind = str(v, "kind", 16);
  if (!EO_KINDS.has(kind)) throw new ApiError(400, "bad-args", `no export objects of "${printable(kind)}": ${[...EO_KINDS].join(", ")}`);
  return kind;
}

/** A failed sharkd call as the panel sees it; filter errors are the caller's to explain. */
function engineFailure(err: unknown): never {
  if (err instanceof ApiError || err instanceof SharkdError) throw err;
  if (err instanceof SharkdTooLarge) throw new ApiError(413, "too-large", `${err.message}: ask for less`);
  throw new ApiError(500, "internal", `the panel engine failed: ${printable((err as Error).message)}`, { retryMs: 1000 });
}

/** Whether `file` on disk is still the one with this inode and first bytes. */
function sameFile(file: string, id: { ino: number; head: Buffer }): boolean {
  let fd = -1;
  try {
    if (statSync(file).ino !== id.ino) return false;
    fd = openSync(file, "r");
    const head = Buffer.alloc(id.head.length);
    const n = readSync(fd, head, 0, head.length, 0);
    return head.subarray(0, n).equals(id.head.subarray(0, n));
  } catch {
    return false;
  } finally {
    if (fd >= 0) closeSync(fd);
  }
}

function stale(epoch: number): ApiError {
  return new ApiError(409, "stale", "the capture changed (another file, re-read extensions, TLS keys or Decode As): start over", { epoch });
}

/** sharkd rejects skip: 0. */
function page(skip: number, limit: number): Record<string, number> {
  return skip > 0 ? { skip, limit } : { limit };
}

function frameChoice(v: unknown): "displayed" | "selected" | "marked" | Ranges | null {
  if (v === undefined || v === null) return null;
  if (v === "displayed" || v === "selected" || v === "marked") return v;
  if (!Array.isArray(v) || v.length > MAX_RANGES) throw new ApiError(400, "bad-args", `frames is "displayed", "selected", "marked" or up to ${MAX_RANGES} ranges [[first, last], ...]`);
  return v.map((r): [number, number] => {
    if (!Array.isArray(r) || r.length !== 2 || !r.every((x) => Number.isInteger(x) && x >= 1 && x <= 0x7fffffff)) throw new ApiError(400, "bad-args", "a frame range is [first, last] with frame numbers from 1");
    return [r[0], r[1]];
  });
}

function str(v: unknown, name: string, max: number): string {
  if (typeof v !== "string") throw new ApiError(400, "bad-args", `${name} must be a string`);
  if (v.length > max) throw new ApiError(400, "bad-args", `${name} is longer than ${max} characters`);
  return v;
}

function int(v: unknown, name: string, fallback: number | undefined, min: number): number {
  if (v === undefined && fallback !== undefined) return fallback;
  if (typeof v !== "number" || !Number.isInteger(v) || v < min || v > Number.MAX_SAFE_INTEGER) throw new ApiError(400, "bad-args", `${name} must be a whole number from ${min}`);
  return v;
}

function bool(v: unknown, name: string): boolean {
  if (typeof v !== "boolean") throw new ApiError(400, "bad-args", `${name} must be true or false`);
  return v;
}

function list(v: unknown, name: string, max: number): string[] {
  if (v === undefined) return [];
  if (!Array.isArray(v) || v.length > max || !v.every((x) => typeof x === "string")) throw new ApiError(400, "bad-args", `${name} must be up to ${max} field names`);
  return v as string[];
}

function fieldName(f: string, name: string): string {
  if (!FIELD_NAME.test(f)) throw new ApiError(400, "bad-args", `${name}: "${printable(f).slice(0, 60)}" is not a field name`);
  return f;
}
