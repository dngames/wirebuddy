/**
 * Capture data for panels, read by a sharkd of their own: the view's engines
 * answer strictly in order, so a panel's queries there would stall the packet
 * list. The panel engine starts on the first request, reads the view's file
 * again when it changes (a growing live file at most once a second), lets the
 * open panels take turns, and stops a minute after the last panel closed.
 */

import type { PanelView } from "../shared/api.ts";
import type { Ranges } from "../shared/ranges.ts";
import type { EventLog } from "./events.ts";
import { findLayer } from "./layers.ts";
import { Sharkd, SharkdError, SharkdTooLarge } from "./sharkd.ts";
import { printable } from "./text.ts";
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
/** Packets per page: without fields or bytes, with fields, with bytes (one sharkd call per packet). */
const MAX_LIMIT = { plain: 50_000, fields: 5_000, bytes: 2_000 };
const DEFAULT_MAX_BYTES = 4 * 1024 * 1024;
const MAX_BYTES = 16 * 1024 * 1024;
const MAX_OBJECT = 64 * 1024 * 1024;
const MAX_OBJECTS = 10_000;
/** Packets whose bytes one turn at the engine asks for. */
const BYTES_BATCH = 32;
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
  /** Why it changed last: file, closed, rewritten, extensions or tls. */
  resetWhy(): string;
  file(): string | null;
  /** The view follows a capture that is running. */
  live(): boolean;
  totalFrames(): number;
  /** The frames the view shows, and its display filter. */
  displayed(): { set: FrameSet; filter: string };
  /** The packets the user selected, else the selected one. */
  selected(): FrameSet;
  marked(): FrameSet;
  tlsKeylog(): string | null;
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
  private keylogSet = false;
  /** Of the current load: filter checks and export object listings; frame sets by filter. */
  private readonly cache = new Map<string, unknown>();
  private readonly sets = new Map<string, unknown>();
  /** The last stream followed, decoded. */
  private lastFollow: { seq: number; key: string; result: FollowData } | null = null;

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
    for (const w of this.waiting.get(label) ?? []) w.fail(new ApiError(404, "gone", "the panel was closed"));
    this.waiting.delete(label);
    this.idle();
  }

  /** Stops the engine IDLE_STOP_MS after no panel is open. */
  private idle(): void {
    if (this.idleTimer) clearTimeout(this.idleTimer);
    this.idleTimer = null;
    if (this.open.size || !this.engine) return;
    this.idleTimer = setTimeout(() => this.close(), IDLE_STOP_MS);
    this.idleTimer.unref();
  }

  setTlsKeylog(path: string | null): void {
    this.keylogSet = true;
    this.engine?.setPref("tls.keylog_file", path ?? "").catch(() => {});
  }

  close(): void {
    this.engine?.close();
    this.engine = null;
    this.loaded = null;
    this.cache.clear();
    this.sets.clear();
    this.lastFollow = null;
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
    const keylog = source.tlsKeylog();
    if (keylog !== null || this.keylogSet) engine.setPref("tls.keylog_file", keylog ?? "").catch(() => {});
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
    return Promise.race([work.catch(engineFailure), over]).finally(() => clearTimeout(timer));
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
        if (was && was.file === file && was.epoch === epoch && (source.totalFrames() <= was.frames || Date.now() - was.at < LIVE_LOAD_MS)) return was;
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
        await this.run(ctx.label, (e) => e.call("check", { filter }), CALL_BUDGET_MS, ctx.loaded);
        return "";
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

  /** The frames a display filter matches in the loaded file. */
  private async matching(ctx: Ctx, filter: string): Promise<FrameSet> {
    await this.checkFilter(ctx, filter);
    return this.cached(
      filter,
      async () => {
        const rows = await this.run(ctx.label, (e) => e.call<{ num: number }[]>("frames", { filter, column0: "frame.number:0" }), CALL_BUDGET_MS, ctx.loaded);
        return FrameSet.fromSorted(rows.map((r) => r.num));
      },
      this.sets,
      MAX_CACHED_SETS,
    );
  }

  // --- methods

  private async packets(label: string, q: Record<string, unknown>): Promise<Buffer> {
    const epoch = this.epochOf(q);
    const fields = [...new Set(list(q.fields, "fields", MAX_FIELDS).map((f) => fieldName(f, "fields")))];
    const bytes = q.bytes === undefined ? "none" : str(q.bytes, "bytes", 128);
    const layer = bytes === "none" || bytes === "frame" || bytes === "ip" || bytes === "payload" ? bytes : fieldName(bytes, "bytes");
    const filter = q.filter === undefined ? "" : str(q.filter, "filter", MAX_FILTER).trim();
    const after = int(q.after, "after", 0, 0);
    const cap = layer !== "none" ? MAX_LIMIT.bytes : fields.length ? MAX_LIMIT.fields : MAX_LIMIT.plain;
    const limit = Math.min(int(q.limit, "limit", DEFAULT_LIMIT, 1), cap);
    const maxBytes = int(q.maxBytes, "maxBytes", DEFAULT_MAX_BYTES, 1);
    if (maxBytes > MAX_BYTES) throw new ApiError(413, "too-large", `maxBytes is at most ${MAX_BYTES} (16 MiB)`);
    const which = frameChoice(q.frames);

    const loaded = await this.load(label, epoch);
    const ctx = { label, loaded };
    for (const f of fields) await this.checkFilter(ctx, f, "field");
    const fieldBytes = layer !== "none" && layer !== "frame" && layer !== "ip" && layer !== "payload";
    if (fieldBytes) await this.checkFilter(ctx, layer, "field");

    // The set of frames, and the filter whose matches it is exactly (sharkd pages those by position)
    const source = this.opts.source;
    let set: FrameSet;
    let byFilter = "";
    if (which === "displayed") {
      const d = source.displayed();
      set = d.set;
      byFilter = d.filter;
    } else if (which === "selected") set = source.selected();
    else if (which === "marked") set = source.marked();
    else if (which) set = FrameSet.fromRanges(which);
    else set = FrameSet.all(loaded.frames);
    // The view's lists are of the file the engine read only while the epoch is the same
    if (source.epoch() !== loaded.epoch) throw stale(source.epoch());
    set = set.clip(loaded.frames);
    if (filter) {
      const m = await this.matching(ctx, filter);
      set = which ? set.intersect(m) : m;
      byFilter = which ? "" : filter;
    }

    const { frames, more } = set.page(after, limit);
    // Third: what the layer is found by, the link type or the field's value
    const columns = ["frame.time_epoch", "frame.len", ...(layer === "ip" || layer === "payload" ? ["frame.encap_type"] : fieldBytes ? [layer] : []), ...fields];
    const values = await this.columns(ctx, frames, columns, byFilter, set);
    const rows: PageRow[] = [];
    const fieldValues: Record<string, string[]> = Object.fromEntries(fields.map((f) => [f, []]));
    const clipped: [number, string][] = [];
    const first = columns.length - fields.length;
    let dropped = 0;
    let size = 0;
    let cut = false;
    for (let i = 0; i < frames.length && !cut; i += BYTES_BATCH) {
      const batch = frames.slice(i, i + BYTES_BATCH).filter((f) => values.has(f));
      const data = layer === "none" ? null : await this.bytesOf(ctx, batch, layer, values);
      for (const [k, frame] of batch.entries()) {
        const c = values.get(frame)!;
        const d = data ? data[k] : EMPTY;
        const bytesHere = d ?? EMPTY;
        let rowSize = bytesHere.length;
        for (let j = first; j < c.length; j++) rowSize += c[j].length;
        // At least one packet, however large
        if (rows.length && size + rowSize > maxBytes) {
          cut = true;
          break;
        }
        if (d === null && fieldBytes && c[2]) {
          throw new ApiError(400, "bad-args", `"${layer}" has a value but no bytes in the packet (a hidden or generated field): ask for a field the packet details show with bytes, e.g. ip.src instead of ip.addr`);
        }
        if (d === null) dropped++;
        size += rowSize;
        for (const [j, f] of fields.entries()) {
          const v = c[first + j] ?? "";
          if (v.startsWith(CLIPPED)) clipped.push([rows.length, f]);
          fieldValues[f].push(v);
        }
        rows.push({ frame, time: c[0] ? Number(c[0]) : NaN, len: Number(c[1]) || 0, data: bytesHere });
      }
    }
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
        pending: loaded.frames < source.totalFrames(),
      },
      rows,
    );
  }

  /** Column values per frame: one sharkd call per page of a filter, else per stretch of nearby frames. */
  private async columns(ctx: Ctx, frames: number[], columns: string[], byFilter: string, set: FrameSet): Promise<Map<number, string[]>> {
    const out = new Map<number, string[]>();
    if (!frames.length) return out;
    const params = Object.fromEntries(columns.map((f, i) => [`column${i}`, `${f}:0`]));
    if (byFilter) {
      const skip = set.rank(frames[0] - 1);
      const rows = await this.run(ctx.label, (e) => e.call<{ num: number; c: string[] }[]>("frames", { filter: byFilter, ...page(skip, frames.length), ...params }), CALL_BUDGET_MS, ctx.loaded).catch((err) => {
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
      const rows = await this.run(ctx.label, (e) => e.call<{ num: number; c: string[] }[]>("frames", { ...page(a - 1, b - a + 1), ...params }), CALL_BUDGET_MS, ctx.loaded);
      for (const r of rows) out.set(r.num, r.c);
      i = j + 1;
    }
    return out;
  }

  /** The bytes of `layer` per frame; null where the frame has no such layer. */
  private async bytesOf(ctx: Ctx, frames: number[], layer: string, values: Map<number, string[]>): Promise<(Uint8Array | null)[]> {
    const tree = layer !== "frame" && layer !== "ip" && layer !== "payload";
    const answers = await this.run(
      ctx.label,
      (e) => Promise.all(frames.map((frame) => e.call<{ bytes?: string; tree?: TreeNode[]; ds?: { bytes?: string }[] }>("frame", { frame, bytes: true, ...(tree ? { proto: true, hidden: true } : {}) }))),
      CALL_BUDGET_MS,
      ctx.loaded,
    );
    return answers.map((r, i) => {
      if (tree) return fieldBytes(r, layer);
      const b = Buffer.from(r.bytes ?? "", "base64");
      if (layer === "frame") return b;
      const at = findLayer(b, values.get(frames[i])?.[2] ?? "", layer as "ip" | "payload");
      return at ? b.subarray(at[0], at[1]) : null;
    });
  }

  private async frame(label: string, q: Record<string, unknown>): Promise<unknown> {
    const epoch = this.epochOf(q);
    const frame = int(q.frame, "frame", undefined, 1);
    const tree = q.tree === undefined ? true : bool(q.tree, "tree");
    const bytes = q.bytes === undefined ? true : bool(q.bytes, "bytes");
    const loaded = await this.load(label, epoch);
    if (frame > loaded.frames) throw new ApiError(404, "gone", `no frame ${frame}: the capture has ${loaded.frames}`);
    const r = await this.run(
      label,
      (e) =>
        e.call<{ tree?: TreeNode[]; bytes?: string; ds?: { name: string; bytes: string }[]; followers?: { protocol: string; filter: string }[] }>("frame", {
          frame,
          ...(tree ? { proto: true } : {}),
          ...(bytes ? { bytes: true } : {}),
        }),
      CALL_BUDGET_MS,
      loaded,
    );
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
      );
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

const EMPTY = new Uint8Array(0);

/** Ascending frame numbers as inclusive ranges, flat: [a0, b0, a1, b1, ...]. */
export class FrameSet {
  /** Frames before each range, for rank(). */
  private before: Float64Array | null = null;

  private constructor(
    private readonly r: Int32Array,
    readonly count: number,
  ) {}

  static all(n: number): FrameSet {
    return n > 0 ? new FrameSet(Int32Array.of(1, n), n) : new FrameSet(new Int32Array(0), 0);
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
    const out: number[] = [];
    let count = 0;
    for (let i = 0; i < this.r.length; i += 2) {
      if (this.r[i] > max) break;
      const b = Math.min(this.r[i + 1], max);
      out.push(this.r[i], b);
      count += b - this.r[i] + 1;
    }
    return count === this.count ? this : new FrameSet(Int32Array.from(out), count);
  }

  intersect(o: FrameSet): FrameSet {
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
  if (err instanceof SharkdTooLarge) throw new ApiError(413, "too-large", `${err.message}: for a large stream read its packets with wb.packets({filter, bytes: "payload"})`);
  throw new ApiError(500, "internal", `the panel engine failed: ${printable((err as Error).message)}`, { retryMs: 1000 });
}

function stale(epoch: number): ApiError {
  return new ApiError(409, "stale", "the capture changed (another file, re-read extensions or TLS keys): start over", { epoch });
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
