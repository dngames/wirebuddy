import { randomBytes } from "node:crypto";
import { EventEmitter } from "node:events";
import { closeSync, openSync, readSync, statSync } from "node:fs";
import { resolve } from "node:path";
import { Sharkd, SharkdError } from "./sharkd.ts";
import { Capture } from "./capture.ts";
import { checkTarget, exportFrames, parseRange, toRanges } from "./export.ts";
import { EventLog } from "./events.ts";
import { launchWireshark } from "./wireshark.ts";
import { countRanges, inRanges, mergeRanges, type Ranges } from "../shared/ranges.ts";
import type {
  ConvRow,
  CaptureState,
  CustomColumn,
  EndpointRow,
  ExpertItem,
  ExpertSeverity,
  ExportRequest,
  ExportResult,
  FilterCheck,
  FindResult,
  FollowResult,
  FrameDetail,
  IoGraphResult,
  IoGraphSpec,
  Mark,
  PacketRow,
  PhsNode,
  RowsResponse,
  TreeNode,
  ViewState,
} from "../shared/api.ts";

export class StaleGenerationError extends Error {}

interface SharkdStatus {
  frames: number;
  duration?: number;
  filesize?: number;
  columns: string[];
}

interface SharkdFrame {
  tree: TreeNode[];
  bytes?: string;
  ds?: { name: string; bytes: string }[];
  followers?: { protocol: string; filter: string | null; stream?: number }[];
  /** Older sharkd versions only send this form. */
  fol?: [string, string | null][];
}

interface SharkdPhs {
  proto: string;
  frames: number;
  bytes: number;
  protos?: SharkdPhs[];
}

const CONV_TAPS = { eth: "Ethernet", ipv4: "IPv4", ipv6: "IPv6", tcp: "TCP", udp: "UDP" } as const;
export type ConvType = keyof typeof CONV_TAPS;
export const CONV_TYPES = Object.keys(CONV_TAPS) as ConvType[];

/** Bytes of payload data a follow result may carry before it is cut. */
const FOLLOW_LIMIT = 4 * 1024 * 1024;
const LIVE_RELOAD_MS = 1000;
const MAX_MARKS = 10000;
/** Row ranges a selection may consist of. */
const MAX_ROW_RANGES = 10000;
const MAX_NOTE = 200;
const MAX_CUSTOM_COLUMNS = 10;
/** Longer custom column values (e.g. whole payloads) are cut to this. */
const MAX_COLUMN_VALUE = 500;
const MAX_IO_BUCKETS = 4000;
/** sharkd computes the interval in 32-bit microseconds; larger intervals overflow. */
const MAX_IO_INTERVAL = 2_000_000;
const MAX_IO_BUCKETS_HARD = 100_000;
const MAX_IO_GRAPHS = 4;
const FIELD_NAME = /^[A-Za-z0-9_][A-Za-z0-9_.-]*$/;

/**
 * Everything the UI and the agent share: the open capture, display filter,
 * selection, marks and the live capture. Emits "state" on every change.
 *
 * Two sharkd instances alternate during a live capture: one answers queries
 * while the other reloads the growing file, then they swap.
 */
export class Viewer extends EventEmitter {
  private engines: [Sharkd, Sharkd];
  /** Problems and user activity for the agent. */
  readonly events = new EventLog((pending) => this.set({ agent: { ...this.state.agent, pending } }));
  private active = 0;
  /** Frame numbers matching the filter; null means all frames 1..totalFrames. */
  private displayed: Int32Array | null = null;
  private mutation: Promise<unknown> = Promise.resolve();
  private reloadTimer: NodeJS.Timeout | null = null;
  private loadedSize = -1;
  private noticeId = 0;
  private readonly wiresharkBin: string | null;
  private readonly profile: string | undefined;
  private readonly editcap: string;
  private readonly mergecap: string;
  /** Columns sharkd reports for the open file, before custom ones. */
  private baseColumns: string[] = [];
  readonly capture: Capture;
  readonly recent: string[] = [];

  state: ViewState;

  constructor(opts: {
    captureDir: string;
    sharkd?: string;
    dumpcap?: string;
    wireshark?: string | null;
    profile?: string;
    editcap?: string;
    mergecap?: string;
  }) {
    super();
    this.engines = [new Sharkd(opts.sharkd, opts.profile), new Sharkd(opts.sharkd, opts.profile)];
    for (const e of this.engines) e.onFailure = (message) => this.events.add("WARNING", message);
    this.profile = opts.profile;
    this.editcap = opts.editcap ?? "editcap";
    this.mergecap = opts.mergecap ?? "mergecap";
    this.wiresharkBin = opts.wireshark ?? null;
    this.capture = new Capture(opts.captureDir, opts.dumpcap);
    this.state = {
      file: null,
      fileSize: 0,
      loading: false,
      loadError: null,
      // Unique per process so a restarted server never reuses a generation the UI has cached
      generation: Date.now() % 1_000_000_000,
      instance: randomBytes(6).toString("hex"),
      columns: [],
      totalFrames: 0,
      displayedFrames: 0,
      duration: 0,
      filter: "",
      selected: null,
      selectedIndex: -1,
      selectedBy: null,
      selectSeq: 0,
      selectedRows: [],
      selectedCount: 0,
      rowsSince: 0,
      marks: [],
      capture: this.capture.state,
      agentNotice: null,
      agent: { attached: false, pending: 0 },
      wiresharkAvailable: !!this.wiresharkBin,
      customColumns: [],
      tlsKeylog: null,
    };
    this.capture.on("change", (capture: CaptureState) => {
      if (capture.status === "error" && this.state.capture.status !== "error") this.events.add("ERROR", `The capture failed: ${capture.error ?? "unknown error"}`, { iface: capture.iface });
      this.set({ capture });
    });
    this.capture.on("file", (file: string) => {
      // A new capture takes over the view; later ring files only if the view still follows it
      const files = this.capture.state.files;
      if (files.length > 1 && !this.followingCapture(files[files.length - 2])) return;
      this.open(file).catch((err) => this.problem(`Live view: ${(err as Error).message}`));
      this.scheduleReload();
    });
    this.capture.on("stopped", () => {
      if (this.reloadTimer) clearTimeout(this.reloadTimer);
      this.reloadTimer = null;
      if (this.followingCapture()) this.reload(true).catch(() => {});
    });
  }

  /** Whether the view shows the live capture's current file (or `file`). */
  private followingCapture(file = this.capture.state.currentFile): boolean {
    return !!file && this.state.file === file;
  }

  private get engine(): Sharkd {
    return this.engines[this.active];
  }

  private set(patch: Partial<ViewState>): void {
    this.state = { ...this.state, ...patch };
    this.emit("state", this.state);
  }

  /** Runs state-changing work one at a time. */
  private exclusive<T>(fn: () => Promise<T>): Promise<T> {
    const next = this.mutation.then(fn, fn);
    this.mutation = next.catch(() => {});
    return next;
  }

  private indexOf(frame: number | null): number {
    if (frame === null) return -1;
    if (!this.displayed) return frame >= 1 && frame <= this.state.totalFrames ? frame - 1 : -1;
    let lo = 0;
    let hi = this.displayed.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      const v = this.displayed[mid];
      if (v === frame) return mid;
      if (v < frame) lo = mid + 1;
      else hi = mid - 1;
    }
    return -1;
  }

  /** Loads `file` into `engine` and computes the displayed frames for `filter`. */
  private async loadInto(engine: Sharkd, file: string, filter: string) {
    const load = await engine.call<{ status: string; err?: number }>("load", { file });
    // A file still being written ends mid-packet; sharkd reports that but keeps what it read.
    if (load.status !== "OK" && load.err !== -12) throw new Error(load.status);
    const status = await engine.call<SharkdStatus>("status");
    const displayed = filter ? await this.matchingFrames(engine, filter) : null;
    return { status, displayed };
  }

  private async matchingFrames(engine: Sharkd, filter: string): Promise<Int32Array> {
    const rows = await engine.call<{ num: number }[]>("frames", { filter, column0: "frame.number:0" });
    return Int32Array.from(rows, (r) => r.num);
  }

  private applyLoad(
    file: string,
    filter: string,
    { status, displayed }: { status: SharkdStatus; displayed: Int32Array | null },
    keepSelection: boolean,
  ): void {
    // A shorter file is a rewritten one, filtered or not
    const keepRows = keepSelection && status.frames >= this.state.totalFrames && appendedOnly(this.displayed, displayed);
    this.displayed = displayed;
    this.baseColumns = status.columns;
    const totalFrames = status.frames;
    const selected = keepSelection && this.state.selected !== null && this.state.selected <= totalFrames ? this.state.selected : null;
    this.state = {
      ...this.state,
      file,
      fileSize: status.filesize ?? safeSize(file),
      loading: false,
      loadError: null,
      columns: [...status.columns, ...this.state.customColumns.map((c) => c.title)],
      totalFrames,
      displayedFrames: displayed ? displayed.length : totalFrames,
      marks: this.state.marks.filter((m) => m.frame <= totalFrames),
      duration: status.duration ?? 0,
      filter,
      selected,
      selectedBy: selected === null ? null : this.state.selectedBy,
      generation: this.state.generation + 1,
    };
    const selectedIndex = this.indexOf(selected);
    const rows = keepRows ? clipRanges(this.state.selectedRows, this.state.displayedFrames) : rowOf(selectedIndex);
    this.set({ selectedIndex, ...rowSelection(rows), rowsSince: keepRows ? this.state.rowsSince : this.state.generation });
  }

  /**
   * Opens a capture in the standby engine and swaps on success; on failure the
   * current view stays as it was.
   */
  open(file: string): Promise<void> {
    file = resolve(file);
    return this.exclusive(async () => {
      this.set({ loading: true, loadError: null });
      const standby = 1 - this.active;
      let filter = this.state.filter;
      try {
        const st = statSync(file, { throwIfNoEntry: false });
        if (!st || !st.isFile()) throw new Error(`no such file: ${file}`);
        if (!looksLikeCapture(file)) throw new Error(`not a capture file: ${file}`);
        let result;
        try {
          result = await this.loadInto(this.engines[standby], file, filter);
        } catch (err) {
          if (!(err instanceof SharkdError) || !filter) throw err;
          // The filter may not apply to this capture's protocols; show everything instead
          filter = "";
          result = await this.loadInto(this.engines[standby], file, filter);
        }
        this.active = standby;
        this.loadedSize = st.size;
        this.state = { ...this.state, marks: [], selected: null, selectedBy: null };
        this.applyLoad(file, filter, result, false);
        this.remember(file);
      } catch (err) {
        const message = (err as Error).message;
        this.set({ loading: false, loadError: message.includes(file) ? message : `${file}: ${message}` });
        throw err;
      }
    });
  }

  /** Re-reads the open file into the standby engine, then swaps engines. */
  reload(force = false): Promise<void> {
    return this.exclusive(async () => {
      const file = this.state.file;
      if (!file) return;
      const size = safeSize(file);
      if (!force && size === this.loadedSize) return;
      const standby = 1 - this.active;
      const result = await this.loadInto(this.engines[standby], file, this.state.filter);
      if (this.state.file !== file) return;
      this.active = standby;
      this.loadedSize = size;
      this.applyLoad(file, this.state.filter, result, true);
    });
  }

  private scheduleReload(): void {
    if (this.reloadTimer) clearTimeout(this.reloadTimer);
    this.reloadTimer = setTimeout(async () => {
      try {
        if (this.followingCapture()) await this.reload();
      } catch (err) {
        this.problem(`Live reload: ${(err as Error).message}`);
      }
      if (this.capture.running) this.scheduleReload();
      else this.reloadTimer = null;
    }, LIVE_RELOAD_MS);
  }

  close(): Promise<void> {
    return this.exclusive(async () => {
      this.displayed = null;
      this.set({
        file: null,
        fileSize: 0,
        loading: false,
        loadError: null,
        columns: [],
        totalFrames: 0,
        displayedFrames: 0,
        duration: 0,
        selected: null,
        selectedIndex: -1,
        selectedBy: null,
        ...rowSelection([]),
        marks: [],
        generation: this.state.generation + 1,
        rowsSince: this.state.generation + 1,
      });
    });
  }

  async checkFilter(filter: string): Promise<FilterCheck> {
    if (!filter.trim()) return { ok: true };
    try {
      const r = await this.engine.call<{ status: string; warning?: string }>("check", { filter });
      return r.warning ? { ok: true, warning: r.warning } : { ok: true };
    } catch (err) {
      const message = (err as Error).message.replace(/^Filter invalid - /, "");
      return { ok: false, error: message + bpfHint(filter) };
    }
  }

  setFilter(filter: string, by: "user" | "agent"): Promise<FilterCheck> {
    filter = filter.trim();
    return this.exclusive(async () => {
      const check = await this.checkFilter(filter);
      if (!check.ok) return check;
      if (this.state.file) {
        const displayed = filter ? await this.matchingFrames(this.engine, filter) : null;
        this.displayed = displayed;
        this.state = {
          ...this.state,
          filter,
          displayedFrames: displayed ? displayed.length : this.state.totalFrames,
          generation: this.state.generation + 1,
        };
        const selectedIndex = this.indexOf(this.state.selected);
        this.set({ selectedIndex, ...rowSelection(rowOf(selectedIndex)), rowsSince: this.state.generation });
      } else {
        this.set({ filter });
      }
      if (by === "agent") this.notice(filter ? `Applied display filter: ${filter}` : "Cleared the display filter");
      return check;
    });
  }

  async complete(field: string): Promise<{ f: string; n?: string }[]> {
    if (!field) return [];
    const r = await this.engine.call<{ field?: { f: string; n?: string }[] }>("complete", { field });
    return (r.field ?? []).slice(0, 50).map(({ f, n }) => ({ f, n }));
  }

  async rows(generation: number, start: number, count: number): Promise<RowsResponse> {
    if (generation !== this.state.generation) throw new StaleGenerationError("stale generation");
    const engine = this.engine;
    const filter = this.state.filter;
    count = Math.max(0, Math.min(count, 500, this.state.displayedFrames - start));
    if (count === 0 || start < 0) return { generation, start, rows: [] };
    const params = page(start, count);
    if (filter) params.filter = filter;
    const rows = await this.framesWithColumns(engine, params);
    if (generation !== this.state.generation) throw new StaleGenerationError("stale generation");
    return { generation, start, rows };
  }

  /** Summary row of one frame, regardless of the display filter. */
  async row(num: number): Promise<PacketRow | null> {
    if (num < 1 || num > this.state.totalFrames) return null;
    const rows = await this.framesWithColumns(this.engine, page(num - 1, 1));
    const r = rows[0];
    return r && r.num === num ? r : null;
  }

  /** sharkd "frames" rows with the custom columns appended. */
  private async framesWithColumns(engine: Sharkd, params: Record<string, unknown>): Promise<PacketRow[]> {
    const custom = this.state.customColumns;
    const [rows, extra] = await Promise.all([
      engine.call<PacketRow[]>("frames", params),
      // Custom column params replace sharkd's default columns, so they come in a second request
      custom.length ? engine.call<PacketRow[]>("frames", { ...params, ...columnParams(custom.map((c) => c.field)) }) : null,
    ]);
    return rows.map((r, i) => {
      const values = extra?.[i]?.num === r.num ? extra[i].c.map(clip) : custom.map(() => "");
      return { num: r.num, c: [...r.c, ...values], bg: r.bg, fg: r.fg };
    });
  }

  /**
   * Field values per frame for `filter`, like `tshark -T fields`; each value
   * holds all occurrences, comma-separated.
   */
  async extract(filter: string, fields: string[], offset: number, limit: number): Promise<{ total: number; rows: { num: number; values: string[] }[] }> {
    this.requireFile();
    await this.checkFields(fields);
    const check = await this.checkFilter(filter);
    if (!check.ok) throw new Error(`invalid display filter: ${check.error}`);
    const total = await this.countMatching(filter);
    const params: Record<string, unknown> = { ...page(offset, limit), ...columnParams(fields) };
    if (filter) params.filter = filter;
    const rows = await this.engine.call<PacketRow[]>("frames", params);
    return { total, rows: rows.map((r) => ({ num: r.num, values: r.c.map(clip) })) };
  }

  private async checkFields(fields: string[]): Promise<void> {
    if (!fields.length) throw new Error("no fields given");
    for (const f of fields) {
      if (!FIELD_NAME.test(f)) throw new Error(`"${f}" is not a field name`);
      const r = await this.checkFilter(f);
      if (!r.ok) throw new Error(`unknown field "${f}": ${r.error}`);
    }
  }

  /** Sets the packet list's custom columns (an empty list removes them). */
  setColumns(columns: CustomColumn[], by: "user" | "agent"): Promise<FilterCheck> {
    return this.exclusive(async () => {
      if (columns.length > MAX_CUSTOM_COLUMNS) return { ok: false, error: `at most ${MAX_CUSTOM_COLUMNS} custom columns` };
      try {
        if (columns.length) await this.checkFields(columns.map((c) => c.field));
      } catch (err) {
        return { ok: false, error: (err as Error).message };
      }
      const customColumns: CustomColumn[] = [];
      for (const c of columns) {
        const title = String(c.title ?? "").trim().slice(0, 60) || (await this.fieldName(c.field));
        customColumns.push({ field: c.field, title });
      }
      this.set({
        customColumns,
        columns: this.state.file ? [...this.baseColumns, ...customColumns.map((c) => c.title)] : [],
        generation: this.state.generation + 1,
      });
      if (by === "agent") this.notice(customColumns.length ? `Columns: ${customColumns.map((c) => c.title).join(", ")}` : "Removed the custom columns");
      return { ok: true };
    });
  }

  /** The field's display name, e.g. "Status Code" for http.response.code. */
  private async fieldName(field: string): Promise<string> {
    try {
      const r = await this.engine.call<{ field?: { f: string; n?: string }[] }>("complete", { field });
      return r.field?.find((x) => x.f === field)?.n ?? field;
    } catch {
      return field;
    }
  }

  async frame(num: number): Promise<FrameDetail> {
    this.requireFile();
    if (!Number.isInteger(num) || num < 1 || num > this.state.totalFrames) throw new Error(`no frame ${num}`);
    const [f, row] = await Promise.all([
      this.engine.call<SharkdFrame>("frame", { frame: num, proto: true, bytes: true }),
      this.row(num),
    ]);
    return {
      num,
      tree: f.tree,
      bytes: f.bytes ?? "",
      ds: f.ds ?? [],
      followers: (f.followers ?? (f.fol ?? []).map(([protocol, filter]) => ({ protocol, filter })))
        .filter((x) => x.filter)
        .map((x) => [x.protocol, x.filter!] as [string, string]),
      row,
    };
  }

  /** Rows for an arbitrary filter, without touching what the UI shows. */
  async query(filter: string, offset: number, limit: number): Promise<{ total: number; rows: PacketRow[] }> {
    this.requireFile();
    const check = await this.checkFilter(filter);
    if (!check.ok) throw new Error(`invalid display filter: ${check.error}`);
    const total = await this.countMatching(filter);
    const params = page(offset, limit);
    if (filter) params.filter = filter;
    const rows = await this.framesWithColumns(this.engine, params);
    return { total, rows };
  }

  private countCache: { generation: number; filter: string; total: number } | null = null;

  /** Frames matching `filter`, reusing the view's count and earlier results. */
  private async countMatching(filter: string): Promise<number> {
    if (!filter) return this.state.totalFrames;
    if (filter === this.state.filter) return this.state.displayedFrames;
    const { generation } = this.state;
    const c = this.countCache;
    if (c && c.generation === generation && c.filter === filter) return c.total;
    const total = (await this.matchingFrames(this.engine, filter)).length;
    this.countCache = { generation, filter, total };
    return total;
  }

  /**
   * Makes `frame` the current packet. `rows` are the rows the user selected in
   * the displayed list (they need not include the frame's row); without them
   * only the frame's row is selected.
   */
  select(frame: number | null, by: "user" | "agent", rows?: Ranges, view?: { file: string; filter: string; generation?: number }): void {
    // Rows clicked, or a frame found, in a list the view has replaced or changed in place since
    if (view && (view.file !== this.state.file || view.filter !== this.state.filter || (view.generation ?? Infinity) < this.state.rowsSince)) {
      throw new StaleGenerationError("the selection belongs to another view");
    }
    if (frame !== null && (!Number.isInteger(frame) || frame < 1 || frame > this.state.totalFrames)) {
      throw new Error(`no frame ${frame}`);
    }
    const selectedIndex = this.indexOf(frame);
    const selectedRows = rows ? this.checkRows(rows) : rowOf(selectedIndex);
    this.set({
      selected: frame,
      selectedIndex,
      selectedBy: frame === null ? null : by,
      selectSeq: by === "agent" ? this.state.selectSeq + 1 : this.state.selectSeq,
      ...rowSelection(selectedRows),
    });
    if (by === "agent" && frame !== null) {
      const hidden = this.state.selectedIndex < 0 ? " (hidden by the current display filter)" : "";
      this.notice(`Selected frame ${frame}${hidden}`);
    }
  }

  /** Checks row ranges against the displayed list and merges them. */
  private checkRows(rows: Ranges): Ranges {
    if (rows.length > MAX_ROW_RANGES) throw new Error(`at most ${MAX_ROW_RANGES} row ranges can be selected`);
    const n = this.state.displayedFrames;
    for (const [a, b] of rows) {
      if (!Number.isInteger(a) || !Number.isInteger(b) || a < 0 || a > b || b >= n) throw new Error(`invalid row range [${a}, ${b}] (${n} rows are displayed)`);
    }
    return mergeRanges(rows);
  }

  /** Frame ranges of the user's selected rows. */
  selectedFrames(): Ranges {
    const rows = clipRanges(this.state.selectedRows, this.state.displayedFrames);
    const displayed = this.displayed;
    if (!displayed) return rows.map(([a, b]) => [a + 1, b + 1]);
    const out: Ranges = [];
    for (const [a, b] of rows) {
      for (let i = a; i <= b; i++) {
        const frame = displayed[i];
        const last = out[out.length - 1];
        if (last && frame === last[1] + 1) last[1] = frame;
        else out.push([frame, frame]);
      }
    }
    return out;
  }

  /** Frames of the selected rows, else the selected frame. */
  private selectedOrCurrent(): Ranges {
    if (this.state.selectedCount) return this.selectedFrames();
    const frame = this.state.selected;
    return frame === null ? [] : [[frame, frame]];
  }

  /** Marks frames and returns the frame numbers that exist. */
  mark(frames: number[], note: string, by: "user" | "agent"): number[] {
    this.requireFile();
    note = note.slice(0, MAX_NOTE);
    const valid = [...new Set(frames)].filter((f) => Number.isInteger(f) && f >= 1 && f <= this.state.totalFrames);
    const marked = new Set(valid);
    const keep = this.state.marks.filter((m) => !marked.has(m.frame));
    if (keep.length + valid.length > MAX_MARKS) throw new Error(`at most ${MAX_MARKS} frames can be marked`);
    const added: Mark[] = valid.map((frame) => ({ frame, note, by }));
    this.set({ marks: [...keep, ...added].sort((a, b) => a.frame - b.frame) });
    if (by === "agent" && valid.length) {
      this.notice(`Marked ${valid.length} frame${valid.length === 1 ? "" : "s"}${note ? `: ${note}` : ""}`);
    }
    return valid;
  }

  clearMarks(frames?: number[]): void {
    const drop = frames && new Set(frames);
    this.set({ marks: drop ? this.state.marks.filter((m) => !drop.has(m.frame)) : [] });
  }

  /** Wireshark's Mark/Unmark Packet(s): flips the mark of each selected frame. */
  toggleMarks(by: "user" | "agent"): void {
    const frames = this.selectedOrCurrent();
    if (!frames.length) return;
    const marks = this.state.marks;
    const removed = marks.filter((m) => inRanges(frames, m.frame)).length;
    if (marks.length - removed + countRanges(frames) - removed > MAX_MARKS) throw new Error(`at most ${MAX_MARKS} frames can be marked`);
    const had = new Set(marks.map((m) => m.frame));
    const added: Mark[] = [];
    for (const [a, b] of frames) for (let f = a; f <= b; f++) if (!had.has(f)) added.push({ frame: f, note: "", by });
    this.set({ marks: [...marks.filter((m) => !inRanges(frames, m.frame)), ...added].sort((a, b) => a.frame - b.frame) });
  }

  /** Wireshark's Mark All Displayed (`on`) / Unmark All Displayed; existing marks keep their notes. */
  markDisplayed(on: boolean, by: "user" | "agent"): void {
    this.requireFile();
    const marks = this.state.marks;
    const shown = (m: Mark) => this.indexOf(m.frame) >= 0;
    if (!on) {
      this.set({ marks: marks.filter((m) => !shown(m)) });
      return;
    }
    const n = this.state.displayedFrames;
    if (marks.length + n - marks.filter(shown).length > MAX_MARKS) throw new Error(`at most ${MAX_MARKS} frames can be marked`);
    const had = new Set(marks.map((m) => m.frame));
    const added: Mark[] = [];
    for (let i = 0; i < n; i++) {
      const frame = this.displayed ? this.displayed[i] : i + 1;
      if (!had.has(frame)) added.push({ frame, note: "", by });
    }
    this.set({ marks: [...marks, ...added].sort((a, b) => a.frame - b.frame) });
  }

  /** Marks the viewer as driven by an MCP agent, which then gets the problems. */
  attachAgent(): void {
    this.set({ agent: { ...this.state.agent, attached: true } });
  }

  /** A problem nobody asked for (live view): the agent gets it, the page shows it only without one. */
  private problem(text: string): void {
    this.events.add("ERROR", text);
    if (!this.state.agent.attached) this.emit("toast", "error", text);
  }

  notice(text: string): void {
    this.set({ agentNotice: { id: ++this.noticeId, text, at: Date.now() } });
  }

  /** sharkd tap parameters, limited to `filter` when given. */
  private async tapParams(tap: string, filter?: string): Promise<Record<string, unknown>> {
    this.requireFile();
    if (!filter?.trim()) return { tap0: tap };
    const check = await this.checkFilter(filter);
    if (!check.ok) throw new Error(`invalid display filter: ${check.error}`);
    return { tap0: tap, filter: filter.trim() };
  }

  async phs(filter?: string): Promise<PhsNode[]> {
    const r = await this.engine.call<{ taps: { protos: SharkdPhs[] }[] }>("tap", await this.tapParams("phs", filter));
    const map = (p: SharkdPhs): PhsNode => ({
      proto: p.proto,
      frames: p.frames,
      bytes: p.bytes,
      children: (p.protos ?? []).map(map),
    });
    return (r.taps[0]?.protos ?? []).map(map);
  }

  async conversations(type: ConvType, filter?: string): Promise<ConvRow[]> {
    const r = await this.engine.call<{ taps: { convs?: Record<string, never>[] }[] }>("tap", await this.tapParams(`conv:${CONV_TAPS[type]}`, filter));
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

  async endpoints(type: ConvType, filter?: string): Promise<EndpointRow[]> {
    const r = await this.engine.call<{ taps: { hosts?: Record<string, never>[] }[] }>("tap", await this.tapParams(`endpt:${CONV_TAPS[type]}`, filter));
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

  async expert(filter?: string): Promise<ExpertItem[]> {
    const r = await this.engine.call<{ taps: { details?: { f: number; s: string; g: string; p: string; m: string }[] }[] }>(
      "tap",
      await this.tapParams("expert", filter),
    );
    return (r.taps[0]?.details ?? [])
      .map((d) => ({ frame: d.f, severity: d.s as ExpertSeverity, group: d.g, protocol: d.p, message: d.m }))
      .sort((a, b) => a.frame - b.frame);
  }

  /**
   * Packets, bytes or bits per interval for up to four filters. The interval
   * grows when the capture would need more than MAX_IO_BUCKETS buckets.
   */
  async ioGraph(specs: IoGraphSpec[], intervalMs: number): Promise<IoGraphResult> {
    this.requireFile();
    if (!specs.length || specs.length > MAX_IO_GRAPHS) throw new Error(`give 1 to ${MAX_IO_GRAPHS} graphs`);
    if (!Number.isFinite(intervalMs) || intervalMs < 1) throw new Error("the interval must be at least 1 ms");
    const params: Record<string, unknown> = {};
    for (const [i, g] of specs.entries()) {
      if (g.metric !== "packets" && g.metric !== "bytes" && g.metric !== "bits") throw new Error(`unknown metric "${g.metric}"`);
      params[`graph${i}`] = g.metric;
      const filter = (g.filter ?? "").trim();
      if (filter) {
        const check = await this.checkFilter(filter);
        if (!check.ok) throw new Error(`invalid display filter "${filter}": ${check.error}`);
        params[`filter${i}`] = filter;
      }
    }
    const spanUs = Math.max(Math.round(this.state.duration * 1e6), 1);
    const interval = Math.min(niceInterval(Math.max(Math.round(intervalMs), Math.ceil(spanUs / 1000 / MAX_IO_BUCKETS))), MAX_IO_INTERVAL);
    const buckets = Math.floor(spanUs / (interval * 1000)) + 1;
    if (buckets > MAX_IO_BUCKETS_HARD) throw new Error("the capture spans too much time for an I/O graph (check for packets with bogus timestamps)");
    const r = await this.engine.call<{ iograph: { items?: (number | string)[] }[] }>("iograph", { interval, ...params });
    return {
      interval,
      series: specs.map((g, i) => ({ metric: g.metric, filter: (g.filter ?? "").trim(), values: denseItems(r.iograph[i]?.items ?? [], buckets) })),
    };
  }

  /** First frame at or after `seconds` since the first frame, within the display filter. */
  async frameAt(seconds: number): Promise<number | null> {
    this.requireFile();
    if (!Number.isFinite(seconds) || seconds < 0) throw new Error("time must be a non-negative number of seconds");
    const at = `frame.time_relative >= ${seconds.toFixed(9)}`;
    return this.firstMatching(this.engine, this.state.filter ? `(${this.state.filter}) && ${at}` : at);
  }

  private async firstMatching(engine: Sharkd, filter: string): Promise<number | null> {
    const rows = await engine.call<{ num: number }[]>("frames", { filter, ...page(0, 1), column0: "frame.number:0" });
    return rows[0]?.num ?? null;
  }

  /**
   * Find Packet: the first displayed frame after `from` (dir 1) or the last
   * one before it (dir -1) matching `filter`, else the first (last) one
   * overall. `from` 0 searches the whole list without wrapping.
   */
  async find(filter: string, from: number, dir: number): Promise<FindResult> {
    this.requireFile();
    if (dir !== 1 && dir !== -1) throw new Error("dir must be 1 or -1");
    if (!Number.isInteger(from) || from < 0) throw new Error("from must be a frame number, or 0 for none");
    filter = filter.trim();
    if (!filter) throw new Error("no display filter to find");
    const check = await this.checkFilter(filter);
    if (!check.ok) throw new Error(`invalid display filter: ${check.error}`);
    const engine = this.engine;
    const { file, filter: view } = this.state;
    const match = view ? `(${view}) && (${filter})` : `(${filter})`;
    let frame: number | null;
    let wrapped = false;
    if (dir === 1) {
      frame = await this.firstMatching(engine, from ? `${match} && frame.number > ${from}` : match);
      if (frame === null && from) {
        frame = await this.firstMatching(engine, match);
        wrapped = frame !== null;
      }
    } else {
      const frames = await this.matchingFrames(engine, match);
      const last = frames.length ? frames[frames.length - 1] : null;
      const before = from ? (frames.findLast((f) => f < from) ?? null) : last;
      frame = before ?? last;
      wrapped = before === null && last !== null;
    }
    // Live reloads keep frame numbers; another file or filter does not
    if (this.state.file !== file || this.state.filter !== view) throw new StaleGenerationError("the view changed during the search");
    return { frame, index: this.indexOf(frame), wrapped };
  }

  /** Reads the keylog file Wireshark's own preferences may already set. */
  async loadTlsPreference(): Promise<void> {
    try {
      const r = await this.engine.call<{ prefs?: Record<string, { s?: string }> }>("dumpconf", { pref: "tls.keylog_file" });
      const path = r.prefs?.["tls.keylog_file"]?.s;
      if (path && !this.state.tlsKeylog) this.set({ tlsKeylog: path });
    } catch {
      // older sharkd without dumpconf
    }
  }

  /** Decrypts TLS with a key log file (null turns it off) and re-dissects the open capture. */
  async setTlsKeylog(path: string | null): Promise<void> {
    if (path !== null) {
      const st = statSync(path, { throwIfNoEntry: false });
      if (!st?.isFile()) throw new Error(`no such file: ${path}`);
    }
    await Promise.all(this.engines.map((e) => e.setPref("tls.keylog_file", path ?? "")));
    this.set({ tlsKeylog: path });
    if (this.state.file) await this.reload(true);
  }

  /** Writes a subset of the open capture to a new file, like Wireshark's Export Specified Packets. */
  async exportPackets(req: ExportRequest & { filter?: string }, by: "user" | "agent"): Promise<ExportResult> {
    this.requireFile();
    const input = this.state.file!;
    const format = checkTarget(String(req.path ?? ""), [input, ...this.capture.state.files], !!req.overwrite);
    // Always explicit frames: a live capture may have written more than the view knows
    const everything: Ranges = this.state.totalFrames ? [[1, this.state.totalFrames]] : [];
    let ranges: Ranges;
    if (req.filter !== undefined) {
      const check = await this.checkFilter(req.filter);
      if (!check.ok) throw new Error(`invalid display filter: ${check.error}`);
      ranges = req.filter.trim() ? toRanges(await this.matchingFrames(this.engine, req.filter.trim())) : everything;
    } else if (req.which === "all") ranges = everything;
    else if (req.which === "displayed") ranges = this.displayed ? toRanges(this.displayed) : everything;
    else if (req.which === "marked") ranges = toRanges(this.state.marks.map((m) => m.frame));
    else if (req.which === "selected") ranges = this.selectedOrCurrent();
    else if (req.which === "range") ranges = parseRange(String(req.range ?? ""), this.state.totalFrames);
    else throw new Error(`unknown selection "${req.which}"`);
    if (!ranges.length) throw new Error("no packets to export");
    const frames = countRanges(ranges);
    const size = await exportFrames({ editcap: this.editcap, mergecap: this.mergecap, input, output: req.path, format, ranges });
    if (by === "agent") this.notice(`Exported ${frames} packet${frames === 1 ? "" : "s"} to ${req.path}`);
    return { path: req.path, frames, size };
  }

  async follow(proto: string, filter: string, limit = FOLLOW_LIMIT): Promise<FollowResult> {
    this.requireFile();
    const r = await this.engine.call<{
      shost: string;
      sport: string;
      chost: string;
      cport: string;
      payloads?: { n: number; d: string; s?: number }[];
    }>("follow", { follow: proto, filter });
    if (r.shost === "NONE" && r.chost === "NONE" && !r.payloads?.length) throw new Error(`no ${proto} stream matches ${filter}`);
    const payloads: FollowResult["payloads"] = [];
    let total = 0;
    let omittedBytes = 0;
    let serverBytes = 0;
    let clientBytes = 0;
    for (const p of r.payloads ?? []) {
      const data = Buffer.from(p.d, "base64");
      if (p.s) serverBytes += data.length;
      else clientBytes += data.length;
      const room = limit - total;
      if (room <= 0) {
        omittedBytes += data.length;
        continue;
      }
      const part = data.length > room ? data.subarray(0, room) : data;
      omittedBytes += data.length - part.length;
      total += part.length;
      payloads.push({ frame: p.n, server: !!p.s, data: part === data ? p.d : part.toString("base64") });
    }
    return {
      proto,
      filter,
      server: { host: r.shost, port: r.sport, bytes: serverBytes },
      client: { host: r.chost, port: r.cport, bytes: clientBytes },
      payloads,
      truncated: omittedBytes > 0,
      omittedBytes,
    };
  }

  async openInWireshark(frame?: number | null): Promise<void> {
    this.requireFile();
    if (!this.wiresharkBin) throw new Error("wireshark was not found on PATH");
    const args = ["-r", this.state.file!];
    if (this.profile) args.push("-C", this.profile);
    if (this.state.tlsKeylog) args.push("-o", `tls.keylog_file:${this.state.tlsKeylog}`);
    if (this.state.filter) args.push("-Y", this.state.filter);
    const target = frame ?? this.state.selected;
    if (target) args.push("-g", String(target));
    await launchWireshark(this.wiresharkBin, args);
  }

  private remember(file: string): void {
    const i = this.recent.indexOf(file);
    if (i >= 0) this.recent.splice(i, 1);
    this.recent.unshift(file);
    this.recent.length = Math.min(this.recent.length, 20);
  }

  private requireFile(): void {
    if (!this.state.file) throw new Error("no capture is open");
  }

  shutdown(): void {
    this.capture.stop();
    this.capture.stopActivity();
    for (const e of this.engines) e.close();
  }
}

/** sharkd custom columns: column0..N as "<field>:0" (all occurrences). */
function columnParams(fields: string[]): Record<string, string> {
  return Object.fromEntries(fields.map((f, i) => [`column${i}`, `${f}:0`]));
}

function clip(value: string): string {
  return value.length > MAX_COLUMN_VALUE ? value.slice(0, MAX_COLUMN_VALUE - 1) + "…" : value;
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

/** sharkd rejects skip: 0, so leave it out. */
function page(skip: number, limit: number): Record<string, unknown> {
  return skip > 0 ? { skip, limit } : { limit };
}

/** The row at `index` alone, or no rows for -1. */
function rowOf(index: number): Ranges {
  return index >= 0 ? [[index, index]] : [];
}

function rowSelection(rows: Ranges): Pick<ViewState, "selectedRows" | "selectedCount"> {
  return { selectedRows: rows, selectedCount: countRanges(rows) };
}

/** Cuts merged `ranges` to 0..n-1. */
function clipRanges(ranges: Ranges, n: number): Ranges {
  return ranges.filter(([a]) => a < n).map(([a, b]) => [a, Math.min(b, n - 1)]);
}

/** Whether every row of `before` shows the same frame in `after` (a growing live capture). */
function appendedOnly(before: Int32Array | null, after: Int32Array | null): boolean {
  if (!before || !after) return !before && !after;
  if (after.length < before.length) return false;
  for (let i = 0; i < before.length; i++) if (before[i] !== after[i]) return false;
  return true;
}

export const CAPTURE_FILE = /\.(pcapng|pcap|cap|ntar|erf|snoop|trc|dmp)(\.(gz|zst|lz4))?$/i;

/** pcap, pcapng, and gzip/zstd/lz4-compressed files, by magic number */
const CAPTURE_MAGIC = ["a1b2c3d4", "d4c3b2a1", "a1b23c4d", "4d3cb2a1", "0a0d0d0a", "1f8b", "28b52ffd", "04224d18"];

/** Keeps open() to capture files, so it can't be used to read arbitrary files. */
function looksLikeCapture(file: string): boolean {
  if (CAPTURE_FILE.test(file)) return true;
  const head = Buffer.alloc(4);
  let fd: number | undefined;
  try {
    fd = openSync(file, "r");
    readSync(fd, head, 0, 4, 0);
  } catch {
    return false;
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
  const hex = head.toString("hex");
  return CAPTURE_MAGIC.some((m) => hex.startsWith(m));
}

function safeSize(file: string): number {
  return statSync(file, { throwIfNoEntry: false })?.size ?? -1;
}

/** Points out capture-filter (BPF) syntax used where a display filter belongs. */
export function bpfHint(filter: string): string {
  const m = /^\s*(?:(tcp|udp)\s+)?(?:(src|dst)\s+)?(port|host|net)\s+(\S+)/i.exec(filter);
  if (!m) return "";
  const [, l4, dir, kind, value] = m;
  let suggestion: string;
  if (kind.toLowerCase() === "port") suggestion = `${l4 ? l4.toLowerCase() : "tcp"}.${dir ? dir.toLowerCase() : ""}port == ${value}`;
  else if (kind.toLowerCase() === "host") suggestion = `ip.${dir ? dir.toLowerCase() : "addr"} == ${value}`;
  else suggestion = `ip.addr == ${value}`;
  return ` (this looks like capture-filter syntax; as a display filter try: ${suggestion})`;
}
