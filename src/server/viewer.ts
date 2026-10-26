import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { EventEmitter } from "node:events";
import { closeSync, openSync, readSync, statSync } from "node:fs";
import { Sharkd, SharkdError } from "./sharkd.ts";
import { Capture } from "./capture.ts";
import type {
  ConvRow,
  EndpointRow,
  FilterCheck,
  FollowResult,
  FrameDetail,
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
const MAX_NOTE = 200;

/**
 * Everything the UI and the agent share: the open capture, display filter,
 * selection, marks and the live capture. Emits "state" on every change.
 *
 * Two sharkd instances alternate during a live capture: one answers queries
 * while the other reloads the growing file, then they swap.
 */
export class Viewer extends EventEmitter {
  private engines: [Sharkd, Sharkd];
  private active = 0;
  /** Frame numbers matching the filter; null means all frames 1..totalFrames. */
  private displayed: Int32Array | null = null;
  private mutation: Promise<unknown> = Promise.resolve();
  private reloadTimer: NodeJS.Timeout | null = null;
  private loadedSize = -1;
  private noticeId = 0;
  private readonly wiresharkBin: string | null;
  private readonly profile: string | undefined;
  readonly capture: Capture;
  readonly recent: string[] = [];

  state: ViewState;

  constructor(opts: { captureDir: string; sharkd?: string; dumpcap?: string; wireshark?: string | null; profile?: string }) {
    super();
    this.engines = [new Sharkd(opts.sharkd, opts.profile), new Sharkd(opts.sharkd, opts.profile)];
    this.profile = opts.profile;
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
      marks: [],
      capture: this.capture.state,
      agentNotice: null,
      wiresharkAvailable: !!this.wiresharkBin,
    };
    this.capture.on("change", (capture) => this.set({ capture }));
    this.capture.on("file", (file: string) => {
      // A new capture takes over the view; later ring files only if the view still follows it
      const files = this.capture.state.files;
      if (files.length > 1 && !this.followingCapture(files[files.length - 2])) return;
      this.open(file).catch((err) => this.emit("toast", "error", `live view: ${(err as Error).message}`));
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
    this.displayed = displayed;
    const totalFrames = status.frames;
    const selected = keepSelection && this.state.selected !== null && this.state.selected <= totalFrames ? this.state.selected : null;
    this.state = {
      ...this.state,
      file,
      fileSize: status.filesize ?? safeSize(file),
      loading: false,
      loadError: null,
      columns: status.columns,
      totalFrames,
      displayedFrames: displayed ? displayed.length : totalFrames,
      duration: status.duration ?? 0,
      filter,
      selected,
      selectedBy: selected === null ? null : this.state.selectedBy,
      generation: this.state.generation + 1,
    };
    this.set({ selectedIndex: this.indexOf(selected) });
  }

  /**
   * Opens a capture in the standby engine and swaps on success; on failure the
   * current view stays as it was.
   */
  open(file: string): Promise<void> {
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
        this.emit("toast", "error", `live reload: ${(err as Error).message}`);
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
        marks: [],
        generation: this.state.generation + 1,
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
        this.set({ selectedIndex: this.indexOf(this.state.selected) });
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
    const rows = await engine.call<PacketRow[]>("frames", params);
    if (generation !== this.state.generation) throw new StaleGenerationError("stale generation");
    return { generation, start, rows: rows.map(({ num, c, bg, fg }) => ({ num, c, bg, fg })) };
  }

  /** Summary row of one frame, regardless of the display filter. */
  async row(num: number): Promise<PacketRow | null> {
    if (num < 1 || num > this.state.totalFrames) return null;
    const rows = await this.engine.call<PacketRow[]>("frames", page(num - 1, 1));
    const r = rows[0];
    return r && r.num === num ? { num: r.num, c: r.c, bg: r.bg, fg: r.fg } : null;
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
    const rows = await this.engine.call<PacketRow[]>("frames", params);
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

  select(frame: number | null, by: "user" | "agent"): void {
    if (frame !== null && (!Number.isInteger(frame) || frame < 1 || frame > this.state.totalFrames)) {
      throw new Error(`no frame ${frame}`);
    }
    this.set({
      selected: frame,
      selectedIndex: this.indexOf(frame),
      selectedBy: frame === null ? null : by,
      selectSeq: by === "agent" ? this.state.selectSeq + 1 : this.state.selectSeq,
    });
    if (by === "agent" && frame !== null) {
      const hidden = this.state.selectedIndex < 0 ? " (hidden by the current display filter)" : "";
      this.notice(`Selected frame ${frame}${hidden}`);
    }
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

  notice(text: string): void {
    this.set({ agentNotice: { id: ++this.noticeId, text, at: Date.now() } });
  }

  async phs(): Promise<PhsNode[]> {
    this.requireFile();
    const r = await this.engine.call<{ taps: { protos: SharkdPhs[] }[] }>("tap", { tap0: "phs" });
    const map = (p: SharkdPhs): PhsNode => ({
      proto: p.proto,
      frames: p.frames,
      bytes: p.bytes,
      children: (p.protos ?? []).map(map),
    });
    return (r.taps[0]?.protos ?? []).map(map);
  }

  async conversations(type: ConvType): Promise<ConvRow[]> {
    this.requireFile();
    const r = await this.engine.call<{ taps: { convs?: Record<string, never>[] }[] }>("tap", {
      tap0: `conv:${CONV_TAPS[type]}`,
    });
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

  async endpoints(type: ConvType): Promise<EndpointRow[]> {
    this.requireFile();
    const r = await this.engine.call<{ taps: { hosts?: Record<string, never>[] }[] }>("tap", {
      tap0: `endpt:${CONV_TAPS[type]}`,
    });
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

  async expert(): Promise<{ frame: number; severity: string; group: string; protocol: string; message: string }[]> {
    this.requireFile();
    const r = await this.engine.call<{ taps: { details?: { f: number; s: string; g: string; p: string; m: string }[] }[] }>(
      "tap",
      { tap0: "expert" },
    );
    return (r.taps[0]?.details ?? []).map((d) => ({ frame: d.f, severity: d.s, group: d.g, protocol: d.p, message: d.m }));
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

  openInWireshark(frame?: number | null): void {
    this.requireFile();
    if (!this.wiresharkBin) throw new Error("wireshark was not found on PATH");
    const args = ["-r", this.state.file!];
    if (this.profile) args.push("-C", this.profile);
    if (this.state.filter) args.push("-Y", this.state.filter);
    const target = frame ?? this.state.selected;
    if (target) args.push("-g", String(target));
    spawn(this.wiresharkBin, args, { detached: true, stdio: "ignore" }).unref();
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
    for (const e of this.engines) e.close();
  }
}

/** sharkd rejects skip: 0, so leave it out. */
function page(skip: number, limit: number): Record<string, unknown> {
  return skip > 0 ? { skip, limit } : { limit };
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
