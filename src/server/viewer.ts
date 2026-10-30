import { createHash, randomBytes } from "node:crypto";
import { EventEmitter } from "node:events";
import { closeSync, createReadStream, openSync, readFileSync, readSync, statSync } from "node:fs";
import { basename, dirname, resolve } from "node:path";
import type { Transform } from "node:stream";
import { createGunzip, createZstdDecompress } from "node:zlib";
import { matchingFrames, Sharkd, SharkdError, SharkdExit, type LuaError, type LuaReport } from "./sharkd.ts";
import { Capture } from "./capture.ts";
import { applyChange, closeMatches, countFilter, parseChange, parseStatus, serialize, type EntryStatus } from "./decodeas.ts";
import { checkTarget, exportFrames, parseRange, toRanges, type FrameComments } from "./export.ts";
import { EventLog, ReportedError } from "./events.ts";
import { Extensions } from "./extensions.ts";
import { FT_FRAMENUM, heldReason, LiveTail, removeStaleSlices, streamNumbered, Superseded, type Numbering, type RowView } from "./livetail.ts";
import { ApiError, FrameSet, PanelData, type PanelSource } from "./paneldata.ts";
import { newObjectFolder, objectDir, objectFileName, writeObject, type CapturedObject, type ObjectKind } from "./objects.ts";
import { Panels } from "./panels.ts";
import { printable } from "./text.ts";
import { changeText, framesWithRefs, MAX_TIME_REFS, refBefore, refsOf, refsUpTo, refTimeError, refTimeFilter, usesRefTime, type RowRefs } from "./timerefs.ts";
import { launchWireshark } from "./wireshark.ts";
import { entryText } from "../shared/decodeas.ts";
import { countRanges, framesFilter, inRanges, mergeRanges, type Ranges } from "../shared/ranges.ts";
import type {
  AskResult,
  ConvRow,
  CaptureState,
  CustomColumn,
  DecodeAsResult,
  EndpointRow,
  ExpertItem,
  ExtensionList,
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
  PanelAct,
  PanelOffer,
  PanelView,
  PhsNode,
  ProvisionalTail,
  RowsResponse,
  TimeRefsChange,
  TreeNode,
  ViewState,
} from "../shared/api.ts";

/** How a load got past a sharkd crash: back to the extensions before their last change, or without any. */
type RollBack = false | "reverted" | "suspended";

/** What extensions(action "test") found. */
export interface ExtensionTest {
  name: string;
  /** Switched on for the user's view. */
  enabled: boolean;
  /** "loaded", or why not. */
  load: string;
  protocols: { name: string; frames: number; first: number | null; error?: string }[];
  /** First frame of the first matching protocol, dissected with the extension. */
  sample: { frame: number; protocol: string; tree: TreeNode[] } | null;
  luaErrors: { frame: number; message: string }[];
  luaErrorCount: number;
  /** The capture tested against, or null when none is open. */
  file: string | null;
  /** sharkd died while dissecting. */
  crashed?: string;
  /** For an extension without a protocol of its own: the capture's protocols with it, deepest first. */
  hierarchy: string[];
}

export class StaleGenerationError extends Error {}

interface SharkdStatus {
  frames: number;
  duration?: number;
  filesize?: number;
  columns: string[];
  /** Column formats: %m the number, %i Info, %Cus:<field>:... a field. */
  column_info?: { format: string }[];
}

/** A sharkd "frames" row: commented packets carry their comments. */
type SharkdRow = PacketRow & { comments?: string[] };

/**
 * A packet's comments as edited in the viewer, in place of the file's: the
 * first `own` of `list` are the file's own ones, all of them, unchanged (-1:
 * they aren't).
 */
interface EditedComments {
  list: string[];
  own: number;
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
/** Largest object Export Objects saves (sharkd sends it as base64 JSON). */
const MAX_OBJECT_SAVE = 128 * 1024 * 1024;
/** Bytes one save of objects may write. */
const MAX_OBJECTS_SAVE = 1024 * 1024 * 1024;
const LIVE_RELOAD_MS = 1000;
const MAX_MARKS = 10000;
/** Between two Wireshark launches. */
const WIRESHARK_GAP_MS = 2000;
/** Row ranges a selection may consist of. */
const MAX_ROW_RANGES = 10000;
const MAX_NOTE = 200;
/** Packets whose comments the viewer holds edited. */
const MAX_COMMENTED = 10_000;
const MAX_COMMENT = 2000;
/** Lines of a comment the details list, as Wireshark's frame.max_comment_lines. */
const COMMENT_LINES = 30;
/** Ranges of frames whose comments are read one by one, however big the capture. */
const COMMENT_READS = 20;
/** Frames a search for the commented ones costs about as much as reading one range's comments. */
const COMMENT_READ_FRAMES = 100;
/** Comments the list's rows carry, and characters of each. */
const ROW_COMMENTS = 5;
const ROW_COMMENT = 300;
/** Wireshark's longest item label, in bytes. */
const ITEM_LABEL_LENGTH = 240;
const MAX_QUESTION = 2000;
/** Longest frame set a question to the agent lists. */
const MAX_QUESTION_FRAMES = 2000;
const MAX_CUSTOM_COLUMNS = 10;
/** Longer custom column values (e.g. whole payloads) are cut to this. */
const MAX_COLUMN_VALUE = 500;
const MAX_IO_BUCKETS = 4000;
/** sharkd computes the interval in 32-bit microseconds; larger intervals overflow. */
const MAX_IO_INTERVAL = 2_000_000;
const MAX_IO_BUCKETS_HARD = 100_000;
const MAX_IO_GRAPHS = 4;
const FIELD_NAME = /^[A-Za-z0-9_][A-Za-z0-9_.-]*$/;
/** Loads tried again after extensions crashed sharkd (each crash switches one off). */
const MAX_CRASH_RETRIES = 10;
/** How long requests in flight may finish before their sharkd restarts with new extensions. */
const RESTART_WAIT_MS = 10_000;
/** Live reloads that fail in a row before they pause. */
const MAX_LIVE_FAILURES = 3;
/** Once a live full read takes this long, newer packets are listed provisionally until it lands. */
const TAIL_AFTER_MS = 1000;
/** What a sharkd holds before it reads a file. */
const SHARKD_BASE_BYTES = 160 * 1024 * 1024;
/** Memory a full read must leave free. */
const MEMORY_MARGIN = 512 * 1024 * 1024;
/** Between two reports of failing provisional rows. */
const TAIL_PROBLEM_MS = 60_000;
/** Provisional rows, details or filter passes that fail in a row before the tail is turned off. */
const MAX_TAIL_FAILURES = 3;
/** Most new provisional rows read before the list shows them: what a page request asks for at most. */
const WARM_ROWS = 500;
/** How long after a client last asked for the list's newest rows the rows it gains are still read ahead. */
const FOLLOWED_MS = 3000;
/** How often unmatched panel offers are checked again during a live capture. */
const OFFER_LIVE_MS = 30_000;
/** The prelude's preferences for the Decode As entries, and for how applying them went. */
const DECODE_AS = "wirebuddy.decode_as";
const DECODE_AS_STATUS = "wirebuddy.decode_as_status";

/**
 * Everything the UI and the agent share: the open capture, display filter,
 * selection, marks, time references and the live capture. Emits "state" on
 * every change.
 *
 * Two sharkd instances alternate during a live capture: one answers queries
 * while the other reloads the growing file, then they swap. Once such a full
 * read takes a second or more, the packets that arrived after it are listed
 * provisionally from slices of the file (LiveTail) until the next one lands.
 */
export class Viewer extends EventEmitter {
  private engines: [Sharkd, Sharkd];
  /** Files the agent exported in this session: the only ones it may overwrite. */
  private readonly agentExports = new Set<string>();
  private wiresharkAt = 0;
  /** Lua dissector extensions sharkd and Wireshark load. */
  readonly extensions: Extensions;
  /** Preferences WireBuddy set for dissection (TLS key log, Decode As), for every sharkd; one turned off holds "". */
  private readonly dissectPrefs = new Map<string, string>();
  /** Extensions' panels open in the UI. */
  readonly panels: Panels;
  /** The sharkd panels read the capture with. */
  private readonly panelData: PanelData;
  /** Why the epoch changed last, for the panels' reset. */
  private epochWhy = "file";
  /** Panel offers for the open file: matched ones (with their filter), invalid filters, dismissed ones. */
  private offerFile: string | null = null;
  private readonly offerMatched = new Map<string, { offer: PanelOffer; filter: string }>();
  private readonly offerErrors = new Map<string, { filter: string; error: string }>();
  private readonly offerDismissed = new Set<string>();
  private offerSeq = 0;
  private offerRun: Promise<void> = Promise.resolve();
  private offerTimer: NodeJS.Timeout | null = null;
  /** Offer filters that matched no packet of the file up to a frame, for the file and epoch they were checked with. */
  private offerChecked = { file: "", epoch: -1, to: new Map<string, number>() };
  /** Inode and first bytes of the file read last: another file at the same path, or other first bytes, is a rewritten capture. */
  private loadedIno = 0;
  private loadedHead: Buffer = Buffer.alloc(0);
  /** sharkd starts an extension crashed; a load is retried after each. */
  private extensionCrashes = 0;
  /** Lua errors the extensions reported for the open file, told to the agent in batches. */
  private luaErrs = { file: "", frames: new Set<number>(), more: false, told: 0, example: null as LuaError | null, timer: null as NodeJS.Timeout | null, since: 0 };
  private readonly sharkdBin: string;
  /** Problems and user activity for the agent. */
  readonly events = new EventLog(
    (pending) => this.set({ agent: { ...this.state.agent, pending } }),
    (watching) => this.set({ agent: { ...this.state.agent, watching } }),
  );
  private active = 0;
  /** Frame numbers matching the filter; null means all frames 1..totalFrames. */
  private displayed: Int32Array | null = null;
  private mutation: Promise<unknown> = Promise.resolve();
  private reloadTimer: NodeJS.Timeout | null = null;
  private liveFailures = 0;
  private loadedSize = -1;
  private noticeId = 0;
  private readonly wiresharkBin: string | null;
  private readonly profile: string | undefined;
  private readonly editcap: string;
  private readonly mergecap: string;
  /** Columns sharkd reports for the open file, before custom ones. */
  private baseColumns: string[] = [];
  /** Their formats (%m the number, %i Info). */
  private columnFormats: string[] = [];
  /** sharkd ftypes of fields, null when unknown; as the extensions of `typesSeq` define them. */
  private readonly fieldTypes = new Map<string, number | null>();
  private typesSeq = 0;
  /** The live capture's packets after the last full read, listed from slices once it is active. */
  private tail: LiveTail | null = null;
  private tailTimer: NodeJS.Timeout | null = null;
  private tailBusy = false;
  /** The capture stopped during a tail tick: one more takes its last packets. */
  private tailLast = false;
  /** When a client last asked for the list's newest rows. */
  private newestAskedAt = 0;
  private tailFiltering = false;
  /** A filter pass was asked for while one ran: the running one goes on. */
  private filterAgain = false;
  /** The full read after the capture stopped is queued or running. */
  private finalRead = false;
  /** A live file whose tail was turned off: it gets none again. */
  private tailOff: string | null = null;
  private tailProblemAt = 0;
  /** When the full read in flight started, 0 for none. */
  private readStartedAt = 0;
  /** How long the last full read took. */
  private lastReadMs = 0;
  /** Full reads applied: the active engine's answers are of this one. */
  private loads = 0;
  /** Why live full reads wait, or null. */
  private paused: string | null = null;
  /** Why the last full read failed while nothing would read the file again by itself: newer packets stay provisional until one succeeds. */
  private readFailed: string | null = null;
  /** Marks, time references and the selection on frames up to here stay although the tail that listed them closed. */
  private keptFrames = 0;
  /** Provisional rows, details or filter passes that failed in a row. */
  private tailFailures = 0;
  /** Packet comments edited in the viewer, by frame: they stand for the file's. */
  private readonly comments = new Map<number, EditedComments>();
  /** Frames up to this one lost the file's comments (Delete All Packet Comments), unless edited since. */
  private cleared = 0;
  /** The frames that had comments then. */
  private clearedFrames = new Int32Array(0);
  /** The edit that cleared them, until every packet was exported to pcapng since; else 0. */
  private clearedEdit = 0;
  /** Frames changed since every packet was last exported to pcapng, with the edit that changed them last. */
  private readonly unexported = new Map<number, number>();
  private commentEdit = 0;
  /** Edits of comments run one at a time, each from what the frames have then. */
  private commenting: Promise<unknown> = Promise.resolve();
  /** Changes when the edited comments go with their file: edits read before go too. */
  private commentsFile = 0;
  /** sharkd's etts of comment nodes, for the ones made here; others until it showed some. */
  private readonly commentEtts = { node: -1, item: -2 };
  /** Frames of the file with comments, as the full read `loads` found them. */
  private commentedFrames: { loads: number; frames: Int32Array } | null = null;
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
    extensions?: Extensions;
    /** Where the panels' bridge and base style are built (dist/panel). */
    panelRuntime?: string;
  }) {
    super();
    this.extensions = opts.extensions ?? new Extensions();
    this.panels = new Panels(this.extensions, this.events, opts.panelRuntime ?? "");
    this.panels.on("change", () => {
      this.set({ panels: this.panels.list() });
      this.showOffers();
    });
    this.sharkdBin = opts.sharkd ?? "sharkd";
    const env = () => this.extensions.env();
    const generation = () => this.extensions.generation;
    this.engines = [new Sharkd(this.sharkdBin, opts.profile, env, generation), new Sharkd(this.sharkdBin, opts.profile, env, generation)];
    for (const e of this.engines) {
      e.onFailure = (message) => {
        // A dissector that crashes sharkd crashes every respawn that reads the same packets; a kill (memory) is no crash
        const crashed = message.startsWith("sharkd exited") && !message.startsWith("sharkd exited (SIGKILL)");
        const hint = this.extensions.any() && crashed ? " — if this repeats, an extension may crash it: test them with extensions(action \"test\") and disable the culprit" : "";
        this.events.add("WARNING", printable(message) + hint);
      };
      e.onLua = (report) => this.luaReport(report);
      e.onLuaError = (error) => this.luaError(error);
    }
    const source: PanelSource = {
      view: () => this.panelView(),
      epoch: () => this.state.epoch,
      resetWhy: () => this.epochWhy,
      file: () => this.state.file,
      live: () => this.followingCapture() && this.capture.running,
      totalFrames: () => this.state.totalFrames,
      displayed: () => ({
        set: this.panelSet("displayed", [this.displayed, this.state.totalFrames], () => (this.displayed ? FrameSet.fromSorted(this.displayed) : FrameSet.all(this.state.totalFrames))),
        filter: this.sharkdFilter(this.state.filter),
      }),
      selected: () => {
        const s = this.state;
        return this.panelSet("selected", [s.selectedRows, s.selected, this.displayed, s.displayedFrames], () =>
          s.selectedCount ? FrameSet.fromRows(clipRanges(s.selectedRows, s.displayedFrames), this.displayed) : FrameSet.fromSorted(s.selected === null ? [] : [s.selected]),
        );
      },
      marked: () => this.panelSet("marked", [this.state.marks], () => FrameSet.fromSorted(this.state.marks.map((m) => m.frame).sort((a, b) => a - b))),
      timeRefs: () => this.state.timeRefs,
      prefs: () => this.dissectPrefs,
      fileId: () => ({ ino: this.loadedIno, head: this.loadedHead }),
    };
    this.panelData = new PanelData({ bin: this.sharkdBin, profile: opts.profile, env, generation, source, events: this.events });
    this.panels.attach(source, this.panelData);
    this.on("state", () => this.panels.viewChanged());
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
      timeRefs: [],
      timeRefsRevision: 0,
      commentEdits: 0,
      commentRevision: 0,
      capture: this.capture.state,
      agentNotice: null,
      agent: { attached: false, pending: 0, name: "Agent", watching: false },
      wiresharkAvailable: !!this.wiresharkBin,
      customColumns: [],
      tlsKeylog: null,
      decodeAs: { entries: [], unavailable: this.extensions.unavailable },
      extensions: { active: 0, failing: 0, revision: 0 },
      panels: [],
      panelOffers: [],
      epoch: 1,
      tail: null,
    };
    this.capture.on("change", (capture: CaptureState) => {
      if (capture.status === "error" && this.state.capture.status !== "error") this.events.add("ERROR", `The capture failed: ${capture.error ?? "unknown error"}`, { iface: capture.iface });
      this.set({ capture });
    });
    this.capture.on("file", (file: string) => {
      // A new capture takes over the view; later ring files only if the view still follows it
      const files = this.capture.state.files;
      if (files.length === 1) removeStaleSlices(dirname(file));
      if (files.length > 1 && !this.followingCapture(files[files.length - 2])) return;
      this.open(file, files.length > 1).catch((err) => this.problem(`Live view: ${(err as Error).message}`));
      this.scheduleReload();
      this.tailTimer ??= setInterval(() => void this.tailTick(), LIVE_RELOAD_MS);
    });
    this.capture.on("stopped", () => {
      if (this.reloadTimer) clearTimeout(this.reloadTimer);
      this.reloadTimer = null;
      if (!this.followingCapture()) return;
      // The last packets show while the final full read runs
      this.finalRead = true;
      void this.tailTick(true);
      this.exclusive(() => this.reloadNow(true, false, false, true))
        .finally(() => {
          this.finalRead = false;
          this.publishTail();
        })
        .then(() => this.checkOffers(false), () => {});
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

  /** Packets read before may read differently now: panels start over. */
  private newEpoch(why: string): number {
    this.epochWhy = why;
    return this.state.epoch + 1;
  }

  /** Frame lists for panels, made again only when what they are of changed. */
  private readonly panelSets = new Map<string, { key: unknown[]; set: FrameSet }>();
  private panelSet(name: string, key: unknown[], make: () => FrameSet): FrameSet {
    const hit = this.panelSets.get(name);
    if (hit && hit.key.every((k, i) => k === key[i])) return hit.set;
    const set = make();
    this.panelSets.set(name, { key, set });
    return set;
  }

  /** What panels see of the view. */
  private panelView(): PanelView {
    const s = this.state;
    // Selections of many rows are left out rather than walked on every change
    const ranges = s.selectedCount > 100_000 ? null : this.selectedOrCurrent();
    return {
      file: s.file ? basename(s.file) : null,
      epoch: s.epoch,
      frames: s.totalFrames,
      displayed: s.displayedFrames,
      filter: s.filter,
      selected: s.selected,
      selection: ranges && ranges.length <= 1000 ? ranges : null,
      marked: s.marks.length,
      timeRefs: s.timeRefs.length,
      live: this.followingCapture() && this.capture.running,
      capture: s.capture.status,
    };
  }

  /** Runs state-changing work one at a time. */
  private exclusive<T>(fn: () => Promise<T>): Promise<T> {
    const next = this.mutation.then(fn, fn);
    this.mutation = next.catch(() => {});
    return next;
  }

  /** The tail when the view lists it. */
  private get listedTail(): LiveTail | null {
    return this.tail?.active ? this.tail : null;
  }

  /** Frames the view knows: read in full, then provisional ones. */
  private known(): number {
    return this.state.totalFrames + (this.listedTail?.frames ?? 0);
  }

  /** Rows of the list: exact ones, then provisional ones. */
  private listLength(): number {
    return this.state.displayedFrames + (this.listedTail?.listed() ?? 0);
  }

  private indexOf(frame: number | null): number {
    if (frame === null) return -1;
    if (frame > this.state.totalFrames) {
      const i = this.listedTail?.indexOf(frame) ?? -1;
      return i < 0 ? -1 : this.state.displayedFrames + i;
    }
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

  /**
   * Loads `file` into `engine` and computes the displayed frames for `filter`
   * (frame.ref_time: the time references `refs`); with `fallback`, a filter
   * that doesn't compile (its protocol is gone) is dropped and the result's
   * `filter` is "". `inPlace`: the engine read the only copy, so a kill
   * (SIGKILL) is the memory running out, not an extension. Without
   * `rollback`, a crash is rethrown at once, not blamed on the extensions.
   */
  private async loadInto(engine: Sharkd, file: string, filter: string, refs: readonly number[], fallback = false, inPlace = false, rollback = true) {
    const memory = (err: unknown): boolean => inPlace && err instanceof SharkdExit && err.signal === "SIGKILL";
    const once = (dropFilter: boolean) =>
      this.crashRetries(async () => {
        await this.current(engine, true);
        const load = await engine.call<{ status: string; err?: number }>("load", { file });
        // A file still being written ends mid-packet; sharkd reports that but keeps what it read.
        if (load.status !== "OK" && load.err !== -12) throw new Error(load.status);
        const status = await engine.call<SharkdStatus>("status");
        if (!filter) return { status, displayed: null, filter, rolledBack: false as RollBack };
        try {
          return { status, displayed: await matchingFrames(engine, refTimeFilter(filter, refs)), filter, rolledBack: false as RollBack };
        } catch (err) {
          if (!(err instanceof SharkdError) || !dropFilter) throw err;
          return { status, displayed: null, filter: "", rolledBack: false as RollBack };
        }
      });
    try {
      return await once(fallback);
    } catch (err) {
      if (!(err instanceof SharkdExit) || !rollback || !this.extensions.any() || memory(err)) throw err;
      // Without the extensions' last change, then without any; if it still dies, they weren't the cause
      const before = this.extensions.saved();
      const steps: [RollBack, () => boolean, string][] = [
        ["reverted", () => this.extensions.revert(), "without the last change to the extensions"],
        ["suspended", () => (this.extensions.suspend(), true), "without extensions until they are reloaded"],
      ];
      for (const [kind, step, how] of steps) {
        if (!step()) continue;
        try {
          // A filter on a protocol that went with the extensions would fail every later reload
          const result = await once(true);
          const cleared = result.filter !== filter ? `; the display filter "${filter}" was cleared` : "";
          this.problem(`sharkd crashed reading ${basename(file)} with the extensions (${printable(err.message)}), so it reads it ${how}${cleared}. Test the extensions to find the one at fault (extensions action "test")`);
          return { ...result, rolledBack: kind };
        } catch (again) {
          if (!(again instanceof SharkdExit) || memory(again)) {
            this.extensions.restore(before);
            throw again;
          }
        }
      }
      this.extensions.restore(before);
      throw err;
    }
  }

  /** Runs `fn` again after each extension that crashed sharkd while loading (it is off then). */
  private async crashRetries<T>(fn: () => Promise<T>): Promise<T> {
    for (let attempt = 0; ; attempt++) {
      const crashes = this.extensionCrashes;
      try {
        return await fn();
      } catch (err) {
        if (this.extensionCrashes === crashes || attempt >= MAX_CRASH_RETRIES) throw err;
      }
    }
  }

  /**
   * Restarts an engine that runs other extensions than the current ones, or
   * (`load`: before it reads a capture) one that would count Cumulative
   * Bytes on from the capture it read before; once its requests are done.
   */
  private async current(engine: Sharkd, load = false): Promise<void> {
    if (!engine.outdated() && !(load && engine.loaded && this.columnFormats.includes("%B"))) return;
    await engine.idle(RESTART_WAIT_MS);
    engine.restart();
  }

  /**
   * Shows what a full read found. `changed`: why packets read differently
   * now (panels start over); `redissected`: TLS keys, Decode As or
   * extensions changed, so the tail checks its filter again (`held`: why it
   * can't now, if typed again); `untrusted`: the tail doesn't line up with
   * the read and goes.
   */
  private applyLoad(
    file: string,
    filter: string,
    { status, displayed }: { status: SharkdStatus; displayed: Int32Array | null },
    keepSelection: boolean,
    { changed = null, redissected = false, untrusted = false, held }: { changed?: string | null; redissected?: boolean; untrusted?: boolean; held?: string | null } = {},
  ): void {
    // Opened, or not just grown: what panels read is outdated
    const why = !keepSelection ? "file" : (changed ?? (status.frames < this.state.totalFrames ? "rewritten" : null));
    const epoch = why ? this.newEpoch(why) : this.state.epoch;
    const before = this.rowFrames();
    if (this.tail && (this.tail.file !== file || why === "rewritten" || untrusted)) this.dropTail();
    this.tail?.rebase(status.frames);
    if (redissected || why === "extensions") this.tail?.setFilter(this.tail.filter, held === undefined ? this.tail.held : held);
    // Read in full after the capture stopped: nothing provisional is left
    if (this.tail && !this.capture.running && this.tail.count <= status.frames) this.dropTail();
    if (!this.listedTail) this.paused = null;
    this.readFailed = null;
    this.displayed = displayed;
    this.baseColumns = status.columns;
    this.columnFormats = (status.column_info ?? []).map((c) => c.format);
    this.loads++;
    const totalFrames = status.frames;
    // Marks, time references and the selection on packets listed before stay until a read covers them
    if (why === "file" || why === "rewritten" || totalFrames >= this.keptFrames) this.keptFrames = 0;
    const known = Math.max(totalFrames + (this.listedTail?.frames ?? 0), this.keptFrames);
    const selected = keepSelection && this.state.selected !== null && this.state.selected <= known ? this.state.selected : null;
    this.state = {
      ...this.state,
      file,
      fileSize: status.filesize ?? safeSize(file),
      loading: false,
      loadError: null,
      columns: [...status.columns, ...this.state.customColumns.map((c) => c.title)],
      totalFrames,
      displayedFrames: displayed ? displayed.length : totalFrames,
      marks: this.state.marks.filter((m) => m.frame <= known),
      timeRefs: refsUpTo(this.state.timeRefs, known),
      ...this.pruneComments(known),
      duration: status.duration ?? 0,
      filter,
      selected,
      selectedBy: selected === null ? null : this.state.selectedBy,
      generation: this.state.generation + 1,
      epoch,
      tail: this.tailState(),
    };
    this.tail?.setRefs(this.state.timeRefs);
    // A shorter file is a rewritten one, filtered or not
    const keepRows = keepSelection && status.frames >= before.exact && startsWith(this.rowFrames(), before);
    const selectedIndex = this.indexOf(selected);
    const rows = keepRows ? clipRanges(this.state.selectedRows, this.listLength()) : rowOf(selectedIndex);
    this.set({ selectedIndex, ...rowSelection(rows), rowsSince: keepRows ? this.state.rowsSince : this.state.generation });
  }

  /** The list's rows as frame numbers, copied: exact rows (of `exact` frames read in full), then provisional ones. */
  private rowFrames(): { exact: number; length: number; at: (i: number) => number } {
    const displayed = this.displayed;
    const n = this.state.displayedFrames;
    const tail = this.listedTail;
    const listed = tail?.listed() ?? 0;
    const matches = tail?.filter ? Int32Array.from({ length: listed }, (_, i) => tail.frameAt(i)) : null;
    const base = this.state.totalFrames;
    return { exact: base, length: n + listed, at: (i) => (i < n ? (displayed ? displayed[i] : i + 1) : matches ? matches[i - n] : base + 1 + i - n) };
  }

  /**
   * Opens a capture in the standby engine and swaps on success; on failure the
   * current view stays as it was. `next`: the live capture went on in this
   * file, nobody asked to discard what was edited in the last one.
   */
  open(file: string, next = false): Promise<void> {
    file = resolve(file);
    return this.exclusive(async () => {
      this.set({ loading: true, loadError: null });
      const standby = 1 - this.active;
      let filter = this.state.filter;
      try {
        const st = statSync(file, { throwIfNoEntry: false });
        if (!st || !st.isFile()) throw new Error(`no such file: ${file}`);
        // A live capture's file may not have its header yet
        if (!this.capture.state.files.includes(file) && !(await looksLikeCapture(file))) throw new Error(`not a capture file: ${file}`);
        // The filter may not apply to this capture's protocols; then it shows everything
        const result = await this.loadInto(this.engines[standby], file, filter, [], true);
        filter = result.filter;
        this.active = standby;
        this.forgetTypes();
        this.lastReadMs = 0;
        this.paused = null;
        this.tailOff = null;
        this.loadedSize = st.size;
        this.loadedIno = st.ino;
        this.loadedHead = fileHead(file);
        const [last, edits] = [this.state.file, this.state.commentEdits];
        this.state = { ...this.state, marks: [], timeRefs: [], ...this.dropComments(), selected: null, selectedBy: null };
        this.applyLoad(file, filter, result, false);
        this.remember(file);
        if (next && last && edits) {
          const text = `The packet comments edited in ${edits} packet${edits === 1 ? "" : "s"} of ${basename(last)} weren't exported and are gone: the capture went on in ${basename(file)}`;
          this.events.add("WARNING", text);
          this.emit("toast", "error", text);
        }
        void this.checkOffers(true);
      } catch (err) {
        const message = printable((err as Error).message);
        this.set({ loading: false, loadError: message.includes(file) ? message : `${file}: ${message}` });
        throw err;
      }
    });
  }

  /** Re-reads the open file into the standby engine, then swaps engines. */
  reload(force = false): Promise<void> {
    return this.exclusive(() => this.reloadNow(force).then(() => {}));
  }

  /**
   * `dropped`: the display filter didn't apply any more (only with
   * `fallback`); `rolledBack`: extensions crashed sharkd. `redissect`: TLS
   * keys, Decode As or extensions changed. `final`: the read after the
   * capture stopped. `rollback`: see loadInto. While full reads wait for
   * memory, the read replaces the active engine's copy if there is no room
   * for a second one.
   */
  private async reloadNow(force: boolean, fallback = false, redissect = false, final = false, rollback = true): Promise<{ dropped: boolean; rolledBack: RollBack }> {
    const file = this.state.file;
    if (!file) return { dropped: false, rolledBack: false };
    const size = safeSize(file);
    if (!force && size === this.loadedSize) return { dropped: false, rolledBack: false };
    const inPlace = await this.readInPlace();
    const target = inPlace ? this.active : 1 - this.active;
    this.readStartedAt = Date.now();
    if (inPlace) {
      const text = `Not enough free memory for a second copy of ${basename(file)}: WireBuddy reads it again in place of the one it has, so the packet list waits until it has`;
      this.events.add("WARNING", text);
      this.emit("toast", "info", text);
      this.set({ loading: true });
      // Requests in flight are answered first
      await this.engines[target].idle(RESTART_WAIT_MS);
      this.engines[target].restart();
    }
    this.publishTail();
    const started = Date.now();
    let result: Awaited<ReturnType<Viewer["loadInto"]>>;
    try {
      result = await this.loadInto(this.engines[target], file, this.state.filter, this.state.timeRefs, fallback, inPlace, rollback);
    } catch (err) {
      this.readStartedAt = 0;
      if (final) this.finalRead = false;
      // The active engine lost its copy, or no full read comes by itself
      if (inPlace || (this.listedTail && !this.capture.running && !this.finalRead)) await this.fullReadFailed(file, err as Error, inPlace);
      throw err;
    } finally {
      this.readStartedAt = 0;
      if (inPlace) this.set({ loading: false });
    }
    if (this.state.file !== file) return { dropped: false, rolledBack: result.rolledBack };
    this.lastReadMs = Date.now() - started;
    const dropped = result.filter !== this.state.filter;
    const ino = statSync(file, { throwIfNoEntry: false })?.ino ?? 0;
    const head = fileHead(file);
    const n = Math.min(head.length, this.loadedHead.length);
    const rewritten = ino !== this.loadedIno || !head.subarray(0, n).equals(this.loadedHead.subarray(0, n));
    // Other extensions: fields may hold frame numbers now, or no longer
    const held = redissect || result.rolledBack ? await this.retype(this.engines[target], result.status, result.filter) : undefined;
    const untrusted = !rewritten && !(await this.checkTail(this.engines[target], file, result));
    if (this.state.file !== file) return { dropped: false, rolledBack: result.rolledBack };
    this.active = target;
    this.loadedSize = size;
    // Read without some extensions now: packets dissect differently
    this.applyLoad(file, result.filter, result, true, { changed: result.rolledBack ? "extensions" : rewritten ? "rewritten" : null, redissected: redissect, untrusted, held });
    this.loadedIno = ino;
    this.loadedHead = head;
    if (redissect || result.rolledBack) void this.filterTail();
    if (result.rolledBack) {
      this.set({ extensions: { ...this.state.extensions, revision: this.state.extensions.revision + 1 } });
      this.refreshExtensions();
    }
    return { dropped, rolledBack: result.rolledBack };
  }

  /**
   * Whether a full read must replace the active engine's copy: full reads
   * wait for memory, or would need to, and even without the standby's copy
   * there is no room for another one.
   */
  private async readInPlace(): Promise<boolean> {
    if (!this.paused && !(this.listedTail && this.memoryShort())) return false;
    // A standby holds on to the memory of its last read until it restarts
    const standby = this.engines[1 - this.active];
    await standby.idle(RESTART_WAIT_MS);
    standby.restart();
    return this.memoryShort();
  }

  /**
   * A full read failed in place, or with none to come by itself (the
   * capture has stopped and its final read is done). Newer packets stay
   * provisional, and live full reads wait, until a read succeeds (View ›
   * Reload, or the capture's end). In place, the active engine holds
   * nothing of the file now and mustn't read it again by itself: the view
   * lists all of its packets provisionally from slices.
   */
  private async fullReadFailed(file: string, err: Error, inPlace: boolean): Promise<void> {
    if (inPlace) this.engine.forgetFile();
    // The packets the capture wrote last, too
    await this.listedTail?.update();
    if (this.state.file !== file) return;
    const tail = this.listedTail;
    this.readFailed = `reading ${basename(file)} in full failed (${printable(err.message)})${inPlace ? ", perhaps for lack of memory" : ""}`;
    this.paused = this.readFailed;
    const listed = !tail ? "" : inPlace || !this.state.totalFrames ? "; its packets are listed provisionally from slices of the file" : "; its newer packets stay provisional";
    // A read in place failed ahead of the capture's final one
    const retry = this.finalRead ? "The full read after the capture's end tries again" : "View › Reload tries again";
    const loadError = `${this.readFailed[0].toUpperCase()}${this.readFailed.slice(1)}${listed}. ${retry}`;
    if (!inPlace) {
      this.set({ loadError, tail: this.tailState() });
      this.events.add("ERROR", loadError);
      return;
    }
    tail?.rebase(0);
    this.displayed = this.state.filter ? new Int32Array(0) : null;
    this.loads++;
    const known = tail?.count ?? 0;
    const selected = this.state.selected !== null && this.state.selected <= known ? this.state.selected : null;
    const generation = this.state.generation + 1;
    this.state = {
      ...this.state,
      loading: false,
      loadError,
      totalFrames: 0,
      displayedFrames: 0,
      marks: this.state.marks.filter((m) => m.frame <= known),
      timeRefs: refsUpTo(this.state.timeRefs, known),
      ...this.pruneComments(known),
      selected,
      selectedBy: selected === null ? null : this.state.selectedBy,
      generation,
      rowsSince: generation,
      tail: this.tailState(),
    };
    tail?.setRefs(this.state.timeRefs);
    const selectedIndex = this.indexOf(selected);
    this.set({ selectedIndex, ...rowSelection(rowOf(selectedIndex)) });
    this.events.add("ERROR", loadError);
    void this.filterTail();
  }

  private scheduleReload(): void {
    if (this.reloadTimer) clearTimeout(this.reloadTimer);
    this.reloadTimer = setTimeout(async () => {
      try {
        if (this.followingCapture() && !this.waitForMemory()) await this.reload();
        this.liveFailures = 0;
      } catch (err) {
        // Once, not every second; after a few in a row the live view waits for the capture's end
        const n = ++this.liveFailures;
        if (n === 1) this.problem(`Live reload: ${printable((err as Error).message)}`);
        if (n >= MAX_LIVE_FAILURES) {
          this.problem(`The live view stopped updating after ${n} failed reloads; it reloads once the capture stops (or with View › Reload)`);
          this.reloadTimer = null;
          return;
        }
      }
      if (this.capture.running) this.scheduleReload();
      else this.reloadTimer = null;
    }, LIVE_RELOAD_MS);
  }

  /**
   * While the provisional tail is listed: whether another full read would
   * need more memory than is free. Then live full reads wait (the tail keeps
   * the list current) until there is, or the capture stops.
   */
  private waitForMemory(): boolean {
    const was = this.paused;
    this.paused = this.listedTail ? (this.readFailed ?? (this.memoryShort() ? "not enough free memory for another full read" : null)) : null;
    if (this.paused && !was) this.events.add("WARNING", `Live view: full reads of ${basename(this.state.file ?? "")} wait: ${this.paused}; newer packets stay provisional until the capture stops (a ring buffer keeps files small)`);
    if (this.paused !== was) this.publishTail();
    return this.paused !== null;
  }

  /** Whether sharkd reading the live file again would need more memory than is free, judged by what the active one needs per frame. */
  private memoryShort(): boolean {
    const activeBytes = rssBytes(this.engine.pid);
    const available = availableBytes();
    if (activeBytes === null || available === null) return false;
    return memoryShort({
      activeBytes,
      frames: this.state.totalFrames,
      standbyBytes: rssBytes(this.engines[1 - this.active].pid) ?? 0,
      next: Math.max(this.tail?.count ?? 0, this.state.totalFrames),
      available,
    });
  }

  /**
   * Indexes what the live file gained, and once full reads have become slow
   * lists the packets after the last one; with a display filter, checks them
   * against it. `last`: the capture stopped; a tick under way runs once more.
   */
  private async tailTick(last = false): Promise<void> {
    if (this.tailBusy) {
      this.tailLast ||= last;
      return;
    }
    this.tailBusy = true;
    try {
      const file = this.state.file;
      if (!file || !this.followingCapture() || file === this.tailOff) return this.closeTail();
      if (this.tail && this.tail.file !== file) this.closeTail();
      if (!this.tail) this.tailFailures = 0;
      const tail = (this.tail ??= new LiveTail({ file, dir: dirname(file), sharkd: () => this.tailEngine() }));
      tail.setRefs(this.state.timeRefs);
      await tail.update();
      if (this.tail !== tail) return;
      const broken = tail.broken();
      if (broken) {
        if (tail.active) this.events.add("WARNING", `Live view: newer packets of ${basename(file)} are listed only once read in full: ${broken}`);
        this.tailOff = file;
        // Their numbers still name the same packets, unless the file changed
        return this.closeTail(tail.store.changed ? this.state.totalFrames : tail.count);
      }
      const slow = this.lastReadMs >= TAIL_AFTER_MS || (this.readStartedAt > 0 && Date.now() - this.readStartedAt >= TAIL_AFTER_MS);
      if (!tail.active && slow && this.capture.running) {
        const filter = this.state.filter;
        const held = await this.heldReason(filter);
        // Another filter meanwhile: the next tick starts with that one
        if (this.tail !== tail || this.state.filter !== filter) return;
        tail.rebase(this.state.totalFrames);
        tail.setFilter(filter, held);
        tail.active = true;
      }
      if (!tail.active) return;
      // Only for a list that shows its end; with a filter, its passes list newer packets
      if (!tail.filter && this.followed()) await this.warmTail(tail);
      this.publishTail();
      void this.filterTail();
    } catch (err) {
      if (this.tail) this.tailFailed(this.tail, err as Error);
    } finally {
      this.tailBusy = false;
      if (!this.capture.running && this.tailTimer) {
        clearInterval(this.tailTimer);
        this.tailTimer = null;
      }
      if (this.tailLast) {
        this.tailLast = false;
        void this.tailTick();
      }
    }
  }

  /**
   * Checks newer packets against the display filter: whole chunks back to
   * back, the newest once a tick. Asked for while a pass runs (another
   * filter, packets checked again), the running one goes on after it.
   */
  private async filterTail(): Promise<void> {
    const tail = this.listedTail;
    if (!tail) return;
    if (this.tailFiltering) {
      this.filterAgain = true;
      return;
    }
    this.tailFiltering = true;
    try {
      for (let more = true; more && this.tail === tail; ) {
        const revision = tail.revision;
        this.filterAgain = false;
        more = (await tail.filterPass(this.followed() ? await this.rowView() : undefined, WARM_ROWS)) || this.filterAgain;
        this.tailWorked(tail);
        if (tail.revision !== revision && this.listedTail === tail) this.tailRevised();
        else this.publishTail();
      }
    } catch (err) {
      if (!(err instanceof Superseded)) this.tailFailed(tail, err as Error);
    } finally {
      this.tailFiltering = false;
    }
    // Asked for by a tail that came meanwhile
    if (this.filterAgain && this.listedTail && this.listedTail !== tail) void this.filterTail();
  }

  /** Whether a client showed the list's newest rows lately: the rows the list gains are read ahead for it. */
  private followed(): boolean {
    return Date.now() - this.newestAskedAt < FOLLOWED_MS;
  }

  /** Before the list grows without a filter: reads the provisional rows it gains, so the followed end shows them at once. */
  private async warmTail(tail: LiveTail): Promise<void> {
    const gained = tail.listed() - (this.state.tail?.displayed ?? 0);
    if (gained <= 0) return;
    try {
      await tail.warm(Math.min(gained, WARM_ROWS), await this.rowView());
      this.tailWorked(tail);
    } catch (err) {
      if (!(err instanceof Superseded)) this.tailFailed(tail, err as Error);
    }
  }

  /** What the view tells about the tail, null while it isn't listed. */
  private tailState(): ProvisionalTail | null {
    const tail = this.listedTail;
    if (!tail) return null;
    const readMs = this.lastReadMs || (this.readStartedAt ? Date.now() - this.readStartedAt : 0);
    return { frames: tail.frames, displayed: tail.listed(), unfiltered: tail.unfiltered(), held: tail.held, readMs, paused: this.paused, exactAfter: this.exactAfter() };
  }

  /** What makes provisional packets exact (see ProvisionalTail.exactAfter). */
  private exactAfter(): ProvisionalTail["exactAfter"] {
    if (this.capture.running) return this.paused ? "stop" : "read";
    return this.readStartedAt || this.finalRead ? "reading" : "reload";
  }

  /** Provisional matches listed before changed: the list's rows are read again, the selection stays on its packet. */
  private tailRevised(): void {
    const generation = this.state.generation + 1;
    this.state = { ...this.state, tail: this.tailState(), generation, rowsSince: generation };
    const selectedIndex = this.indexOf(this.state.selected);
    this.set({ selectedIndex, ...rowSelection(rowOf(selectedIndex)) });
  }

  /** Publishes the tail as it is now; the list's generation moves when its rows grew. */
  private publishTail(): void {
    const tail = this.tailState();
    const was = this.state.tail;
    if (!tail && !was) return;
    if (tail && was && tail.frames === was.frames && tail.displayed === was.displayed && tail.unfiltered === was.unfiltered && tail.held === was.held && tail.paused === was.paused && tail.exactAfter === was.exactAfter) return;
    const grew = (tail?.displayed ?? 0) !== (was?.displayed ?? 0);
    // A selected provisional packet the filter lists now gets its row
    const { selected, selectedIndex, selectedRows } = this.state;
    const index = grew && selectedIndex < 0 && selected !== null && selected > this.state.totalFrames ? this.indexOf(selected) : -1;
    const selection = index >= 0 ? { selectedIndex: index, ...(selectedRows.length ? {} : rowSelection(rowOf(index))) } : {};
    this.set({ tail, ...(grew ? { generation: this.state.generation + 1 } : {}), ...selection });
  }

  /**
   * Closes the tail; the view forgets its packets until a full read covers
   * them. Marks, time references and the selection stay on frames up to
   * `keep` meanwhile.
   */
  private closeTail(keep = this.state.totalFrames): void {
    this.dropTail();
    const s = this.state;
    if (!s.tail) return;
    this.keptFrames = keep > s.totalFrames ? keep : 0;
    const generation = s.generation + 1;
    const selected = s.selected !== null && s.selected <= keep ? s.selected : null;
    this.state = {
      ...s,
      tail: null,
      generation,
      rowsSince: s.tail.displayed ? generation : s.rowsSince,
      selected,
      selectedBy: selected === null ? null : s.selectedBy,
      marks: s.marks.filter((m) => m.frame <= keep),
      timeRefs: refsUpTo(s.timeRefs, keep),
      ...this.pruneComments(keep),
    };
    this.set({ selectedIndex: this.indexOf(selected), ...rowSelection(clipRanges(s.selectedRows, s.displayedFrames)) });
  }

  /** Provisional rows, details or a filter pass failed: a warning now and then; after a few in a row the tail is turned off. */
  private tailFailed(tail: LiveTail, err: Error): void {
    if (this.tail !== tail) return;
    this.tailProblem(err.message);
    if (++this.tailFailures < MAX_TAIL_FAILURES) return;
    if (tail.active) this.events.add("WARNING", `Live view: newer packets of ${basename(tail.file)} are listed only once read in full: reading them from slices failed ${this.tailFailures} times in a row (${printable(err.message)})`);
    this.tailOff = tail.file;
    this.closeTail(tail.store.changed ? this.state.totalFrames : tail.count);
  }

  private tailWorked(tail: LiveTail): void {
    if (this.tail === tail) this.tailFailures = 0;
  }

  /** Closes the tail without telling: the state set next does. */
  private dropTail(): void {
    const tail = this.tail;
    this.tail = null;
    tail?.close();
  }

  /**
   * Before a full read lands: the tail must count the file's packets as
   * sharkd does (count, time of the last one read), else it goes with the
   * read (false). The tail takes a filter the read dropped.
   */
  private async checkTail(engine: Sharkd, file: string, result: { status: SharkdStatus; filter: string }): Promise<boolean> {
    const tail = this.tail;
    if (!tail || tail.file !== file) return true;
    const frames = result.status.frames;
    await tail.update();
    let ok = tail.count >= frames;
    if (ok && frames > 0) {
      const [row] = await engine.call<PacketRow[]>("frames", { ...page(frames - 1, 1), column0: "frame.time_epoch:0" });
      let time = NaN;
      await tail.store.readFrames([frames], (_frame, t) => (time = t));
      ok = !!row && Math.abs(Number(row.c[0]) - time) < 2e-6;
    }
    if (this.tail !== tail) return true;
    if (!ok) {
      if (tail.active) this.events.add("WARNING", `Live view: the newest packets of ${basename(file)} don't line up with its full read, so they are listed only once read in full`);
      this.tailOff = file;
      return false;
    }
    if (tail.active && result.filter !== tail.filter) tail.setFilter(result.filter, await this.heldReason(result.filter, engine));
    return true;
  }

  /** A sharkd for slices: like the view's, its Lua reports aside. */
  private tailEngine(): Sharkd {
    const engine = new Sharkd(this.sharkdBin, this.profile, () => this.extensions.env(), () => this.extensions.generation);
    engine.onFailure = (message) => this.tailProblem(message);
    for (const [name, value] of this.dissectPrefs) engine.setPref(name, value).catch(() => {});
    return engine;
  }

  /** Failing provisional rows: a warning now and then, not every second. */
  private tailProblem(message: string): void {
    if (Date.now() - this.tailProblemAt < TAIL_PROBLEM_MS) return;
    this.tailProblemAt = Date.now();
    this.events.add("WARNING", `Live view: newer packets could not be read provisionally: ${printable(message)}`);
  }

  /** Why the tail can't check `filter`, or null; fields typed by `engine`'s extensions. */
  private heldReason(filter: string, engine = this.engine): Promise<string | null> {
    return filter ? heldReason(filter, (field) => this.fieldType(field, engine)) : Promise.resolve(null);
  }

  /** sharkd's ftype of a field, or null. */
  private async fieldType(field: string, engine = this.engine): Promise<number | null> {
    if (this.fieldTypes.has(field)) return this.fieldTypes.get(field)!;
    const seq = this.typesSeq;
    let type: number | null = null;
    try {
      const r = await engine.call<{ field?: { f: string; t?: number }[] }>("complete", { field });
      type = r.field?.find((x) => x.f === field)?.t ?? null;
    } catch {
      // unknown: treated as an ordinary field
    }
    // Not from extensions replaced meanwhile
    if (seq === this.typesSeq && !engine.outdated()) this.fieldTypes.set(field, type);
    return type;
  }

  /** Field types go with the extensions they were read with. */
  private forgetTypes(): void {
    this.fieldTypes.clear();
    this.typesSeq++;
  }

  /** Types the fields of the view's columns (`formats`, then the custom ones) as `engine` reads them. */
  private async typeColumns(engine = this.engine, formats = this.columnFormats): Promise<void> {
    for (const format of formats) if (format.startsWith("%Cus:")) await this.fieldType(format.split(":")[1], engine);
    for (const c of this.state.customColumns) await this.fieldType(c.field, engine);
  }

  /** Types the columns' fields again for `engine`, read with other extensions; returns why the tail can't check `filter` now. */
  private async retype(engine: Sharkd, status: SharkdStatus, filter: string): Promise<string | null> {
    this.forgetTypes();
    await this.typeColumns(engine, (status.column_info ?? []).map((c) => c.format));
    return this.heldReason(filter, engine);
  }

  /** How provisional rows read: like the exact ones, renumbered once the columns' fields are typed. */
  private async rowView(): Promise<RowView> {
    await this.typeColumns();
    const numbering = this.numbering();
    const { epoch, columns, customColumns } = this.state;
    return {
      numbering,
      fetch: (engine, params, refs) => this.framesWithColumns(engine, params, refs),
      key: [epoch, ...columns, ...customColumns.map((c) => c.field), JSON.stringify(numbering)].join("\u0001"),
    };
  }

  /** Which columns of the view's rows show frame numbers, and which slices can't fill or count alone. */
  private numbering(): Numbering {
    const out: Required<Numbering> = { frames: [], info: -1, blank: [], bytes: [] };
    const classify = (j: number, field: string): void => {
      if (field === "frame.number" || this.fieldTypes.get(field) === FT_FRAMENUM) out.frames.push(j);
      else if (streamNumbered(field)) out.blank.push(j);
    };
    this.columnFormats.forEach((format, j) => {
      if (format === "%m") out.frames.push(j);
      else if (format === "%i") out.info = j;
      else if (format === "%B") out.bytes.push(j);
      else if (format.startsWith("%Cus:")) classify(j, format.split(":")[1]);
    });
    this.state.customColumns.forEach((c, k) => classify(this.baseColumns.length + k, c.field));
    return out;
  }

  close(): Promise<void> {
    return this.exclusive(async () => {
      // A restarted sharkd needn't read the closed file again
      for (const e of this.engines) e.forgetFile();
      this.dropTail();
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
        timeRefs: [],
        ...this.dropComments(),
        generation: this.state.generation + 1,
        rowsSince: this.state.generation + 1,
        epoch: this.newEpoch("closed"),
        tail: null,
      });
      void this.checkOffers(true);
    });
  }

  async checkFilter(filter: string): Promise<FilterCheck> {
    if (!filter.trim()) return { ok: true };
    try {
      const r = await this.engine.call<{ status: string; warning?: string }>("check", { filter });
      const refTime = await refTimeError(filter, (f) => this.engine.call("check", { filter: f }));
      if (refTime) return { ok: false, error: refTime };
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
        let refs: number[];
        let displayed: Int32Array | null;
        let held: string | null;
        // Time references set meanwhile: frame.ref_time matches other frames
        do {
          refs = this.state.timeRefs;
          displayed = filter ? await matchingFrames(this.engine, refTimeFilter(filter, refs)) : null;
          held = this.listedTail ? await this.heldReason(filter) : null;
        } while (refs !== this.state.timeRefs && usesRefTime(filter));
        this.displayed = displayed;
        this.listedTail?.setFilter(filter, held);
        this.state = {
          ...this.state,
          filter,
          displayedFrames: displayed ? displayed.length : this.state.totalFrames,
          generation: this.state.generation + 1,
          tail: this.tailState(),
        };
        const selectedIndex = this.indexOf(this.state.selected);
        this.set({ selectedIndex, ...rowSelection(rowOf(selectedIndex)), rowsSince: this.state.generation });
        void this.filterTail();
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

  /**
   * Rows of the list as they read now, for `generation` or an older one of
   * the same list (since rowsSince): its rows are still where they were.
   * Rows from displayedFrames on are the tail's, provisional.
   */
  async rows(generation: number, start: number, count: number): Promise<RowsResponse> {
    const { rowsSince, displayedFrames, filter } = this.state;
    if (generation > this.state.generation || generation < rowsSince) throw new StaleGenerationError("stale generation");
    // A list that shows its end: the rows it gains are read ahead for a while
    if (start + count >= displayedFrames + (this.state.tail?.displayed ?? 0) - WARM_ROWS) this.newestAskedAt = Date.now();
    const tail = this.listedTail;
    count = Math.max(0, Math.min(count, 500, this.listLength() - start));
    if (count === 0 || start < 0) return { generation, start, rows: [] };
    const exact = Math.max(0, Math.min(count, displayedFrames - start));
    const params = page(start, exact);
    const refs = this.state.timeRefs;
    const sharkd = refTimeFilter(filter, refs);
    if (filter) params.filter = sharkd;
    const [head, rest] = await Promise.all([
      exact ? this.pageRefs(refs, filter, sharkd, start, exact).then((r) => this.framesWithColumns(this.engine, params, r)) : [],
      tail && count > exact ? this.tailRows(tail, generation, start + exact - displayedFrames, count - exact) : [],
    ]);
    if (this.state.rowsSince !== rowsSince) throw new StaleGenerationError("stale generation");
    return { generation, start, rows: this.withComments([...head, ...rest], true) };
  }

  /**
   * Provisional rows of the list of `generation`: slices are read only while
   * it is the newest (the client asks for the newest one's rows anyway).
   * None when they can't be read now: the client asks again.
   */
  private async tailRows(tail: LiveTail, generation: number, i0: number, n: number): Promise<PacketRow[]> {
    try {
      const rows = await tail.rows(i0, n, await this.rowView(), () => generation === this.state.generation);
      this.tailWorked(tail);
      return rows;
    } catch (err) {
      // Closed meanwhile (read in full, another file), or asked for again since
      if (this.tail !== tail || err instanceof Superseded) throw new StaleGenerationError("the live view moved on");
      this.tailFailed(tail, err as Error);
      return [];
    }
  }

  /** Summary row of one frame, regardless of the display filter. */
  async row(num: number): Promise<PacketRow | null> {
    const tail = this.listedTail;
    if (num > this.state.totalFrames && tail && num <= this.known()) {
      const [r] = await tail.rowsOf([num], await this.rowView());
      return r ? this.withComments([r])[0] : null;
    }
    if (num < 1 || num > this.state.totalFrames) return null;
    const rows = await this.framesWithColumns(this.engine, page(num - 1, 1), () => refsOf(this.state.timeRefs, [num]));
    const r = rows[0];
    return r && r.num === num ? this.withComments([r])[0] : null;
  }

  /** sharkd "frames" rows with the custom columns appended and the comments of the file; times count from the references `refs` names (see framesWithRefs). */
  private async framesWithColumns(engine: Sharkd, params: Record<string, unknown>, refs: RowRefs = () => []): Promise<PacketRow[]> {
    const custom = this.state.customColumns;
    const columns = custom.length ? columnParams(custom.map((c) => c.field)) : null;
    // The longer request decides how many rows a part has
    return framesWithRefs(params, refs, async (base) => {
      const [rows, extra] = await Promise.all([
        engine.call<SharkdRow[]>("frames", base),
        // Custom column params replace sharkd's default columns, so they come in a second request
        columns ? engine.call<PacketRow[]>("frames", { ...base, ...columns }) : null,
      ]);
      return rows.map((r, i) => {
        const values = extra?.[i]?.num === r.num ? extra[i].c.map(clip) : custom.map(() => "");
        return { num: r.num, c: [...r.c, ...values], bg: r.bg, fg: r.fg, ...(r.comments ? { cm: r.comments } : {}) };
      });
    }, columns ?? {});
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
    const refs = this.state.timeRefs;
    const sharkd = refTimeFilter(filter, refs);
    const total = await this.countMatching(filter);
    const params: Record<string, unknown> = { ...page(offset, limit), ...columnParams(fields) };
    if (filter) params.filter = sharkd;
    const rows = await framesWithRefs(params, await this.pageRefs(refs, filter, sharkd, offset, limit), (p) => this.engine.call<PacketRow[]>("frames", p));
    return { total, rows: rows.map((r) => ({ num: r.num, values: r.c.map(clip) })) };
  }

  /**
   * The time references rows offset..offset+limit-1 of `filter` (`sharkd`:
   * as sharkd matches it) count from, by row.
   */
  private async pageRefs(refs: readonly number[], filter: string, sharkd: string, offset: number, limit: number): Promise<RowRefs> {
    if (!refs.length || limit <= 0) return () => [];
    let frames: Int32Array;
    if (!filter) frames = Int32Array.from({ length: Math.max(0, Math.min(limit, this.state.totalFrames - offset)) }, (_, i) => offset + 1 + i);
    else if (filter === this.state.filter && this.displayed) frames = this.displayed.subarray(offset, offset + limit);
    else frames = Int32Array.from(await this.engine.call<{ num: number }[]>("frames", { filter: sharkd, ...page(offset, limit), column0: "frame.number:0" }), (r) => r.num);
    return (from, to) => refsOf(refs, frames.subarray(from, to));
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
        // Provisional rows renumber frame-number fields
        await this.fieldType(c.field);
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

  /**
   * Details of a frame. A live capture's frame after the last full read only
   * with `provisional` (the packet list's), dissected from its slice.
   */
  async frame(num: number, provisional = false): Promise<FrameDetail> {
    this.requireFile();
    const tail = this.listedTail;
    if (Number.isInteger(num) && num > this.state.totalFrames && tail && num <= this.known()) {
      if (!provisional) throw new Error(this.notReadYet(num));
      return this.tailFrame(tail, num);
    }
    if (!Number.isInteger(num) || num < 1 || num > this.state.totalFrames) throw new Error(`no frame ${num}`);
    const ref = refBefore(this.state.timeRefs, num);
    const [f, row] = await Promise.all([this.engine.call<SharkdFrame>("frame", { frame: num, proto: true, bytes: true, ...(ref ? { ref_frame: ref } : {}) }), this.row(num)]);
    return { num, tree: this.withCommentNode(num, f.tree), bytes: f.bytes ?? "", ds: f.ds ?? [], followers: followersOf(f), row };
  }

  /**
   * A provisional frame's details. Its streams are followed in what was read
   * in full, by the stream filters of its flow's first packet when that was.
   */
  private async tailFrame(tail: LiveTail, num: number): Promise<FrameDetail> {
    let f: Awaited<ReturnType<LiveTail["frame"]>>;
    let row: PacketRow | null;
    try {
      [f, row] = await Promise.all([tail.frame(num), this.row(num)]);
      this.tailWorked(tail);
    } catch (err) {
      // Closed meanwhile, most likely read in full now
      if (this.tail !== tail) return this.frame(num, true);
      this.tailFailed(tail, err as Error);
      throw err;
    }
    let followers: [string, string][] = [];
    if (f.first !== null && f.first <= this.state.totalFrames) followers = followersOf(await this.engine.call<SharkdFrame>("frame", { frame: f.first, proto: false }));
    return { num, tree: this.withCommentNode(num, f.tree), bytes: f.bytes, ds: f.ds, followers, row, provisional: true };
  }

  /** Why a frame after the last full read can't be read exactly yet. */
  private notReadYet(num: number): string {
    const t = this.tailState();
    const read = this.state.totalFrames;
    const wait = {
      read: `the next full read covers it, in about ${Math.ceil(((t?.readMs ?? 0) + LIVE_RELOAD_MS) / 1000)} s`,
      stop: `it is read in full once the capture stops (full reads wait: ${t?.paused})`,
      reading: "the full read under way covers it",
      reload: `it is read in full once a full read succeeds (View › Reload)${t?.paused ? ` (${t.paused})` : ""}`,
    }[t?.exactAfter ?? "read"];
    const why = read ? `frame ${num} arrived after the last full read of the live capture (frames 1-${read})` : `frame ${num} is not read in full, as no packet of the live capture is`;
    return `${why}: ${wait}`;
  }

  /** Rows for an arbitrary filter, without touching what the UI shows. */
  async query(filter: string, offset: number, limit: number): Promise<{ total: number; rows: PacketRow[] }> {
    this.requireFile();
    const check = await this.checkFilter(filter);
    if (!check.ok) throw new Error(`invalid display filter: ${check.error}`);
    const refs = this.state.timeRefs;
    const sharkd = refTimeFilter(filter, refs);
    const total = await this.countMatching(filter);
    const params = page(offset, limit);
    if (filter) params.filter = sharkd;
    const rows = await this.framesWithColumns(this.engine, params, await this.pageRefs(refs, filter, sharkd, offset, limit));
    return { total, rows: this.withComments(rows) };
  }

  private countCache: { loads: number; filter: string; total: number } | null = null;

  /** Frames read in full matching `filter`, reusing the view's count and earlier results. */
  private async countMatching(filter: string): Promise<number> {
    if (!filter) return this.state.totalFrames;
    if (filter === this.state.filter) return this.state.displayedFrames;
    // As the time references now spell frame.ref_time out
    filter = this.sharkdFilter(filter);
    // Provisional rows bump the generation, not what the engine read
    const { loads } = this;
    const c = this.countCache;
    if (c && c.loads === loads && c.filter === filter) return c.total;
    const total = (await matchingFrames(this.engine, filter)).length;
    this.countCache = { loads, filter, total };
    return total;
  }

  /** `filter` as sharkd matches it: frame.ref_time spelled out as the time references (see refTimeFilter). */
  private sharkdFilter(filter: string): string {
    return refTimeFilter(filter, this.state.timeRefs);
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
    if (frame !== null && (!Number.isInteger(frame) || frame < 1 || frame > this.known())) {
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
      const hidden = this.state.selectedIndex < 0 ? ` (${this.unlisted(frame)})` : "";
      this.notice(`Selected frame ${frame}${hidden}`);
    }
  }

  /** Why the list has no row for `frame`, a frame the view knows: "hidden by the current display filter", or why it isn't listed yet. */
  unlisted(frame: number): string {
    const tail = this.listedTail;
    if (tail && frame > this.state.totalFrames) {
      if (tail.held) return `listed once read in full, as ${tail.held}`;
      if (tail.unchecked(frame)) return "not checked against the display filter yet";
    }
    return "hidden by the current display filter";
  }

  /** Checks row ranges against the displayed list and merges them. */
  private checkRows(rows: Ranges): Ranges {
    if (rows.length > MAX_ROW_RANGES) throw new Error(`at most ${MAX_ROW_RANGES} row ranges can be selected`);
    const n = this.listLength();
    for (const [a, b] of rows) {
      if (!Number.isInteger(a) || !Number.isInteger(b) || a < 0 || a > b || b >= n) throw new Error(`invalid row range [${a}, ${b}] (${n} rows are displayed)`);
    }
    return mergeRanges(rows);
  }

  /** Frame ranges of the user's selected rows. */
  selectedFrames(): Ranges {
    return this.framesOfRows(clipRanges(this.state.selectedRows, this.listLength()));
  }

  /** Frame ranges of displayed rows, provisional ones too. */
  private framesOfRows(rows: Ranges): Ranges {
    const displayed = this.displayed;
    const n = this.state.displayedFrames;
    const tail = this.listedTail;
    // Without a filter, row i is frame i + 1 throughout
    if (!displayed && !tail?.filter) return rows.map(([a, b]) => [a + 1, b + 1]);
    const out: Ranges = [];
    for (const [a, b] of rows) {
      for (let i = a; i <= b; i++) {
        const frame = i < n ? (displayed ? displayed[i] : i + 1) : tail!.frameAt(i - n);
        const last = out[out.length - 1];
        if (last && frame === last[1] + 1) last[1] = frame;
        else out.push([frame, frame]);
      }
    }
    return out;
  }

  /** Frames of the selected rows, else the selected frame. */
  selectedOrCurrent(): Ranges {
    if (this.state.selectedCount) return this.selectedFrames();
    const frame = this.state.selected;
    return frame === null ? [] : [[frame, frame]];
  }

  /** Marks frames and returns the frame numbers that exist. */
  mark(frames: number[], note: string, by: "user" | "agent"): number[] {
    this.requireFile();
    // Notes become packet comments on export, where editcap takes no control characters
    note = printable(note).slice(0, MAX_NOTE);
    const known = this.known();
    const valid = [...new Set(frames)].filter((f) => Number.isInteger(f) && f >= 1 && f <= known);
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
    const n = this.listLength();
    if (marks.length + n - marks.filter(shown).length > MAX_MARKS) throw new Error(`at most ${MAX_MARKS} frames can be marked`);
    const had = new Set(marks.map((m) => m.frame));
    const added: Mark[] = [];
    for (const [a, b] of n ? this.framesOfRows([[0, n - 1]]) : []) {
      for (let frame = a; frame <= b; frame++) if (!had.has(frame)) added.push({ frame, note: "", by });
    }
    this.set({ marks: [...marks, ...added].sort((a, b) => a.frame - b.frame) });
  }

  /** Sets (`on`) or unsets time references on `frames`; frames the view doesn't know are left out. */
  setTimeRefs(frames: number[], on: boolean, by: "user" | "agent"): Promise<TimeRefsChange> {
    this.requireFile();
    const known = this.known();
    const given = new Set(frames.filter((f) => Number.isInteger(f) && f >= 1 && f <= known));
    return this.changeRefs((refs) => {
      if (!on) return refs.filter((f) => !given.has(f));
      const all = new Set([...refs, ...given]);
      if (all.size > MAX_TIME_REFS) throw new Error(`at most ${MAX_TIME_REFS} frames can be time references`);
      return [...all].sort((a, b) => a - b);
    }, by);
  }

  /** Wireshark's Set/Unset Time Reference: flips the reference of each selected frame, else of the current one. */
  toggleTimeRefs(by: "user" | "agent"): Promise<TimeRefsChange> {
    this.requireFile();
    const frames = this.selectedOrCurrent();
    return this.changeRefs((refs) => {
      const removed = refs.filter((f) => inRanges(frames, f)).length;
      if (refs.length - 2 * removed + countRanges(frames) > MAX_TIME_REFS) throw new Error(`at most ${MAX_TIME_REFS} frames can be time references`);
      const had = new Set(refs);
      const added: number[] = [];
      for (const [a, b] of frames) for (let f = a; f <= b; f++) if (!had.has(f)) added.push(f);
      return [...refs.filter((f) => !inRanges(frames, f)), ...added].sort((a, b) => a - b);
    }, by);
  }

  /** Wireshark's Unset All Time References. */
  clearTimeRefs(by: "user" | "agent"): Promise<TimeRefsChange> {
    return this.changeRefs(() => [], by, "Unset all time references");
  }

  /**
   * Makes `next` of the time references the ones the view has. Rows and
   * details read again; a display filter on frame.ref_time is matched again
   * (after reads under way), which may list other rows. The agent's changes
   * show `notice`, or what changed.
   */
  private changeRefs(next: (refs: number[]) => number[], by: "user" | "agent", notice?: string): Promise<TimeRefsChange> {
    const apply = async (): Promise<TimeRefsChange> => {
      for (;;) {
        const before = this.state.timeRefs;
        const refs = next(before);
        const had = new Set(before);
        const now = new Set(refs);
        const change = { set: refs.filter((f) => !had.has(f)), unset: before.filter((f) => !now.has(f)) };
        if (!change.set.length && !change.unset.length) return change;
        const filter = this.state.filter;
        const displayed = this.state.file && usesRefTime(filter) ? await matchingFrames(this.engine, refTimeFilter(filter, refs)) : null;
        // A tail that closed meanwhile took some along
        if (this.state.timeRefs !== before) continue;
        this.tail?.setRefs(refs);
        const generation = this.state.generation + 1;
        const was = this.displayed;
        if (displayed && !(was && was.length === displayed.length && was.every((f, i) => f === displayed[i]))) {
          this.displayed = displayed;
          this.state = { ...this.state, timeRefs: refs, timeRefsRevision: this.state.timeRefsRevision + 1, displayedFrames: displayed.length, generation, rowsSince: generation };
          const selectedIndex = this.indexOf(this.state.selected);
          this.set({ selectedIndex, ...rowSelection(rowOf(selectedIndex)) });
        } else this.set({ timeRefs: refs, timeRefsRevision: this.state.timeRefsRevision + 1, generation });
        if (by === "agent") {
          const text = changeText(change);
          this.notice(notice ?? text[0].toUpperCase() + text.slice(1));
        }
        return change;
      }
    };
    return usesRefTime(this.state.filter) ? this.exclusive(apply) : apply();
  }

  /** Wireshark's Add New Comment…: adds `comment` to the comments of each of `frames`; returns the frames it went to. */
  async addComment(frames: Ranges, comment: string, by: "user" | "agent"): Promise<number[]> {
    const text = commentText(comment);
    if (!text) throw new Error("the comment is empty");
    const changed = await this.editComments(frames, (now) => [...now, text]);
    if (by === "agent" && changed.length) this.notice(`Added a packet comment to ${frameCount(changed)}: ${noticeText(text)}`);
    return changed;
  }

  /** Sets the comments of each of `frames` to just `comment`. */
  async replaceComments(frames: Ranges, comment: string, by: "user" | "agent"): Promise<number[]> {
    const text = commentText(comment);
    if (!text) throw new Error("the comment is empty");
    const changed = await this.editComments(frames, () => [text]);
    if (by === "agent" && changed.length) this.notice(`Set the packet comment of ${frameCount(changed)}: ${noticeText(text)}`);
    return changed;
  }

  /** Wireshark's Edit "…": comment `index` of `frame`, if still `old`, becomes `comment`; "" deletes it. */
  async editComment(frame: number, index: number, old: string, comment: string, by: "user" | "agent"): Promise<number[]> {
    const text = commentText(comment);
    if (!text) return this.deleteComment(frame, index, old, by);
    const changed = await this.editComments(this.oneFrame(frame), (now) => {
      const at = this.commentAt(now, frame, index, old);
      return now.map((c, i) => (i === at ? text : c));
    });
    if (by === "agent" && changed.length) this.notice(`Edited a packet comment of frame ${frame}: ${noticeText(text)}`);
    return changed;
  }

  /** Wireshark's Delete "…": comment `index` of `frame`, if still `old`. */
  async deleteComment(frame: number, index: number, old: string, by: "user" | "agent"): Promise<number[]> {
    const changed = await this.editComments(this.oneFrame(frame), (now) => {
      const at = this.commentAt(now, frame, index, old);
      return now.filter((_, i) => i !== at);
    });
    if (by === "agent" && changed.length) this.notice(`Deleted a packet comment of frame ${frame}`);
    return changed;
  }

  /** Wireshark's Delete packet comments: every comment of `frames`. */
  async deleteComments(frames: Ranges, by: "user" | "agent"): Promise<number[]> {
    const changed = await this.editComments(frames, () => []);
    if (by === "agent" && changed.length) this.notice(`Deleted the packet comments of ${frameCount(changed)}`);
    return changed;
  }

  /**
   * Wireshark's Delete All Packet Comments: the file's too, of every packet
   * the view knows; returns the frames that had comments.
   */
  async clearComments(by: "user" | "agent"): Promise<number[]> {
    const file = this.commentsFile;
    const changed = await this.commentQueue(file, async () => {
      const commented = await this.fileCommented();
      this.sameCapture(file);
      const known = this.known();
      const shown = (f: number): boolean => (this.comments.get(f)?.list.length ?? (f > this.cleared ? 1 : 0)) > 0;
      const gone = commented.filter((f) => f <= known && shown(f));
      const added = [...this.comments.keys()].filter((f) => shown(f) && !hasFrame(commented, f));
      if (!gone.length && !added.length) return [];
      const edit = ++this.commentEdit;
      for (const f of added) this.unexported.set(f, edit);
      this.clearedFrames = this.cleared ? Int32Array.from(new Set([...this.clearedFrames, ...gone])).sort() : gone;
      this.clearedEdit = edit;
      this.cleared = known;
      this.comments.clear();
      this.commentsChanged();
      return [...gone, ...added].sort((a, b) => a - b);
    });
    if (by === "agent" && changed.length) this.notice(`Deleted all packet comments (${frameCount(changed)})`);
    return changed;
  }

  /**
   * Packet comments edited in the viewer: the packets whose comments differ
   * from the file's, the frames Delete All went up to (0: none), and the
   * frames edited since, the first `max` with their comments.
   */
  editedComments(max: number): { packets: number; cleared: number; frames: number; list: [number, string[]][] } {
    const frames = [...this.comments.keys()].sort((a, b) => a - b);
    const both = frames.filter((f) => hasFrame(this.clearedFrames, f)).length;
    const list = frames.slice(0, max).map((f): [number, string[]] => [f, this.comments.get(f)!.list]);
    return { packets: frames.length + this.clearedFrames.length - both, cleared: this.cleared, frames: frames.length, list };
  }

  /** `frame`, a frame the view knows, as ranges. */
  private oneFrame(frame: number): Ranges {
    if (!Number.isInteger(frame) || frame < 1 || frame > this.known()) throw new Error(`no frame ${frame}`);
    return [[frame, frame]];
  }

  /** `index`, a comment `frame` has now (`comments`), as long as it still reads `old`. */
  private commentAt(comments: string[], frame: number, index: number, old: string): number {
    if (!Number.isInteger(index) || index < 0 || index >= comments.length) throw new Error(`frame ${frame} has no comment ${index + 1}`);
    if (comments[index] !== old) throw new StaleGenerationError(`comment ${index + 1} of frame ${frame} changed meanwhile`);
    return index;
  }

  /**
   * Gives each of `frames` the comments `change` makes of the ones it has
   * now (unchanged ones and frames the view doesn't know are left out), one
   * edit after the other, as long as the capture open now stays open;
   * returns the frames whose comments changed.
   */
  private editComments(frames: Ranges, change: (now: string[]) => string[]): Promise<number[]> {
    if (countRanges(frames) > MAX_COMMENTED) throw new Error(`comments of at most ${MAX_COMMENTED} packets can be changed at once`);
    const file = this.commentsFile;
    return this.commentQueue(file, async () => {
      const known = this.known();
      const valid = mergeRanges(frames).flatMap(([a, b]) => Array.from({ length: Math.max(0, Math.min(b, known) - Math.max(a, 1) + 1) }, (_, i) => Math.max(a, 1) + i));
      const now = await this.commentsOf(valid);
      this.sameCapture(file);
      const lists = new Map<number, EditedComments>();
      for (const f of valid) {
        const was = now.get(f) ?? { list: [], own: 0 };
        const list = change(was.list);
        if (list.length === was.list.length && list.every((c, i) => c === was.list[i])) continue;
        // While the file's own comments lead, exports keep them and add the rest
        const own = was.own >= 0 && was.list.slice(0, was.own).every((c, i) => c === list[i]) ? was.own : -1;
        lists.set(f, { list, own });
      }
      this.setComments(lists);
      return [...lists.keys()];
    });
  }

  /** Runs `fn` after the edits of comments before it, if the capture whose comments were `file` is still open. */
  private commentQueue<T>(file: number, fn: () => Promise<T>): Promise<T> {
    const run = (): Promise<T> => {
      this.requireFile();
      this.sameCapture(file);
      return fn();
    };
    const next = this.commenting.then(run, run);
    this.commenting = next.catch(() => {});
    return next;
  }

  /** Refuses to edit comments once their capture is gone. */
  private sameCapture(file: number): void {
    if (file !== this.commentsFile) throw new StaleGenerationError("the capture was closed or another one opened meanwhile");
  }

  /** Puts `lists` in place of the frames' comments. */
  private setComments(lists: Map<number, EditedComments>): void {
    if (!lists.size) return;
    let added = 0;
    for (const f of lists.keys()) if (!this.comments.has(f)) added++;
    if (this.comments.size + added > MAX_COMMENTED) {
      throw new Error(`the viewer holds the comments of at most ${MAX_COMMENTED} packets; export the capture to pcapng and open that file to change more`);
    }
    const edit = ++this.commentEdit;
    for (const [f, e] of lists) {
      this.comments.set(f, e);
      this.unexported.set(f, edit);
    }
    this.commentsChanged();
  }

  /** The list's rows read differently now, in the same places. */
  private commentsChanged(): void {
    this.set({ commentEdits: this.editCount(), commentRevision: this.state.commentRevision + 1, generation: this.state.generation + 1 });
  }

  /** Packets whose comments changed since every packet was last exported to pcapng. */
  private editCount(): number {
    if (!this.clearedEdit) return this.unexported.size;
    let both = 0;
    for (const f of this.unexported.keys()) if (hasFrame(this.clearedFrames, f)) both++;
    return this.unexported.size + this.clearedFrames.length - both;
  }

  /** The comments `frames` (frames the view knows, ascending) have now: as edited here, else the file's. */
  private async commentsOf(frames: number[]): Promise<Map<number, EditedComments>> {
    const out = new Map<number, EditedComments>();
    const file = (f: number, list: string[]): void => void out.set(f, { list, own: list.length });
    const read = this.state.totalFrames;
    const exact: number[] = [];
    const later: number[] = [];
    for (const f of frames) {
      const edited = this.comments.get(f);
      if (edited) out.set(f, edited);
      else if (f <= this.cleared) out.set(f, { list: [], own: 0 });
      else (f <= read ? exact : later).push(f);
    }
    let ranges = toRanges(exact);
    // Many ranges of a small capture: only the frames with comments are read
    if (ranges.length > COMMENT_READS && (this.commentedFrames?.loads === this.loads || ranges.length * COMMENT_READ_FRAMES > read)) {
      const commented = await this.fileCommented();
      for (const f of exact) file(f, []);
      ranges = toRanges(exact.filter((f) => hasFrame(commented, f)));
    }
    const engine = this.engine;
    for (const [a, b] of ranges) {
      for (const r of await engine.call<SharkdRow[]>("frames", { ...page(a - 1, b - a + 1), column0: "frame.number:0" })) file(r.num, r.comments ?? []);
    }
    const tail = this.listedTail;
    if (later.length && tail) for (const r of await tail.rowsOf(later, await this.rowView())) file(r.num, r.cm ?? []);
    return out;
  }

  /** Frames read in full that have comments in the file. */
  private async fileCommented(): Promise<Int32Array> {
    const { loads } = this;
    if (this.commentedFrames?.loads === loads) return this.commentedFrames.frames;
    const frames = await matchingFrames(this.engine, "frame.comment");
    this.commentedFrames = { loads, frames };
    return frames;
  }

  /** The comments edited here in place of frame `num`'s, or null. */
  private editedOf(num: number): string[] | null {
    return this.comments.get(num)?.list ?? (num <= this.cleared ? [] : null);
  }

  /** `rows` with their comments as edited here; `short`: as the list's rows carry them. */
  private withComments(rows: PacketRow[], short = false): PacketRow[] {
    if (!this.comments.size && !this.cleared && !short) return rows;
    return rows.map((r) => {
      const { cm: file, ...row } = r;
      const cm = this.editedOf(r.num) ?? file;
      if (!cm?.length) return row;
      return { ...row, cm: short ? cm.slice(0, ROW_COMMENTS).map((c) => (c.length > ROW_COMMENT ? `${c.slice(0, ROW_COMMENT - 1)}…` : c)) : cm };
    });
  }

  /** Frame `num`'s `tree` with its comments as edited here, in Wireshark's "Packet comments" node. */
  private withCommentNode(num: number, tree: TreeNode[]): TreeNode[] {
    const node = tree.find((n) => n.fn === "pkt_comment");
    // As sharkd's own comment nodes expand
    if (node?.e !== undefined) this.commentEtts.node = node.e;
    const item = node?.n?.find((n) => n.e !== undefined);
    if (item?.e !== undefined) this.commentEtts.item = item.e;
    const cm = this.editedOf(num);
    if (!cm) return tree;
    const rest = tree.filter((n) => n !== node);
    return cm.length ? [commentTree(cm, this.commentEtts), ...rest] : rest;
  }

  /** Drops the comments edited for frames after `last`; what the state says then. */
  private pruneComments(last: number): Partial<ViewState> {
    let gone = 0;
    for (const f of this.comments.keys()) {
      if (f <= last) continue;
      this.comments.delete(f);
      gone++;
    }
    for (const f of this.unexported.keys()) if (f > last) this.unexported.delete(f);
    if (this.cleared > last) {
      this.cleared = last;
      this.clearedFrames = this.clearedFrames.filter((f) => f <= last);
      gone++;
    }
    return gone ? { commentEdits: this.editCount(), commentRevision: this.state.commentRevision + 1 } : {};
  }

  /** The edited comments go with their file, and edits under way with them. */
  private dropComments(): Partial<ViewState> {
    this.commentsFile++;
    this.commentedFrames = null;
    this.clearedEdit = 0;
    return this.pruneComments(0);
  }

  /** Marks the viewer as driven by an MCP agent, which then gets the problems. */
  attachAgent(name = this.state.agent.name): void {
    this.set({ agent: { ...this.state.agent, attached: true, name } });
  }

  /**
   * The user's question about packets: those `about` names (the selection its
   * dialog showed, refused once that view is gone), else the selected ones.
   * It wakes the agent's `--watch`, else comes with its next tool result.
   */
  askAgent(question: string, about?: { frame: number | null; rows?: Ranges; view: { file: string; filter: string; generation?: number } }): AskResult {
    if (!this.state.agent.attached) throw new Error("no agent is attached");
    const text = printable(question.replace(/\s+/g, " ").trim()).slice(0, MAX_QUESTION);
    if (!text) throw new Error("the question is empty");
    let frames: Ranges = [];
    // Also when the capture was closed meanwhile: the question was about packets of it
    if (about) frames = this.framesAbout(about);
    else if (this.state.file) frames = this.selectedOrCurrent();
    const count = countRanges(frames);
    const subject = count === 0 ? "" : count === 1 ? ` about frame ${frames[0][0]}` : ` about ${count} packets`;
    const listed = framesFilter(frames, MAX_QUESTION_FRAMES) ?? `frames ${frames[0][0]} to ${frames[frames.length - 1][1]} (too many ranges to list)`;
    const woken = this.events.watched();
    this.events.add("QUESTION", `The user asks you${subject}: ${text}`, count > 1 ? { frames: listed } : undefined);
    return { woken };
  }

  /**
   * The packets a dialog was opened for: the rows `rows` (else the frame
   * `frame`) of the list `view` showed; refused once that list is gone.
   */
  framesAbout({ frame, rows, view }: { frame: number | null; rows?: Ranges; view: { file: string; filter: string; generation?: number } }): Ranges {
    if (view.file !== this.state.file || view.filter !== this.state.filter || (view.generation ?? Infinity) < this.state.rowsSince) {
      throw new StaleGenerationError("the packet list changed since you chose the packets; select them again");
    }
    if (rows?.length) return this.framesOfRows(this.checkRows(rows));
    if (frame === null) return [];
    if (!Number.isInteger(frame) || frame < 1 || frame > this.known()) throw new Error(`no frame ${frame}`);
    return [[frame, frame]];
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
    return { tap0: tap, filter: this.sharkdFilter(filter.trim()) };
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
      // Lua dissectors can put packet bytes into messages
      .map((d) => ({ frame: d.f, severity: d.s as ExpertSeverity, group: printable(d.g), protocol: printable(d.p), message: printable(d.m) }))
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
        params[`filter${i}`] = this.sharkdFilter(filter);
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
    return this.firstMatching(this.engine, this.state.filter ? `(${this.sharkdFilter(this.state.filter)}) && ${at}` : at);
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
    const match = this.sharkdFilter(view ? `(${view}) && (${filter})` : `(${filter})`);
    let frame: number | null;
    let wrapped = false;
    if (dir === 1) {
      frame = await this.firstMatching(engine, from ? `${match} && frame.number > ${from}` : match);
      if (frame === null && from) {
        frame = await this.firstMatching(engine, match);
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
    // With the reloads: a sharkd restarting meanwhile would miss the key
    await this.exclusive(async () => {
      this.set({ tlsKeylog: path });
      await this.redissectNow("tls.keylog_file", path ?? "", "tls");
    });
  }

  /**
   * Sets a dissection preference in every sharkd, also the ones started
   * later, and reads the open capture again with it; `why` tells panels why
   * they start over. `rollback`: see loadInto.
   */
  private async redissectNow(name: string, value: string, why: string, rollback = true): Promise<void> {
    this.panelData.hold(true);
    this.dissectPrefs.set(name, value);
    try {
      await Promise.all(this.engines.map((e) => e.setPref(name, value)));
      this.tail?.setPref(name, value);
      this.panelData.setPref(name, value);
      await this.reloadNow(true, false, true, false, rollback);
    } finally {
      this.set({ epoch: this.newEpoch(why) });
      this.panelData.hold(false);
      // A panel's offer may need a protocol only this brings
      void this.checkOffers(true);
    }
  }

  /**
   * Changes the Decode As entries, which apply to every capture until
   * WireBuddy exits, and reads the open capture again with them. An entry is
   * kept only once it applied to the open capture; whatever fails leaves the
   * entries and the view as they were.
   */
  decodeAs(raw: unknown, by: "user" | "agent"): Promise<DecodeAsResult> {
    return this.exclusive(async () => {
      const { entries, unavailable } = this.state.decodeAs;
      if (unavailable) throw new ReportedError(`Decode As is unavailable: ${unavailable}`);
      const change = parseChange(raw);
      if (change.action === "set") {
        if (!this.state.file) throw new ReportedError("Decode As needs an open capture to check the entry on; open one (or start a capture) first");
        const name = change.protocol;
        // Protocols (ftype 1) whose names start with `field`
        const protocols = async (field: string) => ((await this.engine.call<{ field?: { f: string; n?: string; t?: number }[] }>("complete", { field })).field ?? []).filter((x) => x.t === 1);
        if (!(await protocols(name)).some((x) => x.f === name)) {
          // By every first character, so a typo there finds them too
          const all = (await Promise.all([..."abcdefghijklmnopqrstuvwxyz0123456789"].map(protocols))).flat();
          const close = closeMatches(name, all.filter((x) => !x.f.includes(".")));
          const hint = close.length ? `close matches: ${close.map((x) => `${x.f}${x.n ? ` (${printable(x.n)})` : ""}`).join(", ")}` : "protocol names are the display-filter names, as in the filter bar";
          throw new ReportedError(`"${name}" is not a protocol Wireshark knows; ${hint}`);
        }
      }
      const next = applyChange(entries, change, by);
      if (serialize(next) === serialize(entries)) return { entries, unchanged: true };
      const entry = change.action === "set" ? next.find((e) => e.table === change.table && e.value === change.value) : undefined;
      const removed = change.action === "clear" ? entries.find((e) => e.table === change.table && e.value === change.value) : undefined;
      // Read again in any case (an entry replaced was undone already); its failure goes into the error
      const restore = () => this.redissectNow(DECODE_AS, serialize(entries), "decode-as", false).then(() => "", (err: Error) => `; reading it as before failed too (${printable(err.message)})`);
      try {
        await this.redissectNow(DECODE_AS, serialize(next), "decode-as", false);
      } catch (err) {
        const again = await restore();
        const what = entry ? `with ${entryText(entry)}` : `without ${removed ? entryText(removed) : "the Decode As entries"}`;
        throw new Error(`reading the capture ${what} failed (${printable((err as Error).message)}); ${entry ? "the entry was not kept" : "nothing changed"}${again}`);
      }
      let set: DecodeAsResult["set"];
      if (entry) {
        const s = (await this.decodeAsStatus().catch(() => null))?.get(serialize([entry]));
        if (s?.status !== "OK") {
          const again = await restore();
          if (s?.status === "no-protocol") throw new ReportedError(`Wireshark knows "${entry.protocol}" but has no dissector by that name to attach to ${entry.table} (it is only reached through another protocol); nothing changed${again}`);
          const why = !s ? "no report from WireBuddy's prelude" : s.status === "no-table" ? `it has no table ${entry.table}` : s.message;
          throw new ReportedError(`applying ${entryText(entry)} failed in Wireshark: ${why}; nothing changed${again}`);
        }
        set = { entry, was: s.was, now: s.now, frames: null };
      }
      this.set({ decodeAs: { ...this.state.decodeAs, entries: next } });
      if (set) set.frames = await this.countMatching(countFilter(set.entry)).catch(() => null);
      if (by === "agent") this.notice(set ? `Decode As: ${set.entry.table} ${set.entry.value} as ${set.now}` : removed ? `Removed Decode As ${entryText(removed)}` : "Removed all Decode As entries");
      return { entries: next, ...(set ? { set } : {}), ...(removed ? { removed } : {}) };
    });
  }

  /** How the active sharkd applied the Decode As entries, by entry. */
  private async decodeAsStatus(): Promise<Map<string, EntryStatus>> {
    const r = await this.engine.call<{ prefs?: Record<string, { s?: string }> }>("dumpconf", { pref: DECODE_AS_STATUS });
    return parseStatus(r.prefs?.[DECODE_AS_STATUS]?.s ?? "");
  }

  /** Writes a subset of the open capture to a new file, like Wireshark's Export Specified Packets. */
  async exportPackets(req: ExportRequest & { filter?: string }, by: "user" | "agent"): Promise<ExportResult> {
    this.requireFile();
    // The agent must not destroy the user's captures: it may only replace its own exports
    if (by === "agent" && req.overwrite && !this.agentExports.has(resolve(String(req.path ?? "")))) {
      throw new Error("the agent can only replace files it exported itself in this session; choose a new file name");
    }
    const input = this.state.file!;
    const format = checkTarget(String(req.path ?? ""), [input, ...this.capture.state.files], !!req.overwrite);
    // Always explicit frames: a live capture may have written more than the view knows
    const known = this.known();
    const everything: Ranges = known ? [[1, known]] : [];
    // Filters match exactly only what was read in full
    let leftOut = 0;
    let ranges: Ranges;
    if (req.filter !== undefined && req.filter.trim()) {
      const check = await this.checkFilter(req.filter);
      if (!check.ok) throw new Error(`invalid display filter: ${check.error}`);
      ranges = toRanges(await matchingFrames(this.engine, this.sharkdFilter(req.filter.trim())));
      leftOut = known - this.state.totalFrames;
    } else if (req.filter !== undefined || req.which === "all") ranges = everything;
    else if (req.which === "displayed") {
      ranges = this.displayed ? toRanges(this.displayed) : everything;
      // Its provisional matches, and newer packets not checked against it
      const tail = this.listedTail;
      if (this.displayed && tail) leftOut = tail.held ? tail.frames : tail.listed() + tail.unfiltered();
    } else if (req.which === "marked") ranges = toRanges(this.state.marks.map((m) => m.frame));
    else if (req.which === "selected") ranges = this.selectedOrCurrent();
    else if (req.which === "range") ranges = parseRange(String(req.range ?? ""), known);
    else throw new Error(`unknown selection "${req.which}"`);
    if (!ranges.length) throw new Error("no packets to export");
    const frames = countRanges(ranges);
    // Packets of the live capture not read in full yet
    const read = this.state.totalFrames;
    const provisional = ranges.reduce((n, [a, b]) => n + Math.max(0, b - Math.max(a, read + 1) + 1), 0);
    // Comments as edited here, then marks, which Wireshark shows as packet comments
    const comments = new Map<number, FrameComments>();
    let marks = 0;
    let edited = 0;
    if (format === "pcapng") {
      for (const [f, e] of this.comments) {
        if (!inRanges(ranges, f)) continue;
        comments.set(f, { own: e.own < 0 ? false : e.own ? true : undefined, texts: e.list.slice(Math.max(e.own, 0)) });
        edited++;
      }
      for (const f of this.clearedFrames) if (!this.comments.has(f) && inRanges(ranges, f)) edited++;
      for (const m of req.markComments ? this.state.marks : []) {
        if (!inRanges(ranges, m.frame)) continue;
        const text = `WireBuddy mark (${m.by === "agent" ? this.state.agent.name : "user"})${m.note ? `: ${m.note}` : ""}`;
        const c = comments.get(m.frame);
        if (c) c.texts.push(text);
        else comments.set(m.frame, { own: true, texts: [text] });
        marks++;
      }
    }
    const [file, edit] = [this.commentsFile, this.commentEdit];
    const size = await exportFrames({ editcap: this.editcap, mergecap: this.mergecap, input, output: req.path, format, ranges, comments, cleared: this.cleared });
    // Every packet in pcapng: the comments edited until then are kept in a file
    if (format === "pcapng" && frames >= known && file === this.commentsFile) {
      for (const [f, e] of this.unexported) if (e <= edit) this.unexported.delete(f);
      if (this.clearedEdit <= edit) this.clearedEdit = 0;
      const edits = this.editCount();
      if (edits !== this.state.commentEdits) this.set({ commentEdits: edits });
    }
    if (by === "agent") {
      this.agentExports.add(resolve(req.path));
      this.notice(`Exported ${frames} packet${frames === 1 ? "" : "s"} to ${req.path}`);
    }
    return { path: req.path, frames, size, comments: marks, ...(edited ? { edited } : {}), ...(leftOut ? { leftOut } : {}), ...(provisional ? { provisional } : {}) };
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

  /** Files carried in the traffic (Wireshark's Export Objects) of `kind`. */
  async capturedObjects(kind: ObjectKind, engine = this.engine): Promise<CapturedObject[]> {
    this.requireFile();
    type Eo = { pkt: number; hostname?: string; type?: string; filename?: string; _download: string; len: number; sha1?: string };
    const r = await engine.call<{ taps?: { objects?: Eo[] }[] }>("tap", { tap0: `eo:${kind}` });
    return (r.taps?.[0]?.objects ?? []).map((o) => ({
      frame: o.pkt,
      host: o.hostname ?? "",
      type: o.type ?? "",
      filename: o.filename ?? "",
      size: o.len,
      sha1: o.sha1 ?? "",
      token: o._download,
    }));
  }

  /**
   * Saves the objects of `kind` into a new folder in `dir`, made once there is
   * one to save: those `pick.keys` ("frame:sha1") name, else those in
   * `pick.frames`, else all.
   */
  async saveObjects(
    kind: ObjectKind,
    pick: { frames?: number[]; keys?: string[] },
    dir: string,
    by: "user" | "agent",
  ): Promise<{ folder: string | null; saved: (CapturedObject & { name: string })[]; skipped: { object: CapturedObject; reason: string }[] }> {
    const codeFolders = this.extensions.codeFolders();
    const real = objectDir(dir, codeFolders);
    // Download tokens belong to the sharkd that listed the objects
    const engine = this.engine;
    const all = await this.capturedObjects(kind, engine);
    const key = (o: CapturedObject): string => `${o.frame}:${o.sha1}`;
    let chosen: CapturedObject[];
    if (pick.keys) {
      const listed = new Set(all.map(key));
      // A key that names nothing came from another capture or dissection
      if (pick.keys.some((k) => !listed.has(k))) throw new StaleGenerationError("the capture changed; list the objects again");
      const want = new Set(pick.keys);
      chosen = all.filter((o) => want.has(key(o)));
    } else {
      const want = pick.frames && new Set(pick.frames);
      chosen = want ? all.filter((o) => want.has(o.frame)) : all;
    }
    if (!all.length) throw new Error(`the capture has no ${kind} objects`);
    if (!chosen.length) throw new Error(`none of the ${kind} objects is in the given frames`);
    let folder: string | null = null;
    const saved: (CapturedObject & { name: string })[] = [];
    const skipped: { object: CapturedObject; reason: string }[] = [];
    let total = 0;
    try {
      for (const o of chosen) {
        // Without one, a token a reload moved would save another object unnoticed
        if (!o.sha1) {
          skipped.push({ object: o, reason: "sharkd gave no checksum to check it by" });
          continue;
        }
        if (o.size > MAX_OBJECT_SAVE) {
          skipped.push({ object: o, reason: `larger than ${MAX_OBJECT_SAVE / 2 ** 20} MiB` });
          continue;
        }
        if (total + o.size > MAX_OBJECTS_SAVE) {
          skipped.push({ object: o, reason: `over the ${MAX_OBJECTS_SAVE / 2 ** 30} GiB one save may write` });
          continue;
        }
        const r = await engine.call<{ data?: string }>("download", { token: o.token });
        const data = Buffer.from(r.data ?? "", "base64");
        // Tokens are positions in sharkd's list: a reload may have moved them
        if (r.data === undefined || createHash("sha1").update(data).digest("hex") !== o.sha1) {
          throw new Error("the capture changed while saving; list the objects again");
        }
        total += data.length;
        folder ??= newObjectFolder(real, kind, codeFolders);
        saved.push({ ...o, name: writeObject(folder, objectFileName(o.frame, o.filename), data) });
      }
    } catch (err) {
      // What is already there stays: say where
      const names = saved.slice(0, 20).map((o) => o.name).join(", ") + (saved.length > 20 ? ", …" : "");
      const done = saved.length ? ` (${saved.length} saved to ${folder}: ${names})` : "";
      throw new Error(`${(err as Error).message}${done}`);
    }
    if (saved.length && by === "agent") this.notice(`Saved ${saved.length} ${kind.toUpperCase()} object${saved.length === 1 ? "" : "s"} to ${folder}`);
    return { folder, saved, skipped };
  }

  /** Opens the capture in Wireshark; returns what doesn't go along, or null. */
  async openInWireshark(frame?: number | null): Promise<string | null> {
    this.requireFile();
    if (!this.wiresharkBin) throw new Error("wireshark was not found on PATH");
    // One window per click, not one per repeated request
    if (Date.now() - this.wiresharkAt < WIRESHARK_GAP_MS) throw new Error("Wireshark is already starting");
    this.wiresharkAt = Date.now();
    const args = ["-r", this.state.file!];
    if (this.profile) args.push("-C", this.profile);
    if (this.state.tlsKeylog) args.push("-o", `tls.keylog_file:${this.state.tlsKeylog}`);
    // Wireshark has none of the view's time references: frame.ref_time goes as their frame numbers
    if (this.state.filter) args.push("-Y", this.sharkdFilter(this.state.filter));
    const target = frame ?? this.state.selected;
    if (target) args.push("-g", String(target));
    await launchWireshark(this.wiresharkBin, args, this.extensions.env());
    const { entries } = this.state.decodeAs;
    return entries.length ? `WireBuddy's Decode As entries don't go along (${entries.map(entryText).join(", ")}); use Analyze › Decode As in Wireshark` : null;
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

  /** Extensions as the UI lists them. */
  extensionList(): ExtensionList {
    const list = this.extensions.listing();
    for (const e of list.extensions) {
      if (!e.panel) continue;
      const bad = this.offerErrors.get(e.name);
      if (bad) e.panel.offerError = `invalid offer filter "${bad.filter}": ${bad.error}`;
      if (!this.panels.isOpen(e.name)) continue;
      e.panel.open = true;
      e.panel.stale = this.panels.report(e.name, false).stale;
    }
    return list;
  }

  /**
   * Checks the offers of enabled panels against the open capture (`all`: also
   * the ones matched already): each filter is checked, then whether a packet
   * matches it (see offerMatches). Matches show as panelOffers.
   */
  private checkOffers(all: boolean): Promise<void> {
    const seq = ++this.offerSeq;
    if (this.offerTimer) clearTimeout(this.offerTimer);
    this.offerTimer = null;
    this.offerRun = this.offerPass(seq, all).catch((err) => {
      if (seq !== this.offerSeq) return;
      this.showOffers();
      // Another file or extensions meanwhile: the pass that follows checks again
      if (!(err instanceof ApiError && ["stale", "busy", "no-capture", "gone"].includes(err.code))) this.events.add("WARNING", `Checking the panels' offers failed: ${printable((err as Error).message)}`);
    });
    return this.offerRun;
  }

  private async offerPass(seq: number, all: boolean): Promise<void> {
    const file = this.state.file;
    if (file !== this.offerFile) {
      this.offerFile = file;
      this.offerMatched.clear();
      this.offerDismissed.clear();
      this.showOffers();
    }
    const offers = this.extensions.offers();
    // Offers gone or changed since are no offers any more
    for (const [name, m] of this.offerMatched) if (!offers.some((o) => o.name === name && o.filter === m.filter)) this.offerMatched.delete(name);
    for (const [name, e] of this.offerErrors) if (!offers.some((o) => o.name === name && o.filter === e.filter)) this.offerErrors.delete(name);
    const valid: typeof offers = [];
    for (const o of offers.filter((x) => all || !this.offerMatched.has(x.name))) {
      const check = await this.checkFilter(o.filter);
      if (seq !== this.offerSeq) return;
      if (check.ok) {
        this.offerErrors.delete(o.name);
        valid.push(o);
        continue;
      }
      const error = check.error ?? "invalid";
      if (this.offerErrors.get(o.name)?.error !== error) this.events.add("WARNING", `The offer filter "${o.filter}" of the panel "${o.name}" is invalid, so it is never offered: ${error}`);
      this.offerErrors.set(o.name, { filter: o.filter, error });
      this.offerMatched.delete(o.name);
    }
    if (file && this.state.totalFrames > 0 && valid.length) {
      const found = await this.offerMatches(file, valid.map((o) => o.filter), () => seq === this.offerSeq);
      if (seq !== this.offerSeq || this.state.file !== file) return;
      for (const o of valid) {
        // Not checked this time: as it was
        if (!found.has(o.filter)) continue;
        if (found.get(o.filter)) this.offerMatched.set(o.name, { offer: { name: o.name, label: o.label, text: o.text }, filter: o.filter });
        else this.offerMatched.delete(o.name);
      }
    }
    this.showOffers();
    // A live capture may bring matching packets later
    if (file && this.capture.running && this.followingCapture() && offers.some((o) => !this.offerMatched.has(o.name) && !this.offerErrors.has(o.name))) {
      this.offerTimer = setTimeout(() => {
        this.offerTimer = null;
        if (this.capture.running && this.followingCapture()) void this.checkOffers(false);
      }, OFFER_LIVE_MS);
      this.offerTimer.unref();
    }
  }

  /**
   * Which of `filters` match a packet of `file`. Of a live capture, from
   * slices of the live tail: each filter from the frame it was found in none
   * up to on. Without a tail, and for filters slices can't check (see
   * heldReason), by the panel engine reading the whole file, which waits
   * while memory is short during a capture. Only while `wanted`.
   */
  private async offerMatches(file: string, filters: string[], wanted: () => boolean): Promise<Map<string, boolean>> {
    const { epoch } = this.state;
    if (this.offerChecked.file !== file || this.offerChecked.epoch !== epoch) this.offerChecked = { file, epoch, to: new Map() };
    const checked = this.offerChecked.to;
    const found = new Map<string, boolean>();
    // Those found are checked from the start again: their match may lie before `to`
    const advance = (fs: string[], to: number): void => {
      if (this.offerChecked.to !== checked || !wanted()) return;
      for (const f of fs) if (!found.get(f)) checked.set(f, Math.max(checked.get(f) ?? 0, to));
    };
    const held = new Set<string>();
    for (const f of filters) if (await this.heldReason(f)) held.add(f);
    const tail = this.tail?.file === file && !this.tail.broken() ? this.tail : null;
    const sliced = tail ? filters.filter((f) => !held.has(f)) : [];
    if (tail && sliced.length) {
      try {
        const r = await tail.anyMatch(sliced, (f) => (checked.get(f) ?? 0) + 1, wanted);
        this.tailWorked(tail);
        if (!wanted()) return found;
        for (const f of sliced) found.set(f, r.found.has(f));
        advance(sliced, r.to);
      } catch (err) {
        // The live tail went, broke or failed: the whole file says
        if (!(err instanceof Superseded)) this.tailFailed(tail, err as Error);
      }
    }
    const whole = filters.filter((f) => !found.has(f));
    if (whole.length && wanted() && !(this.capture.running && this.memoryShort())) {
      // Slices check them next time: the panel engine needn't keep the file
      const release = this.capture.running && whole.every((f) => !held.has(f));
      const { matches, frames } = await this.panelData.anyMatch(whole, release);
      for (const f of whole) found.set(f, matches.get(f) ?? false);
      advance(whole, frames);
    }
    return found;
  }

  /** The matched offers the user sees: not of open panels, not dismissed. */
  private showOffers(): void {
    const offers = this.shownOffers();
    if (JSON.stringify(offers) !== JSON.stringify(this.state.panelOffers)) this.set({ panelOffers: offers });
  }

  private shownOffers(): PanelOffer[] {
    const offers = [...this.offerMatched.values()].map((m) => m.offer).filter((o) => !this.panels.isOpen(o.name) && !this.offerDismissed.has(o.name));
    return offers.sort((a, b) => a.name.localeCompare(b.name));
  }

  /** The user dismissed a panel's offer: not offered again for this file. */
  dismissOffer(name: string): void {
    this.offerDismissed.add(name);
    this.showOffers();
  }

  /** Panels offered for the open capture, once a check that runs now is done (or after `ms`). */
  async matchedOffers(ms = 5000): Promise<PanelOffer[]> {
    let timer: NodeJS.Timeout | undefined;
    await Promise.race([this.offerRun, new Promise<void>((done) => (timer = setTimeout(done, ms)))]);
    clearTimeout(timer);
    return this.shownOffers();
  }

  /**
   * A panel's change to the view (wb.select, wb.setFilter), sent by the page
   * after a click in that panel: made as the user's, with a notice, and told
   * to the agent. Refusals throw an ApiError with the code the panel gets.
   */
  async panelAct({ name, label, m, a, clicked }: PanelAct): Promise<{ ok: true }> {
    if (m !== "select" && m !== "setFilter") throw new ApiError(400, "bad-args", "a panel can only select a frame or set the display filter");
    const title = this.panels.allow(name, label, m, clicked === true);
    if (m === "select") {
      if (typeof a !== "number" || !Number.isInteger(a) || a < 1 || a > this.known()) throw new ApiError(400, "bad-args", `wb.select: no frame ${printable(String(a)).slice(0, 40)} in this capture`);
      this.select(a, "user");
      // The packet list scrolls to it, as to the agent's selections
      this.set({ selectSeq: this.state.selectSeq + 1 });
      this.notice(`Panel "${title}" selected frame ${a}`);
      this.panels.acted(name, `selected frame ${a}`);
      return { ok: true };
    }
    if (typeof a !== "string" || a.length > 4096) throw new ApiError(400, "bad-args", "wb.setFilter takes a display filter of at most 4 KiB");
    const filter = a.trim();
    const check = await this.setFilter(filter, "user");
    if (!check.ok) throw new ApiError(400, "filter", `invalid display filter "${printable(filter).slice(0, 200)}": ${check.error ?? "invalid"}`);
    const did = filter ? `applied the display filter "${printable(filter).slice(0, 200)}"` : "cleared the display filter";
    this.notice(`Panel "${title}" ${did}`);
    this.panels.acted(name, did);
    return { ok: true };
  }

  /** Re-counts active and failing extensions for the status bar. */
  refreshExtensions(): void {
    const active = this.extensions.active();
    const failing = this.extensions.failing();
    if (active !== this.state.extensions.active || failing !== this.state.extensions.failing) this.set({ extensions: { ...this.state.extensions, active, failing } });
  }

  private luaReport(report: LuaReport): void {
    if (report.crashedIn) this.extensionCrashes++;
    for (const e of this.extensions.report(report)) this.events.add(e.level, e.text);
    this.refreshExtensions();
  }

  /**
   * Loads the extensions as they are on disk now (with `change`: switches
   * just that one) and re-dissects the open capture; the view keeps its
   * selection and marks. If sharkd then crashes reading the capture, the view
   * keeps the extensions it had.
   */
  reloadExtensions(change?: { name: string; on: boolean }): Promise<void> {
    if (this.extensions.unavailable) return Promise.reject(new Error(`extensions are unavailable: ${this.extensions.unavailable}`));
    return this.exclusive(async () => {
      if (change) this.extensions.include(change.name, change.on);
      else this.extensions.refresh();
      this.forgetLuaErrors();
      // Panels wait until the view reads with the new extensions, then start over
      this.panelData.hold(true);
      const filter = this.state.filter;
      let rolledBack: RollBack = false;
      try {
        if (this.state.file) {
          const r = await this.reloadNow(true, true, true);
          rolledBack = r.rolledBack;
          // A filter on a protocol whose extension is gone now
          if (r.dropped) this.events.add("WARNING", `The display filter "${filter}" doesn't apply with the extensions as they are now and was cleared`);
        } else {
          const fresh = this.engines[1 - this.active];
          await this.crashRetries(async () => {
            await this.current(fresh);
            await fresh.call("status");
          });
          this.active = 1 - this.active;
          this.forgetTypes();
        }
      } finally {
        this.set({ extensions: { ...this.state.extensions, revision: this.state.extensions.revision + 1 }, epoch: this.newEpoch("extensions") });
        this.panelData.hold(false);
        this.refreshExtensions();
        void this.checkOffers(true);
      }
      if (rolledBack) {
        // Going back without the one switched on fixed it: it stays off
        const culprit = change?.on && rolledBack === "reverted";
        if (culprit) this.extensions.setEnabled(change.name, false, "sharkd crashed reading the capture with it");
        this.refreshExtensions();
        throw new ReportedError(
          culprit
            ? `"${change.name}" crashed sharkd reading the capture and stays off`
            : rolledBack === "reverted"
              ? "sharkd crashed reading the capture with the extensions as they are now, so the view keeps the ones it had"
              : "sharkd crashed reading the capture with the extensions, so the view runs without extensions until they are reloaded",
        );
      }
      await this.engine.luaLoaded();
      this.refreshExtensions();
    });
  }

  async setExtensionEnabled(name: string, on: boolean): Promise<void> {
    this.extensions.check(name, on);
    this.extensions.setEnabled(name, on);
    if (!on) this.panels.close(name);
    // A panel alone needs no sharkd restart
    if (on && !this.extensions.list().find((e) => e.name === name)?.lua) {
      this.refreshExtensions();
      void this.checkOffers(true);
      return;
    }
    await this.reloadExtensions({ name, on });
  }

  /** An extension failed on a packet while a file was read: the agent hears about new ones in batches. */
  private luaError(e: LuaError): void {
    const s = this.luaErrs;
    if (e.file !== s.file) {
      this.tellLuaErrors();
      this.forgetLuaErrors(e.file);
    }
    if (e.frame === 0) s.more = true;
    else if (!s.frames.has(e.frame) && s.frames.size < 100_000) {
      s.frames.add(e.frame);
      if (!s.example || e.frame < s.example.frame) s.example = e;
    }
    // Once they stop coming for 1.5 s (a looping dissector takes 1 s per packet), at most 8 s after the first
    if (s.timer) clearTimeout(s.timer);
    else s.since = Date.now();
    s.timer = setTimeout(() => this.tellLuaErrors(), Math.max(0, Math.min(1500, s.since + 8000 - Date.now())));
  }

  private tellLuaErrors(): void {
    const s = this.luaErrs;
    s.timer = null;
    const n = s.frames.size - s.told;
    if (n <= 0 || !s.example) return;
    const what = `${s.told ? `${n} more packet${n === 1 ? "" : "s"}` : `${n}${s.more ? "+" : ""} packet${n === 1 ? "" : "s"}`} of ${basename(s.file)}`;
    this.events.add("ERROR", `Lua errors in ${what}, e.g. frame ${s.example.frame}: ${printable(s.example.message)} — fix the extension, check it with extensions(action "test"), then reload`);
    s.told = s.frames.size;
    s.example = null;
  }

  /** New code or another file: its errors are all new. */
  private forgetLuaErrors(file = this.state.file ?? ""): void {
    const s = this.luaErrs;
    if (s.timer) clearTimeout(s.timer);
    Object.assign(s, { file, frames: new Set<number>(), more: false, told: 0, example: null, timer: null });
  }

  /** Loads one extension into a separate sharkd with the open capture and reports what it decodes. */
  async testExtension(name: string): Promise<ExtensionTest> {
    if (this.extensions.unavailable) throw new Error(`extensions are unavailable: ${this.extensions.unavailable}`);
    const file = this.state.file;
    const enabled = this.extensions.list().find((e) => e.name === name)?.enabled ?? false;
    const result: ExtensionTest = { name, enabled, load: "", protocols: [], sample: null, luaErrors: [], luaErrorCount: 0, file, hierarchy: [] };
    const { env, done } = this.extensions.testEnv(name);
    const sharkd = new Sharkd(this.sharkdBin, this.profile, () => env);
    try {
      const started = sharkd.call("status").catch(() => {});
      const report = await sharkd.luaLoaded();
      await started;
      const failed = report?.failed.find((f) => f.name === name);
      const loaded = report?.loaded.find((l) => l.name === name);
      if (!report || report.crashedIn === name) result.load = "sharkd crashed while loading it";
      else if (failed) result.load = `error: ${printable(failed.error)}${failed.protocols.length ? ` (it registered ${failed.protocols.join(", ")} before the error; tested anyway)` : ""}`;
      else if (!loaded) result.load = "it did not load (no report from the loader)";
      else result.load = "loaded";
      // What a failed extension registered before its error works all the same
      const protocols = loaded?.protocols ?? failed?.protocols ?? [];
      if ((!loaded && !failed?.protocols.length) || !file) return result;
      for (const [name, value] of this.dissectPrefs) await sharkd.setPref(name, value);
      const load = await sharkd.call<{ status: string; err?: number }>("load", { file });
      if (load.status !== "OK" && load.err !== -12) throw new Error(`could not load ${file}: ${load.status}`);
      for (const proto of protocols) {
        try {
          const frames = await matchingFrames(sharkd, proto);
          result.protocols.push({ name: proto, frames: frames.length, first: frames.length ? frames[0] : null });
        } catch (err) {
          result.protocols.push({ name: proto, frames: 0, first: null, error: (err as Error).message });
        }
      }
      const hit = result.protocols.find((p) => p.first !== null);
      if (hit) {
        const frame = await sharkd.call<SharkdFrame>("frame", { frame: hit.first, proto: true });
        result.sample = { frame: hit.first!, protocol: hit.name, tree: frame.tree };
      }
      // No protocol of its own (e.g. Decode As): what the capture decodes as with it
      if (!protocols.length) {
        const phs = await sharkd.call<{ taps: { protos?: SharkdPhs[] }[] }>("tap", { tap0: "phs" });
        const leaves: string[] = [];
        const walk = (nodes: SharkdPhs[], path: string[]) => {
          for (const n of nodes) n.protos?.length ? walk(n.protos, [...path, n.proto]) : leaves.push(`${[...path, n.proto].join(" > ")}: ${n.frames} frames`);
        };
        walk(phs.taps[0]?.protos ?? [], []);
        result.hierarchy = leaves.slice(0, 12);
      }
      const errors = await luaErrors(sharkd);
      result.luaErrorCount = errors.length;
      result.luaErrors = errors.slice(0, 5);
    } catch (err) {
      result.crashed = (err as Error).message;
    } finally {
      sharkd.close();
      done();
    }
    return result;
  }

  shutdown(): void {
    this.capture.stop();
    this.capture.stopActivity();
    if (this.tailTimer) clearInterval(this.tailTimer);
    this.dropTail();
    for (const e of this.engines) e.close();
    this.panelData.close();
    this.extensions.close();
  }
}

/** Packets an extension's dissector failed on, from the expert items Lua errors leave. */
async function luaErrors(engine: Sharkd): Promise<{ frame: number; message: string }[]> {
  const r = await engine.call<{ taps: { details?: { f: number; m: string }[] }[] }>("tap", { tap0: "expert", filter: "_ws.lua.error" });
  const seen = new Set<number>();
  const out: { frame: number; message: string }[] = [];
  for (const d of r.taps[0]?.details ?? []) {
    if (!d.m.startsWith("Lua Error") || seen.has(d.f)) continue;
    seen.add(d.f);
    out.push({ frame: d.f, message: printable(d.m.replace(/^Lua Error: /, "")) });
  }
  return out.sort((a, b) => a.frame - b.frame);
}

/** A frame's streams as [protocol, filter]. */
function followersOf(f: SharkdFrame): [string, string][] {
  return (f.followers ?? (f.fol ?? []).map(([protocol, filter]) => ({ protocol, filter })))
    .filter((x) => x.filter)
    .map((x) => [x.protocol, x.filter!] as [string, string]);
}

/** sharkd custom columns: column0..N as "<field>:0" (all occurrences). */
function columnParams(fields: string[]): Record<string, string> {
  return Object.fromEntries(fields.map((f, i) => [`column${i}`, `${f}:0`]));
}

function clip(value: string): string {
  return value.length > MAX_COLUMN_VALUE ? value.slice(0, MAX_COLUMN_VALUE - 1) + "…" : value;
}

/** A packet comment as editcap writes it: lines end in "\n", other control characters become "?". */
function commentText(text: string): string {
  if (text.length > MAX_COMMENT) throw new Error(`a packet comment holds at most ${MAX_COMMENT} characters`);
  return text.replace(/\r\n?/g, "\n").replace(/[\u0000-\u0009\u000b-\u001f\u007f-\u009f\u2028\u2029]/g, "?");
}

/** "frame 4" or "3 frames". */
function frameCount(frames: number[]): string {
  return frames.length === 1 ? `frame ${frames[0]}` : `${frames.length} frames`;
}

/** A comment in a notice: one line, short. */
function noticeText(text: string): string {
  const line = printable(text.replace(/\n/g, " "));
  return line.length > 80 ? `${line.slice(0, 79)}…` : line;
}

/**
 * Wireshark's "Packet comments" node: a comment of several lines shows its
 * first line, and each line under it. `ett`: the expansion ids of the node
 * and of its comments.
 */
export function commentTree(comments: string[], ett: { node: number; item: number }): TreeNode {
  const line = (text: string): TreeNode => ({ l: labelText(text), f: `frame.comment == ${filterString(text)}`, fn: "frame.comment" });
  const comment = (text: string): TreeNode => {
    const lines = text.split("\n");
    if (lines.length === 1) return { ...line(text), s: "Comment", e: ett.item, n: [] };
    if (lines[lines.length - 1] === "") lines.pop();
    const n = lines.slice(0, COMMENT_LINES).map(line);
    if (lines.length > COMMENT_LINES) n.push({ l: `[comment truncated at ${COMMENT_LINES} lines]`, f: 'frame.comment == ""', fn: "frame.comment" });
    return { ...line(lines[0]), l: labelText(`${lines[0]} [...]`), s: "Comment", e: ett.item, n };
  };
  return { l: "Packet comments", t: "proto", f: "pkt_comment", fn: "pkt_comment", s: "Comment", e: ett.node, n: comments.map(comment) };
}

/** Escapes of control characters, as Wireshark writes them. */
const ESCAPES: Record<string, string> = { "\u0007": "a", "\b": "b", "\f": "f", "\n": "n", "\r": "r", "\t": "t", "\v": "v" };

/**
 * `text` as sharkd labels it: control characters escaped (\t, \x01, \u0085),
 * and cut to Wireshark's label length as proto.c does, behind "[…] ".
 */
function labelText(text: string): string {
  const label = text.replace(/[\u0000-\u001f\u007f-\u009f]/g, (c) => {
    const code = c.charCodeAt(0);
    return `\\${ESCAPES[c] ?? `${code < 0x80 ? "x" : "u00"}${code.toString(16).toUpperCase().padStart(2, "0")}`}`;
  });
  const bytes = Buffer.from(label);
  if (bytes.length < ITEM_LABEL_LENGTH) return label;
  // The mark goes first, and the last character in the buffer, whole or not, goes
  const cut = Buffer.concat([Buffer.from("[…] "), bytes.subarray(0, ITEM_LABEL_LENGTH - 6)]);
  let end = ITEM_LABEL_LENGTH - 1;
  while (end > 0 && (cut[end] & 0xc0) === 0x80) end--;
  return cut.subarray(0, end).toString();
}

/** `text` as a display filter string, escaped as Wireshark does. */
function filterString(text: string): string {
  return `"${text.replace(/[\u0007\b\f\n\r\t\v\\"]/g, (c) => `\\${ESCAPES[c] ?? c}`)}"`;
}

/** Whether ascending `frames` hold `f`. */
function hasFrame(frames: Int32Array, f: number): boolean {
  let lo = 0;
  let hi = frames.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (frames[mid] === f) return true;
    if (frames[mid] < f) lo = mid + 1;
    else hi = mid - 1;
  }
  return false;
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
function startsWith(after: { length: number; at: (i: number) => number }, before: { length: number; at: (i: number) => number }): boolean {
  if (after.length < before.length) return false;
  for (let i = 0; i < before.length; i++) if (before.at(i) !== after.at(i)) return false;
  return true;
}

/**
 * Whether a sharkd reading `next` frames needs more memory than is
 * `available`, beyond what the standby holds already: as much a frame as the
 * active one needs, which read `frames`.
 */
export function memoryShort(m: { activeBytes: number; frames: number; standbyBytes: number; next: number; available: number }): boolean {
  if (!m.frames) return false;
  const perFrame = Math.max(0, m.activeBytes - SHARKD_BASE_BYTES) / m.frames;
  return SHARKD_BASE_BYTES + perFrame * m.next - m.standbyBytes > m.available - MEMORY_MARGIN;
}

/** Resident memory of a process (Linux), or null. */
function rssBytes(pid: number | null): number | null {
  if (!pid) return null;
  try {
    const kb = /^VmRSS:\s+(\d+) kB/m.exec(readFileSync(`/proc/${pid}/status`, "utf8"));
    return kb ? Number(kb[1]) * 1024 : null;
  } catch {
    return null;
  }
}

/** Memory the system can still give out (Linux), or null; WIREBUDDY_MEM_AVAILABLE (bytes) stands in for it in tests. */
function availableBytes(): number | null {
  const fake = Number(process.env.WIREBUDDY_MEM_AVAILABLE);
  if (fake > 0) return fake;
  try {
    const kb = /^MemAvailable:\s+(\d+) kB/m.exec(readFileSync("/proc/meminfo", "utf8"));
    return kb ? Number(kb[1]) * 1024 : null;
  } catch {
    return null;
  }
}

export const CAPTURE_FILE = /\.(pcapng|pcap|cap|ntar|erf|snoop|trc|dmp)(\.(gz|zst|lz4))?$/i;

/** pcap (both byte orders, µs and ns), pcapng, snoop and Network Monitor 2 files start with these. */
const CAPTURE_MAGIC = ["a1b2c3d4", "d4c3b2a1", "a1b23c4d", "4d3cb2a1", "0a0d0d0a", "736e6f6f70000000", "474d4255"];

/**
 * Keeps open() to capture files, by content (also inside gzip and zstd), so it
 * can't be used to read arbitrary files: names prove nothing.
 */
async function looksLikeCapture(file: string): Promise<boolean> {
  const head = (await firstBytes(file, 8)).toString("hex");
  const inner = head.startsWith("1f8b") ? createGunzip() : head.startsWith("28b52ffd") && typeof createZstdDecompress === "function" ? createZstdDecompress() : null;
  const hex = inner ? (await firstBytes(file, 8, inner)).toString("hex") : head;
  return CAPTURE_MAGIC.some((m) => hex.startsWith(m));
}

/** The first `n` bytes of `file`, through `transform` if given; fewer when it is shorter or broken. */
function firstBytes(file: string, n: number, transform?: Transform): Promise<Buffer> {
  return new Promise((done) => {
    const src = createReadStream(file, transform ? {} : { start: 0, end: n - 1 });
    const out = transform ? src.pipe(transform) : src;
    const chunks: Buffer[] = [];
    let len = 0;
    let finished = false;
    const finish = (): void => {
      if (finished) return;
      finished = true;
      src.destroy();
      transform?.destroy();
      done(Buffer.concat(chunks).subarray(0, n));
    };
    out.on("data", (c: Buffer) => {
      chunks.push(c);
      len += c.length;
      if (len >= n) finish();
    });
    out.on("end", finish);
    out.on("error", finish);
    src.on("error", finish);
  });
}

/** The first bytes of a file: a capture that only grows keeps them. */
function fileHead(file: string): Buffer {
  let fd = -1;
  try {
    fd = openSync(file, "r");
    const buf = Buffer.alloc(4096);
    return buf.subarray(0, readSync(fd, buf, 0, buf.length, 0));
  } catch {
    return Buffer.alloc(0);
  } finally {
    if (fd >= 0) closeSync(fd);
  }
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
