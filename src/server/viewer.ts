import { EventEmitter } from "node:events";
import { statSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { COLUMN_FIELD, matchingFrames, page, Sharkd, type LuaReport } from "./sharkd.ts";
import { Capture } from "./capture.ts";
import { fileHead, looksLikeCapture, safeSize } from "./capturefile.ts";
import { commentsOf, withCommentNode, withComments, type CommentsView, type EditedComments } from "./comments.ts";
import { applyChange, closeMatches, countFilter, parseChange, parseStatus, serialize, type EntryStatus } from "./decodeas.ts";
import { EngineSession, RESTART_WAIT_MS, type LoadResult, type RollBack, type SharkdStatus } from "./enginesession.ts";
import { checkTarget, exportFrames, parseRange, toRanges, type FrameComments } from "./export.ts";
import { commentAt, commentText, displayedMarks, EDIT_LIMITS, Edits, frameList, markNode, marksWith, marksWithout, MAX_COMMENTED, refsChange, refsWith, toggledMarks, toggledRefs, usesFrameNumber } from "./edits.ts";
import { EventLog, ReportedError } from "./events.ts";
import { aboutText, answered, openQuestion, withQuestion } from "./questions.ts";
import { otherCapture } from "../shared/questions.ts";
import { setHint } from "./filterhints.ts";
import { buildFindings, checkReportTarget, MAX_LISTED, writeReport, type CommentedPacket, type MarkedPacket, type RowSummary } from "./findings.ts";
import { checkSummary } from "./markdown.ts";
import { Extensions } from "./extensions.ts";
import { keptSummary, pruneInvestigations } from "./investigation.ts";
import { FT_FRAMENUM, heldReason, LiveTail, removeStaleSlices, streamNumbered, Superseded, type Numbering, type RowView } from "./livetail.ts";
import { availableBytes, memoryShort, rssBytes } from "./memory.ts";
import { ApiError, FrameSet, PanelData, type PanelSource } from "./paneldata.ts";
import type { CapturedObject, ObjectKind } from "./objects.ts";
import { clashKind } from "./protoclash.ts";
import { Keeper, type KeptRead } from "./keeper.ts";
import { MAX_RECENT, parseColumns, parseRecent, readSetting, writeSetting } from "./settings.ts";
import { LuaErrors } from "./luaerrors.ts";
import { PanelOffers } from "./offers.ts";
import { PacketList, clipRanges, listChanged, type AboutView, rowOf, rowSelection, startsWith, type ListView } from "./packetlist.ts";
import { Panels } from "./panels.ts";
import { StaleGenerationError } from "./stale.ts";
import { conversations, endpoints, expert, find, frameAt, ioGraph, phs, type ConvType, type StatsView } from "./stats.ts";
import { FOLLOW_LIMIT, capturedObjects, carriesTls, follow, saveObjects, type StreamsView } from "./streams.ts";
import { printable } from "./text.ts";
import { changeText, framesWithRefs, refBefore, refsOf, refTimeError, refTimeFilter, usesRefTime, type RowRefs } from "./timerefs.ts";
import { initialState, ViewStore } from "./viewstore.ts";
import { openInWireshark } from "./wireshark.ts";
import { entryText } from "../shared/decodeas.ts";
import { VERSION } from "../shared/version.ts";
import { countRanges, framesFilter, inRanges, mergeRanges, type Ranges } from "../shared/ranges.ts";
import type {
  AskResult,
  Question,
  NowResult,
  ConvRow,
  CaptureState,
  CustomColumn,
  DecodeAsResult,
  EndpointRow,
  ExpertItem,
  ExtensionList,
  ExportRequest,
  ExportResult,
  FindingsRequest,
  FindingsResult,
  FindingsSummary,
  FilterCheck,
  ForgetResult,
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
  /** Packets still showing as undecoded payload ("data"), and, for an extension dissecting over TCP, segments of messages reassembled in a later packet (null: not over TCP). */
  undecoded?: { data: number; segments: number | null };
  /** A protocol of the extension has the description or name of one in a Wireshark plugin of the user's, or in another extension: which of the two failed to load, and what it clashes with (null: not found). */
  clash?: { kind: "description" | "name"; with: { plugin: string } | { extension: string } | null; failed: "extension" | "plugin" };
}

/** A sharkd "frames" row: commented packets carry their comments. */
export type SharkdRow = PacketRow & { comments?: string[] };

interface SharkdFrame {
  tree: TreeNode[];
  bytes?: string;
  ds?: { name: string; bytes: string }[];
  followers?: { protocol: string; filter: string | null; stream?: number }[];
  /** Older sharkd versions only send this form. */
  fol?: [string, string | null][];
}

export interface SharkdPhs {
  proto: string;
  frames: number;
  bytes: number;
  protos?: SharkdPhs[];
}

const LIVE_RELOAD_MS = 1000;
const MAX_QUESTION = 2000;
/** What a QUESTION event tells the agent about answering. */
const answerHow = (id: number): string => `question ${id}: answer in the chat and with answer_question, so the user sees it in the page`;
/** Longest frame set a question to the agent lists. */
const MAX_QUESTION_FRAMES = 2000;
/** Longest span a held Now flags. */
const MAX_NOW_MS = 10 * 60 * 1000;
/** After a Now, how long the live file may take to get a packet from after it (dumpcap writes within about half a second). */
const NOW_FILE_MS = 2000;
/** And the view to know the packets it flagged. */
const NOW_VIEW_MS = 5000;
/** How far back a tapped Now has the agent look. */
const NOW_BACK_S = 10;
/** A release time from the page further back than this is another machine's clock (requests may wait in the browser). */
const NOW_CLOCK_MS = 5000;
const MAX_CUSTOM_COLUMNS = 10;
/** Longer custom column values (e.g. whole payloads) are cut to this. */
const MAX_COLUMN_VALUE = 500;
const FIELD_NAME = /^[A-Za-z0-9_][A-Za-z0-9_.-]*$/;
/** Live reloads that fail in a row before they pause. */
const MAX_LIVE_FAILURES = 3;
/** Once a live full read takes this long, newer packets are listed provisionally until it lands. */
const TAIL_AFTER_MS = 1000;
/** Between two reports of failing provisional rows. */
const TAIL_PROBLEM_MS = 60_000;
/** Provisional rows, details or filter passes that fail in a row before the tail is turned off. */
const MAX_TAIL_FAILURES = 3;
/** Most new provisional rows read before the list shows them: what a page request asks for at most. */
const WARM_ROWS = 500;
/** How long after a client last asked for the list's newest rows the rows it gains are still read ahead. */
const FOLLOWED_MS = 3000;
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
  /** The sharkd pair, loading into it, and the queue state-changing work runs in. */
  private readonly session: EngineSession;
  /** Files the agent exported or wrote as findings reports in this session: the only ones it may overwrite. */
  private readonly agentExports = new Set<string>();
  private wiresharkAt = 0;
  /** Lua dissector extensions sharkd and Wireshark load. */
  readonly extensions: Extensions;
  /** Extensions' panels open in the UI. */
  readonly panels: Panels;
  /** The sharkd panels read the capture with. */
  private readonly panelData: PanelData;
  /** Why the epoch changed last, for the panels' reset. */
  private epochWhy = "file";
  /** Inode and first bytes of the file read last: another file at the same path, or other first bytes, is a rewritten capture. */
  private loadedIno = 0;
  private loadedHead: Buffer = Buffer.alloc(0);
  private readonly sharkdBin: string;
  /** Problems and user activity for the agent. */
  readonly events = new EventLog(
    (pending) => this.store.set({ agent: { ...this.state.agent, pending } }),
    (watching) => this.store.set({ agent: { ...this.state.agent, watching } }),
  );
  /** The frames the display filter shows, and which row is which frame. */
  private readonly list = new PacketList();
  private reloadTimer: NodeJS.Timeout | null = null;
  private liveFailures = 0;
  private loadedSize = -1;
  private noticeId = 0;
  private questionId = 0;
  private readonly wiresharkBin: string | null;
  private readonly profile: string | undefined;
  private readonly editcap: string;
  private readonly mergecap: string;
  /** Lua errors of the open file, told to the agent in batches. */
  private readonly luaBatches = new LuaErrors({
    file: () => this.state.file,
    report: (text) => this.events.add("ERROR", text),
  });
  /** The panels offered for the open file. */
  private readonly offers = new PanelOffers({
    state: () => this.state,
    set: (patch) => this.store.set(patch),
    offers: () => this.extensions.offers(),
    checkFilter: (filter) => this.checkFilter(filter),
    warn: (text) => this.events.add("WARNING", text),
    capturing: () => this.capture.running,
    followingCapture: () => this.followingCapture(),
    heldReason: (filter) => this.heldReason(filter),
    liveTail: () => this.tail,
    tailWorked: (tail) => this.tailWorked(tail),
    tailFailed: (tail, err) => this.tailFailed(tail, err),
    memoryShort: () => this.memoryShort(),
    anyMatch: (filters, release) => this.panelData.anyMatch(filters, release),
    isOpen: (name) => this.panels.isOpen(name),
  });
  /** What reading the comments asks of this viewer. */
  private readonly commentsView: CommentsView = {
    totalFrames: () => this.state.totalFrames,
    fileCommentsKnown: () => this.edits.fileCommentsKnown(this.loads),
    fileCommented: () => this.fileCommented(),
    engine: () => this.engine,
    listedTail: () => this.listedTail,
    rowView: () => this.rowView(),
  };
  /** The investigation kept for the open capture. */
  private readonly keeper = new Keeper({
    dir: () => this.investigations,
    state: () => this.state,
    set: (patch) => this.store.set(patch),
    investigation: () => this.edits.snapshot(this.state.marks, this.state.timeRefs),
    loadedHead: () => this.loadedHead,
    growing: (file) => this.capture.running && this.capture.state.currentFile === file,
    warn: (text) => this.events.add("WARNING", text),
  });
  /** Marks, time references and the packet comments edited here, of the open capture. */
  private readonly edits = new Edits({
    requireFile: () => this.requireFile(),
    revision: () => this.state.commentRevision,
  });
  /** What Follow Stream and Export Objects ask of this viewer. */
  private readonly streamsView: StreamsView = {
    engine: () => this.engine,
    requireFile: () => this.requireFile(),
    codeFolders: () => this.extensions.codeFolders(),
    notice: (text) => this.notice(text),
  };
  /** What the statistics and Find ask of this viewer. */
  private readonly statsView: StatsView = {
    engine: () => this.engine,
    state: () => this.state,
    requireFile: () => this.requireFile(),
    checkFilter: (filter) => this.checkFilter(filter),
    sharkdFilter: (filter) => this.sharkdFilter(filter),
    indexOf: (frame) => this.indexOf(frame),
  };
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
  /** When the last capture ended (0: none did). */
  private captureStoppedAt = 0;
  /** sharkd's etts of comment nodes, for the ones made here; others until it showed some. */
  private readonly commentEtts = { node: -1, item: -2 };
  /** Where the marks, time references and edited comments of each capture are kept; null: nowhere. */
  private readonly investigations: string | null;
  /** Where the custom columns and the recent files are kept (see settings.ts); null: nowhere. */
  private readonly settings: string | null;
  /** What keeping them already told the agent. */
  private readonly settingsTold = new Set<string>();
  readonly capture: Capture;
  readonly recent: string[] = [];

  private readonly store: ViewStore;

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
    /** WireBuddy's folder of investigations kept per capture (see investigation.ts); none without. */
    investigations?: string;
    /** WireBuddy's folder for the custom columns and recent files kept across restarts (see settings.ts); none without. */
    settings?: string;
  }) {
    super();
    this.extensions = opts.extensions ?? new Extensions();
    this.panels = new Panels(this.extensions, this.events, opts.panelRuntime ?? "");
    this.panels.on("change", () => {
      this.store.set({ panels: this.panels.list() });
      this.offers.showOffers();
    });
    this.sharkdBin = opts.sharkd ?? "sharkd";
    const env = () => this.extensions.env();
    const generation = () => this.extensions.generation;
    this.session = new EngineSession(
      () => new Sharkd(this.sharkdBin, opts.profile, env, generation),
      {
        onFailure: (message) => {
          // A dissector that crashes sharkd crashes every respawn that reads the same packets; a kill (memory) is no crash
          const crashed = message.startsWith("sharkd exited") && !message.startsWith("sharkd exited (SIGKILL)");
          const hint = this.extensions.any() && crashed ? " — if this repeats, an extension may crash it: test them with extensions(action \"test\") and disable the culprit" : "";
          this.events.add("WARNING", printable(message) + hint);
        },
        onLua: (report) => this.luaReport(report),
        onLuaError: (error) => this.luaBatches.luaError(error),
      },
      {
        extensions: this.extensions,
        cumulativeBytes: () => this.columnFormats.includes("%B"),
        problem: (text) => this.problem(text),
      },
    );
    const source: PanelSource = {
      view: () => this.panelView(),
      epoch: () => this.state.epoch,
      resetWhy: () => this.epochWhy,
      file: () => this.state.file,
      live: () => this.followingCapture() && this.capture.running,
      totalFrames: () => this.state.totalFrames,
      displayed: () => ({
        set: this.panelSet("displayed", [this.list.shown(), this.state.totalFrames], () => (this.list.shown() ? FrameSet.fromSorted(this.list.shown()!) : FrameSet.all(this.state.totalFrames))),
        filter: this.sharkdFilter(this.state.filter),
      }),
      selected: () => {
        const s = this.state;
        return this.panelSet("selected", [s.selectedRows, s.selected, this.list.shown(), s.displayedFrames], () =>
          s.selectedCount ? FrameSet.fromRows(clipRanges(s.selectedRows, s.displayedFrames), this.list.shown()) : FrameSet.fromSorted(s.selected === null ? [] : [s.selected]),
        );
      },
      marked: () => this.panelSet("marked", [this.state.marks], () => FrameSet.fromSorted(this.state.marks.map((m) => m.frame).sort((a, b) => a - b))),
      timeRefs: () => this.state.timeRefs,
      prefs: () => this.session.prefs(),
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
    this.store = new ViewStore(
      initialState({ capture: this.capture.state, wiresharkAvailable: !!this.wiresharkBin, decodeAsUnavailable: this.extensions.unavailable }),
      (state) => this.emit("state", state),
    );
    // Changed since it was last kept: not kept until the next save
    this.store.after((state) => (state.kept && this.keeper.changed() ? { ...state, kept: false } : state));
    this.capture.on("change", (capture: CaptureState) => {
      if (capture.status === "error" && this.state.capture.status !== "error") this.events.add("ERROR", `The capture failed: ${capture.error ?? "unknown error"}`, { iface: capture.iface });
      this.store.set({ capture });
    });
    this.capture.on("file", (file: string) => {
      // A new capture takes over the view; later ring files only if the view still follows it
      const { files, filesWritten } = this.capture.state;
      if (filesWritten === 1) removeStaleSlices(dirname(file));
      if (filesWritten > 1 && !this.followingCapture(files[files.length - 2])) return;
      this.open(file, filesWritten > 1).catch((err) => this.problem(`Live view: ${(err as Error).message}`));
      this.scheduleReload();
      this.tailTimer ??= setInterval(() => void this.tailTick(), LIVE_RELOAD_MS);
    });
    this.capture.on("note", (text: string) => this.events.add("INFO", text));
    this.capture.on("stopped", () => {
      this.captureStoppedAt = Date.now();
      // A capture shorter than the head that names it is kept once it stopped growing
      this.keeper.keepSoon();
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
        .then(() => this.offers.checkOffers(false), () => {});
    });
    this.settings = opts.settings ?? null;
    this.recent.push(...(this.readSetting("recent.json", parseRecent) ?? []));
    this.investigations = opts.investigations ?? null;
    if (this.investigations) {
      try {
        pruneInvestigations(this.investigations);
      } catch (err) {
        this.keeper.keepProblem(`Could not prune the investigations kept in ${this.investigations}: ${(err as Error).message}`);
      }
    }
    this.on("state", () => {
      if (this.keeper.changed()) this.keeper.keepSoon();
    });
  }

  /** The display filter the last open cleared because it named packets of the capture open before ("" if none). */
  droppedFilter = "";

  /** Packets whose comments were edited and not exported in the capture the view left last, if they weren't kept; else 0. */
  get droppedEdits(): number {
    return this.edits.dropped();
  }

  /** Whether the view shows the live capture's current file (or `file`). */
  private followingCapture(file = this.capture.state.currentFile): boolean {
    return !!file && this.state.file === file;
  }

  /** The engine that answers the view's queries. */
  private get engine(): Sharkd {
    return this.session.active;
  }

  /** The view's state; only the store replaces it. */
  get state(): ViewState {
    return this.store.state;
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

  /** Runs state-changing work one at a time (see EngineSession.exclusive). */
  private exclusive<T>(fn: () => Promise<T>): Promise<T> {
    return this.session.exclusive(fn);
  }

  /** The tail when the view lists it. */
  private get listedTail(): LiveTail | null {
    return this.tail?.active ? this.tail : null;
  }

  /** What the packet list reads of the view. */
  private geometry(): ListView {
    return { totalFrames: this.state.totalFrames, displayedFrames: this.state.displayedFrames, tail: this.listedTail };
  }

  /** Frames the view knows: read in full, then provisional ones. */
  private known(): number {
    return this.list.known(this.geometry());
  }

  /** Rows of the list: exact ones, then provisional ones. */
  private listLength(): number {
    return this.list.length(this.geometry());
  }

  private indexOf(frame: number | null): number {
    return this.list.indexOf(frame, this.geometry());
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
    this.list.setDisplayed(displayed);
    this.baseColumns = status.columns;
    this.columnFormats = (status.column_info ?? []).map((c) => c.format);
    this.loads++;
    const totalFrames = status.frames;
    // Marks, time references and the selection on packets listed before stay until a read covers them
    if (why === "file" || why === "rewritten" || totalFrames >= this.keptFrames) this.keptFrames = 0;
    const known = Math.max(totalFrames + (this.listedTail?.frames ?? 0), this.keptFrames);
    const selected = keepSelection && this.state.selected !== null && this.state.selected <= known ? this.state.selected : null;
    this.store.merge({
      file,
      fileSize: status.filesize ?? safeSize(file),
      loading: false,
      loadError: null,
      columns: [...status.columns, ...this.state.customColumns.map((c) => c.title)],
      totalFrames,
      displayedFrames: displayed ? displayed.length : totalFrames,
      ...this.edits.prune(known, this.state.marks, this.state.timeRefs),
      duration: status.duration ?? 0,
      filter,
      selected,
      selectedBy: selected === null ? null : this.state.selectedBy,
      generation: this.state.generation + 1,
      epoch,
      tail: this.tailState(),
    });
    this.tail?.setRefs(this.state.timeRefs);
    // A shorter file is a rewritten one, filtered or not
    const keepRows = keepSelection && status.frames >= before.exact && startsWith(this.rowFrames(), before);
    const selectedIndex = this.indexOf(selected);
    const rows = keepRows ? clipRanges(this.state.selectedRows, this.listLength()) : rowOf(selectedIndex);
    this.store.set({ selectedIndex, ...rowSelection(rows), rowsSince: keepRows ? this.state.rowsSince : this.state.generation });
  }

  /** The list's rows as frame numbers, copied (see PacketList.rowFrames). */
  private rowFrames(): { exact: number; length: number; at: (i: number) => number } {
    return this.list.rowFrames(this.geometry());
  }

  /**
   * Opens a capture in the standby engine and swaps on success; on failure the
   * current view stays as it was. `next`: the live capture went on in this
   * file. What the last capture had is kept with it first; what this one has
   * kept comes back.
   */
  open(file: string, next = false): Promise<void> {
    file = resolve(file);
    return this.exclusive(async () => {
      this.store.set({ loading: true, loadError: null });
      const standby = this.session.standby;
      let filter = this.state.filter;
      try {
        const st = statSync(file, { throwIfNoEntry: false });
        if (!st || !st.isFile()) throw new Error(`no such file: ${file}`);
        // A live capture's file may not have its header yet
        if (!this.capture.state.files.includes(file) && !(await looksLikeCapture(file))) throw new Error(`not a capture file: ${file}`);
        // Kept first: reopened, the capture (or a copy) comes back as it is now
        this.keeper.keepNow();
        const read = this.keeper.held();
        const head = fileHead(file);
        let kept = this.keeper.read(file, head, EDIT_LIMITS);
        // Frame numbers mean the packets of the capture open now: another capture's are other packets (a live capture's next file goes on)
        const before = this.state.file;
        const other = !!before && !next && file !== before && !(kept.key && kept.key === read.key);
        const named = other && usesFrameNumber(filter) ? filter : "";
        if (named) filter = "";
        this.droppedFilter = named;
        const refs = kept.investigation?.timeRefs ?? [];
        // As a reload with these time references: frame.ref_time stands for them, or the filter goes, like one that doesn't apply
        if (refs.length && usesRefTime(filter)) {
          try {
            refTimeFilter(filter, refs);
          } catch {
            filter = "";
          }
        }
        // The filter may not apply to this capture's protocols; then it shows everything
        const result = await this.session.load(standby, file, filter, refs, { fallback: true });
        filter = result.filter;
        const keptLast = this.keeper.keepNow();
        // Changed while this one loaded, and the same capture: what it has now (rows read with the references they have anyway)
        if (kept.key && this.keeper.held().key === kept.key && this.keeper.held() !== read) kept = this.keeper.read(file, head, EDIT_LIMITS);
        this.session.swap(standby);
        this.forgetTypes();
        this.lastReadMs = 0;
        this.paused = null;
        this.tailOff = null;
        this.loadedSize = st.size;
        this.loadedIno = st.ino;
        this.loadedHead = fileHead(file);
        const [last, edits] = [this.state.file, this.state.commentEdits];
        this.edits.left(keptLast, edits);
        const inv = kept.investigation;
        this.store.merge({ ...this.edits.dropAll(), selected: null, selectedBy: null });
        if (inv) this.store.merge({ ...this.edits.restore(inv), timeRefsRevision: this.state.timeRefsRevision + (inv.timeRefs.length ? 1 : 0) });
        this.applyLoad(file, filter, result, false);
        this.remember(file);
        if (named) {
          const text = `The display filter "${noticeText(named)}" names packets of ${basename(before!)}, so it was cleared for ${basename(file)}`;
          this.events.add("INFO", text);
          this.emit("toast", "info", text);
        }
        this.restored(file, kept);
        if (next && last && edits) {
          const where = keptLast ? `are kept with ${basename(last)}, not carried over to ${basename(file)}, where the capture went on` : `are gone: the capture went on in ${basename(file)}`;
          const text = `The packet comments edited in ${edits} packet${edits === 1 ? "" : "s"} of ${basename(last)} weren't exported and ${where}`;
          this.events.add("WARNING", text);
          this.emit("toast", "error", text);
        }
        void this.offers.checkOffers(true);
      } catch (err) {
        const message = printable((err as Error).message);
        this.store.set({ loading: false, loadError: message.includes(file) ? message : `${file}: ${message}` });
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
   * capture stopped. `rollback`: see EngineSession.load. While full reads
   * wait for memory, the read replaces the active engine's copy if there is
   * no room for a second one.
   */
  private async reloadNow(force: boolean, fallback = false, redissect = false, final = false, rollback = true): Promise<{ dropped: boolean; rolledBack: RollBack }> {
    const file = this.state.file;
    if (!file) return { dropped: false, rolledBack: false };
    const size = safeSize(file);
    if (!force && size === this.loadedSize) return { dropped: false, rolledBack: false };
    const inPlace = await this.readInPlace();
    const target = inPlace ? this.session.active : this.session.standby;
    this.readStartedAt = Date.now();
    if (inPlace) {
      const text = `Not enough free memory for a second copy of ${basename(file)}: WireBuddy reads it again in place of the one it has, so the packet list waits until it has`;
      this.events.add("WARNING", text);
      this.emit("toast", "info", text);
      this.store.set({ loading: true });
      // Requests in flight are answered first
      await target.idle(RESTART_WAIT_MS);
      target.restart();
    }
    this.publishTail();
    const started = Date.now();
    let result: LoadResult;
    try {
      result = await this.session.load(target, file, this.state.filter, this.state.timeRefs, { fallback, inPlace, rollback });
    } catch (err) {
      this.readStartedAt = 0;
      if (final) this.finalRead = false;
      // The active engine lost its copy, or no full read comes by itself
      if (inPlace || (this.listedTail && !this.capture.running && !this.finalRead)) await this.fullReadFailed(file, err as Error, inPlace);
      throw err;
    } finally {
      this.readStartedAt = 0;
      if (inPlace) this.store.set({ loading: false });
    }
    if (this.state.file !== file) return { dropped: false, rolledBack: result.rolledBack };
    this.lastReadMs = Date.now() - started;
    const dropped = result.filter !== this.state.filter;
    const ino = statSync(file, { throwIfNoEntry: false })?.ino ?? 0;
    const head = fileHead(file);
    const n = Math.min(head.length, this.loadedHead.length);
    const rewritten = ino !== this.loadedIno || !head.subarray(0, n).equals(this.loadedHead.subarray(0, n));
    // Other extensions: fields may hold frame numbers now, or no longer
    const held = redissect || result.rolledBack ? await this.retype(target, result.status, result.filter) : undefined;
    const untrusted = !rewritten && !(await this.checkTail(target, file, result));
    if (this.state.file !== file) return { dropped: false, rolledBack: result.rolledBack };
    this.session.swap(target);
    this.loadedSize = size;
    // Read without some extensions now: packets dissect differently
    this.applyLoad(file, result.filter, result, true, { changed: result.rolledBack ? "extensions" : rewritten ? "rewritten" : null, redissected: redissect, untrusted, held });
    this.loadedIno = ino;
    // A live capture's first bytes are all there now: what it has can be kept
    if (head.length > this.loadedHead.length) this.keeper.keepSoon();
    this.loadedHead = head;
    if (redissect || result.rolledBack) void this.filterTail();
    if (result.rolledBack) {
      this.store.set({ extensions: { ...this.state.extensions, revision: this.state.extensions.revision + 1 } });
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
    const standby = this.session.standby;
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
      this.store.set({ loadError, tail: this.tailState() });
      this.events.add("ERROR", loadError);
      return;
    }
    tail?.rebase(0);
    this.list.setDisplayed(this.state.filter ? new Int32Array(0) : null);
    this.loads++;
    const known = tail?.count ?? 0;
    const selected = this.state.selected !== null && this.state.selected <= known ? this.state.selected : null;
    const generation = this.state.generation + 1;
    this.store.merge({
      loading: false,
      loadError,
      totalFrames: 0,
      displayedFrames: 0,
      ...this.edits.prune(known, this.state.marks, this.state.timeRefs),
      selected,
      selectedBy: selected === null ? null : this.state.selectedBy,
      generation,
      rowsSince: generation,
      tail: this.tailState(),
    });
    tail?.setRefs(this.state.timeRefs);
    const selectedIndex = this.indexOf(selected);
    this.store.set({ selectedIndex, ...rowSelection(rowOf(selectedIndex)) });
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
      standbyBytes: rssBytes(this.session.standby.pid) ?? 0,
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
    return { frames: tail.frames, displayed: tail.listed(), unfiltered: tail.unfiltered(), held: tail.held, readMs, readingSince: this.readStartedAt || null, paused: this.paused, exactAfter: this.exactAfter() };
  }

  /** What makes provisional packets exact (see ProvisionalTail.exactAfter). */
  private exactAfter(): ProvisionalTail["exactAfter"] {
    if (this.capture.running) return this.paused ? "stop" : "read";
    return this.readStartedAt || this.finalRead ? "reading" : "reload";
  }

  /** Provisional matches listed before changed: the list's rows are read again, the selection stays on its packet. */
  private tailRevised(): void {
    const generation = this.state.generation + 1;
    this.store.merge({ tail: this.tailState(), generation, rowsSince: generation });
    const selectedIndex = this.indexOf(this.state.selected);
    this.store.set({ selectedIndex, ...rowSelection(rowOf(selectedIndex)) });
  }

  /** Publishes the tail as it is now; the list's generation moves when its rows grew. */
  private publishTail(): void {
    const tail = this.tailState();
    const was = this.state.tail;
    if (!tail && !was) return;
    if (tail && was && tail.frames === was.frames && tail.displayed === was.displayed && tail.unfiltered === was.unfiltered && tail.held === was.held && tail.paused === was.paused && tail.exactAfter === was.exactAfter && tail.readingSince === was.readingSince) return;
    const grew = (tail?.displayed ?? 0) !== (was?.displayed ?? 0);
    // A selected provisional packet the filter lists now gets its row
    const { selected, selectedIndex, selectedRows } = this.state;
    const index = grew && selectedIndex < 0 && selected !== null && selected > this.state.totalFrames ? this.indexOf(selected) : -1;
    const selection = index >= 0 ? { selectedIndex: index, ...(selectedRows.length ? {} : rowSelection(rowOf(index))) } : {};
    this.store.set({ tail, ...(grew ? { generation: this.state.generation + 1 } : {}), ...selection });
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
    this.store.merge({
      tail: null,
      generation,
      rowsSince: s.tail.displayed ? generation : s.rowsSince,
      selected,
      selectedBy: selected === null ? null : s.selectedBy,
      ...this.edits.prune(keep, s.marks, s.timeRefs),
    });
    this.store.set({ selectedIndex: this.indexOf(selected), ...rowSelection(clipRanges(s.selectedRows, s.displayedFrames)) });
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
    for (const [name, value] of this.session.prefs()) engine.setPref(name, value).catch(() => {});
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
      this.edits.left(this.keeper.keepNow(), this.state.commentEdits);
      this.keeper.leave();
      // A restarted sharkd needn't read the closed file again
      this.session.forgetFile();
      this.dropTail();
      this.list.setDisplayed(null);
      this.store.set({
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
        ...this.edits.dropAll(),
        generation: this.state.generation + 1,
        rowsSince: this.state.generation + 1,
        epoch: this.newEpoch("closed"),
        tail: null,
      });
      void this.offers.checkOffers(true);
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
      return { ok: false, error: message + bpfHint(filter) + setHint(filter) };
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
        this.list.setDisplayed(displayed);
        this.listedTail?.setFilter(filter, held);
        this.store.merge({
          filter,
          displayedFrames: displayed ? displayed.length : this.state.totalFrames,
          generation: this.state.generation + 1,
          tail: this.tailState(),
        });
        const selectedIndex = this.indexOf(this.state.selected);
        this.store.set({ selectedIndex, ...rowSelection(rowOf(selectedIndex)), rowsSince: this.state.generation });
        void this.filterTail();
      } else {
        this.store.set({ filter });
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
    const shown = this.list.page(start, count, this.geometry());
    count = shown.count;
    if (count === 0 || start < 0) return { generation, start, rows: [] };
    const exact = shown.exact;
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
    await this.checkFields(fields, "without fields, the rows hold the packet list's columns");
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
    else if (filter === this.state.filter && this.list.shown()) frames = this.list.shown()!.subarray(offset, offset + limit);
    else frames = Int32Array.from(await this.engine.call<{ num: number }[]>("frames", { filter: sharkd, ...page(offset, limit), column0: "frame.number:0" }), (r) => r.num);
    return (from, to) => refsOf(refs, frames.subarray(from, to));
  }

  /** Throws for a field sharkd can't give values of; `instead` says what to do for a packet list column. */
  private async checkFields(fields: string[], instead: string): Promise<void> {
    if (!fields.length) throw new Error("no fields given");
    for (const f of fields) {
      if (!FIELD_NAME.test(f)) throw new Error(`"${f}" is not a field name`);
      const r = await this.checkFilter(f);
      if (!r.ok) throw new Error(`unknown field "${f}": ${r.error}`);
      if (COLUMN_FIELD.test(f)) throw new Error(`"${f}" is a packet list column, not a field; ${instead}`);
    }
  }

  /** Sets the packet list's custom columns (an empty list removes them). */
  setColumns(columns: CustomColumn[], by: "user" | "agent", keep = true): Promise<FilterCheck> {
    return this.exclusive(async () => {
      if (columns.length > MAX_CUSTOM_COLUMNS) return { ok: false, error: `at most ${MAX_CUSTOM_COLUMNS} custom columns` };
      try {
        if (columns.length) await this.checkFields(columns.map((c) => c.field), "custom columns take protocol fields such as http.request.uri");
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
      this.store.set({
        customColumns,
        columns: this.state.file ? [...this.baseColumns, ...customColumns.map((c) => c.title)] : [],
        generation: this.state.generation + 1,
      });
      if (keep) this.keepSetting("columns.json", JSON.stringify(customColumns));
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
    if (view && listChanged(view, this.state)) {
      throw new StaleGenerationError("the selection belongs to another view");
    }
    const { selectedIndex, selectedRows } = this.list.select(frame, rows, this.geometry());
    this.store.set({
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

  /** Why the list has no row for `frame`, a frame the view knows. */
  unlisted(frame: number): string {
    return this.list.unlisted(frame, this.geometry());
  }

  private checkRows(rows: Ranges): Ranges {
    return this.list.checkRows(rows, this.geometry());
  }

  /** Frame ranges of the user's selected rows. */
  selectedFrames(): Ranges {
    return this.list.selectedFrames(this.state.selectedRows, this.geometry());
  }

  private framesOfRows(rows: Ranges): Ranges {
    return this.list.framesOfRows(rows, this.geometry());
  }

  /** Frames of the selected rows, else the selected frame. */
  selectedOrCurrent(): Ranges {
    return this.list.selectedOrCurrent(this.state, this.geometry());
  }

  /** Marks frames; returns the frame numbers that exist and those whose mark by the user an agent replaced. */
  mark(frames: number[], note: string, by: "user" | "agent"): { frames: number[]; replaced: number[] } {
    this.requireFile();
    const marked = marksWith(this.state.marks, frames, note, by, this.known());
    this.store.set({ marks: marked.marks });
    const n = marked.frames.length;
    // Before the note: the banner cuts a long line at its end
    const replaced = marked.replaced.length ? ` (replaced the user's mark on ${marked.replaced.length === 1 ? "frame" : "frames"} ${frameList(marked.replaced)})` : "";
    if (by === "agent" && n) this.notice(`Marked ${n} frame${n === 1 ? "" : "s"}${replaced}${marked.note ? `: ${marked.note}` : ""}`);
    return { frames: marked.frames, replaced: marked.replaced };
  }

  clearMarks(frames?: number[]): void {
    this.store.set({ marks: marksWithout(this.state.marks, frames) });
  }

  /** Wireshark's Mark/Unmark Packet(s): flips the mark of each selected frame. */
  toggleMarks(by: "user" | "agent"): void {
    const frames = this.selectedOrCurrent();
    if (!frames.length) return;
    this.store.set({ marks: toggledMarks(this.state.marks, frames, by) });
  }

  /** Wireshark's Mark All Displayed (`on`) / Unmark All Displayed; existing marks keep their notes. */
  markDisplayed(on: boolean, by: "user" | "agent"): void {
    this.requireFile();
    const list = { rows: this.listLength(), shown: (frame: number) => this.indexOf(frame) >= 0, frames: (rows: Ranges) => this.framesOfRows(rows) };
    this.store.set({ marks: displayedMarks(this.state.marks, on, by, list) });
  }

  /** Sets (`on`) or unsets time references on `frames`; frames the view doesn't know are left out. */
  setTimeRefs(frames: number[], on: boolean, by: "user" | "agent"): Promise<TimeRefsChange> {
    this.requireFile();
    const known = this.known();
    return this.changeRefs((refs) => refsWith(refs, frames, on, known), by);
  }

  /** Wireshark's Set/Unset Time Reference: flips the reference of each selected frame, else of the current one. */
  toggleTimeRefs(by: "user" | "agent"): Promise<TimeRefsChange> {
    this.requireFile();
    const frames = this.selectedOrCurrent();
    return this.changeRefs((refs) => toggledRefs(refs, frames), by);
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
        const change = refsChange(before, refs);
        if (!change.set.length && !change.unset.length) return change;
        const filter = this.state.filter;
        const displayed = this.state.file && usesRefTime(filter) ? await matchingFrames(this.engine, refTimeFilter(filter, refs)) : null;
        // A tail that closed meanwhile took some along
        if (this.state.timeRefs !== before) continue;
        this.tail?.setRefs(refs);
        const generation = this.state.generation + 1;
        const was = this.list.shown();
        if (displayed && !(was && was.length === displayed.length && was.every((f, i) => f === displayed[i]))) {
          this.list.setDisplayed(displayed);
          this.store.merge({ timeRefs: refs, timeRefsRevision: this.state.timeRefsRevision + 1, displayedFrames: displayed.length, generation, rowsSince: generation });
          const selectedIndex = this.indexOf(this.state.selected);
          this.store.set({ selectedIndex, ...rowSelection(rowOf(selectedIndex)) });
        } else this.store.set({ timeRefs: refs, timeRefsRevision: this.state.timeRefsRevision + 1, generation });
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
      const at = commentAt(now, frame, index, old);
      return now.map((c, i) => (i === at ? text : c));
    });
    if (by === "agent" && changed.length) this.notice(`Edited a packet comment of frame ${frame}: ${noticeText(text)}`);
    return changed;
  }

  /** Wireshark's Delete "…": comment `index` of `frame`, if still `old`. */
  async deleteComment(frame: number, index: number, old: string, by: "user" | "agent"): Promise<number[]> {
    const changed = await this.editComments(this.oneFrame(frame), (now) => {
      const at = commentAt(now, frame, index, old);
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
    const capture = this.edits.capture();
    const changed = await this.edits.queue(capture, async () => {
      const commented = await this.fileCommented();
      this.edits.sameCapture(capture);
      const cleared = this.edits.clearAll(commented, this.known());
      this.commentsChanged(cleared.patch);
      return cleared.frames;
    });
    if (by === "agent" && changed.length) this.notice(`Deleted all packet comments (${frameCount(changed)})`);
    return changed;
  }

  /**
   * Forgets the open capture's marks, time references and every comment
   * edit, also what is kept of them on disk: its packets read as the capture
   * file has them. Returns what went.
   */
  async forgetKept(): Promise<ForgetResult> {
    this.requireFile();
    const capture = this.edits.capture();
    const gone: ForgetResult = { marks: this.state.marks.length, timeRefs: this.state.timeRefs.length, comments: this.edits.editedPackets() };
    // As the user unsetting them all: sharkd counts from the first packet again, a frame.ref_time filter is matched again
    await this.clearTimeRefs("user");
    await this.edits.queue(capture, async () => {
      this.store.set({ ...this.edits.forget(), generation: this.state.generation + 1 });
    });
    this.keeper.keepNow();
    return gone;
  }

  /**
   * Packet comments edited in the viewer: the packets whose comments differ
   * from the file's, the frames Delete All went up to (0: none), and the
   * frames edited since, the first `max` with their comments.
   */
  editedComments(max: number): { packets: number; cleared: number; frames: number; list: [number, string[]][] } {
    return this.edits.summary(max);
  }

  /** `frame`, a frame the view knows, as ranges. */
  private oneFrame(frame: number): Ranges {
    if (!Number.isInteger(frame) || frame < 1 || frame > this.known()) throw new Error(`no frame ${frame}`);
    return [[frame, frame]];
  }

  /**
   * Gives each of `frames` the comments `change` makes of the ones it has
   * now (unchanged ones and frames the view doesn't know are left out), one
   * edit after the other, as long as the capture open now stays open;
   * returns the frames whose comments changed.
   */
  private editComments(frames: Ranges, change: (now: string[], frame: number) => string[]): Promise<number[]> {
    if (countRanges(frames) > MAX_COMMENTED) throw new Error(`comments of at most ${MAX_COMMENTED} packets can be changed at once`);
    const capture = this.edits.capture();
    return this.edits.queue(capture, async () => {
      const known = this.known();
      const valid = mergeRanges(frames).flatMap(([a, b]) => Array.from({ length: Math.max(0, Math.min(b, known) - Math.max(a, 1) + 1) }, (_, i) => Math.max(a, 1) + i));
      const now = await this.commentsOf(valid);
      this.edits.sameCapture(capture);
      const edited = this.edits.edit(valid, now, change);
      this.commentsChanged(edited.patch);
      return edited.frames;
    });
  }

  /** The list's rows read differently now, in the same places: what the comments say of the state (`patch`, null for no change) is told. */
  private commentsChanged(patch: Partial<ViewState> | null): void {
    if (patch) this.store.set({ ...patch, generation: this.state.generation + 1 });
  }

  private async commentsOf(frames: number[]): Promise<Map<number, EditedComments>> {
    return commentsOf(this.commentsView, this.edits.edited(), frames);
  }

  /** Frames read in full that have comments in the file. */
  private fileCommented(): Promise<Int32Array> {
    return this.edits.fileCommented(this.loads, () => matchingFrames(this.engine, "frame.comment"));
  }

  private withComments(rows: PacketRow[], short = false): PacketRow[] {
    return withComments(rows, this.edits.edited(), short);
  }

  /** Frame `num`'s `tree` with its comments as edited here and, first of all, its mark. */
  private withCommentNode(num: number, tree: TreeNode[]): TreeNode[] {
    const withComments = withCommentNode(num, tree, this.edits.edited(), this.commentEtts);
    const mark = this.state.marks.find((m) => m.frame === num);
    return mark ? [markNode(mark, this.state.agent.name), ...withComments] : withComments;
  }

  /** Tells what came back of the investigation kept for `file` (`kept`, as read at open), or why nothing did. */
  private restored(file: string, kept: KeptRead): void {
    this.keeper.adopt(file, kept);
    if (kept.problem) return;
    const what = keptSummary(this.state.marks.length, this.state.timeRefs.length, this.edits.editedPackets());
    if (!what) return;
    // A mark the display filter hides reads as lost
    const marks = this.state.marks.length;
    const hidden = this.state.filter ? this.state.marks.filter((m) => m.frame <= this.state.totalFrames && this.indexOf(m.frame) < 0).length : 0;
    const hides = !hidden ? "" : hidden === marks ? `; the display filter hides ${marks === 1 ? "it" : "all of them"}` : `; the display filter hides ${hidden} of them`;
    const text = `Restored ${what} kept for this capture${hides}`;
    this.events.add("INFO", text);
    this.emit("toast", "info", text);
  }

  /** Keeps the open capture's marks, time references and comment edits now; whether they are kept (see ViewState.kept). */
  keep(): boolean {
    return this.keeper.keepNow();
  }

  /** Marks the viewer as driven by an MCP agent, which then gets the problems. */
  attachAgent(name = this.state.agent.name): void {
    this.store.set({ agent: { ...this.state.agent, attached: true, name } });
  }

  /**
   * The user's question about packets: those `about` names (the selection its
   * dialog showed, refused once that view is gone), else the selected ones.
   * It wakes the agent's `--watch`, else comes with its next tool result.
   */
  askAgent(question: string, about?: { frame: number | null; rows?: Ranges; view: AboutView }): AskResult {
    if (!this.state.agent.attached) throw new Error("no agent is attached");
    const text = printable(question.replace(/\s+/g, " ").trim()).slice(0, MAX_QUESTION);
    if (!text) throw new Error("the question is empty");
    let frames: Ranges = [];
    // Also when the capture was closed meanwhile: the question was about packets of it
    if (about) frames = this.framesAbout(about);
    else if (this.state.file) frames = this.selectedOrCurrent();
    const count = countRanges(frames);
    const subject = count === 0 ? "" : ` about ${aboutText(frames[0][0], count)}`;
    const listed = framesFilter(frames, MAX_QUESTION_FRAMES) ?? `frames ${frames[0][0]} to ${frames[frames.length - 1][1]} (too many ranges to list)`;
    const woken = this.events.watched();
    const id = this.recordQuestion(text, about?.view.file ?? this.state.file, frames[0]?.[0] ?? null, count);
    this.events.add("QUESTION", `The user asks you${subject} (${answerHow(id)}): ${text}`, count > 1 ? { frames: listed } : undefined);
    return { woken };
  }

  /** Keeps a question the user asked the agent, for the page to show its answer; its id. */
  private recordQuestion(text: string, file: string | null, frame: number | null, count: number): number {
    const id = ++this.questionId;
    this.store.set({ questions: withQuestion(this.state.questions, { id, at: Date.now(), text, file, frame, count }) });
    return id;
  }

  /**
   * The agent's answer to a question of the user's (the oldest unanswered
   * one without `id`), shown in the page; `frame` is selected for the user
   * to look at. Refused when there is no such open question.
   */
  answerQuestion(text: string, id?: number, frame?: number): Question {
    const question = openQuestion(this.state.questions, id);
    const other = otherCapture(question, this.state.file);
    // Its answer is welcome, but a packet of the open capture isn't what it was about
    if (frame !== undefined && other) throw new Error(`question ${question.id} was about ${aboutText(question.frame, question.count)} of ${other}, not the open capture${this.state.file ? ` (${basename(this.state.file)})` : " (none is open)"}: frame would select a packet of the wrong capture; answer without frame`);
    const questions = answered(this.state.questions, question, text, Date.now());
    if (frame !== undefined) this.select(frame, "agent");
    this.store.set({ questions });
    return question;
  }

  /**
   * The user's Now in the live capture, sent on release (`at`, the page's
   * clock): a tap (`heldMs` 0) flags the moment, a hold the span before it.
   * Once the live file has a packet from after it (or NOW_FILE_MS passed)
   * the packets are found by capture time, which comes from the same clock;
   * once the view knows them (or NOW_VIEW_MS passed) they get packet
   * comments, and an agent a QUESTION event. Not in a capture that goes on
   * in new files, which drops edited comments; a hold may end after the
   * capture did.
   */
  async markNow(heldMs: number, at?: number): Promise<NowResult> {
    const now = Date.now();
    // Unless the page's clock is another machine's
    const endMs = at !== undefined && Number.isFinite(at) && at <= now && now - at < NOW_CLOCK_MS ? at : now;
    const held = Math.min(Math.max(0, heldMs), MAX_NOW_MS) / 1000;
    const pressedInCapture = this.capture.running || (this.captureStoppedAt > 0 && endMs - held * 1000 <= this.captureStoppedAt && now - this.captureStoppedAt < NOW_CLOCK_MS);
    if (!this.followingCapture() || !pressedInCapture) throw new Error("Now works while the view follows a running capture");
    if (this.capture.state.ring) throw new Error("Now works in a capture that stays in one file");
    const end = endMs / 1000;
    const capture = this.edits.capture();
    const path = this.state.file!;
    let times: LiveTimes | null = null;
    let frames: number[] = [];
    let spanned = 0;
    // Again when the live tail closed meanwhile (the final read landed): then from the packets read in full
    for (let tries = 0; tries < 3; tries++) {
      times = await this.liveTimes(end, capture);
      if (!times?.complete) break;
      try {
        const last = await framesBefore(times, end, true);
        const first = held ? (await framesBefore(times, end - held, false)) + 1 : last;
        spanned = Math.max(0, last - first + 1);
        frames = !last ? [] : !held || first > last ? [last] : first === last ? [first] : [first, last];
        break;
      } catch (err) {
        if (!(err instanceof Superseded)) throw err;
      }
    }
    const secs = `${held.toFixed(1)} s`;
    const texts = new Map<number, string>();
    if (!held) frames.forEach((f) => texts.set(f, "WireBuddy Now"));
    else if (!spanned) frames.forEach((f) => texts.set(f, `WireBuddy Now: held ${secs} after this packet, none came meanwhile`));
    else if (frames.length === 1) texts.set(frames[0], `WireBuddy Now: held ${secs}, the only packet then`);
    else frames.forEach((f, i) => texts.set(f, i ? "WireBuddy Now: held until here" : `WireBuddy Now: held ${secs} from here`));
    let commented: number[] = [];
    if (frames.length) {
      await this.whenState(() => this.known() >= frames[frames.length - 1] || !this.edits.isCapture(capture), NOW_VIEW_MS);
      if (this.edits.isCapture(capture)) commented = await this.editComments(toRanges(frames), (now, f) => [...now, texts.get(f)!]).catch(() => []);
    }
    // The user opened another file meanwhile: these numbers aren't its packets
    const left = !times || !this.edits.isCapture(capture);
    if (left) frames = [];
    const about = left
      ? `the view left ${basename(path)}`
      : !times!.complete
        ? "its packets aren't read yet"
        : !frames.length
          ? "no packet yet"
          : frames.length > 1
            ? `packets ${frames[0]}–${frames[1]}`
            : `packet ${frames[0]}`;
    const agent = this.state.agent.attached;
    const woken = agent && this.events.watched();
    if (agent) {
      const remark = !commented.length
        ? ""
        : commented.length > 1
          ? ", the first and last with packet comments"
          : `, ${frames.length > 1 ? `frame ${commented[0]} ` : ""}with the packet comment "${texts.get(commented[0])}"`;
      const where = left
        ? `The view left ${basename(path)} meanwhile; the filter in the details finds the moment in it.`
        : !times!.complete
          ? "The view hadn't read the packets of that moment yet; the filter in the details finds them once it has."
          : !frames.length
            ? "No packet was captured before it."
            : !held
              ? `Frame ${frames[0]} is the newest packet then${remark}.`
              : !spanned
                ? `No packet came meanwhile; frame ${frames[0]} is the last one before${remark}.`
                : `${spanned === 1 ? `Frame ${frames[0]} came` : `Frames ${frames[0]} to ${frames[1]} came`} meanwhile${remark}.`;
      const from = held ? end - held : end - NOW_BACK_S;
      const id = this.recordQuestion(held ? `Held Now for ${secs}` : "Pressed Now", left ? null : path, frames[0] ?? null, held && spanned ? spanned : frames.length ? 1 : 0);
      this.events.add("QUESTION", `The user ${held ? `held Now for ${secs}` : "pressed Now"} in the live capture, without words (${answerHow(id)}): what happened ${held ? "then" : "just before"}? ${where}`, {
        filter: `frame.time_epoch >= ${(Math.floor(from * 1000) / 1000).toFixed(3)} && frame.time_epoch <= ${(Math.ceil(end * 1000) / 1000).toFixed(3)}`,
      });
    }
    return { frames, about, commented: commented.length, held: held > 0, agent, woken };
  }

  /**
   * Capture times of the live file's packets once it has one from after `t`
   * (or NOW_FILE_MS passed, or the capture's final read landed); null once
   * another file is open than the one whose comments were of `capture`.
   */
  private async liveTimes(t: number, capture: number): Promise<LiveTimes | null> {
    const deadline = Date.now() + NOW_FILE_MS;
    for (;;) {
      // Taken first: the packets read in full are all there then
      const ended = !this.capture.running && !this.finalRead;
      if (!this.edits.isCapture(capture)) return null;
      const tail = this.tail?.file === this.state.file ? this.tail : null;
      if (tail) await tail.update();
      // Not sliceable: only the packets read in full
      const engine = this.engine;
      const times = tail
        ? { count: tail.count, timeOf: (f: number) => tail.timeOf(f) }
        : {
            count: this.state.totalFrames,
            timeOf: async (f: number) => Number((await engine.call<PacketRow[]>("frames", { ...page(f - 1, 1), column0: "frame.time_epoch:0" }))[0]?.c[0] ?? NaN),
          };
      const after = times.count > 0 && (await times.timeOf(times.count).catch(() => NaN)) > t;
      if (after || ended || Date.now() >= deadline) return this.edits.isCapture(capture) ? { ...times, complete: after || ended || !!tail } : null;
      await sleep(100);
    }
  }

  /** Resolves once `ok()` holds after a change of state, or after `ms`. */
  private whenState(ok: () => boolean, ms: number): Promise<void> {
    if (ok()) return Promise.resolve();
    return new Promise((resolve) => {
      const check = (): void => {
        if (ok()) done();
      };
      const done = (): void => {
        clearTimeout(timer);
        this.off("state", check);
        resolve();
      };
      const timer = setTimeout(done, ms);
      this.on("state", check);
    });
  }

  /**
   * The packets a dialog was opened for: the rows `rows` (else the frame
   * `frame`) of the list `view` showed; refused once that list is gone.
   * A `view` with the capture alone names a frame, whatever the filter is.
   */
  framesAbout({ frame, rows, view }: { frame: number | null; rows?: Ranges; view: AboutView }): Ranges {
    if (view.filter === undefined) {
      if (rows?.length) throw new Error("rows belong to a list: the view needs its filter");
      if (view.file !== this.state.file) throw new StaleGenerationError("the capture changed since you chose the packets; select them again");
    } else if (listChanged(view, this.state)) {
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
    this.store.set({ agentNotice: { id: ++this.noticeId, text, at: Date.now() } });
  }

  async phs(filter?: string): Promise<PhsNode[]> {
    return phs(this.statsView, filter);
  }

  async conversations(type: ConvType, filter?: string): Promise<ConvRow[]> {
    return conversations(this.statsView, type, filter);
  }

  async endpoints(type: ConvType, filter?: string): Promise<EndpointRow[]> {
    return endpoints(this.statsView, type, filter);
  }

  async expert(filter?: string): Promise<ExpertItem[]> {
    return expert(this.statsView, filter);
  }

  async ioGraph(specs: IoGraphSpec[], intervalMs: number): Promise<IoGraphResult> {
    return ioGraph(this.statsView, specs, intervalMs);
  }

  async frameAt(seconds: number, until?: number): Promise<number | null> {
    return frameAt(this.statsView, seconds, until);
  }

  async find(filter: string, from: number, dir: number): Promise<FindResult> {
    return find(this.statsView, filter, from, dir);
  }

  /** Reads the keylog file Wireshark's own preferences may already set. */
  async loadTlsPreference(): Promise<void> {
    try {
      const r = await this.engine.call<{ prefs?: Record<string, { s?: string }> }>("dumpconf", { pref: "tls.keylog_file" });
      const path = r.prefs?.["tls.keylog_file"]?.s;
      if (path && !this.state.tlsKeylog) this.store.set({ tlsKeylog: path });
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
      this.store.set({ tlsKeylog: path });
      await this.redissectNow("tls.keylog_file", path ?? "", "tls");
    });
  }

  /**
   * Sets a dissection preference in every sharkd, also the ones started
   * later, and reads the open capture again with it; `why` tells panels why
   * they start over. `rollback`: see EngineSession.load.
   */
  private async redissectNow(name: string, value: string, why: string, rollback = true): Promise<void> {
    this.panelData.hold(true);
    try {
      await this.session.setPref(name, value);
      this.tail?.setPref(name, value);
      this.panelData.setPref(name, value);
      await this.reloadNow(true, false, true, false, rollback);
    } finally {
      this.store.set({ epoch: this.newEpoch(why) });
      this.panelData.hold(false);
      // A panel's offer may need a protocol only this brings
      void this.offers.checkOffers(true);
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
      this.store.set({ decodeAs: { ...this.state.decodeAs, entries: next } });
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
      const shown = this.list.shown();
      ranges = shown ? toRanges(shown) : everything;
      // Its provisional matches, and newer packets not checked against it
      const tail = this.listedTail;
      if (shown && tail) leftOut = tail.held ? tail.frames : tail.listed() + tail.unfiltered();
    } else if (req.which === "marked") ranges = toRanges(this.state.marks.map((m) => m.frame));
    else if (req.which === "selected") ranges = req.about ? this.framesAbout(req.about) : this.selectedOrCurrent();
    else if (req.which === "range") ranges = parseRange(String(req.range ?? ""), known);
    else throw new Error(`unknown selection "${req.which}"`);
    if (!ranges.length) throw new Error("no packets to export");
    const frames = countRanges(ranges);
    // Packets of the live capture not read in full yet
    const read = this.state.totalFrames;
    const provisional = ranges.reduce((n, [a, b]) => n + Math.max(0, b - Math.max(a, read + 1) + 1), 0);
    // Comments as edited here, then marks, which Wireshark shows as packet comments
    let comments = new Map<number, FrameComments>();
    let marks = 0;
    let edited = 0;
    if (format === "pcapng") {
      ({ comments, edited } = this.edits.forExport(ranges));
      for (const m of req.markComments ? this.state.marks : []) {
        if (!inRanges(ranges, m.frame)) continue;
        const text = `WireBuddy mark (${m.by === "agent" ? this.state.agent.name : "user"})${m.note ? `: ${m.note}` : ""}`;
        const c = comments.get(m.frame);
        if (c) c.texts.push(text);
        else comments.set(m.frame, { own: true, texts: [text] });
        marks++;
      }
    }
    const at = this.edits.checkpoint();
    const size = await exportFrames({ editcap: this.editcap, mergecap: this.mergecap, input, output: req.path, format, ranges, comments, cleared: this.edits.edited().cleared });
    // Every packet in pcapng: the comments edited until then are kept in a file
    if (format === "pcapng" && frames >= known) {
      const edits = this.edits.exported(at);
      if (edits !== null && edits !== this.state.commentEdits) this.store.set({ commentEdits: edits });
    }
    if (by === "agent") {
      this.agentExports.add(resolve(req.path));
      this.notice(`Exported ${frames} packet${frames === 1 ? "" : "s"} to ${req.path}`);
    }
    return { path: req.path, frames, size, comments: marks, ...(edited ? { edited } : {}), ...(leftOut ? { leftOut } : {}), ...(provisional ? { provisional } : {}) };
  }

  /**
   * The packets a findings report lists: the marked ones, and the ones with
   * comments as the viewer shows them (edited here, else the file's, of
   * packets read in full), each in frame order.
   */
  private async findingsFrames(): Promise<{ marks: Mark[]; commented: number[] }> {
    const marks = [...this.state.marks].sort((a, b) => a.frame - b.frame);
    return { marks, commented: await this.edits.commented(() => this.fileCommented()) };
  }

  /** What a findings report would list now: marked packets and packets with comments. */
  async findingsSummary(): Promise<FindingsSummary> {
    this.requireFile();
    const { marks, commented } = await this.findingsFrames();
    return { marks: marks.length, commented: commented.length };
  }

  /** What the packet list shows of frame `num`: its time, source, destination, protocol and info. */
  private async rowSummary(num: number): Promise<RowSummary | null> {
    const row = await this.row(num);
    if (!row) return null;
    const at = (name: string): string => row.c[this.state.columns.indexOf(name)] ?? "";
    return { time: at("Time"), source: at("Source"), destination: at("Destination"), protocol: at("Protocol"), info: at("Info") };
  }

  /**
   * Writes the findings report of the open capture, a Markdown file with the
   * caller's summary, the capture's facts, the marks with their notes and the
   * packet comments, to a new file (see checkReportTarget).
   */
  async writeFindings(req: FindingsRequest, by: "user" | "agent"): Promise<FindingsResult> {
    this.requireFile();
    const path = String(req.path ?? "");
    // The agent must not destroy the user's files: it may only replace its own reports and exports
    if (by === "agent" && req.overwrite && !this.agentExports.has(resolve(path))) {
      throw new Error("the agent can only replace files it wrote itself in this session; choose a new file name");
    }
    const summary = req.summary === undefined ? "" : checkSummary(String(req.summary));
    const input = this.state.file!;
    checkReportTarget(path, [input, ...this.capture.state.files], !!req.overwrite);
    const capture = this.edits.capture();
    const { marks, commented } = await this.findingsFrames();
    const read = this.state.totalFrames;
    const markedOut: MarkedPacket[] = [];
    for (const m of marks.slice(0, MAX_LISTED)) markedOut.push({ frame: m.frame, note: m.note, by: m.by, provisional: m.frame > read, row: await this.rowSummary(m.frame) });
    const listed = commented.slice(0, MAX_LISTED);
    const texts = await this.commentsOf(listed);
    const commentedOut: CommentedPacket[] = [];
    for (const f of listed) {
      const comments = texts.get(f)?.list ?? [];
      if (comments.length) commentedOut.push({ frame: f, comments, provisional: f > read, row: await this.rowSummary(f) });
    }
    // The capture the report is about must still be the one open
    this.edits.sameCapture(capture);
    if (this.state.file !== input) throw new StaleGenerationError("the capture was closed or another one opened meanwhile");
    const s = this.state;
    const text = buildFindings({
      name: basename(input),
      path: input,
      packets: s.totalFrames,
      bytes: s.fileSize,
      duration: s.duration,
      live: this.capture.running && this.followingCapture(),
      filter: s.filter,
      decodeAs: s.decodeAs.entries.map(entryText),
      timeRefs: s.timeRefs,
      version: VERSION,
      at: new Date(),
      summary,
      marks: markedOut,
      commented: commentedOut,
      moreMarks: marks.length - markedOut.length,
      moreCommented: commented.length - listed.length,
    });
    const size = writeReport(path, text, !!req.overwrite);
    if (by === "agent") {
      this.agentExports.add(resolve(path));
      this.notice(`Wrote a findings report to ${path}`);
    }
    return { path, marks: marks.length, commented: commentedOut.length, size };
  }

  async follow(proto: string, filter: string, limit = FOLLOW_LIMIT): Promise<FollowResult> {
    return follow(this.streamsView, proto, filter, limit);
  }

  /** Whether the packets `filter` names (a followed stream) carry TLS. */
  async carriesTls(filter: string): Promise<boolean> {
    return carriesTls(this.streamsView, filter);
  }

  async capturedObjects(kind: ObjectKind, engine = this.engine): Promise<CapturedObject[]> {
    return capturedObjects(this.streamsView, kind, engine);
  }

  async saveObjects(
    kind: ObjectKind,
    pick: { frames?: number[]; keys?: string[] },
    dir: string,
    by: "user" | "agent",
  ): Promise<{ folder: string | null; saved: (CapturedObject & { name: string })[]; skipped: { object: CapturedObject; reason: string }[] }> {
    return saveObjects(this.streamsView, kind, pick, dir, by);
  }

  async openInWireshark(frame?: number | null): Promise<string | null> {
    return openInWireshark(
      {
        bin: this.wiresharkBin,
        profile: this.profile,
        state: () => this.state,
        requireFile: () => this.requireFile(),
        sharkdFilter: (filter) => this.sharkdFilter(filter),
        env: () => this.extensions.env(),
        lastLaunch: () => this.wiresharkAt,
        launching: (at) => {
          this.wiresharkAt = at;
        },
      },
      frame,
    );
  }

  private remember(file: string): void {
    const i = this.recent.indexOf(file);
    if (i >= 0) this.recent.splice(i, 1);
    this.recent.unshift(file);
    this.recent.length = Math.min(this.recent.length, MAX_RECENT);
    this.keepSetting("recent.json", JSON.stringify(this.recent));
  }

  /** What `file` in the settings folder holds, read by `parse`; null for none, or one that doesn't check out (ignored whole, told once). */
  private readSetting<T>(file: string, parse: (text: string) => T | null): T | null {
    if (!this.settings) return null;
    try {
      const text = readSetting(this.settings, file);
      if (text === null) return null;
      const kept = parse(text);
      if (kept) return kept;
      this.settingsProblem(`${join(this.settings, file)} is not what WireBuddy writes there, so it is ignored`);
    } catch (err) {
      this.settingsProblem(`Could not read ${join(this.settings, file)}: ${(err as Error).message}`);
    }
    return null;
  }

  private keepSetting(file: string, text: string): void {
    if (!this.settings) return;
    try {
      writeSetting(this.settings, file, text);
    } catch (err) {
      // One text for all of them: a folder that can't be written says so once
      this.settingsProblem(`Could not keep the custom columns and the recent files in ${this.settings}: ${(err as Error).message}`);
    }
  }

  private settingsProblem(text: string): void {
    if (this.settingsTold.has(text)) return;
    this.settingsTold.add(text);
    this.events.add("WARNING", text);
  }

  /** Brings back the custom columns kept by the run before, if this Wireshark still has their fields; says so. */
  async restoreColumns(): Promise<void> {
    const kept = this.readSetting("columns.json", parseColumns);
    if (!kept?.length) return;
    const r = await this.setColumns(kept, "user", false);
    if (r.ok) this.events.add("INFO", `Restored the custom columns of the run before: ${this.state.customColumns.map((c) => c.title).join(", ")}`);
    else this.settingsProblem(`The custom columns kept by the run before were not restored: ${r.error}`);
  }

  private requireFile(): void {
    if (!this.state.file) throw new Error("no capture is open");
  }

  /** Extensions as the UI lists them. */
  extensionList(): ExtensionList {
    const list = this.extensions.listing();
    for (const e of list.extensions) {
      if (!e.panel) continue;
      const bad = this.offers.errorOf(e.name);
      if (bad) e.panel.offerError = `invalid offer filter "${bad.filter}": ${bad.error}`;
      if (!this.panels.isOpen(e.name)) continue;
      e.panel.open = true;
      e.panel.stale = this.panels.report(e.name, false).stale;
    }
    return list;
  }

  dismissOffer(name: string): void {
    this.offers.dismissOffer(name);
  }

  async matchedOffers(ms = 5000): Promise<PanelOffer[]> {
    return this.offers.matchedOffers(ms);
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
      this.store.set({ selectSeq: this.state.selectSeq + 1 });
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
    if (active !== this.state.extensions.active || failing !== this.state.extensions.failing) this.store.set({ extensions: { ...this.state.extensions, active, failing } });
  }

  private luaReport(report: LuaReport): void {
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
      this.luaBatches.forgetLuaErrors();
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
          const fresh = this.session.standby;
          await this.session.crashRetries(async () => {
            await this.session.current(fresh);
            await fresh.call("status");
          });
          this.session.swap(fresh);
          this.forgetTypes();
        }
      } finally {
        this.store.set({ extensions: { ...this.state.extensions, revision: this.state.extensions.revision + 1 }, epoch: this.newEpoch("extensions") });
        this.panelData.hold(false);
        this.refreshExtensions();
        void this.offers.checkOffers(true);
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
    // A panel alone needs no sharkd restart, nor does a switch where sharkd loads no extensions
    if (this.extensions.unavailable || !this.extensions.list().find((e) => e.name === name)?.lua) {
      this.refreshExtensions();
      void this.offers.checkOffers(true);
      return;
    }
    await this.reloadExtensions({ name, on });
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
      // The user's own Wireshark plugins load in this sharkd too: one that has the protocol's description fails, or makes the extension fail
      const clashed = failed && clashKind(failed.error) ? { kind: clashKind(failed.error)!, failed: "extension" as const } : null;
      const lost = report?.other.map((o) => ({ kind: clashKind(o), text: o })).find((o) => o.kind) ?? null;
      const clash = clashed ?? (lost ? { kind: lost.kind!, failed: "plugin" as const } : null);
      if (clash) result.clash = { kind: clash.kind, with: this.extensions.clashOf(name), failed: clash.failed };
      // What a failed extension registered before its error works all the same
      const protocols = loaded?.protocols ?? failed?.protocols ?? [];
      if ((!loaded && !failed?.protocols.length) || !file) return result;
      for (const [name, value] of this.session.prefs()) await sharkd.setPref(name, value);
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
      const found = result.protocols.filter((p) => p.frames && !p.error).map((p) => p.name);
      if (found.length) {
        // What its packets are not: payload nobody decoded, and segments whose message is decoded in a later packet
        const ours = `(${found.join(" || ")})`;
        const overTcp = (await matchingFrames(sharkd, `tcp && ${ours}`)).length > 0;
        result.undecoded = { data: (await matchingFrames(sharkd, "data")).length, segments: overTcp ? (await matchingFrames(sharkd, `tcp.reassembled_in && !${ours}`)).length : null };
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
    this.keeper.keepNow();
    this.capture.stop();
    this.capture.stopActivity();
    if (this.tailTimer) clearInterval(this.tailTimer);
    this.dropTail();
    this.session.close();
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

/** "frame 4" or "3 frames". */
function frameCount(frames: number[]): string {
  return frames.length === 1 ? `frame ${frames[0]}` : `${frames.length} frames`;
}

/** A comment in a notice: one line, short. */
function noticeText(text: string): string {
  const line = printable(text.replace(/\n/g, " "));
  return line.length > 80 ? `${line.slice(0, 79)}…` : line;
}

/** Frame count and capture times of a capture's packets; `complete`: every packet up to the time asked for is there. */
type LiveTimes = { count: number; timeOf: (frame: number) => Promise<number>; complete: boolean };

/** How many of the frames lie before `t` (at it too with `orAt`): a live file's times ascend, unknown ones count as before. */
async function framesBefore({ count, timeOf }: LiveTimes, t: number, orAt: boolean): Promise<number> {
  let lo = 0;
  let hi = count;
  while (lo < hi) {
    const mid = Math.ceil((lo + hi) / 2);
    const time = await timeOf(mid);
    if (orAt ? !(time > t) : !(time >= t)) lo = mid;
    else hi = mid - 1;
  }
  return lo;
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
