/**
 * Contract between the wirebuddy server and its web UI.
 *
 * All HTTP endpoints live under `/api`, take and return JSON, and require the
 * session token in the `X-WireBuddy-Token` header. The UI reads the token
 * from its own URL (`/?token=...`).
 * Errors come back as a non-2xx status with an {@link ApiError} body.
 *
 * The WebSocket at `/ws?token=...` only pushes {@link ServerEvent}s; the UI
 * sends nothing over it. A client gets the whole `ViewState` once, when it
 * connects (`state`), then `patch`es: the top-level fields whose value changed
 * since the push before, each with its whole new value. Pushes are numbered:
 * a patch's `seq` is one more than the one before, and a client that sees a
 * number skipped reconnects for a whole state. `GET /api/state` answers the
 * whole state, without a number.
 *
 * `POST /api/select` rows are indices into the displayed list of `view`
 * ({ file, filter, generation }); when that list has since been replaced or
 * changed in place (`generation` older than `rowsSince`), or a `view` sent
 * with a plain frame names another file or filter, the server answers 409
 * and keeps its selection.
 *
 * `GET /api/rows` answers for any generation since `rowsSince`, with the
 * rows as they read now; an older one gets 409, and so does one that isn't
 * the newest when provisional rows would have to be read for it. Fewer rows
 * than asked for: provisional ones couldn't be read now; ask again. For a
 * few seconds after a request for the list's newest rows, the provisional
 * rows it gains are read before the list shows them.
 *
 * Packet comments edited in the viewer (`/api/comments*`) are kept by frame
 * number with the capture, like its marks and time references: in
 * WireBuddy's data folder, under a hash of the capture's first 4096 bytes,
 * they come back when that capture (or a copy) is opened again, also after
 * a restart, and an info toast says what came back. Only an export to
 * pcapng writes them to a capture file ({@link PacketRow.cm}). A
 * comment holds at most 2000 characters; newlines are kept, other control
 * characters become "?". `/api/comments` adds `comment` to `frames`, else to
 * the rows `rows` (or the frame `frame`) of the list `view` showed (409 once
 * that list is gone), else to the selected packets. `/api/comments/delete`
 * deletes the comments of `frames` (else of the selected packets), or with
 * `index` one of `frame`'s. Edits and deletes by `index` name the comment's
 * text as `old` and get 409 once it changed; `comment` "" deletes it.
 * `/api/comments/clear` deletes every comment in the capture, the file's too.
 * Edits of a capture closed meanwhile get 409. `/api/marks` marks `frames`,
 * else the rows `rows` (or the frame `frame`) of the list `view` showed, as
 * the user's, with `note` (at most 200 characters; "" for none), replacing
 * the marks they had. `/api/forget` (File › Forget
 * Kept Marks and Comments…) drops the open capture's marks, time
 * references and every comment edit, so that its packets read as the
 * capture file has them, and removes what was kept of them.
 *
 * Endpoints:
 *
 * | Method | Path                          | Body / query                         | Response               |
 * |--------|-------------------------------|--------------------------------------|------------------------|
 * | GET    | /api/state                    |                                      | ViewState              |
 * | GET    | /api/rows                     | ?gen=&start=&count= (count <= 500)   | RowsResponse (409 on stale gen) |
 * | GET    | /api/frame                    | ?num=                                | FrameDetail            |
 * | GET    | /api/filter/check             | ?filter=                             | FilterCheck            |
 * | GET    | /api/filter/complete          | ?field=                              | CompleteResponse       |
 * | POST   | /api/filter                   | { filter }                           | FilterCheck            |
 * | POST   | /api/select                   | { frame: number \| null, rows?: Ranges, view? } (409 if view is stale) | { ok: true } |
 * | POST   | /api/open                     | { path }                             | { ok: true }           |
 * | POST   | /api/close                    |                                      | { ok: true }           |
 * | POST   | /api/reload                   | (re-reads the file, keeps marks)     | { ok: true }           |
 * | GET    | /api/files                    | ?dir=&kind=capture\|any              | DirListing             |
 * | GET    | /api/recent                   |                                      | RecentFiles            |
 * | GET    | /api/stats/phs                | ?filter= (optional)                  | PhsNode[]              |
 * | GET    | /api/stats/conv               | ?type=eth\|ipv4\|ipv6\|tcp\|udp&filter= | ConvRow[]         |
 * | GET    | /api/stats/endpt              | ?type=eth\|ipv4\|ipv6\|tcp\|udp&filter= | EndpointRow[]     |
 * | GET    | /api/stats/expert             | ?filter= (optional)                  | ExpertItem[]           |
 * | GET    | /api/stats/iograph            | ?interval=<ms>&graphs=<JSON IoGraphSpec[]> | IoGraphResult    |
 * | GET    | /api/frame-at                 | ?t=<seconds since first frame>[&until=<seconds>] | { frame: number \| null } |
 * | POST   | /api/columns                  | { columns: CustomColumn[] }          | FilterCheck            |
 * | POST   | /api/tls                      | { keylog: string \| null }           | { ok: true }           |
 * | POST   | /api/decode-as                | DecodeAsChange                       | DecodeAsResult         |
 * | POST   | /api/export                   | ExportRequest                        | ExportResult (400 with code "exists": the file is there, ask before `overwrite`) |
 * | GET    | /api/findings                 |                                      | FindingsSummary        |
 * | POST   | /api/findings                 | FindingsRequest                      | FindingsResult (400 with code "exists": the file is there, ask before `overwrite`) |
 * | GET    | /api/objects                  | ?kind=http\|imf\|smb\|tftp\|dicom\|ftp-data | ObjectList      |
 * | POST   | /api/objects/save             | { kind, dir, file, keys? } (409 if another capture is open) | ObjectSaveResult |
 * | GET    | /api/follow                   | ?proto=TCP\|UDP\|...&filter=         | FollowResult           |
 * | POST   | /api/marks                    | { note, frames } or { note, frame?, rows?, view } (409 if view is stale) | MarkResult |
 * | POST   | /api/marks/clear              | { frames? } (omit: clear all)        | { ok: true }           |
 * | POST   | /api/marks/toggle             |                                      | { ok: true }           |
 * | POST   | /api/marks/displayed          | { on: boolean }                      | { ok: true }           |
 * | POST   | /api/timerefs                 | { frames, on: boolean }              | TimeRefsChange         |
 * | POST   | /api/timerefs/toggle          | (the selected frames, else the current one) | TimeRefsChange  |
 * | POST   | /api/timerefs/clear           |                                      | TimeRefsChange         |
 * | POST   | /api/comments                 | { comment, frames?, view?, ... }     | CommentResult          |
 * | POST   | /api/comments/edit            | { frame, index, old, comment }       | CommentResult          |
 * | POST   | /api/comments/delete          | { frames? } or { frame, index, old } | CommentResult          |
 * | POST   | /api/comments/clear           |                                      | CommentResult          |
 * | POST   | /api/forget                   | (drops marks, time references and comment edits of the open capture, and what is kept of them) | ForgetResult |
 * | GET    | /api/find                     | ?filter=&from=<frame>&dir=1\|-1      | FindResult             |
 * | POST   | /api/wireshark                | { frame? }                           | { ok: true, note: string \| null } |
 * | GET    | /api/extensions               |                                      | ExtensionList          |
 * | POST   | /api/extensions/enable        | { name, on }                         | ExtensionList          |
 * | POST   | /api/extensions/reload        |                                      | ExtensionList          |
 * | POST   | /api/panels/open              | { name }                             | { ok: true }           |
 * | POST   | /api/panels/close             | { name }                             | { ok: true }           |
 * | POST   | /api/panels/reload            | { name }                             | { ok: true }           |
 * | POST   | /api/panels/health            | { name, label, state }               | { ok: true }           |
 * | POST   | /api/panels/act               | PanelAct                             | { ok: true } (403 denied) |
 * | POST   | /api/panels/offers/dismiss    | { name }                             | { ok: true }           |
 * | GET    | /api/events                   | ?after=<seq>&wait=<ms>&problems=1    | { events, last, taken } |
 * | POST   | /api/events                   | { level, text, details? } (from the page) | { ok: true }      |
 * | POST   | /api/events/take              |                                      | { events }             |
 * | POST   | /api/agent/ask                | { question, frame?, rows?, view? } (409 if view is stale) | AskResult |
 * | POST   | /api/now                      | { heldMs (0: a tap), at } on release | NowResult              |
 * | GET    | /api/capture/interfaces       |                                      | CaptureInterface[]     |
 * | GET    | /api/capture/check            | ?iface=&filter=                      | FilterCheck            |
 * | GET    | /api/capture/activity         |                                      | InterfaceActivity      |
 * | POST   | /api/capture/start            | CaptureRequest                       | { ok: true }           |
 * | POST   | /api/capture/stop             |                                      | { ok: true }           |
 *
 * Panels are served on hosts of their own, `p<label>.localhost:<port>`
 * (src/server/panels.ts), never with the token.
 */

import type { Ranges } from "./ranges.ts";

export interface ApiError {
  error: string;
}

/** Severity names sharkd attaches to tree items with expert info. */
export type ExpertSeverity = "Comment" | "Chat" | "Note" | "Warning" | "Warn" | "Error";

export interface ViewState {
  /** Absolute path of the capture being shown, or null when nothing is open. */
  file: string | null;
  fileSize: number;
  /** True while the first load of a file is running (not for live reloads). */
  loading: boolean;
  loadError: string | null;
  /**
   * Bumps whenever the displayed rows change: file opened, live reload,
   * filter applied, provisional rows added, time references set, packet
   * comments edited. Rows fetched for an older generation may be outdated.
   */
  generation: number;
  /** Random id of the server process; a new value means the server restarted. */
  instance: string;
  /** Packet list column titles, e.g. ["No.", "Time", "Source", ...]. */
  columns: string[];
  totalFrames: number;
  /** Frames matching the current display filter. */
  displayedFrames: number;
  /** Capture duration in seconds. */
  duration: number;
  /** Display filter currently applied ("" for none). */
  filter: string;
  /** Selected frame number, or null: the current packet, whose details are shown. */
  selected: number | null;
  /** Row index of the selected frame in the displayed list, or -1. */
  selectedIndex: number;
  /** Who made the last selection. */
  selectedBy: "user" | "agent" | null;
  /**
   * Increments each time the agent selects a frame. The UI scrolls the
   * selected row into view when this changes.
   */
  selectSeq: number;
  /**
   * Rows the user selected in the packet list (Ctrl/Shift+click), as merged
   * row-index ranges of the displayed list. Usually just the selected frame's
   * row; empty when nothing is selected or it is hidden by the filter. Reset to
   * that row when the file or display filter changes, or the agent selects.
   */
  selectedRows: Ranges;
  /** Number of rows in {@link selectedRows}. */
  selectedCount: number;
  /**
   * Generation since which row indices show the same frames, provisional rows
   * included. It changes when the displayed list is rebuilt (file, filter, a
   * re-read that is not just a live capture growing, provisional matches of
   * the display filter that a later check changed, as packets that came since
   * tell more), not when it only grows.
   */
  rowsSince: number;
  /** Frames the agent (or the user) marked, keyed by frame number; kept with the capture like its packet comments. */
  marks: Mark[];
  /**
   * Time references (Edit › Set/Unset Time Reference), ascending frame
   * numbers: the Time column shows *REF* on them and counts each packet from
   * the nearest one before it, and so do the details' times. A change bumps
   * {@link generation} (rows read again, rowsSince stays unless a display
   * filter on frame.ref_time lists other frames now); the shown packet's
   * details are read again too. A display filter that hides a reference
   * keeps it hidden, and packets after it still count from it. Kept with
   * the capture like its packet comments.
   */
  timeRefs: number[];
  /** Grows with every change to the time references, also one undone before the next state: rows and details read differently. */
  timeRefsRevision: number;
  /**
   * Packets whose comments were added, edited or deleted in the viewer and
   * not exported since: an export of every packet to pcapng writes them to a
   * capture file. They are kept with the capture (see the comments above),
   * and stay with the earlier file when a live capture goes on in a new one
   * (a WARNING event and a toast say so).
   */
  commentEdits: number;
  /** Packets whose comments read otherwise than the capture file's, as edited in the viewer, exported or not. */
  commentsEdited: number;
  /**
   * The open capture's marks, time references and comment edits are kept on
   * disk as they are now, so closing it or opening another loses nothing.
   * False right after any change to them until it is written (about a
   * second later), and while it can't be: no capture open, keeping off, a
   * live capture's first 4096 bytes not written yet, more than 4 MiB, or the
   * last write failed.
   */
  kept: boolean;
  /** Grows with every change to packet comments: rows and details read differently. */
  commentRevision: number;
  capture: CaptureState;
  /** Last action the agent took in the UI, shown as a dismissable banner. */
  agentNotice: AgentNotice | null;
  /** The last 20 questions the user asked the agent, oldest first, with the answers `answer_question` gave. Not kept beyond the session. */
  questions: Question[];
  /**
   * An MCP agent is attached: problems also go to it, and the page shows
   * how many are waiting (`pending`). `name` labels it in the UI
   * ("Claude" for Claude clients, else "Agent"); `watching`: its `--watch`
   * waits, so a problem or question wakes it at once.
   */
  agent: { attached: boolean; pending: number; name: string; watching: boolean };
  /** Whether a `wireshark` executable was found for "Open in Wireshark". */
  wiresharkAvailable: boolean;
  /**
   * Extra packet list columns, shown after the default ones. Their titles are
   * the last entries of {@link columns} and their values the last entries of
   * each {@link PacketRow.c}.
   */
  customColumns: CustomColumn[];
  /** Keylog file used to decrypt TLS (SSLKEYLOGFILE format), or null. */
  tlsKeylog: string | null;
  /**
   * Decode As entries, in effect for every capture until WireBuddy exits;
   * `unavailable`: why there can't be any, else null.
   */
  decodeAs: { entries: DecodeAsEntry[]; unavailable: string | null };
  /**
   * Lua extensions: how many decode now, how many failed to load; `revision`
   * grows with every reload, after which packets dissect differently.
   */
  extensions: { active: number; failing: number; revision: number };
  /** Open panel windows (views of the capture that extensions bring). */
  panels: PanelState[];
  /**
   * Panels whose offer filter matches the open capture, shown as status-bar
   * chips; not while the panel is open or after the user dismissed it for this file.
   */
  panelOffers: PanelOffer[];
  /**
   * Changes whenever packets already read may read differently: another file
   * or a rewritten one, a closed capture, re-read extensions, TLS keys or
   * Decode As. Not when a live capture only grows.
   */
  epoch: number;
  /**
   * Packets of a live capture that arrived after the last full read of the
   * file, once full reads take a second or more. The packet list shows them
   * after the exact rows (row indices from displayedFrames on), dissected
   * provisionally ({@link PacketRow.p}); a full read makes them exact (see
   * {@link ProvisionalTail.exactAfter}). totalFrames and displayedFrames
   * count only packets read in full. null otherwise, and once the capture
   * stopped and was read in full.
   */
  tail: ProvisionalTail | null;
}

/** See {@link ViewState.tail}. */
export interface ProvisionalTail {
  /** Packets after the last full read: frames totalFrames+1 .. totalFrames+frames. */
  frames: number;
  /** Rows they add to the list: all of them, or with a display filter its provisional matches. */
  displayed: number;
  /** Of `frames`, the newest ones the display filter wasn't checked against yet. */
  unfiltered: number;
  /** Why newer packets wait for a full read with this display filter (it uses stream indices, TCP conversation completeness or frame numbers), else null. */
  held: string | null;
  /** How long a full read of the file takes now, in ms: provisional packets turn exact with the next one. */
  readMs: number;
  /**
   * Why full reads wait (not enough memory for another copy, or the last
   * full read failed), else null; the capture is read in full once it
   * stops, or after a failed read once one is asked for.
   */
  paused: string | null;
  /**
   * What makes these packets exact: "read" the next live full read (in
   * about readMs), "stop" the capture's end (full reads wait), "reading"
   * the full read under way (the capture has stopped), "reload" only a
   * full read the user asks for (View › Reload), as the last one failed.
   */
  exactAfter: "read" | "stop" | "reading" | "reload";
}

/** A panel window: an extension's web page in a sandboxed frame of its own. */
export interface PanelState {
  /** Extension name. */
  name: string;
  /** This opening's one-time label: its origin is p<label>.localhost. */
  label: string;
  /** Window title: the manifest's, or what the panel set with wb.title(). */
  title: string;
  /** Where the frame loads it: a one-time origin of its own. */
  src: string;
  size: [number, number];
  by: "user" | "agent";
  state: "starting" | "ready" | "not-responding" | "stopped" | "error";
  /** wb.status() text, or why it stopped. */
  statusText: string;
  /** Errors reported since it opened. */
  errors: number;
  /** Whether it runs in a process of its own (null: not probed yet). */
  isolated: boolean | null;
  /** Its manifest grants "control": it may set the display filter (after a click in it). */
  control: boolean;
}

/** A panel offered for the open capture (its extension.json "offer"). */
export interface PanelOffer {
  /** Extension name. */
  name: string;
  /** Extension label. */
  label: string;
  /** The offer's text, e.g. "Show the point cloud". */
  text: string;
}

/**
 * A panel's change to the view, sent by the page that shows it: `select`
 * takes a frame number, `setFilter` a display filter. `clicked`: the user
 * clicked or typed in that panel just before; without it the server only
 * records the refusal.
 */
export interface PanelAct {
  name: string;
  label: string;
  m: "select" | "setFilter";
  a: unknown;
  clicked: boolean;
}

/** What a panel sees of the view: `wb.view`. */
export interface PanelView {
  /** Base name of the open capture, or null. */
  file: string | null;
  /** See {@link ViewState.epoch}: data read before it changed is outdated. */
  epoch: number;
  frames: number;
  displayed: number;
  filter: string;
  selected: number | null;
  /** Frame ranges of the user's selected rows; null when there are too many. */
  selection: Ranges | null;
  marked: number;
  /** Time references the view has (see {@link ViewState.timeRefs}): frame.time_relative and frame.ref_time read from them. */
  timeRefs: number;
  /** The view follows a capture that is running. */
  live: boolean;
  capture: CaptureStatus;
}

export interface Mark {
  frame: number;
  note: string;
  by: "agent" | "user";
}

/** What a change of time references did: frames that became references, and frames that stopped being ones. */
export interface TimeRefsChange {
  set: number[];
  unset: number[];
}

/** What a mark request did: the frames now marked (the first 10000) and how many. */
export interface MarkResult {
  ok: true;
  frames: number[];
  count: number;
}

/** A question the user asked the agent, in words (Ask Agent) or with Now. */
export interface Question {
  /** Ids restart with each server process. */
  id: number;
  /** Epoch milliseconds. */
  at: number;
  /** What was asked, cut at 300 characters (the agent got it in full). */
  text: string;
  /** The capture it was about and its first packet, null for none; `count` packets in all. */
  file: string | null;
  frame: number | null;
  count: number;
  /** What the agent answered, null while it waits. */
  answer: { text: string; at: number } | null;
}

export interface AgentNotice {
  id: number;
  text: string;
  /** Epoch milliseconds. */
  at: number;
}

export interface PacketRow {
  /** Frame number. */
  num: number;
  /** One value per column in {@link ViewState.columns}. */
  c: string[];
  /** Coloring-rule background and foreground, hex without "#", e.g. "daeeff". */
  bg?: string;
  fg?: string;
  /**
   * Packet comments: as edited in the viewer, else the file's. Text from a
   * capture file is untrusted. The list's rows (`/api/rows`) carry the first
   * 5, each cut at 300 characters ("…" ends a cut one); others all of them.
   */
  cm?: string[];
  /**
   * Provisional: a live capture's packet the last full read of the file
   * didn't cover yet, dissected from a slice of the newest packets (see
   * {@link ViewState.tail}). Its number, time, length and bytes are exact.
   */
  p?: true;
}

export interface RowsResponse {
  generation: number;
  /** Index of rows[0] in the displayed list. */
  start: number;
  rows: PacketRow[];
}

/** One node of the packet details tree, as sharkd returns it. */
export interface TreeNode {
  /** Label shown in the tree. */
  l: string;
  /** Filter expression for this item, e.g. `ip.src == 1.2.3.4` or `ip`. */
  f?: string;
  /** Field name, e.g. `ip.src`. */
  fn?: string;
  /** Byte range as [offset, length] within the data source given by `ds`. */
  h?: [number, number];
  /**
   * Data source of `h`: absent or 0 means the frame's own bytes, k >= 1 means
   * {@link FrameDetail.ds}[k - 1] (e.g. "Reassembled TCP (81243 bytes)").
   */
  ds?: number;
  /** Generated field (Wireshark shows these in [brackets]). */
  g?: boolean;
  /** "proto" for protocol nodes, "url" for links, "framenum" for frame references. */
  t?: string;
  /** For `t === "url"`: the link target. */
  url?: string;
  /** Expert info severity, if the item carries one. */
  s?: ExpertSeverity;
  /** Ett id; nodes with the same `e` share an expanded/collapsed state. */
  e?: number;
  /** For `t === "framenum"`: the referenced frame number. */
  fnum?: number;
  n?: TreeNode[];
}

export interface FrameDetail {
  num: number;
  tree: TreeNode[];
  /** Frame bytes, base64. */
  bytes: string;
  /** Extra data sources (reassembled or decrypted buffers). */
  ds: { name: string; bytes: string }[];
  /** Streams this frame belongs to, as [protocol, filter], e.g. ["TCP", "tcp.stream eq 3"]. */
  followers: [string, string][];
  /** Summary row of this frame. */
  row: PacketRow | null;
  /** A live capture's packet the last full read didn't cover: dissected from a slice of the newest packets, see {@link ViewState.tail}. */
  provisional?: true;
}

export interface FilterCheck {
  ok: boolean;
  /** Present when ok is false. */
  error?: string;
  /** Present when the filter is valid but questionable (deprecated field, etc.). */
  warning?: string;
}

export interface CompleteResponse {
  fields: { f: string; n?: string }[];
}

export interface DirEntry {
  name: string;
  path: string;
  isDir: boolean;
  size: number;
  /** Epoch milliseconds. */
  mtime: number;
}

export interface DirListing {
  dir: string;
  parent: string | null;
  /** Directories first, then capture files (pcap, pcapng, cap, ...), or all files with kind=any. */
  entries: DirEntry[];
}

export interface RecentFiles {
  /** Most recent first; only files that still exist. */
  files: { path: string; size: number; mtime: number }[];
}

export interface PhsNode {
  proto: string;
  frames: number;
  bytes: number;
  children: PhsNode[];
}

export interface ConvRow {
  addrA: string;
  portA?: string;
  addrB: string;
  portB?: string;
  framesAB: number;
  bytesAB: number;
  framesBA: number;
  bytesBA: number;
  /** Relative start in seconds. */
  start: number;
  duration: number;
  /** Display filter that selects this conversation. */
  filter: string;
}

export interface EndpointRow {
  addr: string;
  port?: string;
  framesTx: number;
  bytesTx: number;
  framesRx: number;
  bytesRx: number;
  filter: string;
}

export interface FollowResult {
  proto: string;
  filter: string;
  server: { host: string; port: string; bytes: number };
  client: { host: string; port: string; bytes: number };
  /** In order; `server` is true for data sent by the server side. */
  payloads: { frame: number; server: boolean; data: string /* base64 */ }[];
  /** True when payloads were cut to keep the response small. */
  truncated: boolean;
  /** Payload bytes left out when truncated. */
  omittedBytes?: number;
}

export interface CaptureInterface {
  name: string;
  /** Friendly name or description, if any. */
  description: string | null;
  addresses: string[];
  loopback: boolean;
}

/** Recent traffic per capture interface, sampled with `dumpcap -S`. */
export interface InterfaceActivity {
  /** Seconds between samples. */
  interval: number;
  /** Packets received per sample, oldest first, at most 60 per interface. */
  ifaces: Record<string, number[]>;
  /** Set when the statistics can't be collected. */
  error?: string;
}

export interface CaptureRequest {
  iface: string;
  /** Capture (BPF) filter, "" for none. */
  filter: string;
  /** Promiscuous mode (dumpcap's default); false captures only traffic to and from this host. */
  promiscuous?: boolean;
  /** Any combination; omitted values mean no limit. `files` needs `ring`. */
  autostop: { durationSec?: number; filesizeKB?: number; packets?: number; files?: number };
  /**
   * A new file automatically after any of these (at least one); `files` keeps
   * only that many, like a ring buffer, else all are kept. null: a single file.
   */
  ring: { filesizeKB?: number; durationSec?: number; packets?: number; intervalSec?: number; files?: number } | null;
}

export type CaptureStatus = "idle" | "starting" | "running" | "stopping" | "error";

export interface CaptureState {
  status: CaptureStatus;
  iface: string | null;
  filter: string;
  autostop: CaptureRequest["autostop"];
  ring: CaptureRequest["ring"];
  promiscuous: boolean;
  /**
   * The TCP port of WireBuddy's own traffic (the page and the agent talking to its server), which a capture on a
   * loopback interface or `any` leaves out in addition to {@link filter}; null where it doesn't.
   */
  leftOutPort: number | null;
  /** File being written now (the live view shows this file). */
  currentFile: string | null;
  /** Files written by the current or last capture, oldest first: the newest ones of a capture that goes on in new files. */
  files: string[];
  /** How many files it wrote in all. */
  filesWritten: number;
  /** Directory captures are written to. */
  dir: string;
  /** Epoch milliseconds, null when not capturing. */
  startedAt: number | null;
  /** Packets captured so far, as reported by dumpcap. */
  packets: number;
  error: string | null;
  /** Who started the current or last capture. */
  startedBy: "user" | "agent" | null;
}

/** A packet list column showing a field, like Wireshark's "Apply as Column". */
export interface CustomColumn {
  /** Field name, e.g. `http.response.code`. */
  field: string;
  title: string;
}

/** Where Decode As looks a packet up: its TCP or UDP port, the TCP port of its decrypted TLS, its RTP payload type. */
export type DecodeAsTable = "tcp.port" | "udp.port" | "tls.port" | "rtp.pt";

/** Like Wireshark's Decode As: packets with `value` in `table` dissect as `protocol`, a display-filter protocol name. */
export interface DecodeAsEntry {
  table: DecodeAsTable;
  value: number;
  protocol: string;
  by: "user" | "agent";
}

/** Sets an entry (replacing the one for the same table and value), or clears one (table and value) or all. */
export type DecodeAsChange = { action: "set"; table: DecodeAsTable; value: number; protocol: string } | { action: "clear"; table?: DecodeAsTable; value?: number };

/**
 * The entries after a change. `set`: the entry set, what decoded its value
 * before and now (dissector names, "" for none) and the frames it decodes
 * now (null when counting failed); `removed`: the entry cleared.
 */
export interface DecodeAsResult {
  entries: DecodeAsEntry[];
  unchanged?: true;
  set?: { entry: DecodeAsEntry; was: string; now: string; frames: number | null };
  removed?: DecodeAsEntry;
}

export interface ExpertItem {
  frame: number;
  severity: ExpertSeverity;
  /** Expert group, e.g. "Sequence", "Malformed", "Protocol". */
  group: string;
  protocol: string;
  message: string;
}

export interface IoGraphSpec {
  metric: "packets" | "bytes" | "bits";
  /** Display filter for this graph, "" for all packets. */
  filter: string;
}

export interface IoGraphResult {
  /** Bucket width in milliseconds; raised by the server when the capture needs too many buckets. */
  interval: number;
  /** One series per requested graph; values[i] covers [i * interval, (i + 1) * interval) ms after the first frame. */
  series: { metric: IoGraphSpec["metric"]; filter: string; values: number[] }[];
}

export interface ExportRequest {
  /** Absolute path ending in .pcapng or .pcap. */
  path: string;
  /** Which packets: the displayed ones, the marked ones, the selected ones (see {@link ViewState.selectedRows}), or a range like "1-10,25". */
  which: "displayed" | "marked" | "selected" | "range" | "all";
  range?: string;
  /**
   * For "selected": the packets the dialog was opened for (the rows `rows`,
   * else the frame `frame`, of the list `view` showed) in place of the ones
   * selected now; refused with 409 once that list is gone.
   */
  about?: { frame: number | null; rows?: Ranges; view: { file: string; filter: string; generation?: number } };
  /** Replace an existing file. */
  overwrite?: boolean;
  /**
   * Write the marks of the exported packets, with their notes, as packet
   * comments after their own (pcapng only). Packet comments edited in the
   * viewer always go along in pcapng.
   */
  markComments?: boolean;
}

/** Packets whose comments an edit changed. */
/** What `/api/forget` dropped: marks, time references, and packets whose comments were edited. */
export interface ForgetResult {
  marks: number;
  timeRefs: number;
  comments: number;
}

export interface CommentResult {
  /** Their frame numbers, the first 10000. */
  frames: number[];
  count: number;
}

/** Something that happened in the viewer, for the agent: a problem or what the user did. */
export interface ViewerEvent {
  seq: number;
  /** ISO time. */
  time: string;
  /** INFO: what the user did; WARNING and ERROR: problems; QUESTION: the user asks the agent, in words or with Now. */
  level: "INFO" | "WARNING" | "ERROR" | "QUESTION";
  text: string;
  details?: Record<string, unknown>;
  /** It happened this many times in a row. */
  repeated?: number;
}

/** Find Packet: the next displayed frame matching a filter, wrapping around the end once. */
export interface FindResult {
  /** null when no displayed frame matches. */
  frame: number | null;
  /** Row index of `frame` in the displayed list, or -1. */
  index: number;
  /** The search passed the end (or start) of the list and continued from the other side. */
  wrapped: boolean;
}

/** A question for the agent: `woken` when its `--watch` was waiting, else it sees the question with its next tool call. */
export interface AskResult {
  woken: boolean;
}

/**
 * The user's Now in a live capture: `frames` the packet it flagged (a tap),
 * or the first and last one of the span (a hold; one when they are the same,
 * the last one before it when none came meanwhile), [] when there is none
 * in the view; `about` says which in words; `commented` how many have a
 * packet comment now. `agent`: an agent got it, `woken` at once.
 */
export interface NowResult {
  frames: number[];
  about: string;
  commented: number;
  held: boolean;
  agent: boolean;
  woken: boolean;
}

export interface ExportResult {
  path: string;
  frames: number;
  size: number;
  /** Marks written as packet comments. */
  comments: number;
  /** Packets written with their comments as edited in the viewer. */
  edited?: number;
  /** Newer packets of a live capture left out because they weren't read in full yet (export by display filter). */
  leftOut?: number;
  /** Of `frames`, packets of a live capture that weren't read in full yet (written as captured). */
  provisional?: number;
}

/** File > Write Findings Report: a Markdown file with the marks and their notes, the packet comments and the capture's facts. */
export interface FindingsRequest {
  /** Absolute path ending in .md, in a directory that exists. */
  path: string;
  /** The caller's own Markdown, written into the report as given: at most 16 KiB, no control characters but newline and tab. */
  summary?: string;
  /** Replace an existing file. */
  overwrite?: boolean;
}

/** What a report would list now. */
export interface FindingsSummary {
  /** Marked packets. */
  marks: number;
  /** Packets with comments, as the viewer shows them: edited here, else the file's (packets read in full). */
  commented: number;
}

export interface FindingsResult {
  path: string;
  /** Marked packets of the capture (the report lists at most 2,000). */
  marks: number;
  /** Packets with comments written out. */
  commented: number;
  size: number;
}

/** File > Export Objects: what carries the files. */
export type ObjectKind = "http" | "imf" | "smb" | "tftp" | "dicom" | "ftp-data";

/** One file sharkd found in the traffic; `frame:sha1` names it for a save. */
export interface ObjectRow {
  frame: number;
  host: string;
  type: string;
  filename: string;
  size: number;
  sha1: string;
}

export interface ObjectList {
  objects: ObjectRow[];
  /** Where saves go unless the user names another directory. */
  dir: string;
}

export interface ObjectSaveResult {
  /** The new folder, or null when every object was skipped. */
  folder: string | null;
  saved: number;
  skipped: { frame: number; filename: string; reason: string }[];
}

export type ServerEvent =
  /** The whole state, sent when the client connects; `seq` is the number of the last push. */
  | { type: "state"; seq: number; state: ViewState }
  /** What changed since the push before; `seq` is one more than that push's. */
  | { type: "patch"; seq: number; patch: Partial<ViewState> }
  | { type: "toast"; level: "info" | "error"; text: string };

/**
 * A Lua dissector extension. `status`: "new" (not loaded yet), "loaded",
 * "error" (its Lua failed to load), "off", "invalid" (bad folder or
 * extension.json) or "untrusted" (others could have changed its files).
 */
export interface ExtensionInfo {
  name: string;
  folder: string;
  label: string;
  version: string;
  description: string;
  enabled: boolean;
  status: "new" | "loaded" | "error" | "off" | "invalid" | "untrusted";
  error?: string;
  /** Protocols it registered, as filter names. */
  protocols: string[];
  /** It has Lua files for sharkd. */
  lua: boolean;
  /**
   * Its panel, if it has one; `open`, `stale` (files changed since it opened)
   * and `offerError` (its offer filter is invalid) come from the viewer.
   */
  panel: { title: string; open: boolean; stale: boolean; offer: string | null; offerError?: string } | null;
}

export interface ExtensionList {
  /** Where the agent writes extensions. */
  dir: string;
  /** Why extensions can't load, or null. */
  unavailable: string | null;
  extensions: ExtensionInfo[];
  /** Extension folders that were not even looked into, with why (others could change them). */
  ignored: string[];
}
