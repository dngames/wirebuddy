/**
 * Contract between the wirebuddy server and its web UI.
 *
 * All HTTP endpoints live under `/api`, take and return JSON, and require the
 * session token: either the `X-WireBuddy-Token` header or a `token` query
 * parameter. The UI reads the token from its own URL (`/?token=...`).
 * Errors come back as a non-2xx status with an {@link ApiError} body.
 *
 * The WebSocket at `/ws?token=...` only pushes {@link ServerEvent}s; the UI
 * sends nothing over it.
 *
 * `POST /api/select` rows are indices into the displayed list of `view`
 * ({ file, filter, generation }); when that list has since been replaced or
 * changed in place (`generation` older than `rowsSince`), or a `view` sent
 * with a plain frame names another file or filter, the server answers 409
 * and keeps its selection.
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
 * | GET    | /api/frame-at                 | ?t=<seconds since first frame>       | { frame: number \| null } |
 * | POST   | /api/columns                  | { columns: CustomColumn[] }          | FilterCheck            |
 * | POST   | /api/tls                      | { keylog: string \| null }           | { ok: true }           |
 * | POST   | /api/export                   | ExportRequest                        | ExportResult           |
 * | GET    | /api/follow                   | ?proto=TCP\|UDP\|...&filter=         | FollowResult           |
 * | POST   | /api/marks                    | { frames, note }                     | { ok: true }           |
 * | POST   | /api/marks/clear              | { frames? } (omit: clear all)        | { ok: true }           |
 * | POST   | /api/marks/toggle             |                                      | { ok: true }           |
 * | POST   | /api/marks/displayed          | { on: boolean }                      | { ok: true }           |
 * | GET    | /api/find                     | ?filter=&from=<frame>&dir=1\|-1      | FindResult             |
 * | POST   | /api/wireshark                | { frame? }                           | { ok: true }           |
 * | GET    | /api/capture/interfaces       |                                      | CaptureInterface[]     |
 * | GET    | /api/capture/check            | ?iface=&filter=                      | FilterCheck            |
 * | GET    | /api/capture/activity         |                                      | InterfaceActivity      |
 * | POST   | /api/capture/start            | CaptureRequest                       | { ok: true }           |
 * | POST   | /api/capture/stop             |                                      | { ok: true }           |
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
   * filter applied. Rows fetched for an older generation are stale.
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
   * Generation since which row indices show the same frames. It changes when
   * the displayed list is rebuilt (file, filter, a re-read that is not just a
   * live capture growing), not when it only grows.
   */
  rowsSince: number;
  /** Frames the agent (or the user) marked, keyed by frame number. */
  marks: Mark[];
  capture: CaptureState;
  /** Last action the agent took in the UI, shown as a dismissable banner. */
  agentNotice: AgentNotice | null;
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
}

export interface Mark {
  frame: number;
  note: string;
  by: "agent" | "user";
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
  /** Any combination; omitted values mean no limit. */
  autostop: { durationSec?: number; filesizeKB?: number; packets?: number };
  /** Ring buffer; null for a single file. */
  ring: { filesizeKB?: number; durationSec?: number; files: number } | null;
}

export type CaptureStatus = "idle" | "starting" | "running" | "stopping" | "error";

export interface CaptureState {
  status: CaptureStatus;
  iface: string | null;
  filter: string;
  autostop: CaptureRequest["autostop"];
  ring: CaptureRequest["ring"];
  /** File being written now (the live view shows this file). */
  currentFile: string | null;
  /** All files written by the current or last capture, oldest first. */
  files: string[];
  /** Directory captures are written to. */
  dir: string;
  /** Epoch milliseconds, null when not capturing. */
  startedAt: number | null;
  /** Packets captured so far, as reported by dumpcap. */
  packets: number;
  error: string | null;
}

/** A packet list column showing a field, like Wireshark's "Apply as Column". */
export interface CustomColumn {
  /** Field name, e.g. `http.response.code`. */
  field: string;
  title: string;
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
  /** Replace an existing file. */
  overwrite?: boolean;
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

export interface ExportResult {
  path: string;
  frames: number;
  size: number;
}

export type ServerEvent =
  | { type: "state"; state: ViewState }
  | { type: "toast"; level: "info" | "error"; text: string };
