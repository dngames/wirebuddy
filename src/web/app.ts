/** Shared client state and the event bus that connects the UI modules. */

import type { FrameDetail, Mark, ViewState } from "../shared/api.ts";
import type { Ranges } from "../shared/ranges.ts";
import { Emitter, load } from "./util.ts";

export type ConnState = "connecting" | "open" | "closed";

export type AppEvents = {
  /** New server state; `prev` is null for the first one. */
  state: [s: ViewState, prev: ViewState | null];
  conn: [c: ConnState];
  /** Local selection (app.selFrame / app.selIndex) changed. */
  selection: [];
  /** Packet details of the selected frame loaded (or cleared). */
  frame: [fd: FrameDetail | null];
  /** Scroll a packet list row into view, optionally flashing it. */
  reveal: [index: number, flash: boolean];
  /** Status bar text for the selected details item. */
  fieldInfo: [text: string];
  autoscroll: [on: boolean];
  /** Colorize or zoom changed. */
  view: [];
  /** One-second heartbeat while a capture is running. */
  tick: [];
  /** A Now was pressed, released or answered. */
  now: [];
};

export const bus = new Emitter<AppEvents>();

export const app = {
  state: null as ViewState | null,
  conn: "connecting" as ConnState,
  /** Epoch ms of the next WebSocket reconnect attempt while closed. */
  reconnectAt: 0,
  selFrame: null as number | null,
  /** Row index of selFrame in the displayed list, -1 when unknown. */
  selIndex: -1,
  /** Selected rows (Ctrl/Shift+click) as merged ranges of displayed-list indices. */
  selRows: [] as Ranges,
  frame: null as FrameDetail | null,
  marks: new Map<number, Mark>(),
  autoScroll: load<boolean>("autoscroll", true),
  colorize: load<boolean>("colorize", true),
  /** Scale of the packet list, details and bytes, like Wireshark's View > Zoom. */
  zoom: load<number>("zoom", 1),
};

/** Late-bound hooks so modules can call each other without import cycles. */
export const hooks = {
  /** Row index of a frame if its row is cached, else -1. */
  indexOfFrame: (_frame: number): number => -1,
  /** Current display filter bar text. */
  filterText: (): string => app.state?.filter ?? "",
  /** Put a filter into the bar, optionally applying it. */
  setFilter: (_text: string, _apply: boolean): void => {},
  /** Start a capture with the capture options. */
  startCapture: (_iface?: string): void => {},
  /** Opens Capture › Options…, on a tab. */
  captureOptions: (_tab?: "input" | "output" | "options"): void => {},
  /** A Shift/Ctrl selection waits for its rows to load. */
  selectionLoading: (): boolean => false,
  /** Puts keyboard focus back in the packet list. */
  focusMain: (): void => {},
};

/** "Claude" or "Agent", after the MCP client driving the viewer. */
export function agentName(): string {
  return app.state?.agent.name ?? "Agent";
}

/** Frames the view knows: read in full, then a live capture's provisional ones. */
export function knownFrames(s: ViewState | null = app.state): number {
  return (s?.totalFrames ?? 0) + (s?.tail?.frames ?? 0);
}

export function captureActive(s: ViewState | null = app.state): boolean {
  const st = s?.capture.status;
  return st === "starting" || st === "running" || st === "stopping";
}
