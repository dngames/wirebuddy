/** Commands behind the menu bar, the main toolbar and their keyboard shortcuts. */

import * as act from "./actions.ts";
import { app, captureActive, hooks } from "./app.ts";
import { cap, loadInterfaces, restartCaptureClicked, setBarOpen } from "./capture.ts";
import { applySelectedAsColumn, collapseAll, expandAll, expandSubtrees, selectedField } from "./details.ts";
import { openConvDialog } from "./dialogs/conv.ts";
import { openExpertDialog } from "./dialogs/expert.ts";
import { openExportDialog } from "./dialogs/export.ts";
import { FOLLOW, openFollowDialog } from "./dialogs/follow.ts";
import { openGotoDialog } from "./dialogs/goto.ts";
import { openIoGraphDialog } from "./dialogs/iograph.ts";
import { openFileDialog } from "./dialogs/openfile.ts";
import { openPhsDialog } from "./dialogs/phs.ts";
import { openTlsDialog } from "./dialogs/tls.ts";
import { focusFilter } from "./filterbar.ts";
import { findAgain, openFindBar } from "./findbar.ts";
import { canGoBack, canGoForward, goHistory } from "./history.ts";
import type { MenuItem } from "./menu.ts";
import { resizeColumns, selectEdge, stepPacket } from "./packetlist.ts";
import { resetLayout } from "./panes.ts";
import { IS_MAC, isMod, isTextInput, keyLabel, keyLetter } from "./util.ts";

export interface Command {
  /** Menu text. */
  label: string;
  /** Toolbar tooltip, when it should differ from the label. */
  tip?: string;
  /** Key binding shown in menus and tooltips, e.g. "Ctrl+Shift+X". */
  shortcut?: string;
  /** Further bindings that are not shown. */
  keys?: string[];
  /** Also active while typing in a text field. */
  anywhere?: boolean;
  /** Its keys never reach the browser, even while disabled (they would navigate, reload or zoom the page). */
  owns?: () => boolean;
  enabled?: () => boolean;
  checked?: () => boolean;
  run: () => void;
}

const ZOOMS = [0.7, 0.8, 0.9, 1, 1.1, 1.2, 1.35, 1.5, 1.7, 2];

function zoomStep(dir: 1 | -1): void {
  const next = dir > 0 ? ZOOMS.find((z) => z > app.zoom + 0.001) : [...ZOOMS].reverse().find((z) => z < app.zoom - 0.001);
  if (next !== undefined) act.setZoom(next);
}

const hasFile = (): boolean => !!app.state?.file && !app.state.loading;
// From the state, not the packet list: listeners run in registration order
const hasRows = (): boolean => hasFile() && (app.state?.displayedFrames ?? 0) > 0;
const capturing = (): boolean => app.state?.capture.status === "running" || app.state?.capture.status === "starting";

/** Follow > <proto> Stream for the current packet, if it has one. */
export function followerOf(proto: string): string | null {
  return app.frame?.followers?.find(([p]) => p === proto)?.[1] ?? null;
}

function follow(proto: string): Command {
  const f = FOLLOW.find((x) => x.proto === proto);
  return {
    label: f?.label ?? `${proto} Stream`,
    shortcut: f?.key,
    enabled: () => followerOf(proto) !== null,
    run: () => {
      const f = followerOf(proto);
      if (f) openFollowDialog(proto, f);
    },
  };
}

export const commands = {
  // File
  open: { label: "Open…", tip: "Open a capture file", shortcut: "Ctrl+O", anywhere: true, run: () => openFileDialog() },
  close: { label: "Close", tip: "Close this capture file", enabled: () => !!app.state?.file, run: () => void act.closeFile() },
  saveAs: { label: "Save As…", tip: "Save this capture file as…", shortcut: "Ctrl+Shift+S", anywhere: true, enabled: hasFile, run: () => openExportDialog("all") },
  exportSpecified: { label: "Export Specified Packets…", shortcut: "Ctrl+Shift+X", anywhere: true, enabled: hasFile, run: () => openExportDialog() },

  // Edit
  find: { label: "Find Packet…", tip: "Find a packet", shortcut: "Ctrl+F", anywhere: true, enabled: hasFile, run: openFindBar },
  // Browsers keep Wireshark's Ctrl+N for themselves
  findNext: { label: "Find Next", shortcut: "F3", keys: ["Ctrl+N"], anywhere: true, enabled: hasFile, run: () => void findAgain(1) },
  findPrevious: { label: "Find Previous", shortcut: "Shift+F3", keys: ["Ctrl+B"], anywhere: true, enabled: hasFile, run: () => void findAgain(-1) },
  markToggle: {
    label: "Mark/Unmark Packet(s)",
    shortcut: "Ctrl+M",
    enabled: () => hasFile() && (app.selFrame !== null || app.selRows.length > 0),
    run: () => void act.toggleMarkSelected(),
  },
  markAllDisplayed: { label: "Mark All Displayed", shortcut: "Ctrl+Shift+M", enabled: () => hasFile() && hasRows(), run: () => void act.markDisplayed(true) },
  unmarkAllDisplayed: { label: "Unmark All Displayed", shortcut: "Ctrl+Alt+M", enabled: () => hasFile() && app.marks.size > 0, run: () => void act.markDisplayed(false) },
  unmarkAll: { label: "Unmark All", tip: "Also marks hidden by the display filter", enabled: () => app.marks.size > 0, run: () => void act.clearMarks() },
  nextMark: { label: "Next Mark", shortcut: "Ctrl+Shift+N", enabled: () => app.marks.size > 0, run: () => act.gotoMark(1) },
  previousMark: { label: "Previous Mark", shortcut: "Ctrl+Shift+B", enabled: () => app.marks.size > 0, run: () => act.gotoMark(-1) },

  // View
  zoomIn: {
    label: "Zoom In",
    tip: "Enlarge the main window text",
    shortcut: "Ctrl++",
    keys: ["Ctrl+="],
    anywhere: true,
    owns: () => true,
    enabled: () => app.zoom < ZOOMS[ZOOMS.length - 1],
    run: () => zoomStep(1),
  },
  zoomOut: { label: "Zoom Out", tip: "Shrink the main window text", shortcut: "Ctrl+-", anywhere: true, owns: () => true, enabled: () => app.zoom > ZOOMS[0], run: () => zoomStep(-1) },
  zoomNormal: { label: "Normal Size", tip: "Return the main window text to its normal size", shortcut: "Ctrl+0", anywhere: true, enabled: () => app.zoom !== 1, run: () => act.setZoom(1) },
  resizeColumns: { label: "Resize Columns", tip: "Resize packet list columns to fit contents", shortcut: "Ctrl+Shift+R", enabled: hasRows, run: resizeColumns },
  resetLayout: { label: "Reset Layout", tip: "Reset appearance layout to default size", shortcut: "Ctrl+Shift+W", run: resetLayout },
  expandSubtrees: { label: "Expand Subtrees", shortcut: "Shift+Right", enabled: () => !!selectedField()?.n?.length, run: () => expandSubtrees(true) },
  collapseSubtrees: { label: "Collapse Subtrees", shortcut: "Shift+Left", enabled: () => !!selectedField()?.n?.length, run: () => expandSubtrees(false) },
  // Cmd+Left/Right are Back/Forward in browsers on macOS
  expandAll: { label: "Expand All", shortcut: "Ctrl+Right", owns: () => IS_MAC, enabled: () => !!app.frame, run: expandAll },
  collapseAll: { label: "Collapse All", shortcut: "Ctrl+Left", owns: () => IS_MAC, enabled: () => !!app.frame, run: collapseAll },
  colorize: { label: "Colorize Packet List", tip: "Draw packets using your coloring rules", checked: () => app.colorize, run: () => act.setColorize(!app.colorize) },
  autoScroll: {
    label: "Auto Scroll in Live Capture",
    tip: "Automatically scroll to the last packet during a live capture",
    checked: () => app.autoScroll,
    run: () => act.setAutoScroll(!app.autoScroll),
  },
  // Ctrl+R during a capture is Restart, never a page reload
  reload: { label: "Reload", tip: "Reload this file", shortcut: "Ctrl+R", owns: captureActive, enabled: () => hasFile() && !captureActive(), run: () => void act.reloadFile() },

  // Go
  gotoPacket: { label: "Go to Packet…", tip: "Go to specified packet", shortcut: "Ctrl+G", anywhere: true, enabled: hasFile, run: () => openGotoDialog() },
  back: { label: "Previous Packet in History", tip: "Go back in packet history", shortcut: "Alt+Left", owns: () => true, enabled: canGoBack, run: () => goHistory(-1) },
  forward: { label: "Next Packet in History", tip: "Go forward in packet history", shortcut: "Alt+Right", owns: () => true, enabled: canGoForward, run: () => goHistory(1) },
  nextPacket: { label: "Next Packet", tip: "Go to the next packet", shortcut: "Ctrl+Down", enabled: hasRows, run: () => stepPacket(1) },
  previousPacket: { label: "Previous Packet", tip: "Go to the previous packet", shortcut: "Ctrl+Up", enabled: hasRows, run: () => stepPacket(-1) },
  firstPacket: { label: "First Packet", tip: "Go to first packet", shortcut: "Ctrl+Home", enabled: hasRows, run: () => selectEdge(-1) },
  lastPacket: { label: "Last Packet", tip: "Go to last packet", shortcut: "Ctrl+End", enabled: hasRows, run: () => selectEdge(1) },

  // Capture: starting needs the user's click or key press here, never the agent
  captureOptions: { label: "Options…", tip: "Show the capture options", shortcut: "Ctrl+K", anywhere: true, checked: () => cap.barOpen, run: () => setBarOpen(!cap.barOpen) },
  startCapture: { label: "Start", tip: "Start capturing packets", shortcut: "Ctrl+E", anywhere: true, enabled: () => !captureActive(), run: () => hooks.startCapture() },
  stopCapture: { label: "Stop", tip: "Stop capturing packets", shortcut: "Ctrl+E", anywhere: true, enabled: capturing, run: () => void act.stopCapture() },
  restartCapture: { label: "Restart", tip: "Restart current capture", shortcut: "Ctrl+R", enabled: capturing, run: () => void restartCaptureClicked() },
  // Only while interfaces are shown, so F5 reloads the page otherwise
  refreshInterfaces: {
    label: "Refresh Interfaces",
    shortcut: "F5",
    anywhere: true,
    enabled: () => cap.barOpen || (!!app.state && !app.state.file && !app.state.loading),
    run: () => void loadInterfaces(),
  },

  // Analyze
  applyAsColumn: { label: "Apply as Column", shortcut: "Ctrl+Shift+I", enabled: () => !!selectedField()?.fn, run: applySelectedAsColumn },
  followTcp: follow("TCP"),
  followUdp: follow("UDP"),
  followTls: follow("TLS"),
  followHttp: follow("HTTP"),
  expertInfo: { label: "Expert Information", enabled: hasFile, run: () => openExpertDialog() },

  // Statistics
  protocolHierarchy: { label: "Protocol Hierarchy", enabled: hasFile, run: () => openPhsDialog() },
  conversations: { label: "Conversations", enabled: hasFile, run: () => openConvDialog("conv") },
  endpoints: { label: "Endpoints", enabled: hasFile, run: () => openConvDialog("endpt") },
  ioGraphs: { label: "I/O Graphs", enabled: hasFile, run: () => openIoGraphDialog() },

  // Tools
  openInWireshark: {
    label: "Open in Wireshark",
    enabled: () => !!app.state?.wiresharkAvailable && !!app.state.file,
    run: () => void act.openInWireshark(app.selFrame),
  },
  tlsKeys: { label: "TLS Keys…", tip: "Decrypt TLS with a key log file", checked: () => !!app.state?.tlsKeylog, run: () => openTlsDialog() },

  focusFilter: { label: "Display Filter", shortcut: "Ctrl+/", anywhere: true, run: focusFilter },
} satisfies Record<string, Command>;

export type CommandId = keyof typeof commands;

export function isEnabled(c: Command): boolean {
  return !c.enabled || c.enabled();
}

/** Menu entry for a command. */
export function item(id: CommandId): MenuItem {
  const c: Command = commands[id];
  return { label: c.label, shortcut: c.shortcut && keyLabel(c.shortcut), disabled: !isEnabled(c), checked: c.checked?.(), action: c.run };
}

/** "Start capturing packets (Ctrl+E)". */
export function tooltip(c: Command): string {
  return `${c.tip ?? c.label}${c.shortcut ? ` (${keyLabel(c.shortcut)})` : ""}`;
}

const NAMED: Record<string, string> = { Up: "ArrowUp", Down: "ArrowDown", Left: "ArrowLeft", Right: "ArrowRight" };

function matches(e: KeyboardEvent, binding: string): boolean {
  const m = /^((?:(?:Ctrl|Alt|Shift)\+)*)(.+)$/.exec(binding);
  if (!m) return false;
  const mods = m[1];
  const key = NAMED[m[2]] ?? m[2];
  if (isMod(e) !== mods.includes("Ctrl") || e.altKey !== mods.includes("Alt")) return false;
  // The other platform's modifier (Control on macOS, the Windows key elsewhere) is not ours
  if (IS_MAC ? e.ctrlKey : e.metaKey) return false;
  if (/^[A-Z]$/.test(key)) return keyLetter(e) === key && e.shiftKey === mods.includes("Shift");
  // Symbols need Shift on some layouts ("+" on US), so it is not compared
  if (key.length === 1) return e.key === key;
  return e.key === key && e.shiftKey === mods.includes("Shift");
}

function bindings(c: Command): string[] {
  return [c.shortcut, ...(c.keys ?? [])].filter((b): b is string => !!b);
}

/**
 * Keeps owned keys from the browser even while their command can't run (a
 * dialog or menu is open, it is disabled); caret keys in text fields stay.
 */
export function claimOwnedKey(e: KeyboardEvent): void {
  const active = document.activeElement;
  const caretField = isTextInput(active) && !(active instanceof HTMLSelectElement);
  // Arrows move the caret; Alt+arrows only on macOS (by word)
  const caretKey = (b: string): boolean => /Left|Right|Up|Down|Home|End/.test(b) && (IS_MAC || !b.startsWith("Alt+"));
  for (const c of Object.values(commands) as Command[]) {
    if (!c.owns?.()) continue;
    if (bindings(c).some((b) => matches(e, b) && !(caretField && caretKey(b)))) {
      e.preventDefault();
      return;
    }
  }
}

/** Runs the enabled command bound to `e`; true if there was one. */
export function handleCommandKey(e: KeyboardEvent): boolean {
  const inText = isTextInput(document.activeElement);
  for (const c of Object.values(commands) as Command[]) {
    if (inText && !c.anywhere) continue;
    // Ctrl+E and Ctrl+R mean different commands depending on the capture state
    if (!isEnabled(c) || !bindings(c).some((b) => matches(e, b))) continue;
    e.preventDefault();
    c.run();
    return true;
  }
  return false;
}
