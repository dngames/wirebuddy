/** State synchronisation and the actions the UI performs against the server. */

import type { CaptureRequest, CustomColumn, ExportRequest, ExportResult, FilterCheck, FindResult, FrameDetail, ViewState } from "../shared/api.ts";
import type { Ranges } from "../shared/ranges.ts";
import { errorText, get, HttpError, post } from "./api.ts";
import { app, bus, hooks } from "./app.ts";
import { toast, toastError } from "./toast.ts";
import { save } from "./util.ts";

// ---------------------------------------------------------------- state sync

let wsStateSeq = 0;
let stateReq: Promise<void> | null = null;
let stateAgain = false;

/** Called for every state pushed over the WebSocket. */
export function noteWsState(): void {
  wsStateSeq++;
}

/** GET /api/state; dropped if a pushed state arrives while it is in flight. */
export function refreshState(): Promise<void> {
  if (stateReq) {
    stateAgain = true;
    return stateReq;
  }
  const seqAtStart = wsStateSeq;
  stateReq = get<ViewState>("api/state")
    .then((s) => {
      if (wsStateSeq === seqAtStart) applyState(s);
    })
    .catch((e: unknown) => {
      if (!(e instanceof HttpError && e.status === 0)) toastError(e, "Loading state failed");
    })
    .finally(() => {
      stateReq = null;
      if (stateAgain) {
        stateAgain = false;
        void refreshState();
      }
    });
  return stateReq;
}

/** Frame the user jumped to; its row is revealed once the server reports its index. */
let pendingReveal: number | null = null;
/** Set on WebSocket reconnect; if the server restarted, its counters are not comparable. */
let resync = false;

export function markResync(): void {
  resync = true;
}

export function applyState(s: ViewState): void {
  const prev = app.state;
  const fresh = !prev || (resync && prev.instance !== s.instance);
  resync = false;
  const prevSel = app.selFrame;
  const prevIdx = app.selIndex;
  const prevRows = app.selRows;
  app.state = s;
  app.marks = new Map(s.marks.map((m) => [m.frame, m]));

  let reveal: { index: number; flash: boolean } | null = null;
  if (fresh || !prev) {
    app.selFrame = s.selected;
    app.selIndex = s.selectedIndex;
    app.selRows = s.selectedRows;
    selRefused = false;
    if (s.selectedIndex >= 0) reveal = { index: s.selectedIndex, flash: false };
  } else if (s.selectSeq !== prev.selectSeq) {
    // The agent selected a frame: it wins over anything the user has pending.
    cancelPendingSelect();
    pendingReveal = null;
    app.selFrame = s.selected;
    app.selIndex = s.selectedIndex;
    app.selRows = s.selectedRows;
    selRefused = false;
    if (s.selectedIndex >= 0) reveal = { index: s.selectedIndex, flash: true };
  } else if (pendingReveal !== null && s.selected === pendingReveal) {
    app.selFrame = s.selected;
    app.selIndex = s.selectedIndex;
    app.selRows = s.selectedRows;
    selRefused = false;
    if (s.selectedIndex >= 0) reveal = { index: s.selectedIndex, flash: false };
    else toast("info", `Packet ${pendingReveal} is hidden by the display filter`);
    pendingReveal = null;
  } else if (!selectBusy() || s.file !== prev.file || s.filter !== prev.filter) {
    // Row indices of another file or filter mean nothing, even with a selection pending
    app.selFrame = s.selected;
    app.selIndex = s.selected === null ? -1 : s.selectedIndex;
    app.selRows = s.selectedRows;
    selRefused = false;
  } else if (s.generation !== prev.generation && s.selected === app.selFrame) {
    app.selIndex = s.selectedIndex;
  }

  if (prev && (s.file !== prev.file || fresh)) {
    // Frame numbers of the new file are unrelated to the old one.
    cancelPendingSelect();
    resetFrame();
    if (app.frame) {
      app.frame = null;
      bus.emit("frame", null);
    }
  }
  if (!s.file) {
    app.selFrame = null;
    app.selIndex = -1;
    app.selRows = [];
    selRefused = false;
  }

  bus.emit("state", s, prev);
  if (app.selFrame !== prevSel || app.selIndex !== prevIdx || !sameRanges(app.selRows, prevRows)) bus.emit("selection");
  if (app.selFrame !== (app.frame?.num ?? null)) loadFrame(app.selFrame);
  if (reveal) bus.emit("reveal", reveal.index, reveal.flash);
}

// ----------------------------------------------------------------- selection

let selPending: { frame: number | null; rows?: Ranges; view?: { file: string; filter: string; generation: number } } | null = null;
let selTimer = 0;
let selInflight = 0;
let selPost: Promise<void> = Promise.resolve();
/** The server refused the last selection and the UI has not taken the server's since. */
let selRefused = false;

function sameRanges(a: Ranges, b: Ranges): boolean {
  return a.length === b.length && a.every((r, i) => r[0] === b[i][0] && r[1] === b[i][1]);
}

function selectBusy(): boolean {
  return selPending !== null || selInflight > 0;
}

function cancelPendingSelect(): void {
  selPending = null;
  window.clearTimeout(selTimer);
}

/** `checked`: the server refuses the selection if the view changed since (rows always are). */
function postSelect(frame: number | null, delay: number, rows?: Ranges, checked = false): void {
  // Rows are indices into the list shown now
  const s = app.state;
  selPending = { frame, rows, view: (rows || checked) && s?.file ? { file: s.file, filter: s.filter, generation: s.generation } : undefined };
  window.clearTimeout(selTimer);
  selTimer = window.setTimeout(() => void flushSelect(), delay);
}

function flushSelect(): Promise<void> {
  window.clearTimeout(selTimer);
  selPost = sendSelect();
  return selPost;
}

/**
 * Sends a pending selection now. False while the server holds another
 * selection than the one shown: refused, or rows still loading.
 */
export async function flushSelection(): Promise<boolean> {
  await (selPending ? flushSelect() : selPost);
  return !selRefused && !hooks.selectionLoading();
}

async function sendSelect(): Promise<void> {
  if (!selPending) return;
  const { frame, rows, view } = selPending;
  selPending = null;
  selInflight++;
  try {
    await post("api/select", view ? { frame, rows, view } : { frame });
    selRefused = false;
  } catch (e) {
    // 409: the list changed under the click
    if (!(e instanceof HttpError && e.status === 409)) toastError(e, "Selecting the packet failed");
    selRefused = true;
    void refreshState();
    return;
  } finally {
    selInflight--;
  }
  // The pushed state may not have arrived (or nothing changed): ask for it.
  if (pendingReveal !== null && pendingReveal === frame) void refreshState();
}

/**
 * User selected the row at `index` showing `frame`; `rows` are all selected
 * rows after a Ctrl/Shift+click, else just this one.
 */
export function selectRow(index: number, frame: number, rows?: Ranges): void {
  pendingReveal = null;
  const sel: Ranges = rows ?? [[index, index]];
  if (app.selFrame === frame && app.selIndex === index && sameRanges(app.selRows, sel)) return;
  app.selFrame = frame;
  app.selIndex = index;
  app.selRows = sel;
  bus.emit("selection");
  // A row clicked in the list shown now: refused if that list is gone by then
  postSelect(frame, 60, rows, true);
  loadFrame(frame);
}

/**
 * Select a frame by number (Go to packet, frame links, marks menu). `checked`:
 * the server refuses it once the file or filter changed (a Find result).
 */
export function jumpToFrame(n: number, checked = false): void {
  const s = app.state;
  if (!s || !s.file) return;
  if (!Number.isInteger(n) || n < 1 || (s.totalFrames > 0 && n > s.totalFrames)) {
    toast("error", `Packet ${n} doesn't exist (1 – ${s.totalFrames})`);
    return;
  }
  const idx = hooks.indexOfFrame(n);
  app.selFrame = n;
  app.selIndex = idx;
  app.selRows = idx >= 0 ? [[idx, idx]] : [];
  bus.emit("selection");
  if (idx >= 0) {
    pendingReveal = null;
    bus.emit("reveal", idx, false);
  } else {
    pendingReveal = n;
  }
  postSelect(n, 0, undefined, checked);
  loadFrame(n);
}

// ------------------------------------------------------------- frame detail

let frameSeq = 0;
let frameTimer = 0;
/** Frame whose details are scheduled or in flight, else null. */
let loadingNum: number | null = null;
let lastFailedNum: number | null = null;

/** Cancels any scheduled or in-flight detail load. */
function resetFrame(): void {
  window.clearTimeout(frameTimer);
  frameSeq++;
  loadingNum = null;
  lastFailedNum = null;
}

/** Shows the selected packet's details again, e.g. after its file was re-read. */
export function reloadFrame(): void {
  const num = app.selFrame;
  resetFrame();
  if (num !== null) frameTimer = window.setTimeout(() => void fetchFrame(num), 0);
}

/** Loads the details of `num` (debounced) unless shown or already loading. */
export function loadFrame(num: number | null): void {
  if (num === null) {
    resetFrame();
    if (app.frame) {
      app.frame = null;
      bus.emit("frame", null);
    }
    return;
  }
  if (app.frame && app.frame.num === num) {
    // Back on the shown frame: drop a load of another frame that is still pending.
    if (loadingNum !== null) resetFrame();
    return;
  }
  if (loadingNum === num) return;
  window.clearTimeout(frameTimer);
  loadingNum = num;
  frameTimer = window.setTimeout(() => void fetchFrame(num), 30);
}

async function fetchFrame(num: number): Promise<FrameDetail | null> {
  const seq = ++frameSeq;
  loadingNum = num;
  try {
    const fd = await get<FrameDetail>("api/frame", { num });
    if (seq !== frameSeq) return fd;
    loadingNum = null;
    lastFailedNum = null;
    // The selection moved on while this was loading.
    if (num !== app.selFrame) return fd;
    app.frame = fd;
    bus.emit("frame", fd);
    return fd;
  } catch (e) {
    if (seq === frameSeq) {
      loadingNum = null;
      // Live reloads retry on every push: report a failing frame once.
      if (lastFailedNum !== num) toastError(e, `Loading packet ${num} failed`);
      lastFailedNum = num;
    }
    return null;
  }
}

/** Details of `num`, from the current selection when possible. */
export async function frameDetail(num: number): Promise<FrameDetail | null> {
  if (app.frame && app.frame.num === num) return app.frame;
  window.clearTimeout(frameTimer);
  return fetchFrame(num);
}

// ------------------------------------------------------------------ filters

/** POST /api/filter; a rejected filter comes back as `{ ok: false }`. */
export async function applyFilter(text: string): Promise<FilterCheck> {
  try {
    const r = await post<FilterCheck>("api/filter", { filter: text });
    if (r && typeof r.ok === "boolean") {
      if (r.ok && app.conn !== "open") void refreshState();
      return r;
    }
    return { ok: true };
  } catch (e) {
    if (e instanceof HttpError && e.status >= 400 && e.status < 500 && e.status !== 401 && e.status !== 403) {
      return { ok: false, error: e.message };
    }
    toastError(e, "Applying the filter failed");
    return { ok: false, error: errorText(e) };
  }
}

// -------------------------------------------------------------------- marks

export async function markFrames(frames: number[], note: string): Promise<void> {
  try {
    await post("api/marks", { frames, note });
    if (app.conn !== "open") void refreshState();
  } catch (e) {
    toastError(e, "Marking failed");
  }
}

export async function clearMarks(frames?: number[]): Promise<void> {
  try {
    await post("api/marks/clear", frames ? { frames } : {});
    if (app.conn !== "open") void refreshState();
  } catch (e) {
    toastError(e, "Unmarking failed");
  }
}

/** Mark/Unmark Packet(s): flips the mark of each selected packet. */
export async function toggleMarkSelected(): Promise<void> {
  if (!(await flushSelection())) {
    toast("error", "The selection isn't settled yet; select the packets again");
    return;
  }
  try {
    await post("api/marks/toggle", {});
    if (app.conn !== "open") void refreshState();
  } catch (e) {
    toastError(e, "Marking failed");
  }
}

/** Mark All Displayed / Unmark All Displayed. */
export async function markDisplayed(on: boolean): Promise<void> {
  try {
    await post("api/marks/displayed", { on });
    if (app.conn !== "open") void refreshState();
  } catch (e) {
    toastError(e, on ? "Marking failed" : "Unmarking failed");
  }
}

/** Next/previous marked frame relative to the selection. */
export function gotoMark(dir: 1 | -1): void {
  const frames = [...app.marks.keys()].sort((a, b) => a - b);
  if (!frames.length) return;
  const cur = app.selFrame ?? (dir > 0 ? 0 : Number.MAX_SAFE_INTEGER);
  const next = dir > 0 ? frames.find((f) => f > cur) ?? frames[0] : [...frames].reverse().find((f) => f < cur) ?? frames[frames.length - 1];
  jumpToFrame(next);
}

// -------------------------------------------------------------- files, misc

/** Returns an error message, or null on success. */
export async function openFile(path: string): Promise<string | null> {
  try {
    await post("api/open", { path });
    if (app.conn !== "open") void refreshState();
    return null;
  } catch (e) {
    return errorText(e);
  }
}

export async function closeFile(): Promise<void> {
  try {
    await post("api/close", {});
    if (app.conn !== "open") void refreshState();
  } catch (e) {
    toastError(e, "Closing failed");
  }
}

export async function openInWireshark(frame?: number | null): Promise<void> {
  try {
    await post("api/wireshark", frame !== null && frame !== undefined ? { frame } : {});
    toast("info", frame ? `Opening packet ${frame} in Wireshark…` : "Opening in Wireshark…");
  } catch (e) {
    toastError(e, "Opening Wireshark failed");
  }
}

export async function startCapture(req: CaptureRequest): Promise<boolean> {
  try {
    await post("api/capture/start", req);
    if (app.conn !== "open") void refreshState();
    return true;
  } catch (e) {
    toastError(e, "Starting the capture failed");
    return false;
  }
}

export async function stopCapture(): Promise<boolean> {
  try {
    await post("api/capture/stop", {});
    if (app.conn !== "open") void refreshState();
    return true;
  } catch (e) {
    toastError(e, "Stopping the capture failed");
    return false;
  }
}

// ------------------------------------------------------------ columns, tls

/** Replaces the custom columns; false (after a toast) when the server rejects them. */
export async function setCustomColumns(columns: CustomColumn[]): Promise<boolean> {
  try {
    const r = await post<FilterCheck>("api/columns", { columns });
    if (r && r.ok === false) {
      toast("error", `Column not applied: ${r.error ?? "rejected"}`);
      return false;
    }
    if (app.conn !== "open") void refreshState();
    return true;
  } catch (e) {
    toastError(e, "Changing the columns failed");
    return false;
  }
}

/** "Apply as Column" for a details field. */
export function addCustomColumn(field: string, title: string): void {
  const cur = app.state?.customColumns ?? [];
  if (cur.some((c) => c.field === field)) {
    toast("info", `${field} is already a column`);
    return;
  }
  void setCustomColumns([...cur, { field, title }]);
}

/** Sets or clears the TLS key log file; returns an error message or null. */
export async function setTlsKeylog(keylog: string | null): Promise<string | null> {
  try {
    await post("api/tls", { keylog });
    if (app.conn !== "open") void refreshState();
    // Decryption changes the dissection of the shown packet
    reloadFrame();
    return null;
  } catch (e) {
    return errorText(e);
  }
}

export function exportPackets(req: ExportRequest): Promise<ExportResult> {
  return post<ExportResult>("api/export", req);
}

/** Selects the next (or previous) displayed packet matching `filter`; throws on a bad filter. */
export async function findPacket(filter: string, dir: 1 | -1): Promise<FindResult> {
  const view = (s = app.state) => `${s?.instance}\u0001${s?.file}\u0001${s?.filter}`;
  const before = view();
  const r = await get<FindResult>("api/find", { filter, from: app.selFrame ?? 0, dir });
  // A live capture may have found a packet the pushed state doesn't count yet
  for (let k = 0; k < 3 && r.frame !== null && r.frame > (app.state?.totalFrames ?? 0); k++) await refreshState();
  if (view() !== before) throw new Error("the packet list changed, find again");
  if (r.frame !== null) {
    jumpToFrame(r.frame, true);
    if (!(await flushSelection())) throw new Error("the packet list changed, find again");
  }
  return r;
}

/** View > Reload: re-reads the file, keeping marks and selection. */
export async function reloadFile(): Promise<void> {
  try {
    await post("api/reload", {});
    if (app.conn !== "open") void refreshState();
    reloadFrame();
  } catch (e) {
    toastError(e, "Reloading failed");
  }
}

export function setColorize(on: boolean): void {
  if (app.colorize === on) return;
  app.colorize = on;
  save("colorize", on);
  bus.emit("view");
}

export function setZoom(zoom: number): void {
  if (app.zoom === zoom) return;
  app.zoom = zoom;
  save("zoom", zoom);
  bus.emit("view");
}

export function setAutoScroll(on: boolean): void {
  if (app.autoScroll === on) return;
  app.autoScroll = on;
  save("autoscroll", on);
  bus.emit("autoscroll", on);
}
