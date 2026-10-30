/**
 * Virtualized packet list.
 *
 * Rows are fetched in pages from /api/rows and cached per generation. Only the
 * visible rows exist in the DOM: a sticky layer the height of the viewport
 * holds them, and a spacer gives the scrollbar its range. When rows * RH is
 * taller than browsers allow, the scroll position is scaled into the virtual
 * range, so 1M+ rows still scroll from top to bottom.
 */

import type { PacketRow, RowsResponse, ViewState } from "../shared/api.ts";
import { countRanges, inRanges, mergeRanges, toggleInRanges, type Ranges } from "../shared/ranges.ts";
import { get, HttpError } from "./api.ts";
import * as act from "./actions.ts";
import { agentName, app, bus, captureActive, hooks } from "./app.ts";
import { promptDialog } from "./dialog.ts";
import { openAskDialog } from "./dialogs/ask.ts";
import { commentItems } from "./dialogs/comment.ts";
import { decodeAsItem } from "./dialogs/decodeas.ts";
import { openExportDialog } from "./dialogs/export.ts";
import { followItems } from "./dialogs/follow.ts";
import { conversationFilters } from "./frame.ts";
import { SEP, showMenu, type MenuItem } from "./menu.ts";
import { toastError } from "./toast.ts";
import { clamp, copyText, csvField, fontOf, h, IS_MAC, isMod, keyLabel, keyLetter, load, measureText, save } from "./util.ts";

const RH = 20;
const PAGE = 200;
const OVERSCAN = 100;
/** Stay well below the smallest browser limit for element heights (Firefox ~17.9M px). */
const MAX_SCROLL = 8_000_000;
const MAX_INFLIGHT = 4;
const MAX_PAGES = 300;
const MAX_VIEW = 4000;
/** Copying more rows than this asks for a smaller selection. */
const MAX_COPY = 10000;

const DEFAULT_WIDTHS: Record<string, number> = {
  "No.": 72,
  Time: 104,
  Source: 150,
  Destination: 150,
  Protocol: 76,
  Length: 64,
  Info: 320,
};

interface RowEl {
  el: HTMLDivElement;
  cells: HTMLSpanElement[];
}

let root: HTMLDivElement;
let headerInner: HTMLDivElement;
let scroller: HTMLDivElement;
let layer: HTMLDivElement;
let spacer: HTMLDivElement;
let overlay: HTMLDivElement;

let columns: string[] = [];
/** Titles plus custom column fields; the header is rebuilt when it changes. */
let headerKey = "";
let widths: number[] = [];
const colW: Record<string, number> = load<Record<string, number>>("colwidths", {});
let total = 0;
let gen = -1;
let pages = new Map<number, PacketRow[]>();
/** Older generations' pages of the same list (it only grew): the same frames, until the page comes again. */
let stale = new Map<number, PacketRow[]>();
/** Pages of an earlier list of the same file and filter, shown as placeholders while it refetches. */
let ghosts = new Map<number, PacketRow[]>();
/** Pages asked for, with the rows asked for; requests for older generations of the list count too. */
let inflight = new Map<number, number>();
/** Generation the time references last changed at: rows of older generations read other times. */
let timesGen = 0;
const failed = new Map<number, number>();
let errorToastAt = 0;

let virtTop = 0;
let lastSetScroll = -1;
let pool: RowEl[] = [];
let flashIdx = -1;
let flashUntil = 0;
let flashTimer = 0;
/** Row to select once its page arrives, with the rows selected along with it. */
let pendingSel: { i: number; rows?: Ranges } | null = null;
/** Following the live end: the view waits on the newest rows it has until the end's arrive. */
let followPending = false;
/** Row Shift+click and Shift+arrows extend the selection from. */
let anchor = -1;
let userInputAt = 0;
let rafQueued = false;

function defaultWidth(c: string): number {
  return DEFAULT_WIDTHS[c] ?? 110;
}

function rightAligned(c: string): boolean {
  return /^(No\.|Length|Len|Size|Frame length)$/i.test(c.trim());
}

// ------------------------------------------------------------------ geometry

function metrics(): { vh: number; virtH: number; scrollH: number; maxVirt: number; maxScroll: number } {
  // Capped so an unconstrained layout can never ask for hundreds of thousands of rows.
  const vh = Math.min(scroller.clientHeight, MAX_VIEW);
  const virtH = total * RH;
  const scrollH = Math.min(virtH, MAX_SCROLL);
  return { vh, virtH, scrollH, maxVirt: Math.max(0, virtH - vh), maxScroll: Math.max(0, scrollH - vh) };
}

function updateHeights(): void {
  const m = metrics();
  layer.style.height = `${m.vh}px`;
  spacer.style.height = `${Math.max(0, m.scrollH - m.vh)}px`;
  virtTop = clamp(virtTop, 0, m.maxVirt);
  syncScrollFromVirt();
}

function syncScrollFromVirt(): void {
  const m = metrics();
  const st = m.maxVirt > 0 ? (virtTop * m.maxScroll) / m.maxVirt : 0;
  lastSetScroll = st;
  if (Math.abs(scroller.scrollTop - st) >= 1) scroller.scrollTop = st;
}

function setVirtTop(v: number): void {
  const m = metrics();
  virtTop = clamp(v, 0, m.maxVirt);
  followPending = false;
  syncScrollFromVirt();
  render();
}

function onScroll(): void {
  headerInner.style.transform = `translateX(${-scroller.scrollLeft}px)`;
  const st = scroller.scrollTop;
  if (Math.abs(st - lastSetScroll) >= 1) {
    const m = metrics();
    const before = virtTop;
    virtTop = m.maxScroll > 0 ? (st * m.maxVirt) / m.maxScroll : 0;
    lastSetScroll = st;
    if (performance.now() - userInputAt < 800) {
      followPending = false;
      scrolledBy(virtTop - before);
    }
  }
  render();
}

/** Scrolling up by hand during a live capture turns auto-scroll off, as in Wireshark. */
function scrolledBy(d: number): void {
  if (d < -1 && app.autoScroll && captureActive()) act.setAutoScroll(false);
}

function isAtBottom(): boolean {
  const m = metrics();
  return virtTop >= m.maxVirt - RH;
}

/**
 * Scrolls to the end of the list, or while its rows are still loading to
 * the newest rows the list has, and on to the end once they arrive: a
 * followed live capture never shows a screen of placeholders it has rows for.
 */
function follow(): void {
  const m = metrics();
  const n = Math.min(total, Math.ceil(m.vh / RH));
  const end = newestWindow(n);
  if (end >= total - 1 || (end < 0 && !showsRows())) {
    setVirtTop(m.maxVirt);
    return;
  }
  const t = clamp((end + 1) * RH - m.vh, 0, m.maxVirt);
  if (end >= 0 && (t > virtTop || !showsRows())) {
    virtTop = t;
    syncScrollFromVirt();
  }
  followPending = true;
  render();
}

/** Last row of the newest `n` rows in a row that all have data, at or after the view's first row; -1 if there are none. */
function newestWindow(n: number): number {
  const from = Math.floor(virtTop / RH);
  const keys = [...new Set([...pages.keys(), ...stale.keys()])].filter((p) => (p + 1) * PAGE > from).sort((a, b) => b - a);
  for (const p of keys) {
    const rows = pages.get(p) ?? stale.get(p)!;
    let k = Math.min(rows.length, total - p * PAGE) - 1;
    while (k >= 0 && !rows[k]) k--;
    const end = p * PAGE + k;
    if (k < 0 || end - n + 1 < 0) continue;
    let i = end;
    while (i > end - n && validRowAt(i)) i--;
    if (i === end - n) return end;
  }
  return -1;
}

/** Whether any row on screen has data, if only a placeholder's. */
function showsRows(): boolean {
  const first = Math.floor(virtTop / RH);
  const n = Math.ceil(metrics().vh / RH) + 1;
  for (let i = first; i < Math.min(total, first + n); i++) if (rowAt(i)) return true;
  return false;
}

function ensureVisible(i: number, mode: "nearest" | "center" | "centerIfHidden"): void {
  if (i < 0 || i >= total) return;
  const vh = scroller.clientHeight;
  const top = i * RH;
  const hidden = top < virtTop || top + RH > virtTop + vh;
  let t = virtTop;
  if (mode === "center" || (mode === "centerIfHidden" && hidden)) t = top - (vh - RH) / 2;
  else if (top < virtTop) t = top;
  else if (top + RH > virtTop + vh) t = top + RH - vh;
  else return;
  setVirtTop(t);
}

// ------------------------------------------------------------------- columns

function computeWidths(): void {
  const avail = scroller.clientWidth || root.clientWidth || 800;
  widths = columns.map((c) => colW[c] ?? defaultWidth(c));
  if (widths.length) {
    const others = widths.slice(0, -1).reduce((a, b) => a + b, 0);
    widths[widths.length - 1] = Math.max(widths[widths.length - 1], avail - others);
  }
  const totalW = widths.reduce((a, b) => a + b, 0);
  widths.forEach((w, j) => root.style.setProperty(`--c${j}`, `${w}px`));
  headerInner.style.width = `${totalW}px`;
  layer.style.width = `${totalW}px`;
  spacer.style.width = `${totalW}px`;
}

/** Index into state.customColumns for list column j, or -1 for a default column. */
function customIndex(j: number): number {
  const custom = app.state?.customColumns ?? [];
  const k = j - (columns.length - custom.length);
  return k >= 0 && k < custom.length ? k : -1;
}

async function editColumnTitle(k: number): Promise<void> {
  const c = app.state?.customColumns[k];
  if (!c) return;
  const t = await promptDialog("Edit Column Title", "Title:", c.title, "Apply");
  if (t === null) return;
  const title = t.trim() || c.field;
  const now = app.state?.customColumns ?? [];
  void act.setCustomColumns(now.map((x) => (x.field === c.field ? { ...x, title } : x)));
}

function headerMenu(j: number, x: number, y: number): void {
  const custom = app.state?.customColumns ?? [];
  const k = customIndex(j);
  const why = k < 0 ? "Only custom columns can be changed" : undefined;
  const items: MenuItem[] = [];
  if (k >= 0) items.push({ label: `Custom column: ${custom[k].field}`, header: true });
  items.push(
    { label: "Resize to Contents", action: () => autosize(j) },
    SEP,
    { label: "Edit Column Title…", disabled: k < 0, title: why, action: () => void editColumnTitle(k) },
    { label: "Remove Column", disabled: k < 0, title: why, action: () => void act.setCustomColumns(custom.filter((_, i) => i !== k)) },
    SEP,
    { label: "Reset Custom Columns", disabled: !custom.length, action: () => void act.setCustomColumns([]) },
  );
  showMenu(items, x, y);
}

function buildHeader(): void {
  headerInner.replaceChildren();
  columns.forEach((c, j) => {
    const k = customIndex(j);
    const field = k >= 0 ? app.state?.customColumns[k]?.field : undefined;
    const grip = h("div", { class: "pl-grip", title: "Drag to resize, double-click to fit" });
    const cell = h(
      "div",
      { class: `pl-hcell${rightAligned(c) ? " right" : ""}${k >= 0 ? " custom" : ""}`, style: `width:var(--c${j})`, title: field ? `${c} (${field})` : c },
      h("span", { class: "pl-htext" }, c),
      grip,
    );
    cell.addEventListener("contextmenu", (e) => {
      e.preventDefault();
      headerMenu(j, e.clientX, e.clientY);
    });
    grip.addEventListener("pointerdown", (e) => startResize(e, j));
    grip.addEventListener("dblclick", (e) => {
      e.stopPropagation();
      autosize(j);
    });
    headerInner.appendChild(cell);
  });
  pool.forEach((r) => r.el.remove());
  pool = [];
  computeWidths();
}

function startResize(e: PointerEvent, j: number): void {
  if (e.button !== 0) return;
  e.preventDefault();
  e.stopPropagation();
  const grip = e.currentTarget as HTMLElement;
  grip.setPointerCapture(e.pointerId);
  const startX = e.clientX;
  const startW = widths[j];
  root.classList.add("resizing");
  const move = (ev: PointerEvent): void => {
    // Pointer moves are in screen pixels; widths are in the zoomed panes' own
    colW[columns[j]] = Math.max(28, Math.round(startW + (ev.clientX - startX) / app.zoom));
    computeWidths();
  };
  const up = (): void => {
    grip.removeEventListener("pointermove", move);
    grip.removeEventListener("pointerup", up);
    grip.removeEventListener("pointercancel", up);
    root.classList.remove("resizing");
    save("colwidths", colW);
  };
  grip.addEventListener("pointermove", move);
  grip.addEventListener("pointerup", up);
  grip.addEventListener("pointercancel", up);
}

function autosize(j: number): void {
  const font = fontOf(pool[0]?.el ?? root);
  let w = measureText(columns[j], font) + 22;
  const first = Math.floor(virtTop / RH);
  const n = Math.ceil(scroller.clientHeight / RH) + 1;
  for (let i = first; i < Math.min(total, first + n); i++) {
    const row = rowAt(i);
    if (row) w = Math.max(w, measureText(row.c[j] ?? "", font) + 14);
  }
  colW[columns[j]] = Math.round(clamp(w, 36, 1200));
  computeWidths();
  save("colwidths", colW);
}

// ---------------------------------------------------------------------- data

function rowAt(i: number): PacketRow | undefined {
  const p = Math.floor(i / PAGE);
  return pages.get(p)?.[i - p * PAGE] ?? stale.get(p)?.[i - p * PAGE] ?? ghosts.get(p)?.[i - p * PAGE];
}

function freshRowAt(i: number): PacketRow | undefined {
  const p = Math.floor(i / PAGE);
  return pages.get(p)?.[i - p * PAGE];
}

/** Row `i` of the list shown now, if only as an older generation read it. */
function validRowAt(i: number): PacketRow | undefined {
  const p = Math.floor(i / PAGE);
  return pages.get(p)?.[i - p * PAGE] ?? stale.get(p)?.[i - p * PAGE];
}

function want(first: number, last: number): void {
  if (!app.state?.file || total === 0) return;
  const lo = Math.max(0, first - OVERSCAN);
  const hi = Math.min(total - 1, last + OVERSCAN);
  const pageOf = (i: number): number => Math.floor(i / PAGE);
  const vis: number[] = [];
  for (let p = pageOf(first); p <= pageOf(Math.min(total - 1, last)); p++) vis.push(p);
  const extra: number[] = [];
  for (let p = pageOf(lo); p <= pageOf(hi); p++) if (!vis.includes(p)) extra.push(p);
  // A clicked row, until it is selected; while the view waits on the live end, only the end's pages
  const urgent: number[] = pendingSel ? [pageOf(pendingSel.i)] : [];
  if (followPending) for (let p = pageOf(Math.max(0, total - Math.ceil(metrics().vh / RH))); p <= pageOf(total - 1); p++) urgent.push(p);
  const now = performance.now();
  for (const p of followPending ? urgent : [...urgent, ...vis, ...extra]) {
    if (inflight.size >= MAX_INFLIGHT) break;
    if (pages.has(p) || (inflight.get(p) ?? 0) >= Math.min(PAGE, total - p * PAGE)) continue;
    const f = failed.get(p);
    if (f !== undefined && now - f < 2500) continue;
    void fetchPage(p);
  }
}

async function fetchPage(p: number): Promise<void> {
  const g = gen;
  const view = viewKey();
  const comments = app.state?.commentRevision;
  const start = p * PAGE;
  const count = Math.min(PAGE, total - start);
  if (count <= 0) return;
  inflight.set(p, count);
  try {
    const r = await get<RowsResponse>("api/rows", { gen: g, start, count });
    // Rows of another list since
    if (viewKey() !== view || r.generation !== g) return;
    const rows = r.start === start ? r.rows : alignRows(r, start, count);
    if (g !== gen) {
      // The list only grew since (a live capture): the same frames, as the server reads them now, unless their times or comments changed
      if (pages.has(p)) return;
      if (g >= timesGen && current(rows, start) && comments === app.state?.commentRevision) setPage(p, rows);
      else {
        stale.set(p, [...rows, ...(stale.get(p)?.slice(rows.length) ?? [])]);
        trimStale();
      }
    } else if (r.rows.length < count) {
      // Provisional rows that couldn't be read now: the others show, the page comes again
      stale.set(p, [...rows, ...(stale.get(p)?.slice(rows.length) ?? [])]);
      failed.set(p, performance.now());
      window.setTimeout(scheduleRender, 2600);
    } else setPage(p, rows);
    resolvePending();
    if (followPending) follow();
  } catch (e) {
    if (g !== gen) return;
    failed.set(p, performance.now());
    window.setTimeout(scheduleRender, 2600);
    if (e instanceof HttpError && e.status === 409) {
      void act.refreshState();
    } else if (performance.now() - errorToastAt > 10000) {
      errorToastAt = performance.now();
      toastError(e, "Loading packets failed");
    }
  } finally {
    if (inflight.get(p) === count && viewKey() === view && g >= timesGen) inflight.delete(p);
    scheduleRender();
  }
}

function setPage(p: number, rows: PacketRow[]): void {
  pages.set(p, rows);
  stale.delete(p);
  failed.delete(p);
  evict(p);
}

/** Whether an older generation's page is the whole page of the list now, its rows read in full or provisional as they are now. */
function current(rows: PacketRow[], start: number): boolean {
  const exact = app.state?.displayedFrames ?? 0;
  if (rows.length !== Math.min(PAGE, total - start)) return false;
  for (let k = 0; k < rows.length; k++) if (!rows[k] || !!rows[k].p !== start + k >= exact) return false;
  return true;
}

/** Selects a clicked row once its frame is known. */
function resolvePending(): void {
  const row = pendingSel && validRowAt(pendingSel.i);
  if (!pendingSel || !row) return;
  const { i, rows } = pendingSel;
  pendingSel = null;
  act.selectRow(i, row.num, rows);
}

/** Server answered with a different start: keep only the rows of page p. */
function alignRows(r: RowsResponse, start: number, count: number): PacketRow[] {
  const out: PacketRow[] = [];
  for (let k = 0; k < r.rows.length; k++) {
    const idx = r.start + k - start;
    if (idx >= 0 && idx < count) out[idx] = r.rows[k];
  }
  return out;
}

/** Keeps pages, stale and ghost pages within MAX_PAGES, dropping ghosts, then stale pages, far from the view first. */
function trimStale(): void {
  const center = Math.floor(virtTop / RH / PAGE);
  for (const old of [ghosts, stale]) {
    const room = Math.max(0, MAX_PAGES - pages.size - (old === ghosts ? stale.size : 0));
    if (old.size <= room) continue;
    const keys = [...old.keys()].sort((a, b) => Math.abs(a - center) - Math.abs(b - center));
    for (const k of keys.slice(room)) old.delete(k);
  }
}

function evict(keep: number): void {
  trimStale();
  if (pages.size <= MAX_PAGES) return;
  const center = Math.floor(virtTop / RH / PAGE);
  const keys = [...pages.keys()].filter((k) => k !== keep).sort((a, b) => Math.abs(b - center) - Math.abs(a - center));
  for (const k of keys.slice(0, pages.size - Math.floor(MAX_PAGES * 0.8))) pages.delete(k);
}

/** Row index of a frame if its row is cached, else -1. */
function indexOfFrame(frame: number): number {
  for (const cache of [pages, stale]) {
    for (const [p, rows] of cache) {
      const k = rows.findIndex((r) => r?.num === frame);
      if (k >= 0) return p * PAGE + k;
    }
  }
  return -1;
}

// ------------------------------------------------------------------ rendering

function scheduleRender(): void {
  if (rafQueued) return;
  rafQueued = true;
  requestAnimationFrame(() => {
    rafQueued = false;
    render();
  });
}

function makeRow(): RowEl {
  const el = h("div", { class: "pl-row" });
  const cells = columns.map((c, j) => {
    const cell = h("span", { class: `pl-cell${rightAligned(c) ? " right" : ""}`, style: `width:var(--c${j})` });
    el.appendChild(cell);
    return cell;
  });
  el.prepend(h("span", { class: "pl-badge" }, "✦"), h("span", { class: "pl-cm" }));
  layer.appendChild(el);
  return { el, cells };
}

function isSelected(i: number): boolean {
  if (pendingSel) return pendingSel.rows ? inRanges(pendingSel.rows, i) : i === pendingSel.i;
  return inRanges(app.selRows, i);
}

function currentIndex(): number {
  return pendingSel ? pendingSel.i : app.selIndex;
}

function fillRow(r: RowEl, i: number, row: PacketRow | undefined, now: number): void {
  let cls = "pl-row";
  const sel = isSelected(i);
  if (sel) cls += " sel";
  // Focus frame on the current row when several are selected, or it was Ctrl+clicked off
  if (i === currentIndex() && (!sel || countRanges(pendingSel?.rows ?? app.selRows) > 1)) cls += " cur";
  if (i === flashIdx && now < flashUntil) cls += " flash";
  if (!row) {
    cls += " pending";
    for (const c of r.cells) if (c.textContent) c.textContent = "";
    r.el.style.backgroundColor = "";
    r.el.style.color = "";
    r.el.title = "";
  } else {
    for (let j = 0; j < r.cells.length; j++) {
      const t = row.c[j] ?? "";
      if (r.cells[j].textContent !== t) r.cells[j].textContent = t;
    }
    const mark = app.marks.get(row.num);
    if (mark) cls += mark.by === "agent" ? " mark-agent" : " mark-user";
    if (sel && app.state?.selectedBy === "agent" && row.num === app.state.selected) cls += " agent-sel";
    if (row.p) cls += " prov";
    if (row.cm?.length) cls += " commented";
    const useColors = app.colorize && !sel && mark?.by !== "user";
    r.el.style.backgroundColor = useColors && row.bg ? `#${row.bg}` : "";
    r.el.style.color = useColors && row.fg ? `#${row.fg}` : "";
    const marked = mark ? `${mark.by === "agent" ? `Marked by ${agentName()}` : "Marked"}${mark.note ? `: ${mark.note}` : ""}` : "";
    const comments = (row.cm ?? []).map((c) => `Comment: ${c || "(empty comment)"}`);
    const title = [marked, ...comments, row.p ? provisionalTitle() : ""].filter(Boolean).join("\n");
    if (r.el.title !== title) r.el.title = title;
  }
  if (r.el.className !== cls) r.el.className = cls;
}

function render(): void {
  if (!scroller.isConnected) return;
  const m = metrics();
  const first = Math.floor(virtTop / RH);
  const off = virtTop - first * RH;
  const count = total === 0 ? 0 : Math.max(0, Math.min(total - first, Math.ceil((m.vh + off) / RH) + 1));
  while (pool.length < count) pool.push(makeRow());
  const now = performance.now();
  for (let k = 0; k < pool.length; k++) {
    const r = pool[k];
    if (k >= count) {
      if (r.el.style.display !== "none") r.el.style.display = "none";
      continue;
    }
    const i = first + k;
    r.el.style.display = "";
    r.el.style.transform = `translateY(${k * RH - off}px)`;
    r.el.dataset.i = String(i);
    fillRow(r, i, rowAt(i), now);
  }
  want(first, first + count);
}

/** Tooltip of provisional rows. */
function provisionalTitle(): string {
  const t = app.state?.tail;
  const when = {
    read: `with the next full read of the capture (about ${Math.max(1, Math.round((t?.readMs ?? 0) / 1000))} s)`,
    stop: "once the capture stops",
    reading: "once the full read under way finishes",
    reload: "once read in full (View › Reload)",
  }[t?.exactAfter ?? "read"];
  return `Provisional: read from the newest packets, with their connections' start, before WireBuddy read the whole capture again. Exact ${when}.`;
}

function updateOverlay(s: ViewState): void {
  let msg = "";
  if (s.loading) msg = "Loading capture…";
  else if (s.file && total === 0 && s.tail?.held) msg = `Newer packets wait for a full read: ${s.tail.held}`;
  else if (s.file && total === 0 && s.tail?.unfiltered) msg = "Checking newer packets against the display filter…";
  else if (s.file && total === 0 && s.totalFrames > 0) msg = "No packets match the display filter";
  else if (s.file && total === 0 && captureActive(s)) msg = "Waiting for packets…";
  else if (s.file && total === 0 && !s.loadError) msg = "No packets";
  overlay.textContent = msg;
  overlay.hidden = !msg;
  overlay.classList.toggle("busy", s.loading);
}

// ------------------------------------------------------------------ selection

/** Makes row `i` current; `rows` are the selected rows, default just `i`. */
function selectIndex(i: number, rows?: Ranges): void {
  if (total === 0) return;
  i = clamp(i, 0, total - 1);
  if (!rows) anchor = i;
  ensureVisible(i, "nearest");
  // A ghost row may show another frame: the list was rebuilt since
  const row = validRowAt(i);
  if (row) {
    pendingSel = null;
    act.selectRow(i, row.num, rows);
  } else {
    pendingSel = { i, rows };
    render();
  }
}

/** Shift+click: the rows from the anchor to `i`, added to the selection with Ctrl. */
function extendTo(i: number, add: boolean): void {
  if (total === 0) return;
  i = clamp(i, 0, total - 1);
  const cur = currentIndex();
  const a = anchor >= 0 && anchor < total ? anchor : cur >= 0 ? cur : i;
  const span: [number, number] = [Math.min(a, i), Math.max(a, i)];
  selectIndex(i, add ? mergeRanges([...app.selRows, span]) : [span]);
}

/** Ctrl+click: toggles row `i` and makes it current. */
function toggleRow(i: number): void {
  anchor = i;
  selectIndex(i, toggleInRanges(app.selRows, i));
}

export function selectAllRows(): void {
  if (total === 0) return;
  const cur = currentIndex();
  selectIndex(cur >= 0 ? cur : 0, [[0, total - 1]]);
}

function firstVisibleIndex(): number {
  return Math.min(total - 1, Math.ceil(virtTop / RH));
}

function onKey(e: KeyboardEvent): void {
  if (e.altKey || total === 0) return;
  const page = Math.max(1, Math.floor(scroller.clientHeight / RH) - 1);
  const cur = currentIndex();
  if (isMod(e) && !e.shiftKey && keyLetter(e) === "A") {
    e.preventDefault();
    selectAllRows();
    return;
  }
  let i: number;
  switch (e.key) {
    case "ArrowDown":
      i = cur < 0 ? firstVisibleIndex() : cur + 1;
      break;
    case "ArrowUp":
      i = cur < 0 ? firstVisibleIndex() : cur - 1;
      break;
    case "PageDown":
      i = cur < 0 ? firstVisibleIndex() + page : cur + page;
      break;
    case "PageUp":
      i = cur < 0 ? firstVisibleIndex() : cur - page;
      break;
    case "Home":
      i = 0;
      break;
    case "End":
      i = total - 1;
      break;
    case "ArrowLeft":
    case "ArrowRight":
      // Ctrl: Expand/Collapse All, Shift: Expand/Collapse Subtrees of the details
      if (isMod(e) || e.shiftKey) return;
      scroller.scrollLeft += e.key === "ArrowLeft" ? -40 : 40;
      e.preventDefault();
      return;
    default:
      return;
  }
  e.preventDefault();
  userInputAt = performance.now();
  if (e.shiftKey) extendTo(i, false);
  else selectIndex(i);
}

function rowIndexFromEvent(e: MouseEvent): number {
  const el = (e.target as HTMLElement).closest<HTMLElement>(".pl-row");
  if (!el || el.dataset.i === undefined) return -1;
  return Number(el.dataset.i);
}

/** Changes when row indices stop meaning the same frames. */
function viewKey(): string {
  const s = app.state;
  return `${s?.instance}\u0001${s?.file}\u0001${s?.filter}\u0001${s?.rowsSince}`;
}

/** Summary rows of the selected packets, from the cache or the server. */
async function selectedRowData(): Promise<PacketRow[]> {
  const sel = app.selRows;
  const n = countRanges(sel);
  if (n > MAX_COPY) throw new Error(`select at most ${MAX_COPY} packets to copy (${n} are selected)`);
  const view = viewKey();
  const out: PacketRow[] = [];
  let retries = 0;
  for (const [a, b] of sel) {
    for (let i = a; i <= b; ) {
      // Live reloads keep the rows; another file or filter does not
      if (viewKey() !== view) throw new Error("the packet list changed, copy again");
      const cached = freshRowAt(i);
      if (cached) {
        out.push(cached);
        i++;
        continue;
      }
      let r: RowsResponse;
      try {
        r = await get<RowsResponse>("api/rows", { gen, start: i, count: Math.min(500, b - i + 1) });
      } catch (e) {
        // A live reload replaced the generation: same rows, ask again
        if (!(e instanceof HttpError && e.status === 409) || ++retries > 5) throw e;
        await act.refreshState();
        continue;
      }
      if (r.start !== i || !r.rows.length) throw new Error("the packet list changed, copy again");
      out.push(...r.rows);
      i += r.rows.length;
    }
  }
  return out;
}

async function copyRows(format: (r: PacketRow) => string): Promise<void> {
  try {
    if (pendingSel) throw new Error("the selected packets are still loading, copy again");
    await copyText((await selectedRowData()).map(format).join("\n"));
  } catch (e) {
    toastError(e, "Copying failed");
  }
}

/** Edit > Copy items for the selected packets. */
export function packetCopyItems(): MenuItem[] {
  const n = countRanges(app.selRows);
  return [
    { label: "Summary as Text", disabled: !n, action: () => void copyRows((r) => r.c.join("\t")) },
    { label: "…as CSV", disabled: !n, action: () => void copyRows((r) => r.c.map(csvField).join(",")) },
    { label: n > 1 ? "Packet Numbers" : "Packet Number", disabled: !n, action: () => void copyRows((r) => String(r.num)) },
  ];
}

async function openRowMenu(i: number, x: number, y: number): Promise<void> {
  const row = validRowAt(i);
  if (!row) return;
  // Right-click inside the selection keeps it, like Wireshark
  if (inRanges(app.selRows, i)) act.selectRow(i, row.num, app.selRows);
  else {
    anchor = i;
    act.selectRow(i, row.num);
  }
  const n = countRanges(app.selRows);
  const fd = await act.frameDetail(row.num);
  const s = app.state;
  const marked = app.marks.has(row.num);
  const conv = fd ? conversationFilters(fd) : [];
  const filterItems = (apply: boolean): MenuItem[] =>
    conv.map((c) => ({ label: `${c.label} Conversation`, action: () => hooks.setFilter(c.filter, apply) }));
  const ask: MenuItem[] = s?.agent.attached
    ? [{ label: n > 1 ? `Ask ${agentName()} about These ${n} Packets…` : `Ask ${agentName()} about This Packet…`, action: openAskDialog }, SEP]
    : [];
  const items: MenuItem[] = [
    ...ask,
    {
      label: n > 1 ? `Mark/Unmark ${n} Packets` : marked ? "Unmark Packet" : "Mark Packet",
      shortcut: keyLabel("Ctrl+M"),
      action: () => void act.toggleMarkSelected(),
    },
    { label: n > 1 ? `Set/Unset Time References on ${n} Packets` : "Set/Unset Time Reference", action: () => void act.toggleTimeRefSelected() },
    { label: "Packet Comments", sub: commentItems(fd) },
    SEP,
    { label: "Apply as Filter", sub: filterItems(true), disabled: !conv.length },
    { label: "Prepare as Filter", sub: filterItems(false), disabled: !conv.length },
    SEP,
    { label: "Follow", disabled: !fd, sub: followItems(fd) },
    decodeAsItem(fd),
    SEP,
    { label: "Copy", sub: packetCopyItems() },
    { label: n > 1 ? `Export ${n} Selected Packets…` : "Export Selected Packet…", action: () => openExportDialog("selected") },
    SEP,
    {
      label: "Open in Wireshark at This Packet",
      disabled: !s?.wiresharkAvailable || !s.file,
      title: s?.wiresharkAvailable ? undefined : "No wireshark executable found",
      action: () => void act.openInWireshark(row.num),
    },
  ];
  showMenu(items, x, y);
}

// ---------------------------------------------------------------------- setup

/** Ctrl+Up / Ctrl+Down: previous / next packet from anywhere. */
export function stepPacket(d: 1 | -1): void {
  if (total === 0) return;
  const cur = currentIndex();
  selectIndex(cur < 0 ? firstVisibleIndex() : cur + d);
}

/** Go > First Packet / Last Packet. */
export function selectEdge(d: 1 | -1): void {
  selectIndex(d < 0 ? 0 : total - 1);
}

/** View > Resize Columns: every column fits the visible rows. */
export function resizeColumns(): void {
  columns.forEach((_, j) => autosize(j));
}

export function focusPacketList(): void {
  scroller?.focus();
}

export function createPacketList(): HTMLElement {
  headerInner = h("div", { class: "pl-header-inner" });
  const header = h("div", { class: "pl-header" }, headerInner);
  layer = h("div", { class: "pl-layer" });
  spacer = h("div", { class: "pl-spacer" });
  scroller = h("div", { class: "pl-scroll", tabIndex: 0, attrs: { role: "grid", "aria-label": "Packet list" } }, layer, spacer);
  overlay = h("div", { class: "pl-overlay", hidden: true });
  root = h("div", { class: "pl" }, header, scroller, overlay);

  scroller.addEventListener("scroll", onScroll, { passive: true });
  scroller.addEventListener(
    "wheel",
    (e: WheelEvent) => {
      userInputAt = performance.now();
      const m = metrics();
      if (m.virtH <= MAX_SCROLL || e.ctrlKey) return;
      // Scaled range: scroll by real rows instead of scaled pixels.
      e.preventDefault();
      const unit = e.deltaMode === 1 ? RH : e.deltaMode === 2 ? m.vh : 1;
      const before = virtTop;
      if (e.deltaY) setVirtTop(virtTop + e.deltaY * unit);
      scrolledBy(virtTop - before);
      if (e.deltaX) scroller.scrollLeft += e.deltaX * unit;
    },
    { passive: false },
  );
  scroller.addEventListener("keydown", onKey);
  scroller.addEventListener("pointerdown", () => {
    userInputAt = performance.now();
  });
  layer.addEventListener("mousedown", (e: MouseEvent) => {
    if (e.button !== 0) return;
    const i = rowIndexFromEvent(e);
    // Control+click is the context click on macOS
    if (i < 0 || (IS_MAC && e.ctrlKey)) return;
    if (e.shiftKey) {
      // No text selection; focus as a plain click would
      e.preventDefault();
      scroller.focus();
      extendTo(i, isMod(e));
    } else if (isMod(e)) toggleRow(i);
    else selectIndex(i);
  });
  scroller.addEventListener("contextmenu", (e: MouseEvent) => {
    e.preventDefault();
    let i = rowIndexFromEvent(e);
    let x = e.clientX;
    let y = e.clientY;
    // The Menu key or Shift+F10: the current row's menu, under that row
    if (i < 0) {
      i = currentIndex();
      if (i < 0) return;
      const r = (layer.querySelector<HTMLElement>(`.pl-row[data-i="${i}"]`) ?? scroller).getBoundingClientRect();
      x = r.left + 40;
      y = r.bottom;
    }
    scroller.focus();
    void openRowMenu(i, x, y);
  });

  let lastVh = 0;
  new ResizeObserver(() => {
    if (!columns.length) return;
    // Keep the bottom row in place when the pane resizes while scrolled to the end.
    const wasBottom = lastVh > 0 && virtTop >= Math.max(0, total * RH - lastVh) - 1;
    lastVh = scroller.clientHeight;
    computeWidths();
    updateHeights();
    if (wasBottom) setVirtTop(metrics().maxVirt);
    else render();
  }).observe(scroller);

  hooks.indexOfFrame = indexOfFrame;
  hooks.selectionLoading = () => pendingSel !== null;
  hooks.focusMain = focusPacketList;

  bus.on("state", (s, prev) => {
    const cols = s.columns ?? [];
    const key = `${cols.join("\u0001")}\u0002${(s.customColumns ?? []).map((c) => c.field).join("\u0001")}`;
    if (key !== headerKey) {
      headerKey = key;
      columns = cols.slice();
      buildHeader();
    }
    const fileChanged = !prev || s.file !== prev.file;
    // A restarted server's rows and generations have nothing to do with the cached ones
    const reset = !!prev && prev.instance !== s.instance;
    const genChanged = reset || fileChanged || s.generation !== gen;
    const sameView = !!prev && !fileChanged && !reset && s.filter === prev.filter;
    // The list only grew: row indices show the same frames
    const sameRows = sameView && s.rowsSince === prev.rowsSince;
    // Measured before the row count changes; a file that just finished loading starts at the top.
    // An empty list counts as at the bottom, so the first rows of a live file are followed too
    const wasAtBottom = !prev?.loading && (total === 0 || isAtBottom() || followPending);
    // The final reload after a stop arrives with the capture already idle
    const wasCapturing = !!prev && captureActive(prev);
    // Provisional rows of a live capture follow the ones read in full
    total = s.file ? Math.max(0, s.displayedFrames + (s.tail?.displayed ?? 0)) : 0;
    if (genChanged) {
      if (sameRows) {
        stale = new Map([...stale, ...pages]);
        // Other time references: pages asked for before come again
        if (prev.timeRefsRevision !== s.timeRefsRevision) {
          timesGen = s.generation;
          inflight = new Map();
        }
      } else {
        // Same file and filter: old rows stay as placeholders until refetched
        ghosts = sameView ? new Map([...ghosts, ...stale, ...pages]) : new Map();
        stale = new Map();
        inflight = new Map();
        timesGen = 0;
      }
      gen = s.generation;
      pages = new Map();
      failed.clear();
      trimStale();
      // A pending selection's row belongs to the old list
      if (!sameRows || (pendingSel && pendingSel.i >= total)) pendingSel = null;
      if (!sameView) {
        anchor = -1;
        followPending = false;
      }
    }
    updateHeights();
    if (fileChanged) {
      virtTop = 0;
      scroller.scrollLeft = 0;
      pendingSel = null;
      anchor = -1;
      followPending = false;
      syncScrollFromVirt();
      // New capture or ring-buffer file switch: follow the live end.
      if (prev && app.autoScroll && captureActive(s)) setVirtTop(metrics().maxVirt);
    } else if (genChanged && sameView && app.autoScroll && (captureActive(s) || wasCapturing || wasAtBottom)) {
      follow();
    } else if (genChanged && prev && s.filter !== prev.filter && app.selIndex >= 0) {
      ensureVisible(app.selIndex, "center");
    }
    updateOverlay(s);
    render();
  });

  bus.on("selection", () => {
    if (app.selIndex >= 0 && pendingSel && app.selIndex !== pendingSel.i) pendingSel = null;
    // After a jump or an agent selection Shift extends from the new row
    if (!pendingSel && countRanges(app.selRows) <= 1) anchor = app.selIndex;
    render();
  });

  bus.on("view", render);

  bus.on("reveal", (i, flash) => {
    ensureVisible(i, flash ? "centerIfHidden" : "center");
    if (flash) {
      flashIdx = i;
      flashUntil = performance.now() + 1600;
      window.clearTimeout(flashTimer);
      flashTimer = window.setTimeout(() => {
        flashIdx = -1;
        render();
      }, 1650);
    }
    render();
  });

  bus.on("autoscroll", (on) => {
    if (on && captureActive() && !isAtBottom()) follow();
    else if (!on) followPending = false;
  });

  return root;
}
