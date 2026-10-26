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
import { get, HttpError } from "./api.ts";
import * as act from "./actions.ts";
import { app, bus, captureActive, hooks } from "./app.ts";
import { openFollowDialog } from "./dialogs/follow.ts";
import { conversationFilters } from "./frame.ts";
import { SEP, showMenu, type MenuItem } from "./menu.ts";
import { toastError } from "./toast.ts";
import { clamp, copyText, csvField, fontOf, h, load, measureText, save } from "./util.ts";

const RH = 20;
const PAGE = 200;
const OVERSCAN = 100;
/** Stay well below the smallest browser limit for element heights (Firefox ~17.9M px). */
const MAX_SCROLL = 8_000_000;
const MAX_INFLIGHT = 4;
const MAX_PAGES = 300;
const MAX_VIEW = 4000;

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
let widths: number[] = [];
const colW: Record<string, number> = load<Record<string, number>>("colwidths", {});
let total = 0;
let gen = -1;
let pages = new Map<number, PacketRow[]>();
/** Previous generation's pages, shown while a live reload refetches. */
let stale = new Map<number, PacketRow[]>();
let inflight = new Set<number>();
const failed = new Map<number, number>();
let errorToastAt = 0;

let virtTop = 0;
let lastSetScroll = -1;
let pool: RowEl[] = [];
let flashIdx = -1;
let flashUntil = 0;
let flashTimer = 0;
let pendingSelIdx = -1;
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
    // Scrolling up by hand during a live capture turns auto-scroll off, as in Wireshark.
    if (virtTop < before - 1 && app.autoScroll && captureActive() && performance.now() - userInputAt < 800) {
      act.setAutoScroll(false);
    }
  }
  render();
}

function isAtBottom(): boolean {
  const m = metrics();
  return virtTop >= m.maxVirt - RH;
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

function buildHeader(): void {
  headerInner.replaceChildren();
  columns.forEach((c, j) => {
    const grip = h("div", { class: "pl-grip", title: "Drag to resize, double-click to fit" });
    const cell = h("div", { class: `pl-hcell${rightAligned(c) ? " right" : ""}`, style: `width:var(--c${j})`, title: c }, h("span", { class: "pl-htext" }, c), grip);
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
    colW[columns[j]] = Math.max(28, Math.round(startW + ev.clientX - startX));
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
  return pages.get(p)?.[i - p * PAGE] ?? stale.get(p)?.[i - p * PAGE];
}

function freshRowAt(i: number): PacketRow | undefined {
  const p = Math.floor(i / PAGE);
  return pages.get(p)?.[i - p * PAGE];
}

function want(first: number, last: number): void {
  if (!app.state?.file || total === 0) return;
  const lo = Math.max(0, first - OVERSCAN);
  const hi = Math.min(total - 1, last + OVERSCAN);
  const vis: number[] = [];
  for (let p = Math.floor(first / PAGE); p <= Math.floor(Math.min(total - 1, last) / PAGE); p++) vis.push(p);
  const extra: number[] = [];
  for (let p = Math.floor(lo / PAGE); p <= Math.floor(hi / PAGE); p++) if (!vis.includes(p)) extra.push(p);
  const now = performance.now();
  for (const p of [...vis, ...extra]) {
    if (inflight.size >= MAX_INFLIGHT) break;
    if (pages.has(p) || inflight.has(p)) continue;
    const f = failed.get(p);
    if (f !== undefined && now - f < 2500) continue;
    void fetchPage(p);
  }
}

async function fetchPage(p: number): Promise<void> {
  const g = gen;
  const start = p * PAGE;
  const count = Math.min(PAGE, total - start);
  if (count <= 0) return;
  inflight.add(p);
  try {
    const r = await get<RowsResponse>("api/rows", { gen: g, start, count });
    if (g !== gen || r.generation !== g) return;
    const rows = r.start === start ? r.rows : alignRows(r, start, count);
    pages.set(p, rows);
    stale.delete(p);
    failed.delete(p);
    evict(p);
    if (pendingSelIdx >= start && pendingSelIdx < start + rows.length) {
      const i = pendingSelIdx;
      pendingSelIdx = -1;
      const row = rows[i - start];
      if (row) act.selectRow(i, row.num);
    }
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
    if (g === gen) inflight.delete(p);
    scheduleRender();
  }
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

/** Keeps pages + stale within MAX_PAGES, dropping stale pages far from the view first. */
function trimStale(): void {
  const room = Math.max(0, MAX_PAGES - pages.size);
  if (stale.size <= room) return;
  const center = Math.floor(virtTop / RH / PAGE);
  const keys = [...stale.keys()].sort((a, b) => Math.abs(a - center) - Math.abs(b - center));
  for (const k of keys.slice(room)) stale.delete(k);
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
  for (const [p, rows] of pages) {
    const k = rows.findIndex((r) => r?.num === frame);
    if (k >= 0) return p * PAGE + k;
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
  el.prepend(h("span", { class: "pl-badge", title: "Marked by Claude" }, "✦"));
  layer.appendChild(el);
  return { el, cells };
}

function isSelected(i: number, row: PacketRow | undefined): boolean {
  if (pendingSelIdx >= 0) return i === pendingSelIdx;
  if (row) return row.num === app.selFrame;
  return i === app.selIndex && app.selIndex >= 0;
}

function fillRow(r: RowEl, i: number, row: PacketRow | undefined, now: number): void {
  let cls = "pl-row";
  const sel = isSelected(i, row);
  if (sel) cls += " sel";
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
    const useColors = !sel && mark?.by !== "user";
    r.el.style.backgroundColor = useColors && row.bg ? `#${row.bg}` : "";
    r.el.style.color = useColors && row.fg ? `#${row.fg}` : "";
    const title = mark ? `${mark.by === "agent" ? "Marked by Claude" : "Marked"}${mark.note ? `: ${mark.note}` : ""}` : "";
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

function updateOverlay(s: ViewState): void {
  let msg = "";
  if (s.loading) msg = "Loading capture…";
  else if (s.file && total === 0 && s.totalFrames > 0) msg = "No packets match the display filter";
  else if (s.file && total === 0 && captureActive(s)) msg = "Waiting for packets…";
  else if (s.file && total === 0 && !s.loadError) msg = "No packets";
  overlay.textContent = msg;
  overlay.hidden = !msg;
  overlay.classList.toggle("busy", s.loading);
}

// ------------------------------------------------------------------ selection

function selectIndex(i: number): void {
  if (total === 0) return;
  i = clamp(i, 0, total - 1);
  ensureVisible(i, "nearest");
  const row = freshRowAt(i) ?? rowAt(i);
  if (row) {
    pendingSelIdx = -1;
    act.selectRow(i, row.num);
  } else {
    pendingSelIdx = i;
    render();
  }
}

function firstVisibleIndex(): number {
  return Math.min(total - 1, Math.ceil(virtTop / RH));
}

function onKey(e: KeyboardEvent): void {
  if (e.altKey || total === 0) return;
  const page = Math.max(1, Math.floor(scroller.clientHeight / RH) - 1);
  const cur = pendingSelIdx >= 0 ? pendingSelIdx : app.selIndex;
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
      if (e.ctrlKey || e.metaKey) return;
      scroller.scrollLeft += e.key === "ArrowLeft" ? -40 : 40;
      e.preventDefault();
      return;
    default:
      return;
  }
  e.preventDefault();
  userInputAt = performance.now();
  selectIndex(i);
}

function rowIndexFromEvent(e: MouseEvent): number {
  const el = (e.target as HTMLElement).closest<HTMLElement>(".pl-row");
  if (!el || el.dataset.i === undefined) return -1;
  return Number(el.dataset.i);
}

async function openRowMenu(i: number, x: number, y: number): Promise<void> {
  const row = rowAt(i);
  if (!row) return;
  act.selectRow(i, row.num);
  const fd = await act.frameDetail(row.num);
  const s = app.state;
  const marked = app.marks.has(row.num);
  const conv = fd ? conversationFilters(fd) : [];
  const followers = fd?.followers ?? [];
  const filterItems = (apply: boolean): MenuItem[] =>
    conv.map((c) => ({ label: `${c.label} Conversation`, action: () => hooks.setFilter(c.filter, apply) }));
  const items: MenuItem[] = [
    { label: marked ? "Unmark Packet" : "Mark Packet", shortcut: "Ctrl+M", action: () => act.toggleMark(row.num) },
    SEP,
    { label: "Apply as Filter", sub: filterItems(true), disabled: !conv.length },
    { label: "Prepare as Filter", sub: filterItems(false), disabled: !conv.length },
    SEP,
    {
      label: "Follow",
      disabled: !followers.length,
      sub: followers.map(([proto, filter]) => ({ label: `${proto} Stream`, action: () => openFollowDialog(proto, filter) })),
    },
    SEP,
    {
      label: "Copy",
      sub: [
        { label: "Summary as Text", action: () => void copyText(row.c.join("\t")) },
        { label: "…as CSV", action: () => void copyText(row.c.map(csvField).join(",")) },
        { label: "Packet Number", action: () => void copyText(String(row.num)) },
      ],
    },
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
  const cur = pendingSelIdx >= 0 ? pendingSelIdx : app.selIndex;
  selectIndex(cur < 0 ? firstVisibleIndex() : cur + d);
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
      if (e.deltaY) setVirtTop(virtTop + e.deltaY * unit);
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
    if (i >= 0) selectIndex(i);
  });
  layer.addEventListener("contextmenu", (e: MouseEvent) => {
    e.preventDefault();
    const i = rowIndexFromEvent(e);
    if (i < 0) return;
    scroller.focus();
    void openRowMenu(i, e.clientX, e.clientY);
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

  bus.on("state", (s, prev) => {
    const cols = s.columns ?? [];
    if (cols.join("\u0001") !== columns.join("\u0001")) {
      columns = cols.slice();
      buildHeader();
    }
    const fileChanged = !prev || s.file !== prev.file;
    // A restarted server's rows and generations have nothing to do with the cached ones
    const reset = !!prev && prev.instance !== s.instance;
    const genChanged = reset || fileChanged || s.generation !== gen;
    const sameView = !!prev && !fileChanged && !reset && s.filter === prev.filter;
    // Measured before the row count changes; a file that just finished loading starts at the top.
    // An empty list counts as at the bottom, so the first rows of a live file are followed too
    const wasAtBottom = !prev?.loading && (total === 0 || isAtBottom());
    // The final reload after a stop arrives with the capture already idle
    const wasCapturing = !!prev && captureActive(prev);
    total = s.file ? Math.max(0, s.displayedFrames) : 0;
    if (genChanged) {
      // Same file and filter: old rows stay as placeholders until refetched.
      stale = sameView ? new Map([...stale, ...pages]) : new Map();
      gen = s.generation;
      pages = new Map();
      inflight = new Set();
      failed.clear();
      trimStale();
      if (pendingSelIdx >= total) pendingSelIdx = -1;
    }
    updateHeights();
    if (fileChanged) {
      virtTop = 0;
      scroller.scrollLeft = 0;
      pendingSelIdx = -1;
      syncScrollFromVirt();
      // New capture or ring-buffer file switch: follow the live end.
      if (prev && app.autoScroll && captureActive(s)) setVirtTop(metrics().maxVirt);
    } else if (genChanged && sameView && app.autoScroll && (captureActive(s) || wasCapturing || wasAtBottom)) {
      setVirtTop(metrics().maxVirt);
    } else if (genChanged && prev && s.filter !== prev.filter && app.selIndex >= 0) {
      ensureVisible(app.selIndex, "center");
    }
    updateOverlay(s);
    render();
  });

  bus.on("selection", () => {
    if (app.selIndex >= 0 && pendingSelIdx >= 0 && app.selIndex !== pendingSelIdx) pendingSelIdx = -1;
    render();
  });

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
    if (on && captureActive() && !isAtBottom()) setVirtTop(metrics().maxVirt);
  });

  return root;
}
