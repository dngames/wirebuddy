/** Packet details tree with Wireshark's per-ett expansion memory. */

import type { FrameDetail, TreeNode } from "../shared/api.ts";
import * as act from "./actions.ts";
import { bus, hooks } from "./app.ts";
import { fieldInfoText, fieldName, fieldValue, frameInfo, nodeLabel, sevClass, srcIndex, walk } from "./frame.ts";
import { followItems } from "./dialogs/follow.ts";
import { SEP, showMenu, type MenuItem } from "./menu.ts";
import { bytesToHex, copyText, h, isMod, keyLabel } from "./util.ts";
import { VList } from "./vlist.ts";

const RH = 20;
const INDENT = 16;
const CHAR_W = 7.4;

let vl: VList;
let fd: FrameDetail | null = null;
let vis: TreeNode[] = [];
let sel: TreeNode | null = null;
/** Field of the last user selection; re-selected in the next frame like Wireshark. */
let selFn: string | null = null;
const expandedEtt = new Set<number>();
let expandedNode = new WeakSet<TreeNode>();
let onSelect: (n: TreeNode | null) => void = () => {};

function hasKids(n: TreeNode): boolean {
  return !!n.n && n.n.length > 0;
}

function isExpanded(n: TreeNode): boolean {
  return n.e !== undefined ? expandedEtt.has(n.e) : expandedNode.has(n);
}

function setExpanded(n: TreeNode, on: boolean): void {
  if (n.e !== undefined) {
    if (on) expandedEtt.add(n.e);
    else expandedEtt.delete(n.e);
  } else if (on) expandedNode.add(n);
  else expandedNode.delete(n);
}

function depthOf(n: TreeNode): number {
  return fd ? frameInfo(fd).depth.get(n) ?? 0 : 0;
}

function parentOf(n: TreeNode): TreeNode | null {
  return fd ? frameInfo(fd).parent.get(n) ?? null : null;
}

function rebuild(): void {
  vis = [];
  let maxW = 0;
  const add = (nodes: TreeNode[] | undefined, d: number): void => {
    if (!nodes) return;
    for (const n of nodes) {
      vis.push(n);
      maxW = Math.max(maxW, d * INDENT + Math.min(nodeLabel(n).length, 400) * CHAR_W);
      if (hasKids(n) && isExpanded(n)) add(n.n, d + 1);
    }
  };
  add(fd?.tree, 0);
  // A collapsed ancestor hides the selection: select that ancestor instead.
  if (sel && !vis.includes(sel)) {
    let p = parentOf(sel);
    while (p && !vis.includes(p)) p = parentOf(p);
    sel = p;
    report();
  }
  vl.setCount(vis.length, maxW + 48);
}

function renderRow(i: number): HTMLElement {
  const n = vis[i];
  const kids = hasKids(n);
  const label = nodeLabel(n);
  let cls = "dt-row";
  if (n.t === "proto") cls += " proto";
  if (n === sel) cls += " sel";
  let lab: HTMLElement;
  if (n.t === "framenum" && n.fnum) {
    lab = h("span", { class: "dt-label dt-link", title: `Go to packet ${n.fnum}` }, label);
  } else if (n.t === "url" && n.url && /^https?:\/\//i.test(n.url)) {
    lab = h("span", { class: "dt-label dt-link", title: `Open ${n.url.length > 200 ? `${n.url.slice(0, 200)}…` : n.url}` }, label);
  } else {
    lab = h("span", { class: "dt-label" }, label);
  }
  const sc = sevClass(n.s);
  if (sc) lab.classList.add("sev", sc);
  return h(
    "div",
    { class: cls },
    h("span", { class: "dt-indent", style: `width:${depthOf(n) * INDENT}px` }),
    h("span", { class: `dt-tog${kids ? (isExpanded(n) ? " open" : " closed") : ""}` }),
    lab,
  );
}

function report(): void {
  bus.emit("fieldInfo", sel ? fieldInfoText(sel) : "");
  onSelect(sel);
}

function selectNode(n: TreeNode | null, scroll = true, remember = true): void {
  sel = n;
  if (remember) selFn = n?.fn ?? null;
  vl.forEachRow((el, i) => el.classList.toggle("sel", vis[i] === sel));
  if (n && scroll) vl.scrollTo(vis.indexOf(n));
  report();
}

function toggle(n: TreeNode): void {
  if (!hasKids(n)) return;
  setExpanded(n, !isExpanded(n));
  rebuild();
}

function setSubtree(n: TreeNode, on: boolean): void {
  if (hasKids(n)) setExpanded(n, on);
  walk(n.n, (c) => {
    if (hasKids(c)) setExpanded(c, on);
  });
  rebuild();
  if (sel) vl.scrollTo(vis.indexOf(sel));
}

export function expandAll(): void {
  walk(fd?.tree, (c) => {
    if (hasKids(c)) setExpanded(c, true);
  });
  rebuild();
}

export function collapseAll(): void {
  expandedEtt.clear();
  expandedNode = new WeakSet();
  rebuild();
}

/** Expands the path to `n` and selects it. */
function revealNode(n: TreeNode): void {
  let changed = false;
  for (let p = parentOf(n); p; p = parentOf(p)) {
    if (!isExpanded(p)) {
      setExpanded(p, true);
      changed = true;
    }
  }
  if (changed) rebuild();
  selectNode(n, true);
}

/** Byte clicked in the bytes pane: select the deepest field covering it. */
export function selectByOffset(n: TreeNode | null): void {
  if (n) revealNode(n);
}

function activateLink(n: TreeNode): void {
  if (n.t === "framenum" && n.fnum) act.jumpToFrame(n.fnum);
  else if (n.t === "url" && n.url && /^https?:\/\//i.test(n.url)) window.open(n.url, "_blank", "noopener,noreferrer");
}

function needsParens(t: string): boolean {
  return /&&|\|\||\^\^|\b(and|or|xor|not)\b|^\s*!/.test(t);
}

/** Column title like Wireshark's: the field's display name, else its field name. */
function columnTitle(n: TreeNode): string {
  const name = fieldName(n).trim();
  const t = name && name.length <= 40 && !name.includes(": ") ? name : (n.fn ?? name);
  return t.length > 40 ? `${t.slice(0, 39)}…` : t;
}

function applyAsColumn(n: TreeNode): void {
  if (n.fn) act.addCustomColumn(n.fn, columnTitle(n));
}

/** Apply/Prepare as Filter: the field's filter, alone or combined with the current one. */
function filterCombos(f: string, apply: boolean): MenuItem[] {
  const cur = hooks.filterText().trim();
  const c = needsParens(cur) ? `(${cur})` : cur;
  const ff = needsParens(f) ? `(${f})` : f;
  const set = (t: string) => () => hooks.setFilter(t, apply);
  return [
    { label: "Selected", action: set(f) },
    { label: "Not Selected", action: set(`!(${f})`) },
    { label: "…and Selected", action: set(cur ? `${c} && ${ff}` : f) },
    { label: "…or Selected", action: set(cur ? `${c} || ${ff}` : f) },
    { label: "…and not Selected", action: set(cur ? `${c} && !(${f})` : `!(${f})`) },
    { label: "…or not Selected", action: set(cur ? `${c} || !(${f})` : `!(${f})`) },
  ];
}

function copyItems(n: TreeNode | null): MenuItem[] {
  const f = n?.f;
  const bytes = (): Uint8Array | null => {
    if (!fd || !n?.h || n.h[1] <= 0) return null;
    const src = frameInfo(fd).sources[srcIndex(fd, n)];
    return src ? src.bytes.subarray(n.h[0], n.h[0] + n.h[1]) : null;
  };
  const visibleText = (): string =>
    vis.map((v) => `${"    ".repeat(depthOf(v))}${nodeLabel(v)}`).join("\n");
  return [
    { label: "All Visible Items", disabled: !vis.length, action: () => void copyText(visibleText()) },
    SEP,
    { label: "Description", disabled: !n, action: () => void copyText(n ? nodeLabel(n) : "") },
    { label: "Field Name", disabled: !n?.fn, action: () => void copyText(n?.fn ?? "") },
    { label: "Value", disabled: !n, action: () => void copyText(n ? fieldValue(n) : "") },
    { label: "As Filter", disabled: !f, action: () => void copyText(f ?? "") },
    {
      label: "Bytes as Hex Stream",
      disabled: !n?.h || n.h[1] <= 0,
      action: () => {
        const b = bytes();
        if (b) void copyText(bytesToHex(b));
      },
    },
  ];
}

/** The selected details item, for the menu bar. */
export function selectedField(): TreeNode | null {
  return sel;
}

export function expandSubtrees(on: boolean): void {
  if (sel) setSubtree(sel, on);
}

export function applySelectedAsColumn(): void {
  if (sel) applyAsColumn(sel);
}

/** Analyze > Apply as Filter / Prepare as Filter for the selected item. */
export function fieldFilterItems(apply: boolean): MenuItem[] {
  return sel?.f ? filterCombos(sel.f, apply) : [];
}

/** Edit > Copy items for the selected details item. */
export function fieldCopyItems(): MenuItem[] {
  return copyItems(sel);
}

function nodeMenu(n: TreeNode, x: number, y: number): void {
  const f = n.f;
  const kids = hasKids(n);
  const items: MenuItem[] = [
    { label: "Expand Subtrees", shortcut: keyLabel("Shift+Right"), disabled: !kids, action: () => setSubtree(n, true) },
    { label: "Collapse Subtrees", shortcut: keyLabel("Shift+Left"), disabled: !kids, action: () => setSubtree(n, false) },
    { label: "Expand All", shortcut: keyLabel("Ctrl+Right"), action: expandAll },
    { label: "Collapse All", shortcut: keyLabel("Ctrl+Left"), action: collapseAll },
    SEP,
    { label: "Apply as Column", shortcut: keyLabel("Ctrl+Shift+I"), disabled: !n.fn, title: n.fn ? `Add a packet list column showing ${n.fn}` : undefined, action: () => applyAsColumn(n) },
    SEP,
    { label: "Apply as Filter", disabled: !f, sub: f ? filterCombos(f, true) : [] },
    { label: "Prepare as Filter", disabled: !f, sub: f ? filterCombos(f, false) : [] },
    SEP,
    { label: "Follow", disabled: !fd, sub: followItems(fd) },
    SEP,
    { label: "Copy", sub: copyItems(n) },
  ];
  if (n.t === "framenum" && n.fnum) items.push(SEP, { label: `Go to Packet ${n.fnum}`, action: () => activateLink(n) });
  if (n.t === "url" && n.url && /^https?:\/\//i.test(n.url)) items.push(SEP, { label: "Open Link in New Tab", action: () => activateLink(n) });
  showMenu(items, x, y);
}

function onKey(e: KeyboardEvent): void {
  // Alt+Left/Right are Back/Forward; Ctrl+Up/Down/Home/End go to other packets
  if (!vis.length || e.altKey || (isMod(e) && e.key !== "ArrowLeft" && e.key !== "ArrowRight")) return;
  const i = sel ? vis.indexOf(sel) : -1;
  const go = (k: number): void => selectNode(vis[Math.max(0, Math.min(vis.length - 1, k))]);
  switch (e.key) {
    case "ArrowDown":
      go(i + 1);
      break;
    case "ArrowUp":
      go(i < 0 ? 0 : i - 1);
      break;
    case "PageDown":
      go(i + vl.visibleRows() - 1);
      break;
    case "PageUp":
      go(i - vl.visibleRows() + 1);
      break;
    case "Home":
      go(0);
      break;
    case "End":
      go(vis.length - 1);
      break;
    case "ArrowRight":
      if (isMod(e)) expandAll();
      else if (sel && e.shiftKey) setSubtree(sel, true);
      else if (sel && hasKids(sel) && !isExpanded(sel)) toggle(sel);
      else if (sel && hasKids(sel)) go(i + 1);
      else return;
      break;
    case "ArrowLeft":
      if (isMod(e)) collapseAll();
      else if (sel && e.shiftKey) setSubtree(sel, false);
      else if (sel && hasKids(sel) && isExpanded(sel)) toggle(sel);
      else if (sel && parentOf(sel)) selectNode(parentOf(sel));
      else return;
      break;
    case "Enter":
      if (sel && (sel.t === "framenum" || sel.t === "url")) activateLink(sel);
      else if (sel) toggle(sel);
      break;
    case " ":
      if (sel) toggle(sel);
      break;
    case "*":
      if (sel) setSubtree(sel, true);
      break;
    default:
      return;
  }
  e.preventDefault();
}

function nodeFromEvent(e: Event): TreeNode | null {
  const row = (e.target as HTMLElement).closest<HTMLElement>(".dt-row");
  if (!row || row.dataset.i === undefined) return null;
  return vis[Number(row.dataset.i)] ?? null;
}

export function setDetailsFrame(frame: FrameDetail | null): void {
  fd = frame;
  expandedNode = new WeakSet();
  sel = null;
  rebuild();
  vl.el.scrollTop = 0;
  vl.refresh();
  const again = selFn ? vis.find((n) => n.fn === selFn) ?? null : null;
  selectNode(again, true, false);
}

export function createDetailsPane(opts: { onSelect: (n: TreeNode | null) => void }): HTMLElement {
  onSelect = opts.onSelect;
  vl = new VList(RH, renderRow, "dt");
  vl.el.setAttribute("role", "tree");
  vl.el.setAttribute("aria-label", "Packet details");
  vl.el.addEventListener("mousedown", (e) => {
    if (e.button !== 0) return;
    const n = nodeFromEvent(e);
    if (!n) return;
    if ((e.target as HTMLElement).closest(".dt-tog") && hasKids(n)) {
      if (n !== sel) selectNode(n, false);
      toggle(n);
      e.preventDefault();
      vl.el.focus();
    } else if (n !== sel) {
      selectNode(n, false);
    }
  });
  vl.el.addEventListener("click", (e) => {
    const n = nodeFromEvent(e);
    if (n && (e.target as HTMLElement).closest(".dt-link")) activateLink(n);
  });
  vl.el.addEventListener("dblclick", (e) => {
    const n = nodeFromEvent(e);
    if (!n || (e.target as HTMLElement).closest(".dt-tog, .dt-link")) return;
    toggle(n);
  });
  vl.el.addEventListener("contextmenu", (e) => {
    e.preventDefault();
    const n = nodeFromEvent(e);
    if (!n) return;
    if (n !== sel) selectNode(n, false);
    vl.el.focus();
    nodeMenu(n, e.clientX, e.clientY);
  });
  vl.el.addEventListener("keydown", onKey);
  return vl.el;
}
