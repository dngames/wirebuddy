/** Qt-style popup menus with submenus and keyboard navigation. */

import { h } from "./util.ts";

export interface MenuItem {
  label: string;
  action?: () => void;
  disabled?: boolean;
  checked?: boolean;
  shortcut?: string;
  title?: string;
  sub?: MenuItem[];
  sep?: boolean;
  /** Non-interactive section heading. */
  header?: boolean;
  /** Secondary text under the label (e.g. a note). */
  detail?: string;
}

export const SEP: MenuItem = { label: "", sep: true };

interface Row {
  el: HTMLElement;
  item: MenuItem;
}

interface OpenMenu {
  el: HTMLElement;
  rows: Row[];
  active: number;
  /** Row in the parent menu that opened this submenu. */
  parentRow: HTMLElement | null;
}

const stack: OpenMenu[] = [];
let owner: HTMLElement | null = null;
let lastClosedOwner: HTMLElement | null = null;
let lastClosedAt = 0;
let subTimer = 0;

export function menuOpen(): boolean {
  return stack.length > 0;
}

export function closeMenus(): void {
  window.clearTimeout(subTimer);
  if (!stack.length) return;
  while (stack.length) stack.pop()?.el.remove();
  if (owner) {
    owner.classList.remove("menu-owner-open");
    lastClosedOwner = owner;
    lastClosedAt = performance.now();
  }
  owner = null;
  document.removeEventListener("pointerdown", onOutside, true);
  document.removeEventListener("keydown", onKey, true);
  window.removeEventListener("blur", closeMenus);
  window.removeEventListener("resize", closeMenus);
}

function closeAbove(level: number): void {
  while (stack.length > level + 1) stack.pop()?.el.remove();
}

function onOutside(e: Event): void {
  const t = e.target as Node | null;
  if (t && stack.some((m) => m.el.contains(t))) return;
  closeMenus();
}

function setActive(m: OpenMenu, idx: number): void {
  if (m.active >= 0 && m.rows[m.active]) m.rows[m.active].el.classList.remove("active");
  m.active = idx;
  if (idx >= 0 && m.rows[idx]) {
    m.rows[idx].el.classList.add("active");
    m.rows[idx].el.scrollIntoView({ block: "nearest" });
  }
}

function enabled(r: Row): boolean {
  return !r.item.disabled && !r.item.header && !r.item.sep;
}

function activate(level: number, idx: number): void {
  const m = stack[level];
  const r = m?.rows[idx];
  if (!r || !enabled(r)) return;
  if (r.item.sub) {
    openSub(level, idx, true);
    return;
  }
  const fn = r.item.action;
  closeMenus();
  fn?.();
}

function openSub(level: number, idx: number, focusFirst: boolean): void {
  const m = stack[level];
  const r = m.rows[idx];
  if (!r.item.sub || !enabled(r)) return;
  if (stack[level + 1]?.parentRow === r.el) {
    if (focusFirst) setActive(stack[level + 1], firstEnabled(stack[level + 1], 0, 1));
    return;
  }
  closeAbove(level);
  const sub = build(r.item.sub, r.el);
  stack.push(sub);
  document.body.appendChild(sub.el);
  const pr = r.el.getBoundingClientRect();
  const mr = sub.el.getBoundingClientRect();
  let x = pr.right - 2;
  if (x + mr.width > window.innerWidth - 4) x = Math.max(4, pr.left - mr.width + 2);
  let y = pr.top - 4;
  if (y + mr.height > window.innerHeight - 4) y = Math.max(4, window.innerHeight - 4 - mr.height);
  sub.el.style.left = `${x}px`;
  sub.el.style.top = `${y}px`;
  if (focusFirst) setActive(sub, firstEnabled(sub, 0, 1));
}

function firstEnabled(m: OpenMenu, from: number, dir: 1 | -1): number {
  const n = m.rows.length;
  for (let k = 0; k < n; k++) {
    const i = (((from + dir * k) % n) + n) % n;
    if (enabled(m.rows[i])) return i;
  }
  return -1;
}

function onKey(e: KeyboardEvent): void {
  // A submenu opened by hovering has no active item: keys still drive its parent.
  let level = stack.length - 1;
  while (level > 0 && stack[level].active < 0) level--;
  const m = stack[level];
  if (!m) return;
  let handled = true;
  switch (e.key) {
    case "ArrowDown":
      closeAbove(level);
      setActive(m, firstEnabled(m, m.active < 0 ? 0 : m.active + 1, 1));
      break;
    case "ArrowUp":
      closeAbove(level);
      setActive(m, firstEnabled(m, m.active < 0 ? m.rows.length - 1 : m.active - 1, -1));
      break;
    case "Home":
      setActive(m, firstEnabled(m, 0, 1));
      break;
    case "End":
      setActive(m, firstEnabled(m, m.rows.length - 1, -1));
      break;
    case "ArrowRight":
      if (m.active >= 0 && m.rows[m.active].item.sub) openSub(level, m.active, true);
      break;
    case "ArrowLeft":
      if (level > 0) closeAbove(level - 1);
      break;
    case "Enter":
    case " ":
      if (m.active >= 0) activate(level, m.active);
      break;
    case "Escape":
      if (level > 0) closeAbove(level - 1);
      else closeMenus();
      break;
    case "Tab":
      closeMenus();
      break;
    default:
      handled = false;
  }
  if (handled) {
    e.preventDefault();
    e.stopPropagation();
  }
}

function build(items: MenuItem[], parentRow: HTMLElement | null): OpenMenu {
  const el = h("div", { class: "menu", role: "menu" });
  const m: OpenMenu = { el, rows: [], active: -1, parentRow };
  for (const item of items) {
    if (item.sep) {
      // Drop leading, trailing and doubled separators.
      const prev = m.rows[m.rows.length - 1];
      if (!prev || prev.item.sep) continue;
      const sepEl = h("div", { class: "menu-sep", role: "separator" });
      el.appendChild(sepEl);
      m.rows.push({ el: sepEl, item });
      continue;
    }
    if (item.header) {
      const hd = h("div", { class: "menu-header" }, item.label);
      el.appendChild(hd);
      m.rows.push({ el: hd, item });
      continue;
    }
    const cls = `menu-item${item.disabled ? " disabled" : ""}${item.sub ? " has-sub" : ""}`;
    const row = h(
      "div",
      { class: cls, role: "menuitem", title: item.title, attrs: { "aria-disabled": item.disabled ? "true" : "false" } },
      h("span", { class: "menu-check" }, item.checked ? "✓" : ""),
      h(
        "span",
        { class: "menu-label" },
        item.label,
        item.detail ? h("span", { class: "menu-detail" }, item.detail) : null,
      ),
      h("span", { class: "menu-shortcut" }, item.shortcut ?? ""),
      h("span", { class: "menu-arrow" }, item.sub ? "▸" : ""),
    );
    const idx = m.rows.length;
    m.rows.push({ el: row, item });
    row.addEventListener("pointerenter", () => {
      const lvl = stack.indexOf(m);
      if (lvl < 0) return;
      setActive(m, enabled(m.rows[idx]) ? idx : -1);
      window.clearTimeout(subTimer);
      if (item.sub && !item.disabled) subTimer = window.setTimeout(() => openSub(lvl, idx, false), 120);
      else subTimer = window.setTimeout(() => closeAbove(lvl), 200);
    });
    row.addEventListener("click", (e) => {
      e.stopPropagation();
      const lvl = stack.indexOf(m);
      if (lvl >= 0) activate(lvl, idx);
    });
    el.appendChild(row);
  }
  const last = m.rows[m.rows.length - 1];
  if (last?.item.sep) {
    last.el.remove();
    m.rows.pop();
  }
  if (!m.rows.length) el.appendChild(h("div", { class: "menu-header" }, "(empty)"));
  el.addEventListener("contextmenu", (e) => e.preventDefault());
  return m;
}

export interface MenuOptions {
  /** Toolbar button that opened the menu; clicking it again closes it. */
  owner?: HTMLElement;
  minWidth?: number;
  /** Highlight the first item (keyboard-opened menus). */
  focusFirst?: boolean;
}

export function showMenu(items: MenuItem[], x: number, y: number, opts: MenuOptions = {}): void {
  closeMenus();
  const m = build(items, null);
  stack.push(m);
  if (opts.minWidth) m.el.style.minWidth = `${opts.minWidth}px`;
  document.body.appendChild(m.el);
  const r = m.el.getBoundingClientRect();
  let px = x;
  let py = y;
  if (px + r.width > window.innerWidth - 4) px = Math.max(4, window.innerWidth - 4 - r.width);
  if (py + r.height > window.innerHeight - 4) py = Math.max(4, Math.min(y, window.innerHeight) - r.height);
  m.el.style.left = `${px}px`;
  m.el.style.top = `${py}px`;
  owner = opts.owner ?? null;
  owner?.classList.add("menu-owner-open");
  if (opts.focusFirst) setActive(m, firstEnabled(m, 0, 1));
  document.addEventListener("pointerdown", onOutside, true);
  document.addEventListener("keydown", onKey, true);
  window.addEventListener("blur", closeMenus);
  window.addEventListener("resize", closeMenus);
}

/** Opens a dropdown under `btn`, or closes it if this press just closed it. */
export function toggleMenuAt(btn: HTMLElement, items: () => MenuItem[], opts: MenuOptions = {}): void {
  if (lastClosedOwner === btn && performance.now() - lastClosedAt < 300) {
    lastClosedOwner = null;
    return;
  }
  const r = btn.getBoundingClientRect();
  showMenu(items(), r.left, r.bottom + 1, { ...opts, owner: btn });
}
