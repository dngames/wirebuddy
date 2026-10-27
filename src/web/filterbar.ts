/** Display filter bar: validation colors, field completion, history, apply. */

import type { CompleteResponse, FilterCheck } from "../shared/api.ts";
import { get } from "./api.ts";
import * as act from "./actions.ts";
import { bus, hooks } from "./app.ts";
import { icon } from "./icons.ts";
import { SEP, toggleMenuAt, type MenuItem } from "./menu.ts";
import { debounce, fontOf, h, keyLabel, load, measureText, save } from "./util.ts";

type Status = "none" | "ok" | "error" | "warn";

interface PopItem {
  text: string;
  detail?: string;
}

const HISTORY_MAX = 30;
const FIELD_CHARS = /[A-Za-z0-9_.-]/;

let input: HTMLInputElement;
let box: HTMLDivElement;
let msgEl: HTMLDivElement;
let pop: HTMLDivElement;
let clearBtn: HTMLButtonElement;
let applyBtn: HTMLButtonElement;
let lastServerFilter: string | null = null;
let checkSeq = 0;
let completeSeq = 0;
let history: string[] = load<string[]>("filterhistory", []).filter((x) => typeof x === "string");

let popMode: "complete" | "history" | null = null;
let popItems: PopItem[] = [];
let popActive = -1;
let tokenRange: { start: number; end: number } | null = null;

// ------------------------------------------------------------- status, hints

function setStatus(st: Status): void {
  box.classList.remove("st-ok", "st-error", "st-warn");
  if (st !== "none") box.classList.add(`st-${st}`);
}

function showMsg(m: { kind: "error" | "warn"; text: string; hint?: string | null } | null): void {
  msgEl.replaceChildren();
  msgEl.hidden = !m;
  input.title = m ? m.text : "";
  if (!m) return;
  msgEl.className = `fb-msg ${m.kind}`;
  msgEl.append(h("span", { class: "fb-msg-text" }, m.text));
  if (m.hint) {
    const hint = m.hint;
    msgEl.append(
      h(
        "span",
        { class: "fb-hint" },
        "Looks like a capture filter — try ",
        h("button", { class: "fb-suggest", title: "Use this display filter", onclick: () => setFilterText(hint, false, true) }, hint),
      ),
    );
  }
}

function showCheck(text: string, r: FilterCheck): void {
  if (!text.trim()) {
    setStatus("none");
    showMsg(null);
  } else if (!r.ok) {
    setStatus("error");
    const hint = bpfHint(text);
    // The server appends its own capture-filter hint for agents; the chip replaces it here
    const error = (r.error || "Invalid display filter").replace(/ \(this looks like capture-filter syntax;.*\)$/, "");
    showMsg({ kind: "error", text: hint ? error : r.error || "Invalid display filter", hint });
  } else if (r.warning) {
    setStatus("warn");
    showMsg({ kind: "warn", text: r.warning });
  } else {
    setStatus("ok");
    showMsg(null);
  }
}

/** Display filter equivalent of simple BPF capture filter syntax, if it is one. */
export function bpfHint(text: string): string | null {
  const parts = text.trim().split(/\s+(and|or|&&|\|\|)\s+/i);
  if (!parts[0]) return null;
  const out: string[] = [];
  for (let k = 0; k < parts.length; k++) {
    if (k % 2 === 1) {
      out.push(/^(and|&&)$/i.test(parts[k]) ? "&&" : "||");
      continue;
    }
    const neg = /^not\s+|^!\s*/i.test(parts[k]);
    const t = bpfTerm(parts[k].replace(/^not\s+|^!\s*/i, ""));
    if (!t) return null;
    out.push(neg ? `!(${t})` : parts.length > 1 && t.includes("||") ? `(${t})` : t);
  }
  const joined = out.join(" ");
  return joined === text.trim() ? null : joined;
}

function bpfTerm(raw: string): string | null {
  const t = raw.trim().toLowerCase();
  let m: RegExpExecArray | null;
  const ipField = (addr: string, dir?: string): string => {
    const base = addr.includes(":") ? "ipv6" : "ip";
    return `${base}.${dir ?? "addr"}`;
  };
  if ((m = /^(tcp|udp|sctp)\s+(?:(src|dst)\s+)?port\s+(\d+)$/.exec(t))) return `${m[1]}.${m[2] ? `${m[2]}port` : "port"} == ${m[3]}`;
  if ((m = /^(?:(src|dst)\s+)?port\s+(\d+)$/.exec(t))) {
    const f = m[1] ? `${m[1]}port` : "port";
    return `tcp.${f} == ${m[2]} || udp.${f} == ${m[2]}`;
  }
  if ((m = /^(tcp|udp)?\s*portrange\s+(\d+)-(\d+)$/.exec(t))) {
    const p = m[1] ?? "tcp";
    return `${p}.port >= ${m[2]} && ${p}.port <= ${m[3]}`;
  }
  if ((m = /^ether\s+(?:(src|dst)\s+)?host\s+(\S+)$/.exec(t))) return `eth.${m[1] ?? "addr"} == ${m[2]}`;
  if ((m = /^(?:ip6?\s+)?(?:(src|dst)\s+)?host\s+(\S+)$/.exec(t))) {
    const addr = m[2];
    if (/^[\d.]+$/.test(addr) || addr.includes(":")) return `${ipField(addr, m[1])} == ${addr}`;
    return `ip.host == "${addr}"`;
  }
  if ((m = /^(?:(src|dst)\s+)?net\s+(\S+)$/.exec(t))) return `${ipField(m[2], m[1])} == ${m[2]}`;
  if ((m = /^(?:(src|dst)\s+)(\d[\d.]*|[0-9a-f:]+:[0-9a-f:]*)$/.exec(t))) return `${ipField(m[2], m[1])} == ${m[2]}`;
  if ((m = /^vlan\s+(\d+)$/.exec(t))) return `vlan.id == ${m[1]}`;
  if (t === "ip6") return "ipv6";
  if (t === "ether broadcast") return "eth.dst == ff:ff:ff:ff:ff:ff";
  if (/^(tcp|udp|icmp|arp|ip|vlan|sctp|icmp6)$/.test(t)) return t;
  return null;
}

// ----------------------------------------------------------------- checking

const check = debounce(async (text: string) => {
  const seq = ++checkSeq;
  if (!text.trim()) {
    showCheck(text, { ok: true });
    return;
  }
  try {
    const r = await get<FilterCheck>("api/filter/check", { filter: text });
    if (seq === checkSeq) showCheck(text, r);
  } catch {
    if (seq === checkSeq) setStatus("none");
  }
}, 250);

function onEdited(): void {
  clearBtn.hidden = !input.value;
  check(input.value);
}

// ---------------------------------------------------------------- applying

async function apply(): Promise<void> {
  closePop();
  // A completion still pending or in flight would reopen the popup after applying
  complete.cancel();
  completeSeq++;
  check.cancel();
  checkSeq++;
  const text = input.value.trim();
  box.classList.add("busy");
  applyBtn.disabled = true;
  const r = await act.applyFilter(text);
  box.classList.remove("busy");
  applyBtn.disabled = false;
  showCheck(text, r);
  if (r.ok && text) addHistory(text);
}

function addHistory(text: string): void {
  if (text.length > 2000) return;
  history = [text, ...history.filter((x) => x !== text)].slice(0, HISTORY_MAX);
  save("filterhistory", history);
}

/** Puts text in the bar; applies it or just validates it. */
export function setFilterText(text: string, apply_: boolean, focus = false): void {
  input.value = text;
  clearBtn.hidden = !text;
  closePop();
  if (focus) {
    input.focus();
    input.setSelectionRange(text.length, text.length);
  }
  if (apply_) void apply();
  else {
    check(text);
    check.flush();
  }
}

export function getFilterText(): string {
  return input?.value ?? "";
}

export function focusFilter(): void {
  input.focus();
  input.select();
}

// -------------------------------------------------------------- completion

function tokenAtCursor(): { start: number; end: number; text: string } | null {
  const v = input.value;
  const pos = input.selectionStart ?? v.length;
  if (input.selectionEnd !== pos) return null;
  let s = pos;
  while (s > 0 && FIELD_CHARS.test(v[s - 1])) s--;
  let e = pos;
  while (e < v.length && FIELD_CHARS.test(v[e])) e++;
  const text = v.slice(s, pos);
  if (!text || !/^[A-Za-z_]/.test(text)) return null;
  // Right of a comparison operator the token is a value, not a field.
  const before = v.slice(0, s).trimEnd();
  if (/(==|!=|~=|>=|<=|>|<|[{,"]|\b(eq|ne|gt|lt|ge|le|contains|matches|in|any_eq|all_ne|all_eq|any_ne))$/i.test(before)) return null;
  return { start: s, end: e, text };
}

const complete = debounce(async () => {
  const tok = tokenAtCursor();
  if (!tok || document.activeElement !== input) {
    if (popMode === "complete") closePop();
    return;
  }
  const seq = ++completeSeq;
  try {
    const r = await get<CompleteResponse>("api/filter/complete", { field: tok.text });
    if (seq !== completeSeq || document.activeElement !== input) return;
    const cur = tokenAtCursor();
    if (!cur || cur.text !== tok.text) return;
    const items = (r.fields ?? []).slice(0, 300);
    if (!items.length || (items.length === 1 && items[0].f === tok.text)) {
      if (popMode === "complete") closePop();
      return;
    }
    openPop("complete", items.map((f) => ({ text: f.f, detail: f.n })), cur);
  } catch {
    // completion is best effort
  }
}, 120);

function openPop(mode: "complete" | "history", items: PopItem[], range: { start: number; end: number } | null): void {
  popMode = mode;
  popItems = items;
  popActive = mode === "history" ? 0 : -1;
  tokenRange = range;
  pop.replaceChildren(
    ...items.map((it, k) =>
      h(
        "div",
        { class: `fb-pop-item${k === popActive ? " active" : ""}`, data: { k } },
        h("span", { class: "fb-pop-text" }, it.text.length > 300 ? `${it.text.slice(0, 300)}…` : it.text),
        it.detail ? h("span", { class: "fb-pop-detail" }, it.detail) : null,
      ),
    ),
  );
  pop.hidden = false;
  let left = 0;
  if (range) {
    const cs = getComputedStyle(input);
    const x = measureText(input.value.slice(0, range.start), fontOf(input)) + parseFloat(cs.paddingLeft || "0") - input.scrollLeft;
    left = input.offsetLeft + Math.max(0, x) - 8;
  }
  pop.style.left = "0px";
  const maxLeft = Math.max(0, box.clientWidth - pop.offsetWidth);
  pop.style.left = `${Math.min(Math.max(0, left), maxLeft)}px`;
}

function closePop(): void {
  popMode = null;
  popItems = [];
  popActive = -1;
  tokenRange = null;
  if (pop) {
    pop.hidden = true;
    pop.replaceChildren();
  }
}

function moveActive(d: number): void {
  if (!popItems.length) return;
  const n = popItems.length;
  popActive = popActive < 0 ? (d > 0 ? 0 : n - 1) : Math.max(0, Math.min(n - 1, popActive + d));
  pop.querySelectorAll<HTMLElement>(".fb-pop-item").forEach((el, k) => {
    el.classList.toggle("active", k === popActive);
    if (k === popActive) el.scrollIntoView({ block: "nearest" });
  });
}

function accept(k: number): void {
  const it = popItems[k];
  if (!it) return;
  if (popMode === "history" || !tokenRange) {
    input.value = it.text;
    input.setSelectionRange(it.text.length, it.text.length);
  } else {
    const v = input.value;
    input.value = v.slice(0, tokenRange.start) + it.text + v.slice(tokenRange.end);
    const p = tokenRange.start + it.text.length;
    input.setSelectionRange(p, p);
  }
  closePop();
  onEdited();
}

function showHistoryPop(): void {
  if (!history.length) return;
  openPop("history", history.map((t) => ({ text: t })), null);
}

function historyMenu(): MenuItem[] {
  const items: MenuItem[] = [{ label: "Recent Display Filters", header: true }];
  if (!history.length) items.push({ label: "No recent filters", disabled: true });
  for (const t of history) {
    items.push({ label: t.length > 90 ? `${t.slice(0, 90)}…` : t, title: t.length > 500 ? undefined : t, action: () => setFilterText(t, true) });
  }
  items.push(SEP, {
    label: "Clear Recent Filters",
    disabled: !history.length,
    action: () => {
      history = [];
      save("filterhistory", history);
    },
  });
  return items;
}

function onKey(e: KeyboardEvent): void {
  if (e.isComposing) return;
  switch (e.key) {
    case "ArrowDown":
      if (popMode) moveActive(1);
      else showHistoryPop();
      break;
    case "ArrowUp":
      if (!popMode) return;
      moveActive(-1);
      break;
    case "PageDown":
      if (!popMode) return;
      moveActive(8);
      break;
    case "PageUp":
      if (!popMode) return;
      moveActive(-8);
      break;
    case "Tab":
      if (popMode !== "complete" || e.shiftKey) return;
      accept(popActive >= 0 ? popActive : 0);
      break;
    case "Enter":
      if (popMode && popActive >= 0) accept(popActive);
      else void apply();
      break;
    case "Escape":
      if (!popMode) return;
      closePop();
      e.stopPropagation();
      break;
    default:
      return;
  }
  e.preventDefault();
}

// -------------------------------------------------------------------- build

export function createFilterBar(): HTMLElement {
  input = h("input", {
    class: "fb-input",
    type: "text",
    placeholder: `Apply a display filter … <${keyLabel("Ctrl+/").replace("+", "-")}>`,
    spellcheck: false,
    autocomplete: "off",
    attrs: { "aria-label": "Display filter", autocapitalize: "off", autocorrect: "off" },
  });
  const bookmark = h("button", { class: "fb-btn fb-bookmark", title: "Recent display filters", attrs: { "aria-label": "Recent display filters" } }, icon("bookmark"));
  bookmark.addEventListener("mousedown", (e) => e.preventDefault());
  bookmark.addEventListener("click", () => toggleMenuAt(bookmark, historyMenu, { minWidth: 320 }));
  clearBtn = h("button", { class: "fb-btn fb-clear", title: "Clear display filter", hidden: true, attrs: { "aria-label": "Clear display filter" } }, icon("clear"));
  clearBtn.addEventListener("click", () => {
    setFilterText("", true);
    input.focus();
  });
  const dropBtn = h("button", { class: "fb-btn fb-drop", title: "Recent display filters", attrs: { "aria-label": "Show recent filters" } }, icon("chevron"));
  dropBtn.addEventListener("mousedown", (e) => e.preventDefault());
  dropBtn.addEventListener("click", () => {
    if (popMode === "history") closePop();
    else {
      input.focus();
      showHistoryPop();
    }
  });
  applyBtn = h("button", { class: "fb-btn fb-apply", title: "Apply display filter (Enter)", attrs: { "aria-label": "Apply display filter" } }, icon("apply"));
  applyBtn.addEventListener("click", () => void apply());
  pop = h("div", { class: "fb-pop", hidden: true, role: "listbox" });
  pop.addEventListener("mousedown", (e) => {
    e.preventDefault();
    const it = (e.target as HTMLElement).closest<HTMLElement>(".fb-pop-item");
    if (it) accept(Number(it.dataset.k));
  });
  box = h("div", { class: "fb-box" }, bookmark, input, clearBtn, dropBtn, applyBtn, pop);
  msgEl = h("div", { class: "fb-msg", hidden: true, role: "status" });

  input.addEventListener("input", () => {
    onEdited();
    complete();
  });
  input.addEventListener("keydown", onKey);
  input.addEventListener("blur", () => {
    closePop();
    complete.cancel();
  });
  input.addEventListener("click", () => {
    if (popMode === "complete") complete();
  });

  hooks.filterText = getFilterText;
  hooks.setFilter = (t, a) => setFilterText(t, a);

  bus.on("state", (s) => {
    if (s.filter === lastServerFilter) return;
    const prevServer = lastServerFilter ?? "";
    lastServerFilter = s.filter;
    const editing = document.activeElement === input && input.value !== prevServer;
    if (editing) return;
    input.value = s.filter;
    clearBtn.hidden = !s.filter;
    closePop();
    check.cancel();
    checkSeq++;
    setStatus(s.filter ? "ok" : "none");
    showMsg(null);
  });

  return h("div", { class: "filterbar" }, box, msgEl);
}
