/** Small DOM, formatting and storage helpers shared by the UI modules. */

export type Child = Node | string | number | null | undefined | false;

export type Props = Record<string, unknown>;

/**
 * Creates an element. Props: `class`, `style` (string or object), `data`
 * (dataset), `attrs` (raw attributes), `on<event>` listeners, otherwise DOM
 * properties when the element has them, else attributes.
 */
export function h<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  props?: Props | null,
  ...children: Array<Child | Child[]>
): HTMLElementTagNameMap[K] {
  const el = document.createElement(tag);
  if (props) {
    for (const [k, v] of Object.entries(props)) {
      if (v === undefined || v === null || v === false) continue;
      if (k === "class") el.className = String(v);
      else if (k === "style") {
        if (typeof v === "string") el.style.cssText = v;
        else Object.assign(el.style, v);
      } else if (k === "data") {
        for (const [dk, dv] of Object.entries(v as Record<string, unknown>)) el.dataset[dk] = String(dv);
      } else if (k === "attrs") {
        for (const [ak, av] of Object.entries(v as Record<string, unknown>)) el.setAttribute(ak, String(av));
      } else if (k.startsWith("on") && typeof v === "function") {
        el.addEventListener(k.slice(2).toLowerCase(), v as EventListener);
      } else if (k in el) {
        (el as unknown as Record<string, unknown>)[k] = v;
      } else {
        el.setAttribute(k, String(v));
      }
    }
  }
  append(el, children);
  return el;
}

/** Sets text only when it changed, so periodic refreshes keep selection and tooltips. */
export function setText(el: HTMLElement, text: string): void {
  if (el.textContent !== text) el.textContent = text;
}

export function setTitle(el: HTMLElement, title: string): void {
  if (el.title !== title) el.title = title;
}

export function append(parent: Node, children: Array<Child | Child[]>): void {
  for (const c of children) {
    if (Array.isArray(c)) append(parent, c);
    else if (c === null || c === undefined || c === false) continue;
    else if (typeof c === "string" || typeof c === "number") parent.appendChild(document.createTextNode(String(c)));
    else parent.appendChild(c);
  }
}

export function clamp(v: number, lo: number, hi: number): number {
  return Math.max(lo, Math.min(hi, v));
}

export interface Debounced<A extends unknown[]> {
  (...a: A): void;
  cancel(): void;
  flush(): void;
}

export function debounce<A extends unknown[]>(fn: (...a: A) => void, ms: number): Debounced<A> {
  let timer = 0;
  let pending: A | null = null;
  const run = (): void => {
    timer = 0;
    const args = pending;
    pending = null;
    if (args) fn(...args);
  };
  const d = ((...a: A) => {
    pending = a;
    if (timer) window.clearTimeout(timer);
    timer = window.setTimeout(run, ms);
  }) as Debounced<A>;
  d.cancel = () => {
    if (timer) window.clearTimeout(timer);
    timer = 0;
    pending = null;
  };
  d.flush = () => {
    if (timer) {
      window.clearTimeout(timer);
      run();
    }
  };
  return d;
}

type Listener<A extends unknown[]> = (...a: A) => void;

/** Minimal typed event emitter. */
export class Emitter<E extends Record<string, unknown[]>> {
  private handlers: { [K in keyof E]?: Array<Listener<E[K]>> } = {};

  on<K extends keyof E>(k: K, fn: Listener<E[K]>): () => void {
    const list = (this.handlers[k] ??= []);
    list.push(fn);
    return () => {
      const i = list.indexOf(fn);
      if (i >= 0) list.splice(i, 1);
    };
  }

  emit<K extends keyof E>(k: K, ...a: E[K]): void {
    const list = this.handlers[k];
    if (!list) return;
    for (const fn of [...list]) {
      try {
        fn(...a);
      } catch (e) {
        console.error(e);
      }
    }
  }
}

export function fmtInt(n: number): string {
  return Math.round(n).toLocaleString("en-US");
}

/** Wireshark-style decimal size: "740 bytes", "1.2 kB", "35 MB". */
export function fmtSize(n: number): string {
  if (!Number.isFinite(n) || n < 0) return "";
  if (n < 1000) return `${n} byte${n === 1 ? "" : "s"}`;
  const units = ["kB", "MB", "GB", "TB"];
  let v = n;
  let i = -1;
  while (v >= 1000 && i < units.length - 1) {
    v /= 1000;
    i++;
  }
  return `${v < 10 ? v.toFixed(1) : Math.round(v)} ${units[i]}`;
}

export function fmtPct(part: number, whole: number): string {
  if (!whole) return "0.0%";
  return `${((100 * part) / whole).toFixed(1)}%`;
}

/** Elapsed seconds as h:mm:ss or m:ss. */
export function fmtElapsed(sec: number): string {
  const s = Math.max(0, Math.floor(sec));
  const hh = Math.floor(s / 3600);
  const mm = Math.floor((s % 3600) / 60);
  const ss = s % 60;
  const p2 = (x: number): string => String(x).padStart(2, "0");
  return hh > 0 ? `${hh}:${p2(mm)}:${p2(ss)}` : `${mm}:${p2(ss)}`;
}

export function fmtDateTime(ms: number): string {
  const d = new Date(ms);
  if (Number.isNaN(d.getTime())) return "";
  const p2 = (x: number): string => String(x).padStart(2, "0");
  return `${d.getFullYear()}-${p2(d.getMonth() + 1)}-${p2(d.getDate())} ${p2(d.getHours())}:${p2(d.getMinutes())}`;
}

export function fmtAgo(ms: number): string {
  const s = Math.round((Date.now() - ms) / 1000);
  if (s < 10) return "just now";
  if (s < 60) return `${s} s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m} min ago`;
  const hrs = Math.round(m / 60);
  if (hrs < 24) return `${hrs} h ago`;
  return fmtDateTime(ms);
}

export function baseName(path: string): string {
  const parts = path.split(/[\\/]/);
  return parts[parts.length - 1] || path;
}

export function dirName(path: string): string {
  const i = Math.max(path.lastIndexOf("/"), path.lastIndexOf("\\"));
  return i > 0 ? path.slice(0, i) : i === 0 ? path.slice(0, 1) : "";
}

export function b64ToBytes(s: string): Uint8Array {
  let bin: string;
  try {
    bin = atob(s);
  } catch {
    return new Uint8Array(0);
  }
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function hex2(b: number): string {
  return (b < 16 ? "0" : "") + b.toString(16);
}

export function bytesToHex(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i++) s += hex2(b[i]);
  return s;
}

export async function copyText(text: string): Promise<boolean> {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    // fall through to the textarea route
  }
  const ta = h("textarea", { style: "position:fixed;left:-9999px;top:0;opacity:0" });
  ta.value = text;
  document.body.appendChild(ta);
  ta.select();
  let ok = false;
  try {
    ok = document.execCommand("copy");
  } catch {
    ok = false;
  }
  ta.remove();
  return ok;
}

const STORAGE_PREFIX = "wirebuddy.";

/** Reads a JSON value from localStorage; keys get the app prefix. */
export function load<T>(key: string, fallback: T): T {
  try {
    const s = localStorage.getItem(STORAGE_PREFIX + key);
    if (s === null) return fallback;
    return JSON.parse(s) as T;
  } catch {
    return fallback;
  }
}

export function save(key: string, value: unknown): void {
  try {
    localStorage.setItem(STORAGE_PREFIX + key, JSON.stringify(value));
  } catch {
    // storage unavailable (private mode, blocked)
  }
}

let measureCtx: CanvasRenderingContext2D | null = null;

export function measureText(text: string, font: string): number {
  if (!measureCtx) measureCtx = document.createElement("canvas").getContext("2d");
  if (!measureCtx) return text.length * 7;
  measureCtx.font = font;
  return measureCtx.measureText(text).width;
}

export function fontOf(el: Element): string {
  const cs = getComputedStyle(el);
  return `${cs.fontStyle} ${cs.fontWeight} ${cs.fontSize} ${cs.fontFamily}`;
}

export const IS_MAC = /Mac|iPhone|iPad/.test(navigator.platform);

/** Ctrl on Linux/Windows, Cmd on macOS, where Control+key edits text and Control+click opens the context menu. */
export function isMod(e: KeyboardEvent | MouseEvent): boolean {
  return IS_MAC ? e.metaKey : e.ctrlKey;
}

/** Letter key pressed, "A"–"Z", on any layout; "" for other keys. */
export function keyLetter(e: KeyboardEvent): string {
  if (e.key.length === 1 && /[a-z]/i.test(e.key)) return e.key.toUpperCase();
  // Punctuation at a letter's place (AZERTY ",") is its own key; AltGr types characters
  if (/^[\x20-\x7e]$/.test(e.key) || (!IS_MAC && e.getModifierState?.("AltGraph"))) return "";
  // Option on macOS and non-Latin layouts: the key's position
  return /^Key[A-Z]$/.test(e.code) ? e.code[3] : "";
}

const MAC_KEYS: Record<string, string> = { Left: "←", Right: "→", Up: "↑", Down: "↓" };

/** A binding as shown: "Ctrl+Shift+X", or "⇧⌘X" on macOS. */
export function keyLabel(binding: string): string {
  if (!IS_MAC) return binding;
  const m = /^((?:(?:Ctrl|Alt|Shift)\+)*)(.+)$/.exec(binding);
  if (!m) return binding;
  const mods = m[1];
  return `${mods.includes("Alt") ? "⌥" : ""}${mods.includes("Shift") ? "⇧" : ""}${mods.includes("Ctrl") ? "⌘" : ""}${MAC_KEYS[m[2]] ?? m[2]}`;
}

export function isTextInput(el: Element | null): boolean {
  if (!el) return false;
  if (el instanceof HTMLTextAreaElement) return true;
  if (el instanceof HTMLSelectElement) return true;
  if (el instanceof HTMLInputElement) {
    return !["button", "checkbox", "radio", "submit", "reset", "range", "color", "file"].includes(el.type);
  }
  return (el as HTMLElement).isContentEditable === true;
}

export function csvField(s: string): string {
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

/** Parses a positive integer from an input; empty or invalid gives undefined. */
export function posInt(s: string): number | undefined {
  const t = s.trim();
  if (!/^\d+$/.test(t)) return undefined;
  const n = Number(t);
  return n > 0 ? n : undefined;
}
