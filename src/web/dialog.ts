/** Draggable, resizable dialog windows (closable with Esc), modal or modeless. */

import { hooks } from "./app.ts";
import { icon } from "./icons.ts";
import { clamp, h, isTextInput } from "./util.ts";

const open: Dialog[] = [];
const Z_BASE = 900;

/** Stacks dialogs by their order in `open`, staying below menus and toasts. */
function restack(): void {
  open.forEach((d, i) => {
    d.overlay.style.zIndex = String(Z_BASE + i);
  });
}

export interface DialogOptions {
  width?: number;
  height?: number;
  cls?: string;
  resizable?: boolean;
  /** Modeless dialogs leave the main window usable, like Wireshark's statistics windows. */
  modal?: boolean;
}

export class Dialog {
  readonly overlay: HTMLDivElement;
  readonly win: HTMLDivElement;
  readonly body: HTMLDivElement;
  readonly footer: HTMLDivElement;
  /** Left side of the footer, for status text or extra controls. */
  readonly footerLeft: HTMLDivElement;
  readonly footerRight: HTMLDivElement;
  private titleEl: HTMLSpanElement;
  /** Runs on Enter in a single-line input inside the dialog. */
  defaultAction: (() => void) | null = null;
  onClose: (() => void) | null = null;
  readonly modal: boolean;
  private closed = false;
  /** Focused element when the dialog opened. */
  private returnFocus: HTMLElement | null = null;

  constructor(title: string, opts: DialogOptions = {}) {
    this.titleEl = h("span", { class: "dlg-title-text" }, title);
    const closeBtn = h("button", { class: "dlg-close", title: "Close (Esc)", attrs: { "aria-label": "Close" }, onclick: () => this.close() }, icon("x"));
    const titleBar = h("div", { class: "dlg-titlebar" }, this.titleEl, closeBtn);
    this.body = h("div", { class: "dlg-body" });
    this.footerLeft = h("div", { class: "dlg-footer-left" });
    this.footerRight = h("div", { class: "dlg-footer-right" });
    this.footer = h("div", { class: "dlg-footer" }, this.footerLeft, this.footerRight);
    this.modal = opts.modal !== false;
    this.win = h("div", { class: `dlg${opts.cls ? ` ${opts.cls}` : ""}${opts.resizable === false ? "" : " resizable"}`, role: "dialog", attrs: { "aria-modal": this.modal ? "true" : "false", "aria-label": title } }, titleBar, this.body, this.footer);
    this.overlay = h("div", { class: `dlg-overlay${this.modal ? "" : " modeless"}` }, this.win);
    this.win.addEventListener("pointerdown", () => this.raise(), true);
    const vw = window.innerWidth;
    const vh = window.innerHeight;
    if (opts.width) this.win.style.width = `${Math.min(opts.width, vw - 16)}px`;
    if (opts.height) this.win.style.height = `${Math.min(opts.height, vh - 16)}px`;

    titleBar.addEventListener("pointerdown", (e) => this.startDrag(e));
    this.win.addEventListener("keydown", (e) => {
      if (e.key === "Enter" && this.defaultAction && e.target instanceof HTMLInputElement && isTextInput(e.target) && !e.isComposing) {
        e.preventDefault();
        this.defaultAction();
      }
    });
  }

  setTitle(t: string): void {
    this.titleEl.textContent = t;
  }

  button(label: string, fn: () => void, opts: { primary?: boolean; disabled?: boolean; title?: string } = {}): HTMLButtonElement {
    const b = h("button", { class: `btn${opts.primary ? " primary" : ""}`, disabled: !!opts.disabled, title: opts.title, onclick: fn }, label);
    this.footerRight.appendChild(b);
    return b;
  }

  /** Brings the dialog to the front (and makes it the one Esc closes). */
  raise(): void {
    if (this.closed) return;
    const i = open.indexOf(this);
    if (i < 0 || i === open.length - 1) return;
    open.splice(i, 1);
    open.push(this);
    restack();
  }

  show(focus?: HTMLElement | null): void {
    watchMainFocus();
    const active = document.activeElement;
    this.returnFocus = active instanceof HTMLElement && active !== document.body ? active : null;
    document.body.appendChild(this.overlay);
    open.push(this);
    restack();
    const r = this.win.getBoundingClientRect();
    this.win.style.left = `${Math.max(8, (window.innerWidth - r.width) / 2)}px`;
    this.win.style.top = `${Math.max(8, (window.innerHeight - r.height) / 3)}px`;
    const target =
      focus ??
      this.body.querySelector<HTMLElement>("input, select, textarea") ??
      this.footer.querySelector<HTMLElement>("button.primary") ??
      this.footer.querySelector<HTMLElement>("button");
    target?.focus();
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.overlay.remove();
    const i = open.indexOf(this);
    if (i >= 0) open.splice(i, 1);
    restack();
    this.onClose?.();
    // Keys work again where they did before, unless another dialog has the focus
    if (!open.some((d) => d.win.contains(document.activeElement))) {
      // A modeless dialog: the user may have worked in the main window since it opened
      const back = this.modal ? this.returnFocus : mainFocus;
      if (back?.isConnected) back.focus();
      else hooks.focusMain();
    }
  }

  get isOpen(): boolean {
    return !this.closed;
  }

  private startDrag(e: PointerEvent): void {
    if (e.button !== 0 || (e.target as HTMLElement).closest("button")) return;
    e.preventDefault();
    const bar = e.currentTarget as HTMLElement;
    bar.setPointerCapture(e.pointerId);
    // Panel frames would swallow the pointer while it moves over them
    document.body.classList.add("dlg-moving");
    const r = this.win.getBoundingClientRect();
    const dx = e.clientX - r.left;
    const dy = e.clientY - r.top;
    const move = (ev: PointerEvent): void => {
      this.win.style.left = `${clamp(ev.clientX - dx, 40 - r.width, window.innerWidth - 40)}px`;
      this.win.style.top = `${clamp(ev.clientY - dy, 0, window.innerHeight - 30)}px`;
    };
    const up = (): void => {
      document.body.classList.remove("dlg-moving");
      bar.removeEventListener("pointermove", move);
      bar.removeEventListener("pointerup", up);
      bar.removeEventListener("pointercancel", up);
    };
    bar.addEventListener("pointermove", move);
    bar.addEventListener("pointerup", up);
    bar.addEventListener("pointercancel", up);
  }
}

/** True while a modal dialog is open (global shortcuts are off then). */
/** Last focused element outside dialogs and menus. */
let mainFocus: HTMLElement | null = null;
let watching = false;

function watchMainFocus(): void {
  if (watching) return;
  watching = true;
  document.addEventListener("focusin", (e) => {
    const t = e.target;
    if (t instanceof HTMLElement && !t.closest(".dlg, .menu")) mainFocus = t;
  });
}

export function dialogOpen(): boolean {
  return open.some((d) => d.modal);
}

/** Closes the topmost modal dialog, or the modeless one holding focus; true if one closed. */
export function closeTopDialog(): boolean {
  for (let i = open.length - 1; i >= 0; i--) {
    const d = open[i];
    if (d.modal || d.win.contains(document.activeElement)) {
      d.close();
      return true;
    }
  }
  return false;
}

/** Small "label: control" row used inside dialogs. */
export function field(label: string, control: HTMLElement, extra?: HTMLElement | null): HTMLDivElement {
  return h("div", { class: "dlg-field" }, h("label", null, label, control), extra ?? null);
}

/** Asks for one line of text; resolves null on cancel. */
export function promptDialog(title: string, label: string, value: string, okLabel = "OK"): Promise<string | null> {
  return new Promise((resolve) => {
    const d = new Dialog(title, { width: 400, resizable: false });
    const input = h("input", { type: "text", class: "prompt-in", value, spellcheck: false });
    d.body.append(field(label, input));
    let result: string | null = null;
    const ok = (): void => {
      result = input.value;
      d.close();
    };
    d.button(okLabel, ok, { primary: true });
    d.button("Cancel", () => d.close());
    d.defaultAction = ok;
    d.onClose = () => resolve(result);
    d.show(input);
    input.select();
  });
}

/** Yes/no question; resolves true when confirmed. */
export function confirmDialog(title: string, text: string, okLabel = "OK"): Promise<boolean> {
  return new Promise((resolve) => {
    const d = new Dialog(title, { width: 420, resizable: false });
    d.body.append(h("div", { class: "confirm-text" }, text));
    let result = false;
    const ok = d.button(okLabel, () => {
      result = true;
      d.close();
    }, { primary: true });
    d.button("Cancel", () => d.close());
    d.onClose = () => resolve(result);
    d.show(ok);
  });
}
