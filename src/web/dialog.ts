/** Modal, draggable, resizable dialog windows (closable with Esc). */

import { icon } from "./icons.ts";
import { clamp, h, isTextInput } from "./util.ts";

const open: Dialog[] = [];

export interface DialogOptions {
  width?: number;
  height?: number;
  cls?: string;
  resizable?: boolean;
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
  private closed = false;

  constructor(title: string, opts: DialogOptions = {}) {
    this.titleEl = h("span", { class: "dlg-title-text" }, title);
    const closeBtn = h("button", { class: "dlg-close", title: "Close (Esc)", attrs: { "aria-label": "Close" }, onclick: () => this.close() }, icon("x"));
    const titleBar = h("div", { class: "dlg-titlebar" }, this.titleEl, closeBtn);
    this.body = h("div", { class: "dlg-body" });
    this.footerLeft = h("div", { class: "dlg-footer-left" });
    this.footerRight = h("div", { class: "dlg-footer-right" });
    this.footer = h("div", { class: "dlg-footer" }, this.footerLeft, this.footerRight);
    this.win = h("div", { class: `dlg${opts.cls ? ` ${opts.cls}` : ""}${opts.resizable === false ? "" : " resizable"}`, role: "dialog", attrs: { "aria-modal": "true", "aria-label": title } }, titleBar, this.body, this.footer);
    this.overlay = h("div", { class: "dlg-overlay" }, this.win);
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

  show(focus?: HTMLElement | null): void {
    document.body.appendChild(this.overlay);
    open.push(this);
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
    this.onClose?.();
  }

  get isOpen(): boolean {
    return !this.closed;
  }

  private startDrag(e: PointerEvent): void {
    if (e.button !== 0 || (e.target as HTMLElement).closest("button")) return;
    e.preventDefault();
    const bar = e.currentTarget as HTMLElement;
    bar.setPointerCapture(e.pointerId);
    const r = this.win.getBoundingClientRect();
    const dx = e.clientX - r.left;
    const dy = e.clientY - r.top;
    const move = (ev: PointerEvent): void => {
      this.win.style.left = `${clamp(ev.clientX - dx, 40 - r.width, window.innerWidth - 40)}px`;
      this.win.style.top = `${clamp(ev.clientY - dy, 0, window.innerHeight - 30)}px`;
    };
    const up = (): void => {
      bar.removeEventListener("pointermove", move);
      bar.removeEventListener("pointerup", up);
      bar.removeEventListener("pointercancel", up);
    };
    bar.addEventListener("pointermove", move);
    bar.addEventListener("pointerup", up);
    bar.addEventListener("pointercancel", up);
  }
}

export function dialogOpen(): boolean {
  return open.length > 0;
}

/** Closes the topmost dialog; true if there was one. */
export function closeTopDialog(): boolean {
  const d = open[open.length - 1];
  if (!d) return false;
  d.close();
  return true;
}

/** Small "label: control" row used inside dialogs. */
export function field(label: string, control: HTMLElement, extra?: HTMLElement | null): HTMLDivElement {
  return h("div", { class: "dlg-field" }, h("label", null, label, control), extra ?? null);
}
