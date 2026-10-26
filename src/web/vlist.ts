/** Fixed-row-height virtual list for the details tree and the hex dump. */

import { clamp, h } from "./util.ts";

export class VList {
  /** The scrolling element; focusable. */
  readonly el: HTMLDivElement;
  private inner: HTMLDivElement;
  private count = 0;
  private queued = false;
  private rendered = new Map<number, HTMLElement>();

  constructor(
    private readonly rowH: number,
    private readonly renderRow: (i: number) => HTMLElement,
    cls: string,
  ) {
    this.inner = h("div", { class: "vl-inner" });
    this.el = h("div", { class: `vl ${cls}`, tabIndex: 0 }, this.inner);
    this.el.addEventListener("scroll", () => this.render(false));
    new ResizeObserver(() => this.schedule()).observe(this.el);
  }

  get length(): number {
    return this.count;
  }

  /** Sets the row count and content width, then re-renders all rows. */
  setCount(n: number, width?: number): void {
    this.count = n;
    this.inner.style.height = `${n * this.rowH}px`;
    this.inner.style.width = width ? `${Math.ceil(width)}px` : "";
    this.render(true);
  }

  /** Re-renders every visible row. */
  refresh(): void {
    this.render(true);
  }

  schedule(): void {
    if (this.queued) return;
    this.queued = true;
    requestAnimationFrame(() => {
      this.queued = false;
      this.render(false);
    });
  }

  scrollTo(i: number, mode: "nearest" | "center" | "top" = "nearest"): void {
    if (i < 0 || i >= this.count) return;
    const vh = this.el.clientHeight;
    const top = i * this.rowH;
    let t = this.el.scrollTop;
    if (mode === "top") t = top;
    else if (mode === "center") t = top - (vh - this.rowH) / 2;
    else if (top < t) t = top;
    else if (top + this.rowH > t + vh) t = top + this.rowH - vh;
    else return;
    this.el.scrollTop = clamp(t, 0, Math.max(0, this.count * this.rowH - vh));
    this.render(false);
  }

  /** Patches the rendered rows in place (keeps elements, so clicks survive). */
  forEachRow(cb: (el: HTMLElement, i: number) => void): void {
    for (const [i, el] of this.rendered) cb(el, i);
  }

  visibleRows(): number {
    return Math.max(1, Math.floor(this.el.clientHeight / this.rowH));
  }

  private render(force: boolean): void {
    const st = this.el.scrollTop;
    const vh = Math.min(this.el.clientHeight || 400, 4000);
    const first = Math.max(0, Math.floor(st / this.rowH) - 4);
    const last = Math.min(this.count, Math.ceil((st + vh) / this.rowH) + 4);
    const next = new Map<number, HTMLElement>();
    for (let i = first; i < last; i++) {
      let r = force ? undefined : this.rendered.get(i);
      if (!r) {
        r = this.renderRow(i);
        r.dataset.i = String(i);
        r.style.top = `${i * this.rowH}px`;
        r.style.height = `${this.rowH}px`;
        this.inner.appendChild(r);
      }
      next.set(i, r);
    }
    for (const [i, r] of this.rendered) if (next.get(i) !== r) r.remove();
    this.rendered = next;
  }
}
