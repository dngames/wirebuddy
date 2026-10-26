/** Packet list / details / bytes stacked with draggable splitters. */

import { clamp, h, load, save } from "./util.ts";

const MIN = 44;
const DEFAULT: [number, number] = [0.48, 0.3];

export function createPanes(list: HTMLElement, details: HTMLElement, bytes: HTMLElement): HTMLElement {
  const p1 = h("div", { class: "pane pane-list" }, list);
  const p2 = h("div", { class: "pane pane-details" }, details);
  const p3 = h("div", { class: "pane pane-bytes" }, bytes);
  const s1 = h("div", { class: "splitter", role: "separator", title: "Drag to resize, double-click to reset", attrs: { "aria-orientation": "horizontal" } });
  const s2 = h("div", { class: "splitter", role: "separator", title: "Drag to resize, double-click to reset", attrs: { "aria-orientation": "horizontal" } });
  const root = h("div", { class: "panes" }, p1, s1, p2, s2, p3);

  let fr = load<[number, number]>("panes", DEFAULT);
  if (!Array.isArray(fr) || fr.length !== 2 || !fr.every((x) => typeof x === "number" && x > 0 && x < 1)) fr = DEFAULT;

  const avail = (): number => root.clientHeight - s1.offsetHeight - s2.offsetHeight;

  const sizes = (): [number, number] => {
    const H = avail();
    const a = clamp(Math.round(fr[0] * H), MIN, Math.max(MIN, H - 2 * MIN));
    const b = clamp(Math.round(fr[1] * H), MIN, Math.max(MIN, H - a - MIN));
    return [a, b];
  };

  const apply = (a: number, b: number): void => {
    p1.style.height = `${a}px`;
    p2.style.height = `${b}px`;
  };

  const layout = (): void => {
    if (avail() <= 0) return;
    const [a, b] = sizes();
    apply(a, b);
  };

  const drag = (which: 0 | 1) => (e: PointerEvent): void => {
    if (e.button !== 0) return;
    e.preventDefault();
    const sp = e.currentTarget as HTMLElement;
    sp.setPointerCapture(e.pointerId);
    sp.classList.add("active");
    const H = avail();
    const [a0, b0] = sizes();
    const y0 = e.clientY;
    const move = (ev: PointerEvent): void => {
      const dy = ev.clientY - y0;
      let a = a0;
      let b = b0;
      if (which === 0) {
        a = clamp(a0 + dy, MIN, a0 + b0 - MIN);
        b = a0 + b0 - a;
      } else {
        b = clamp(b0 + dy, MIN, H - a0 - MIN);
      }
      fr = [a / H, b / H];
      apply(a, b);
    };
    const up = (): void => {
      sp.classList.remove("active");
      sp.removeEventListener("pointermove", move);
      sp.removeEventListener("pointerup", up);
      sp.removeEventListener("pointercancel", up);
      save("panes", fr);
    };
    sp.addEventListener("pointermove", move);
    sp.addEventListener("pointerup", up);
    sp.addEventListener("pointercancel", up);
  };

  s1.addEventListener("pointerdown", drag(0));
  s2.addEventListener("pointerdown", drag(1));
  for (const s of [s1, s2]) {
    s.addEventListener("dblclick", () => {
      fr = DEFAULT;
      save("panes", fr);
      layout();
    });
  }
  new ResizeObserver(layout).observe(root);
  return root;
}
