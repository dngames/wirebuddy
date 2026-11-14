/** Packet list / docked panel / details / bytes stacked with draggable splitters. */

import { app } from "./app.ts";
import { clamp, h, load, save } from "./util.ts";

const MIN = 44;
/** A docked panel's title bar and a few rows of its page. */
const DOCK_MIN = 120;
const DEFAULT: [number, number] = [0.48, 0.3];
/** The docked panel's share of the height the splitters leave. The list and details then share the rest as before. */
const DOCK_DEFAULT = 0.3;

let reset = (): void => {};

/** View > Reset Layout: the default pane sizes. */
export function resetLayout(): void {
  reset();
}

/** The pane under the packet list that a docked panel takes; empty and hidden while no panel is docked. */
const dockPane = h("div", { class: "pane pane-dock" });
const dockSplitter = h("div", { class: "splitter", role: "separator", title: "Drag to resize, double-click to reset", attrs: { "aria-orientation": "horizontal" } });
dockPane.hidden = true;
dockSplitter.hidden = true;
let relayout = (): void => {};
const moved = new Set<() => void>();

/** Where a docked panel lives: the pane to put its place in. */
export function dockSlot(): HTMLElement {
  return dockPane;
}

/** Shows or hides the dock pane; the other panes make room at once. */
export function setDock(on: boolean): void {
  if (dockPane.hidden === !on) return;
  dockPane.hidden = !on;
  dockSplitter.hidden = !on;
  relayout();
}

/** Calls `fn` after the panes were laid out again (a window, splitter or zoom changed their places). */
export function onPanesLaidOut(fn: () => void): void {
  moved.add(fn);
}

export function createPanes(list: HTMLElement, details: HTMLElement, bytes: HTMLElement): HTMLElement {
  const p1 = h("div", { class: "pane pane-list" }, list);
  const p2 = h("div", { class: "pane pane-details" }, details);
  const p3 = h("div", { class: "pane pane-bytes" }, bytes);
  const s1 = h("div", { class: "splitter", role: "separator", title: "Drag to resize, double-click to reset", attrs: { "aria-orientation": "horizontal" } });
  const s2 = h("div", { class: "splitter", role: "separator", title: "Drag to resize, double-click to reset", attrs: { "aria-orientation": "horizontal" } });
  const root = h("div", { class: "panes" }, p1, s1, dockPane, dockSplitter, p2, s2, p3);

  let fr = load<[number, number]>("panes", DEFAULT);
  if (!Array.isArray(fr) || fr.length !== 2 || !fr.every((x) => typeof x === "number" && x > 0 && x < 1)) fr = DEFAULT;
  let frDock = load<number>("dock", DOCK_DEFAULT);
  if (typeof frDock !== "number" || !(frDock > 0 && frDock < 1)) frDock = DOCK_DEFAULT;

  const docked = (): boolean => !dockPane.hidden;
  const avail = (): number => root.clientHeight - s1.offsetHeight - s2.offsetHeight - dockSplitter.offsetHeight;

  /** Heights of the list, the dock (0 when not shown) and the details; the bytes take the rest. */
  const sizes = (): [number, number, number] => {
    const H = avail();
    let d = 0;
    if (docked()) {
      const most = Math.max(MIN, H - 3 * MIN);
      d = clamp(Math.round(frDock * H), Math.min(DOCK_MIN, most), most);
    }
    const R = H - d;
    const a = clamp(Math.round(fr[0] * R), MIN, Math.max(MIN, R - 2 * MIN));
    const b = clamp(Math.round(fr[1] * R), MIN, Math.max(MIN, R - a - MIN));
    return [a, d, b];
  };

  const apply = (a: number, d: number, b: number): void => {
    p1.style.height = `${a}px`;
    dockPane.style.height = `${d}px`;
    p2.style.height = `${b}px`;
  };

  const layout = (): void => {
    if (avail() <= 0) return;
    const [a, d, b] = sizes();
    apply(a, d, b);
    for (const fn of moved) fn();
  };
  relayout = layout;

  /** A splitter moves the pane above it against the one below it; under the details, the bytes take what is left. */
  const drag = (which: "list" | "dock" | "details") => (e: PointerEvent): void => {
    if (e.button !== 0) return;
    e.preventDefault();
    const sp = e.currentTarget as HTMLElement;
    sp.setPointerCapture(e.pointerId);
    sp.classList.add("active");
    const H = avail();
    const [a0, d0, b0] = sizes();
    const withDock = docked();
    const hs = withDock ? [a0, d0, b0] : [a0, b0];
    const mins = withDock ? [MIN, Math.min(DOCK_MIN, d0), MIN] : [MIN, MIN];
    const i = which === "list" ? 0 : which === "dock" ? 1 : hs.length - 1;
    const y0 = e.clientY;
    const move = (ev: PointerEvent): void => {
      // Screen pixels to the zoomed panes' own
      const dy = (ev.clientY - y0) / app.zoom;
      const now = [...hs];
      if (i < hs.length - 1) {
        const both = hs[i] + hs[i + 1];
        now[i] = clamp(hs[i] + dy, mins[i], both - mins[i + 1]);
        now[i + 1] = both - now[i];
      } else {
        const above = hs.slice(0, i).reduce((x, y) => x + y, 0);
        now[i] = clamp(hs[i] + dy, mins[i], H - above - MIN);
      }
      const [a, d, b] = withDock ? now : [now[0], 0, now[1]];
      if (withDock) frDock = d / H;
      fr = [a / (H - d), b / (H - d)];
      apply(a, d, b);
      for (const fn of moved) fn();
    };
    const up = (): void => {
      sp.classList.remove("active");
      sp.removeEventListener("pointermove", move);
      sp.removeEventListener("pointerup", up);
      sp.removeEventListener("pointercancel", up);
      save("panes", fr);
      save("dock", frDock);
    };
    sp.addEventListener("pointermove", move);
    sp.addEventListener("pointerup", up);
    sp.addEventListener("pointercancel", up);
  };

  s1.addEventListener("pointerdown", drag("list"));
  dockSplitter.addEventListener("pointerdown", drag("dock"));
  s2.addEventListener("pointerdown", drag("details"));
  reset = () => {
    fr = DEFAULT;
    frDock = DOCK_DEFAULT;
    save("panes", fr);
    save("dock", frDock);
    layout();
  };
  for (const s of [s1, dockSplitter, s2]) s.addEventListener("dblclick", reset);
  new ResizeObserver(layout).observe(root);
  return root;
}
