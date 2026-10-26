/** Hex dump of the selected frame, with data-source tabs and field highlighting. */

import type { FrameDetail } from "../shared/api.ts";
import { frameInfo, type Source } from "./frame.ts";
import { fontOf, h, hex2, measureText } from "./util.ts";
import { VList } from "./vlist.ts";

const LH = 17;

let vl: VList;
let tabsEl: HTMLDivElement;
let sources: Source[] = [];
let tab = 0;
let hl: { src: number; off: number; len: number } | null = null;
let onByteClick: (src: number, off: number) => void = () => {};
let charW = 0;

function offDigits(): number {
  const len = sources[tab]?.bytes.length ?? 0;
  return len > 0x10000 ? 8 : 4;
}

function renderLine(li: number): HTMLElement {
  const b = sources[tab]?.bytes ?? new Uint8Array(0);
  const start = li * 16;
  const end = Math.min(b.length, start + 16);
  const on = hl !== null && hl.src === tab;
  const hs = hl?.off ?? 0;
  const he = hs + (hl?.len ?? 0);
  const inHl = (k: number): boolean => on && k >= hs && k < he && k < end;

  const line = document.createElement("div");
  line.className = "bx-line";
  const off = document.createElement("span");
  off.className = "bx-off";
  off.textContent = start.toString(16).padStart(offDigits(), "0");
  line.append(off, "  ");

  for (let k = start; k < start + 16; k++) {
    if (k < end) {
      const s = document.createElement("span");
      s.className = inHl(k) ? "bx-b hl" : "bx-b";
      s.dataset.o = String(k);
      s.textContent = hex2(b[k]);
      line.appendChild(s);
    } else {
      line.append("  ");
    }
    if (k < start + 15) {
      const gap = k === start + 7 ? "  " : " ";
      if (inHl(k) && inHl(k + 1)) {
        const s = document.createElement("span");
        s.className = "bx-sp hl";
        s.textContent = gap;
        line.appendChild(s);
      } else {
        line.append(gap);
      }
    }
  }
  line.append("   ");
  for (let k = start; k < end; k++) {
    const s = document.createElement("span");
    s.className = inHl(k) ? "bx-a hl" : "bx-a";
    s.dataset.o = String(k);
    const c = b[k];
    s.textContent = c >= 0x20 && c < 0x7f ? String.fromCharCode(c) : ".";
    line.appendChild(s);
  }
  return line;
}

function contentWidth(): number {
  if (!charW) {
    const w = measureText("0123456789", fontOf(vl.el)) / 10;
    charW = w > 0 ? w : 7.5;
  }
  return (offDigits() + 2 + 16 * 3 + 1 + 3 + 16) * charW + 24;
}

function renderTabs(): void {
  tabsEl.replaceChildren();
  tabsEl.hidden = sources.length < 2;
  if (sources.length < 2) return;
  sources.forEach((s, k) => {
    tabsEl.appendChild(
      h(
        "button",
        {
          class: `bx-tab${k === tab ? " active" : ""}`,
          role: "tab",
          attrs: { "aria-selected": k === tab ? "true" : "false" },
          onclick: () => {
            if (tab === k) return;
            tab = k;
            renderTabs();
            rebuild();
          },
        },
        s.name,
      ),
    );
  });
}

function rebuild(): void {
  const len = sources[tab]?.bytes.length ?? 0;
  vl.setCount(Math.ceil(len / 16), contentWidth());
}

export function setBytesFrame(fd: FrameDetail | null): void {
  sources = fd ? frameInfo(fd).sources : [];
  tab = 0;
  hl = null;
  renderTabs();
  vl.el.scrollTop = 0;
  rebuild();
}

/** Highlights a field's bytes, switching to its data source tab. */
export function highlightBytes(src: number, off: number, len: number): void {
  hl = len > 0 && src < sources.length ? { src, off, len } : null;
  if (hl && hl.src !== tab) {
    tab = hl.src;
    renderTabs();
    rebuild();
  } else {
    vl.refresh();
  }
  if (hl) {
    const firstLine = Math.floor(off / 16);
    const lastLine = Math.floor((off + len - 1) / 16);
    vl.scrollTo(lastLine, "nearest");
    vl.scrollTo(firstLine, "nearest");
  }
}

export function clearBytesHighlight(): void {
  if (!hl) return;
  hl = null;
  vl.refresh();
}

export function createBytesPane(opts: { onByteClick: (src: number, off: number) => void }): HTMLElement {
  onByteClick = opts.onByteClick;
  vl = new VList(LH, renderLine, "bx");
  vl.el.setAttribute("aria-label", "Packet bytes");
  vl.el.addEventListener("mousedown", (e) => {
    if (e.button !== 0) return;
    const t = (e.target as HTMLElement).closest<HTMLElement>("[data-o]");
    if (t) onByteClick(tab, Number(t.dataset.o));
  });
  tabsEl = h("div", { class: "bx-tabs", role: "tablist", hidden: true });
  return h("div", { class: "bx-pane" }, vl.el, tabsEl);
}
