/** Main toolbar. */

import { APP_NAME } from "./api.ts";
import * as act from "./actions.ts";
import { app, bus, captureActive, hooks } from "./app.ts";
import { cap, capBus, setBarOpen } from "./capture.ts";
import { openConvDialog } from "./dialogs/conv.ts";
import { openGotoDialog } from "./dialogs/goto.ts";
import { openFileDialog } from "./dialogs/openfile.ts";
import { openPhsDialog } from "./dialogs/phs.ts";
import { icon, type IconName } from "./icons.ts";
import { SEP, toggleMenuAt, type MenuItem } from "./menu.ts";
import { h } from "./util.ts";

function tbButton(ic: IconName, label: string, title: string, opts: { menu?: boolean; cls?: string } = {}): HTMLButtonElement {
  return h(
    "button",
    { class: `tb-btn${opts.cls ? ` ${opts.cls}` : ""}`, title, attrs: { "aria-label": label } },
    icon(ic),
    h("span", { class: "tb-label" }, label),
    opts.menu ? icon("chevron", "icon tb-chev") : null,
  );
}

function marksMenu(): MenuItem[] {
  const marks = [...app.marks.values()].sort((a, b) => a.frame - b.frame);
  const items: MenuItem[] = [{ label: marks.length ? `Marked Packets (${marks.length})` : "No Marked Packets", header: true }];
  for (const m of marks.slice(0, 300)) {
    items.push({
      label: `No. ${m.frame}`,
      detail: m.note || undefined,
      shortcut: m.by === "agent" ? "Claude" : "",
      checked: m.frame === app.selFrame,
      title: m.note || undefined,
      action: () => act.jumpToFrame(m.frame),
    });
  }
  if (marks.length > 300) items.push({ label: `…and ${marks.length - 300} more`, disabled: true });
  items.push(
    SEP,
    { label: "Next Mark", disabled: !marks.length, action: () => act.gotoMark(1) },
    { label: "Previous Mark", disabled: !marks.length, action: () => act.gotoMark(-1) },
    SEP,
    {
      label: app.selFrame !== null && app.marks.has(app.selFrame) ? "Unmark Selected Packet" : "Mark Selected Packet",
      shortcut: "Ctrl+M",
      disabled: app.selFrame === null,
      action: () => act.toggleMark(app.selFrame),
    },
    { label: "Unmark All", disabled: !marks.length, action: () => void act.clearMarks() },
  );
  return items;
}

export function createToolbar(): HTMLElement {
  const openBtn = tbButton("open", "Open", "Open a capture file (Ctrl+O)");
  const closeBtn = tbButton("close", "Close", "Close this capture file");
  const startBtn = tbButton("fin", "Start", "Start capturing packets");
  const stopBtn = tbButton("stop", "Stop", "Stop capturing packets");
  const optsBtn = tbButton("options", "Options", "Show capture options");
  const statsBtn = tbButton("stats", "Statistics", "Statistics", { menu: true });
  const gotoBtn = tbButton("goto", "Go to", "Go to packet (Ctrl+G)");
  const marksBtn = tbButton("marks", "Marks", "Marked packets", { menu: true });
  const autoBtn = tbButton("autoscroll", "Auto-scroll", "Scroll to the last packet during a live capture");
  const wsBtn = h(
    "button",
    { class: "tb-wireshark", title: "Open this capture in Wireshark at the selected packet" },
    icon("wireshark"),
    h("span", { class: "tb-ws-label" }, "Open in Wireshark"),
  );

  openBtn.addEventListener("click", () => openFileDialog());
  closeBtn.addEventListener("click", () => void act.closeFile());
  startBtn.addEventListener("click", () => hooks.startCapture());
  stopBtn.addEventListener("click", () => void act.stopCapture());
  optsBtn.addEventListener("click", () => setBarOpen(!cap.barOpen));
  statsBtn.addEventListener("click", () =>
    toggleMenuAt(statsBtn, () => [
      { label: "Protocol Hierarchy", action: () => openPhsDialog() },
      { label: "Conversations", action: () => openConvDialog("conv") },
      { label: "Endpoints", action: () => openConvDialog("endpt") },
    ]),
  );
  gotoBtn.addEventListener("click", () => openGotoDialog());
  marksBtn.addEventListener("click", () => toggleMenuAt(marksBtn, marksMenu, { minWidth: 240 }));
  autoBtn.addEventListener("click", () => act.setAutoScroll(!app.autoScroll));
  wsBtn.addEventListener("click", () => void act.openInWireshark(app.selFrame));

  const sep = (): HTMLElement => h("span", { class: "tb-sep" });
  const bar = h(
    "div",
    { class: "toolbar", role: "toolbar" },
    h("span", { class: "tb-brand", title: APP_NAME }, icon("fin"), h("span", { class: "tb-brand-name" }, APP_NAME)),
    sep(),
    openBtn,
    closeBtn,
    sep(),
    startBtn,
    stopBtn,
    optsBtn,
    sep(),
    statsBtn,
    gotoBtn,
    marksBtn,
    autoBtn,
    h("span", { class: "tb-spacer" }),
    wsBtn,
  );

  const update = (): void => {
    const s = app.state;
    const hasFile = !!s?.file && !s.loading;
    const active = captureActive(s);
    closeBtn.disabled = !s?.file;
    startBtn.disabled = active;
    stopBtn.disabled = !(s && (s.capture.status === "running" || s.capture.status === "starting"));
    startBtn.classList.toggle("live", s?.capture.status === "running");
    statsBtn.disabled = !hasFile;
    gotoBtn.disabled = !hasFile;
    marksBtn.disabled = !s?.file;
    const nMarks = app.marks.size;
    marksBtn.querySelector(".tb-label")!.textContent = nMarks ? `Marks (${nMarks})` : "Marks";
    autoBtn.classList.toggle("pressed", app.autoScroll);
    autoBtn.setAttribute("aria-pressed", app.autoScroll ? "true" : "false");
    optsBtn.classList.toggle("pressed", cap.barOpen);
    optsBtn.setAttribute("aria-pressed", cap.barOpen ? "true" : "false");
    const wsOk = !!s?.wiresharkAvailable && !!s.file;
    wsBtn.disabled = !wsOk;
    wsBtn.title = !s?.wiresharkAvailable
      ? "Wireshark was not found on this machine"
      : !s.file
        ? "Open a capture file first"
        : app.selFrame
          ? `Open this capture in Wireshark at packet ${app.selFrame}`
          : "Open this capture in Wireshark";
  };

  bus.on("state", update);
  bus.on("selection", update);
  bus.on("autoscroll", update);
  capBus.on("bar", update);
  update();
  return bar;
}
