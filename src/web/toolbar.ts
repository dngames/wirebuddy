/** Main toolbar: Wireshark's icon bar, then TLS keys and Open in Wireshark. */

import * as act from "./actions.ts";
import { app, bus } from "./app.ts";
import { capBus } from "./capture.ts";
import { commands, isEnabled, tooltip, type Command, type CommandId } from "./commands.ts";
import { icon, type IconName } from "./icons.ts";
import { h } from "./util.ts";

/** Wireshark's main toolbar in its order; "|" separates the groups. */
const LAYOUT: ([CommandId, IconName] | "|")[] = [
  ["startCapture", "fin"],
  ["stopCapture", "stop"],
  ["restartCapture", "restart"],
  ["captureOptions", "gear"],
  "|",
  ["open", "open"],
  ["saveAs", "save"],
  ["close", "close"],
  ["reload", "refresh"],
  "|",
  ["find", "find"],
  ["back", "back"],
  ["forward", "forward"],
  ["gotoPacket", "goto"],
  ["firstPacket", "first"],
  ["lastPacket", "last"],
  ["autoScroll", "autoscroll"],
  ["colorize", "colorize"],
  "|",
  ["zoomIn", "zoomIn"],
  ["zoomOut", "zoomOut"],
  ["zoomNormal", "zoomNormal"],
  ["resizeColumns", "resize"],
];

function iconButton(c: Command, ic: IconName): HTMLButtonElement {
  const el = h("button", { class: "tb-icon", title: tooltip(c), attrs: { "aria-label": c.label } }, icon(ic));
  // Keyboard focus stays in the packet list, as in Wireshark
  el.addEventListener("mousedown", (e) => e.preventDefault());
  el.addEventListener("click", () => {
    if (isEnabled(c)) c.run();
  });
  return el;
}

export function createToolbar(): HTMLElement {
  const bar = h("div", { class: "toolbar", role: "toolbar", attrs: { "aria-label": "Main toolbar" } });
  const buttons: { el: HTMLButtonElement; c: Command }[] = [];
  let startBtn: HTMLButtonElement | null = null;
  for (const entry of LAYOUT) {
    if (entry === "|") {
      bar.append(h("span", { class: "tb-sep" }));
      continue;
    }
    const c: Command = commands[entry[0]];
    const el = iconButton(c, entry[1]);
    if (entry[0] === "startCapture") startBtn = el;
    buttons.push({ el, c });
    bar.append(el);
  }

  const tls: Command = commands.tlsKeys;
  const tlsBtn = iconButton(tls, "lock");
  buttons.push({ el: tlsBtn, c: tls });
  const wsBtn = h(
    "button",
    { class: "tb-wireshark", title: "Open this capture in Wireshark at the selected packet" },
    icon("wireshark"),
    h("span", { class: "tb-ws-label" }, "Open in Wireshark"),
  );
  wsBtn.addEventListener("mousedown", (e) => e.preventDefault());
  wsBtn.addEventListener("click", () => void act.openInWireshark(app.selFrame));
  bar.append(h("span", { class: "tb-spacer" }), tlsBtn, wsBtn);

  const update = (): void => {
    const s = app.state;
    for (const { el, c } of buttons) {
      el.disabled = !isEnabled(c);
      const on = c.checked?.();
      if (on === undefined) continue;
      el.classList.toggle("pressed", on);
      el.setAttribute("aria-pressed", on ? "true" : "false");
    }
    startBtn?.classList.toggle("live", s?.capture.status === "running");
    tlsBtn.title = s?.tlsKeylog ? `Decrypting TLS with ${s.tlsKeylog}` : tooltip(tls);
    wsBtn.disabled = !s?.wiresharkAvailable || !s.file;
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
  bus.on("view", update);
  bus.on("frame", update);
  capBus.on("bar", update);
  update();
  return bar;
}
