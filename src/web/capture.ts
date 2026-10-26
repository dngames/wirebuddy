/**
 * Capture options (shared by the capture bar and the welcome page) and the
 * collapsible capture bar. A capture is only ever started from a user click.
 */

import type { CaptureInterface, CaptureRequest, FilterCheck, ViewState } from "../shared/api.ts";
import { errorText, get } from "./api.ts";
import * as act from "./actions.ts";
import { app, bus, captureActive, hooks } from "./app.ts";
import { icon } from "./icons.ts";
import { toast, toastError } from "./toast.ts";
import { baseName, debounce, Emitter, fmtElapsed, fmtInt, h, load, posInt, save } from "./util.ts";

export interface CaptureOpts {
  iface: string;
  filter: string;
  stopDur: string;
  stopSize: string;
  stopPkts: string;
  ring: boolean;
  ringFiles: string;
  ringSize: string;
  ringDur: string;
}

const DEFAULTS: CaptureOpts = {
  iface: "",
  filter: "",
  stopDur: "",
  stopSize: "",
  stopPkts: "",
  ring: false,
  ringFiles: "2",
  ringSize: "",
  ringDur: "",
};

export const capOpts: CaptureOpts = { ...DEFAULTS, ...load<Partial<CaptureOpts>>("capture", {}) };

export const cap = {
  interfaces: null as CaptureInterface[] | null,
  ifaceError: null as string | null,
  ifaceLoading: false,
  filterState: "none" as "none" | "checking" | "ok" | "error",
  filterError: "",
  barOpen: load<boolean>("capturebar", false),
};

type CapEvents = {
  /** Options changed; `source` tells which control changed them. */
  opts: [source: string];
  ifaces: [];
  check: [];
  bar: [open: boolean];
};

export const capBus = new Emitter<CapEvents>();

let checkSeq = 0;

export function setOpts(p: Partial<CaptureOpts>, source: string): void {
  const refilter = (p.filter !== undefined && p.filter !== capOpts.filter) || (p.iface !== undefined && p.iface !== capOpts.iface);
  Object.assign(capOpts, p);
  save("capture", capOpts);
  capBus.emit("opts", source);
  if (refilter) {
    if (cap.filterState !== "none") {
      cap.filterState = "checking";
      capBus.emit("check");
    }
    runCheck();
  }
}

const runCheck = debounce(async () => {
  const seq = ++checkSeq;
  const f = capOpts.filter.trim();
  if (!f) {
    cap.filterState = "ok";
    cap.filterError = "";
  } else if (!capOpts.iface) {
    cap.filterState = "none";
    cap.filterError = "";
  } else {
    try {
      const r = await get<FilterCheck>("api/capture/check", { iface: capOpts.iface, filter: f });
      if (seq !== checkSeq) return;
      cap.filterState = r.ok ? "ok" : "error";
      cap.filterError = r.ok ? "" : r.error || "Invalid capture filter";
    } catch (e) {
      if (seq !== checkSeq) return;
      cap.filterState = "none";
      cap.filterError = errorText(e);
    }
  }
  capBus.emit("check");
}, 300);

export async function loadInterfaces(): Promise<void> {
  if (cap.ifaceLoading) return;
  cap.ifaceLoading = true;
  capBus.emit("ifaces");
  try {
    const list = await get<CaptureInterface[]>("api/capture/interfaces");
    cap.interfaces = Array.isArray(list) ? list : [];
    cap.ifaceError = null;
    if (cap.interfaces.length && !cap.interfaces.some((i) => i.name === capOpts.iface)) {
      const pick = cap.interfaces.find((i) => !i.loopback) ?? cap.interfaces[0];
      setOpts({ iface: pick.name }, "ifaces");
    }
  } catch (e) {
    cap.ifaceError = errorText(e);
  } finally {
    cap.ifaceLoading = false;
    capBus.emit("ifaces");
    runCheck();
  }
}

export function ifaceLabel(i: CaptureInterface): string {
  let s = i.name;
  if (i.description && i.description !== i.name) s += ` — ${i.description}`;
  if (i.addresses.length) s += ` (${i.addresses.join(", ")})`;
  return s;
}

export function ringError(): string | null {
  if (!capOpts.ring) return null;
  const files = posInt(capOpts.ringFiles);
  if (!files || files < 2) return "The ring buffer needs at least 2 files";
  if (!posInt(capOpts.ringSize) && !posInt(capOpts.ringDur)) return "The ring buffer needs a file size or a duration per file";
  return null;
}

export function buildRequest(iface: string): CaptureRequest {
  const autostop: CaptureRequest["autostop"] = {};
  const d = posInt(capOpts.stopDur);
  const sz = posInt(capOpts.stopSize);
  const pk = posInt(capOpts.stopPkts);
  if (d) autostop.durationSec = d;
  // With a ring buffer dumpcap reads a size limit as the file switch size, not a stop condition.
  if (sz && !capOpts.ring) autostop.filesizeKB = sz;
  if (pk) autostop.packets = pk;
  let ring: CaptureRequest["ring"] = null;
  if (capOpts.ring) {
    ring = { files: posInt(capOpts.ringFiles) ?? 2 };
    const rs = posInt(capOpts.ringSize);
    const rd = posInt(capOpts.ringDur);
    if (rs) ring.filesizeKB = rs;
    if (rd) ring.durationSec = rd;
  }
  return { iface, filter: capOpts.filter.trim(), autostop, ring };
}

export function canStart(s: ViewState | null = app.state): boolean {
  const st = s?.capture.status ?? "idle";
  return (st === "idle" || st === "error") && !!capOpts.iface && cap.filterState === "ok" && !ringError();
}

export function setBarOpen(open: boolean): void {
  if (cap.barOpen === open) return;
  cap.barOpen = open;
  save("capturebar", open);
  capBus.emit("bar", open);
}

/**
 * Starts a capture on `iface` (default: the bar's interface). Only called from
 * click handlers of Start buttons.
 */
export async function startCaptureClicked(iface?: string): Promise<void> {
  if (captureActive()) return;
  const target = iface ?? capOpts.iface;
  if (!target) {
    setBarOpen(true);
    toast("info", "Choose an interface to capture on");
    return;
  }
  const rErr = ringError();
  if (rErr) {
    setBarOpen(true);
    toast("error", rErr);
    return;
  }
  const f = capOpts.filter.trim();
  if (f) {
    try {
      const r = await get<FilterCheck>("api/capture/check", { iface: target, filter: f });
      if (!r.ok) {
        setBarOpen(true);
        toast("error", `Invalid capture filter for ${target}: ${r.error ?? "syntax error"}`);
        return;
      }
    } catch (e) {
      toastError(e, "Checking the capture filter failed");
      return;
    }
  }
  if (target !== capOpts.iface) setOpts({ iface: target }, "start");
  await act.startCapture(buildRequest(target));
}

export function captureStatusText(s: ViewState): { text: string; cls: string } {
  const c = s.capture;
  switch (c.status) {
    case "starting":
      return { text: `Starting capture on ${c.iface ?? "?"}…`, cls: "starting" };
    case "running": {
      const el = c.startedAt ? ` · ${fmtElapsed((Date.now() - c.startedAt) / 1000)}` : "";
      return { text: `Capturing on ${c.iface ?? "?"} · ${fmtInt(c.packets)} packets${el}`, cls: "running" };
    }
    case "stopping":
      return { text: "Stopping capture…", cls: "stopping" };
    case "error":
      return { text: `Capture failed: ${c.error ?? "unknown error"}`, cls: "error" };
    default:
      return { text: c.files.length ? `Idle · last capture wrote ${c.files.length} file${c.files.length === 1 ? "" : "s"}` : "Idle", cls: "idle" };
  }
}

/** Applies validation colors to a capture filter input. */
export function paintFilterInput(el: HTMLInputElement): void {
  el.classList.toggle("valid", cap.filterState === "ok" && !!capOpts.filter.trim());
  el.classList.toggle("invalid", cap.filterState === "error");
  el.title = cap.filterState === "error" ? cap.filterError : "";
}

// ------------------------------------------------------------------ the bar

function numInput(key: keyof CaptureOpts, placeholder: string, title: string): HTMLInputElement {
  const el = h("input", { class: "cb-num", type: "text", inputMode: "numeric", placeholder, title, value: String(capOpts[key]) });
  el.addEventListener("input", () => {
    el.classList.toggle("invalid", !!el.value.trim() && !posInt(el.value));
    setOpts({ [key]: el.value } as Partial<CaptureOpts>, `bar:${key}`);
  });
  capBus.on("opts", (src) => {
    if (src !== `bar:${key}` && document.activeElement !== el) el.value = String(capOpts[key]);
  });
  return el;
}

export function createCaptureBar(): HTMLElement {
  const ifaceSel = h("select", { class: "cb-iface", title: "Capture interface", attrs: { "aria-label": "Capture interface" } });
  const refreshBtn = h("button", { class: "tb-mini", title: "Refresh interfaces", attrs: { "aria-label": "Refresh interfaces" }, onclick: () => void loadInterfaces() }, icon("refresh"));
  const filterIn = h("input", {
    class: "cb-filter",
    type: "text",
    spellcheck: false,
    autocomplete: "off",
    placeholder: "Enter a capture filter … (e.g. tcp port 443)",
    value: capOpts.filter,
    attrs: { "aria-label": "Capture filter" },
  });
  const startBtn = h("button", { class: "btn cb-start", title: "Start capturing with these options" }, icon("fin"), h("span", null, "Start"));
  const stopBtn = h("button", { class: "btn cb-stop", title: "Stop the running capture" }, icon("stop"), h("span", null, "Stop"));
  const errLine = h("div", { class: "cb-err", hidden: true });
  const ringChk = h("input", { type: "checkbox", checked: capOpts.ring });
  const ringFiles = numInput("ringFiles", "2", "Number of files in the ring");
  const ringSize = numInput("ringSize", "KB", "Switch to the next file after this many kilobytes");
  const ringDur = numInput("ringDur", "s", "Switch to the next file after this many seconds");
  const stopSize = numInput("stopSize", "KB", "Stop after this many kilobytes");
  const statusDot = h("span", { class: "cb-dot" });
  const statusText = h("span", { class: "cb-status-text" });
  const fileText = h("span", { class: "cb-file" });

  filterIn.addEventListener("input", () => setOpts({ filter: filterIn.value }, "bar:filter"));
  ifaceSel.addEventListener("change", () => setOpts({ iface: ifaceSel.value }, "bar:iface"));
  ringChk.addEventListener("change", () => setOpts({ ring: ringChk.checked }, "bar:ring"));
  startBtn.addEventListener("click", () => void startCaptureClicked());
  stopBtn.addEventListener("click", () => void act.stopCapture());

  const row1 = h(
    "div",
    { class: "cb-row" },
    h("label", { class: "cb-lbl" }, "Interface"),
    ifaceSel,
    refreshBtn,
    h("label", { class: "cb-lbl" }, "Capture filter"),
    filterIn,
    startBtn,
    stopBtn,
  );
  const row2 = h(
    "div",
    { class: "cb-row cb-row2" },
    h("span", { class: "cb-group" }, h("span", { class: "cb-lbl" }, "Stop after"), numInput("stopDur", "s", "Stop after this many seconds"), h("span", { class: "cb-unit" }, "s"), stopSize, h("span", { class: "cb-unit" }, "KB"), numInput("stopPkts", "pkts", "Stop after this many packets"), h("span", { class: "cb-unit" }, "packets")),
    h("span", { class: "cb-group" }, h("label", { class: "cb-check" }, ringChk, "Ring buffer"), ringFiles, h("span", { class: "cb-unit" }, "files of"), ringSize, h("span", { class: "cb-unit" }, "KB or"), ringDur, h("span", { class: "cb-unit" }, "s")),
  );
  const row3 = h("div", { class: "cb-row cb-status" }, statusDot, statusText, fileText);
  const bar = h("div", { class: "capturebar", hidden: !cap.barOpen }, row1, errLine, row2, row3);

  const renderIfaces = (): void => {
    const opts: HTMLOptionElement[] = [];
    if (cap.ifaceLoading && !cap.interfaces) opts.push(h("option", { value: "" }, "Loading interfaces…"));
    else if (cap.ifaceError) opts.push(h("option", { value: "" }, `No interfaces: ${cap.ifaceError}`));
    else if (cap.interfaces && !cap.interfaces.length) opts.push(h("option", { value: "" }, "No capture interfaces found"));
    for (const i of cap.interfaces ?? []) opts.push(h("option", { value: i.name, title: ifaceLabel(i) }, ifaceLabel(i)));
    ifaceSel.replaceChildren(...opts);
    ifaceSel.value = capOpts.iface;
    ifaceSel.title = cap.ifaceError ?? "Capture interface";
  };

  let fileKey = "";
  // Runs every second: touch only what changed so selection and tooltips survive.
  const renderStatus = (): void => {
    const s = app.state;
    if (!s) return;
    const st = captureStatusText(s);
    const dotCls = `cb-dot ${st.cls}`;
    if (statusDot.className !== dotCls) statusDot.className = dotCls;
    if (statusText.textContent !== st.text) statusText.textContent = st.text;
    const c = s.capture;
    const file = c.currentFile ?? c.files[c.files.length - 1] ?? null;
    const key = `${file ?? ""}|${c.dir}|${c.files.length}`;
    if (key === fileKey) return;
    fileKey = key;
    fileText.replaceChildren();
    if (file) fileText.append("File: ", h("span", { class: "cb-path", title: file }, baseName(file)));
    if (c.dir) fileText.append(file ? " in " : "Directory: ", h("span", { class: "cb-path", title: c.dir }, c.dir));
    if (c.files.length > 1) fileText.append(` · ${c.files.length} files`);
  };

  const renderState = (): void => {
    const s = app.state;
    const active = captureActive(s);
    startBtn.disabled = !canStart(s);
    const rErr = ringError();
    startBtn.title = rErr ?? (cap.filterState === "error" ? "Fix the capture filter first" : active ? "A capture is running" : "Start capturing with these options");
    stopBtn.disabled = !(s && (s.capture.status === "running" || s.capture.status === "starting"));
    ringFiles.disabled = ringSize.disabled = ringDur.disabled = !capOpts.ring;
    stopSize.disabled = capOpts.ring;
    stopSize.title = capOpts.ring ? "Not available with a ring buffer (use duration or packets)" : "Stop after this many kilobytes";
    paintFilterInput(filterIn);
    const errs = [cap.filterState === "error" ? cap.filterError : "", rErr ?? ""].filter(Boolean).join(" · ");
    if (errLine.textContent !== errs) errLine.textContent = errs;
    errLine.hidden = !errs;
    renderStatus();
  };

  capBus.on("ifaces", renderIfaces);
  capBus.on("check", renderState);
  capBus.on("opts", (src) => {
    if (src !== "bar:filter" && document.activeElement !== filterIn) filterIn.value = capOpts.filter;
    if (src !== "bar:iface") ifaceSel.value = capOpts.iface;
    ringChk.checked = capOpts.ring;
    renderState();
  });
  capBus.on("bar", (open) => {
    bar.hidden = !open;
    if (open && !cap.interfaces && !cap.ifaceLoading) void loadInterfaces();
  });
  bus.on("state", renderState);
  bus.on("tick", renderStatus);

  hooks.startCapture = (iface) => void startCaptureClicked(iface);
  renderIfaces();
  renderState();
  runCheck();
  if (cap.barOpen) void loadInterfaces();
  return bar;
}
