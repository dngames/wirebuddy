/**
 * Capture options, shared by the Capture Options dialog and the welcome page,
 * and starting a capture. A capture is only ever started from a user click.
 */

import type { CaptureInterface, CaptureRequest, FilterCheck, ViewState } from "../shared/api.ts";
import { errorText, get } from "./api.ts";
import * as act from "./actions.ts";
import { app, bus, captureActive, hooks } from "./app.ts";
import { toast, toastError } from "./toast.ts";
import { debounce, Emitter, fmtElapsed, fmtInt, load, posInt, save } from "./util.ts";

export type SizeUnit = "kB" | "MB" | "GB";
export type TimeUnit = "s" | "min" | "h";

/** Like Wireshark's Capture Options; numbers as typed, "" for off. */
export interface CaptureOpts {
  iface: string;
  filter: string;
  promisc: boolean;
  /** "Create a new file automatically…" after any of these. */
  newFile: boolean;
  newPkts: string;
  newSize: string;
  newSizeUnit: SizeUnit;
  newTime: string;
  newTimeUnit: TimeUnit;
  newEvery: string;
  newEveryUnit: TimeUnit;
  /** "Use a ring buffer with N files". */
  ring: boolean;
  ringFiles: string;
  /** "Stop capture automatically after…". */
  stopPkts: string;
  stopFiles: string;
  stopSize: string;
  stopSizeUnit: SizeUnit;
  stopTime: string;
  stopTimeUnit: TimeUnit;
}

const DEFAULTS: CaptureOpts = {
  iface: "",
  filter: "",
  promisc: true,
  newFile: false,
  newPkts: "",
  newSize: "",
  newSizeUnit: "MB",
  newTime: "",
  newTimeUnit: "s",
  newEvery: "",
  newEveryUnit: "h",
  ring: false,
  ringFiles: "2",
  stopPkts: "",
  stopFiles: "",
  stopSize: "",
  stopSizeUnit: "MB",
  stopTime: "",
  stopTimeUnit: "s",
};

const KB: Record<SizeUnit, number> = { kB: 1, MB: 1000, GB: 1000 * 1000 };
const SECONDS: Record<TimeUnit, number> = { s: 1, min: 60, h: 3600 };

/** Options saved by the capture bar of earlier versions. */
function migrate(o: Record<string, unknown>): Partial<CaptureOpts> {
  if (!("ringSize" in o || "ringDur" in o || "stopDur" in o)) return o as Partial<CaptureOpts>;
  const str = (k: string): string => (typeof o[k] === "string" ? (o[k] as string) : "");
  return {
    iface: str("iface"),
    filter: str("filter"),
    newFile: o.ring === true,
    ring: o.ring === true,
    ringFiles: str("ringFiles") || "2",
    newSize: str("ringSize"),
    newSizeUnit: "kB",
    newTime: str("ringDur"),
    stopPkts: str("stopPkts"),
    stopSize: str("stopSize"),
    stopSizeUnit: "kB",
    stopTime: str("stopDur"),
  };
}

export const capOpts: CaptureOpts = { ...DEFAULTS, ...migrate(load<Record<string, unknown>>("capture", {})) };

export const cap = {
  interfaces: null as CaptureInterface[] | null,
  ifaceError: null as string | null,
  ifaceLoading: false,
  filterState: "none" as "none" | "checking" | "ok" | "error",
  filterError: "",
};

type CapEvents = {
  /** Options changed; `source` tells which control changed them. */
  opts: [source: string];
  ifaces: [];
  check: [];
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

/** What keeps the options from starting a capture, with the dialog tab to fix it on. */
export function optionsError(): { tab: "input" | "output" | "options"; text: string } | null {
  if (cap.filterState === "error") return { tab: "input", text: cap.filterError || "Invalid capture filter" };
  const bad = (v: string): boolean => !!v.trim() && !posInt(v);
  if (capOpts.newFile) {
    if ([capOpts.newPkts, capOpts.newSize, capOpts.newTime, capOpts.newEvery].some(bad)) return { tab: "output", text: "New files need whole numbers" };
    if (![capOpts.newPkts, capOpts.newSize, capOpts.newTime, capOpts.newEvery].some((v) => posInt(v))) return { tab: "output", text: "Choose when to create a new file" };
    if (capOpts.ring && (posInt(capOpts.ringFiles) ?? 0) < 2) return { tab: "output", text: "The ring buffer needs at least 2 files" };
  }
  if ([capOpts.stopPkts, capOpts.stopFiles, capOpts.stopSize, capOpts.stopTime].some(bad)) return { tab: "options", text: "Stop conditions need whole numbers" };
  if (posInt(capOpts.stopFiles) && !capOpts.newFile) return { tab: "options", text: "Stopping after a number of files needs new files to be created automatically" };
  // dumpcap reads a size limit as the size of new files
  if (posInt(capOpts.stopSize) && capOpts.newFile) return { tab: "options", text: "Stopping after a size can't be combined with new files" };
  return null;
}

export function buildRequest(iface: string): CaptureRequest {
  const num = (v: string, scale = 1): number | undefined => {
    const n = posInt(v);
    return n ? n * scale : undefined;
  };
  const autostop: CaptureRequest["autostop"] = {
    packets: num(capOpts.stopPkts),
    files: capOpts.newFile ? num(capOpts.stopFiles) : undefined,
    filesizeKB: capOpts.newFile ? undefined : num(capOpts.stopSize, KB[capOpts.stopSizeUnit]),
    durationSec: num(capOpts.stopTime, SECONDS[capOpts.stopTimeUnit]),
  };
  const ring: CaptureRequest["ring"] = capOpts.newFile
    ? {
        packets: num(capOpts.newPkts),
        filesizeKB: num(capOpts.newSize, KB[capOpts.newSizeUnit]),
        durationSec: num(capOpts.newTime, SECONDS[capOpts.newTimeUnit]),
        intervalSec: num(capOpts.newEvery, SECONDS[capOpts.newEveryUnit]),
        files: capOpts.ring ? num(capOpts.ringFiles) : undefined,
      }
    : null;
  return { iface, filter: capOpts.filter.trim(), promiscuous: capOpts.promisc, autostop, ring };
}

export function canStart(s: ViewState | null = app.state): boolean {
  const st = s?.capture.status ?? "idle";
  return (st === "idle" || st === "error") && !!capOpts.iface && cap.filterState === "ok" && !optionsError();
}

/**
 * Starts a capture on `iface` (default: the options' interface). Only called
 * from click handlers. What keeps it from starting opens the options dialog.
 */
export async function startCaptureClicked(iface?: string): Promise<boolean> {
  if (captureActive()) return false;
  const target = iface ?? capOpts.iface;
  if (!target) {
    hooks.captureOptions("input");
    return false;
  }
  const problem = optionsError();
  if (problem && problem.tab !== "input") {
    hooks.captureOptions(problem.tab);
    return false;
  }
  const f = capOpts.filter.trim();
  if (f) {
    try {
      const r = await get<FilterCheck>("api/capture/check", { iface: target, filter: f });
      if (!r.ok) {
        hooks.captureOptions("input");
        toast("error", `Invalid capture filter for ${target}: ${r.error ?? "syntax error"}`);
        return false;
      }
    } catch (e) {
      toastError(e, "Checking the capture filter failed");
      return false;
    }
  }
  if (target !== capOpts.iface) setOpts({ iface: target }, "start");
  return act.startCapture(buildRequest(target));
}

/** Capture > Restart: stops, waits until the capture is down, starts it again as it was. */
export async function restartCaptureClicked(): Promise<void> {
  const c = app.state?.capture;
  if (!c?.iface || !captureActive()) return;
  const req: CaptureRequest = { iface: c.iface, filter: c.filter, promiscuous: c.promiscuous, autostop: c.autostop, ring: c.ring };
  if (!(await act.stopCapture())) return;
  // The idle state may already be here
  const stopped = !captureActive() || await new Promise<boolean>((resolve) => {
    const done = (ok: boolean): void => {
      window.clearTimeout(timer);
      off();
      resolve(ok);
    };
    const timer = window.setTimeout(() => done(false), 15000);
    const off = bus.on("state", (s) => {
      if (!captureActive(s)) done(true);
    });
  });
  if (stopped) await act.startCapture(req);
  else toast("error", "The capture did not stop; not restarting it");
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

export function initCapture(): void {
  hooks.startCapture = (iface) => void startCaptureClicked(iface);
  runCheck();
}
