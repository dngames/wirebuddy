/**
 * Panel windows: an extension's page in a sandboxed frame on a one-time origin
 * of its own. The page watches each frame: one that stops answering is
 * stopped, one that navigates or floods the page is closed, and the agent
 * hears about it through the server. A panel's wb.select and wb.setFilter go
 * through here, only right after the user clicked or typed in it.
 */

import type { ExtensionList, PanelState, ViewState } from "../shared/api.ts";
import { apart, verdict } from "../shared/isolation.ts";
import type { Round } from "../shared/isolation.ts";
import { errorText, get, HttpError, post } from "./api.ts";
import { agentName, app, bus } from "./app.ts";
import { Dialog } from "./dialog.ts";
import type { MenuItem } from "./menu.ts";
import { dockSlot, onPanesLaidOut, setDock } from "./panes.ts";
import { toastError } from "./toast.ts";
import { h, load, save, setText } from "./util.ts";

const PING_MS = 2000;
/** Missed pings before a panel counts as not responding, and seconds until it is stopped. */
const MISSED_PINGS = 3;
const STOP_AFTER_MS = 20_000;
const MAX_MESSAGES_PER_SECOND = 200;

type Health = "not-responding" | "responding" | "stopped" | "navigated" | "isolated" | "not-isolated" | "flooding";

interface Win {
  name: string;
  label: string;
  dialog: Dialog;
  frame: HTMLIFrameElement | null;
  origin: string;
  loads: number;
  lastPong: number;
  seq: number;
  ping: number;
  messages: number;
  second: number;
  /** The probe round waiting for its answer. */
  probing: ((answer: { from: number; to: number } | null) => void) | null;
  /** Counts probe sequences: a newer one ends the older. */
  probeRun: number;
  probeRound: number;
  footer: HTMLElement;
  maximized: boolean;
  title: string;
  /** Whether the panel is meant to sit in the dock (the user's choice, kept per panel), not whether it does right now. */
  docked: boolean;
  /** Where it is now: in the dock's place, or floating. */
  shown: "float" | "dock";
  /** The floating window's place and size while the panel is docked. */
  floatAt: { left: string; top: string; width: string; height: string } | null;
  dockBtn: HTMLButtonElement | null;
  /** When the pointer entered the frame, or 0 while it is outside. */
  pointerIn: number;
}

/** The last click or key press in this page itself (never one in a panel: those stay in its frame). */
let pageInput = 0;
/** How long a click or key press gives transient activation (Chrome: 5 s). */
const ACTIVATION_MS = 5000;

const wins = new Map<string, Win>();
/** The panels meant for the dock, the one on show among them last. */
const dockOrder: Win[] = [];
let dockActive: Win | null = null;
/** Tabs for the docked panels, shown from the second one on, and the room below them that the shown panel's window fills. */
const dockTabs = h("div", { class: "pn-tabs", role: "tablist" });
const dockArea = h("div", { class: "pn-dock-area" });
dockTabs.hidden = true;
let tabsKey = "";
/** Labels of panels closed here that the server may still list: a state sent before it heard doesn't open them again. */
const closing = new Set<string>();
/** Extensions with a panel, for the menus. */
let available: { name: string; title: string }[] = [];

export function initPanels(): void {
  // Only the list of panels matters to sync, and it keeps its identity while it doesn't change
  bus.on("state", (s, prev) => {
    if (!prev || s.panels !== prev.panels) sync(s);
  });
  window.addEventListener("message", onMessage);
  dockSlot().append(dockTabs, dockArea);
  // Docked windows sit over the dock's place, which the page lays out and moves around
  new ResizeObserver(placeDock).observe(dockArea);
  onPanesLaidOut(placeDock);
  window.addEventListener("resize", placeDock);
  for (const type of ["pointerdown", "keydown"]) {
    window.addEventListener(
      type,
      (e) => {
        if (e.isTrusted) pageInput = performance.now();
      },
      true,
    );
  }
  // Frames must not catch the pointer while a window moves or resizes
  document.addEventListener("pointerup", () => document.body.classList.remove("dlg-moving"), true);
  let extKey = "";
  bus.on("state", (s) => {
    const key = `${s.instance}|${s.extensions.revision}|${s.extensions.active}|${s.extensions.failing}`;
    if (key !== extKey) void refreshAvailable();
    extKey = key;
  });
}

async function refreshAvailable(): Promise<void> {
  try {
    const list = await get<ExtensionList>("api/extensions");
    available = list.extensions.filter((e) => e.panel && e.enabled && e.status !== "invalid" && e.status !== "untrusted").map((e) => ({ name: e.name, title: e.panel!.title }));
  } catch {
    available = [];
  }
}

/** View › Panels: every extension with a panel, checked while open. */
export function panelItems(): MenuItem[] {
  const open = new Set(app.state?.panels.map((p) => p.name) ?? []);
  const items: MenuItem[] = available.map((p) => ({
    label: p.title,
    checked: open.has(p.name),
    action: () => void (open.has(p.name) ? closePanel(p.name) : openPanel(p.name)),
  }));
  if (!items.length) items.push({ label: "No extension has a panel", disabled: true, action: () => {} });
  items.push({ label: "Close All Panels", disabled: !open.size, action: () => void Promise.all([...open].map(closePanel)) });
  return items;
}

export async function openPanel(name: string): Promise<void> {
  try {
    await post("api/panels/open", { name });
  } catch (e) {
    toastError(e, "Opening the panel failed");
  }
}

/** Hides a panel's offer in the status bar for this capture. */
export async function dismissOffer(name: string): Promise<void> {
  try {
    await post("api/panels/offers/dismiss", { name });
  } catch (e) {
    toastError(e);
  }
}

export async function closePanel(name: string): Promise<void> {
  try {
    await post("api/panels/close", { name });
  } catch {
    // gone already
  }
}

function health(w: Win, state: Health): void {
  void post("api/panels/health", { name: w.name, label: w.label, state }).catch(() => {});
}

function sync(s: ViewState): void {
  const live = new Map(s.panels.map((p) => [p.name, p]));
  for (const label of closing) if (!s.panels.some((p) => p.label === label)) closing.delete(label);
  for (const [name, w] of wins) {
    if (!live.has(name)) {
      wins.delete(name);
      w.dialog.close();
    }
  }
  for (const p of s.panels) {
    const w = wins.get(p.name);
    if (!w) {
      if (!closing.has(p.label)) open(p);
    } else if (w.label !== p.label) restart(w, p);
    else render(wins.get(p.name)!, p);
  }
}

function open(p: PanelState): void {
  const geo = load<{ w: number; h: number } | null>(`panel:${p.name}`, null);
  // 0 or none: the panel's own size
  const dialog = new Dialog(p.title, { width: geo?.w || p.size[0], height: geo?.h || p.size[1], cls: "dlg-panel", modal: false });
  const footer = h("span", { class: "pn-status" });
  dialog.footerLeft.append(footer);
  // A panel opens docked: what the agent shows must not cover what the user looks at
  const docked = load<boolean>(`panel-dock:${p.name}`, true) !== false;
  const w: Win = { name: p.name, label: p.label, dialog, frame: null, origin: "", loads: 0, lastPong: 0, seq: 0, ping: 0, messages: 0, second: 0, probing: null, probeRun: 0, probeRound: 0, footer, maximized: false, title: p.title, docked, shown: "float", floatAt: null, dockBtn: null, pointerIn: 0 };
  w.dockBtn = dialog.titleButton("Float", () => setDocked(w, !w.docked), "");
  dialog.button("Reload", () => void post("api/panels/reload", { name: p.name }).catch((e) => toastError(e)), { title: "Read the panel's files again and restart it" });
  const maxBtn = dialog.button("Maximize", () => {
    w.maximized = !w.maximized;
    dialog.win.classList.toggle("pn-max", w.maximized);
    maxBtn.textContent = w.maximized ? "Restore" : "Maximize";
    // Docked, it goes back to its place; floating, the window may have shrunk while it was maximized
    placeDock();
    if (!w.maximized && w.shown === "float") dialog.keepInView();
  });
  dialog.button("Close", () => dialog.close(), { primary: true });
  dialog.onClose = () => {
    stopWatch(w);
    if (!w.maximized && w.shown === "float" && dialog.closedSize) save(`panel:${p.name}`, dialog.closedSize);
    else if (w.shown === "dock" && w.floatAt) {
      // The size the floating window had
      const size = { w: Math.round(parseFloat(w.floatAt.width)), h: Math.round(parseFloat(w.floatAt.height)) };
      if (size.w > 0 && size.h > 0) save(`panel:${p.name}`, size);
    }
    leaveDock(w);
    // Closed here (Close, Esc): the server forgets it too
    if (wins.get(p.name) === w) {
      wins.delete(p.name);
      const label = w.label;
      closing.add(label);
      // Not closed there after all: the next state shows it again
      void post("api/panels/close", { name: p.name }).catch(() => closing.delete(label));
    }
  };
  // A resize starts on the window's own edge
  dialog.win.addEventListener("pointerdown", (e) => {
    if (e.target === dialog.win) document.body.classList.add("dlg-moving");
  });
  wins.set(p.name, w);
  restart(w, p);
  // Docked, it takes no focus from the packet list the user works in
  dialog.show(docked ? false : null);
  setDocked(w, docked, false);
}

/** Docks or floats a panel and remembers the choice. The window and its frame stay where they are in the page: only their place and size change. */
function setDocked(w: Win, on: boolean, remember = true): void {
  w.docked = on;
  if (remember) save(`panel-dock:${w.name}`, on);
  const i = dockOrder.indexOf(w);
  if (on && i < 0) dockOrder.push(w);
  if (!on && i >= 0) dockOrder.splice(i, 1);
  if (on) dockActive = w;
  else if (dockActive === w) dockActive = dockOrder[dockOrder.length - 1] ?? null;
  placeDock();
}

/** A panel that closed takes its place in the dock with it. */
function leaveDock(w: Win): void {
  const i = dockOrder.indexOf(w);
  if (i >= 0) dockOrder.splice(i, 1);
  if (dockActive === w) dockActive = dockOrder[dockOrder.length - 1] ?? null;
  placeDock();
}

/** Puts every window where it belongs: a docked panel's over the dock's place, the others where the user left them. */
function placeDock(): void {
  const docked = dockOrder.filter((w) => wins.get(w.name) === w);
  setDock(docked.length > 0);
  const tabbed = docked.length > 1;
  dockTabs.hidden = !tabbed;
  // Rebuilt only when it changed: a click must find the button it went down on
  const key = tabbed ? docked.map((w) => `${w.title}${w === dockActive ? "*" : ""}`).join("\n") : "";
  if (tabbed && key !== tabsKey) {
    tabsKey = key;
    dockTabs.replaceChildren(
      ...docked.map((w) => {
        const on = w === dockActive;
        return h("button", { class: `pn-tab${on ? " on" : ""}`, role: "tab", attrs: { "aria-selected": String(on) }, title: w.title, onclick: () => {
          dockActive = w;
          placeDock();
        } }, w.title);
      }),
    );
  }
  const r = dockArea.getBoundingClientRect();
  // No room: the page shows no capture, so the panes are hidden. The panels float until it does.
  const room = docked.length > 0 && r.width > 0 && r.height > 0;
  for (const w of wins.values()) {
    const dock = room && docked.includes(w);
    const { win, overlay } = w.dialog;
    if (dock && w.shown === "float") {
      w.floatAt = { left: win.style.left, top: win.style.top, width: win.style.width, height: win.style.height };
      w.shown = "dock";
      w.dialog.movable = false;
      win.classList.add("pn-docked");
    } else if (!dock && w.shown === "dock") {
      w.shown = "float";
      w.dialog.movable = true;
      win.classList.remove("pn-docked");
      if (w.floatAt) Object.assign(win.style, w.floatAt);
      w.floatAt = null;
      w.dialog.keepInView();
    }
    // Under the dialogs that open over the page, until it is maximized
    overlay.classList.toggle("pn-docked", w.shown === "dock" && !w.maximized);
    overlay.classList.toggle("pn-tabbed-out", w.shown === "dock" && w !== dockActive);
    if (w.shown === "dock") Object.assign(win.style, { left: `${r.left}px`, top: `${r.top}px`, width: `${r.width}px`, height: `${r.height}px` });
    if (w.dockBtn) {
      w.dockBtn.textContent = w.docked ? "Float" : "Dock";
      w.dockBtn.title = w.docked ? "Take the panel out of the layout: it floats over the page" : "Put the panel in the layout, under the packet list";
    }
  }
}

/** A new frame for a new label: reopened, reloaded or restarted. */
function restart(w: Win, p: PanelState): void {
  stopWatch(w);
  w.frame?.remove();
  w.frame = null;
  w.label = p.label;
  // Stopped stays stopped, also in a page loaded later, until Reload
  if (p.state === "stopped" || p.state === "error") {
    w.dialog.body.replaceChildren(h("div", { class: "pn-dead" }, p.statusText || "The panel was stopped.", h("br"), "Reload starts it again."));
    render(w, p);
    return;
  }
  w.origin = new URL(p.src).origin;
  w.loads = 0;
  w.lastPong = Date.now();
  const frame = h("iframe", { class: "panel-frame", title: `${p.title} (panel of the extension ${p.name})` }) as HTMLIFrameElement;
  frame.setAttribute("sandbox", "allow-scripts allow-same-origin");
  frame.setAttribute("credentialless", "");
  frame.setAttribute("referrerpolicy", "no-referrer");
  frame.setAttribute("allow", "clipboard-write");
  frame.addEventListener("load", () => {
    // The first load is the panel; any other means it navigated
    if (++w.loads > 1) kill(w, "navigated");
  });
  // The page sees the pointer enter and leave a frame, which the panel can't fake
  w.pointerIn = 0;
  frame.addEventListener("pointerenter", () => (w.pointerIn = performance.now()));
  frame.addEventListener("pointerleave", () => (w.pointerIn = 0));
  frame.src = p.src;
  w.frame = frame;
  w.dialog.body.replaceChildren(frame);
  w.ping = window.setInterval(() => watch(w), PING_MS);
  render(w, p);
}

function watch(w: Win): void {
  if (!w.frame) return;
  // A hidden page throttles timers: no verdicts then
  if (document.hidden) {
    w.lastPong = Date.now();
    return;
  }
  const silent = Date.now() - w.lastPong;
  if (silent >= STOP_AFTER_MS) return kill(w, "stopped");
  if (silent >= MISSED_PINGS * PING_MS && !w.dialog.win.classList.contains("pn-hung")) {
    w.dialog.win.classList.add("pn-hung");
    health(w, "not-responding");
  }
  w.frame.contentWindow?.postMessage({ wb: 1, t: "ping", seq: ++w.seq }, w.origin);
}

function stopWatch(w: Win): void {
  if (w.ping) window.clearInterval(w.ping);
  w.ping = 0;
  // Ends a probe sequence and its round
  w.probeRun++;
  w.probing?.(null);
}

/** Removes the frame, which ends its process, and tells the server why. */
function kill(w: Win, why: Health): void {
  stopWatch(w);
  w.frame?.remove();
  w.frame = null;
  w.dialog.body.replaceChildren(h("div", { class: "pn-dead" }, why === "stopped" ? "The panel stopped responding and was stopped." : why === "navigated" ? "The panel tried to navigate and was closed." : "The panel sent too many messages and was closed.", h("br"), "Reload starts it again."));
  health(w, why);
}

function onMessage(e: MessageEvent): void {
  const w = [...wins.values()].find((x) => x.frame && e.source === x.frame.contentWindow && e.origin === x.origin);
  if (!w) return;
  const sec = Math.floor(Date.now() / 1000);
  if (sec !== w.second) [w.second, w.messages] = [sec, 0];
  if (++w.messages > MAX_MESSAGES_PER_SECOND) return kill(w, "flooding");
  const m = e.data as { wb?: number; t?: string; key?: string; id?: unknown; m?: unknown; a?: unknown } | null;
  if (m?.wb !== 1) return;
  if (m.t === "hello") {
    w.lastPong = Date.now();
    w.probeRun++;
    w.probing?.(null);
    void probe(w, w.probeRun);
  } else if (m.t === "pong") {
    w.lastPong = Date.now();
    if (w.dialog.win.classList.contains("pn-hung")) {
      w.dialog.win.classList.remove("pn-hung");
      health(w, "responding");
    }
  } else if (m.t === "probed") {
    const p = m as { n?: unknown; from?: unknown; to?: unknown };
    if (p.n === w.probeRound && typeof p.from === "number" && typeof p.to === "number") w.probing?.({ from: p.from, to: p.to });
  }
  else if (m.t === "key" && m.key === "Escape") w.dialog.close();
  else if (m.t === "act") void act(w, m.id, m.m, m.a);
}

/**
 * A panel's wb.select or wb.setFilter. A click or key press in the panel
 * focuses its frame and gives this page transient activation (Chrome passes
 * it up from the frame). A panel can take the focus itself, though, right
 * after the user clicked elsewhere: so an activation this page may have got
 * from its own click or key press doesn't count, unless the pointer entered
 * the panel since; nor does one while the pointer is over another panel.
 * The server applies it, refuses setFilter without "control", and tells the
 * agent about refusals.
 */
async function act(w: Win, id: unknown, m: unknown, a: unknown): Promise<void> {
  const frame = w.frame;
  const reply = (r: { ok: boolean; code?: string; error?: string }): void => frame?.contentWindow?.postMessage({ wb: 1, t: "actres", id, ...r }, w.origin);
  if (m !== "select" && m !== "setFilter") return reply({ ok: false, code: "bad-args", error: "a panel can only select a frame or set the display filter" });
  const now = performance.now();
  const ownActivation = pageInput > 0 && now - pageInput < ACTIVATION_MS && !(w.pointerIn > pageInput);
  const overOther = [...wins.values()].some((x) => x !== w && x.pointerIn > 0);
  const clicked = !!frame && document.activeElement === frame && navigator.userActivation?.isActive === true && !ownActivation && !overOther;
  try {
    await post("api/panels/act", { name: w.name, label: w.label, m, a, clicked });
    reply({ ok: true });
  } catch (e) {
    reply({ ok: false, code: e instanceof HttpError ? (e.code ?? "internal") : "internal", error: errorText(e) });
  }
}

/** Pauses before the next round after an empty one, and after an unanswered one (then it gives up). */
const EMPTY_PAUSES_MS = [250, 1000];
const UNANSWERED_PAUSES_MS = [2000, 5000, 15000];
const ROUND_TIMEOUT_MS = 1500;

const sleep = (ms: number): Promise<void> => new Promise((done) => window.setTimeout(done, ms));
const visible = (): Promise<void> =>
  new Promise((done) => {
    const on = (): void => {
      if (document.hidden) return;
      document.removeEventListener("visibilitychange", on);
      done();
    };
    document.addEventListener("visibilitychange", on);
  });

/**
 * One round: the panel busy-loops 60 ms and says when; meanwhile this page records the time of
 * a task every 4 ms. A timer, not a message loop: it costs this page nothing between rounds and a
 * busy window of 60 ms holds a dozen ticks, while a message loop would itself load a loaded CPU.
 */
async function round(w: Win): Promise<Round> {
  if (document.hidden) return "unanswered";
  const ticks: number[] = [];
  const ticker = window.setInterval(() => ticks.push(Date.now()), 4);
  const n = ++w.probeRound;
  const sent = Date.now();
  let finish: ((answer: { from: number; to: number } | null) => void) | null = null;
  const answer = await new Promise<{ from: number; to: number } | null>((done) => {
    finish = w.probing = done;
    w.frame?.contentWindow?.postMessage({ wb: 1, t: "probe", ms: 60, n }, w.origin);
    window.setTimeout(() => done(null), ROUND_TIMEOUT_MS);
  });
  const got = Date.now();
  if (w.probing === finish) w.probing = null;
  window.clearInterval(ticker);
  if (!answer || document.hidden) return "unanswered";
  // The window can't reach outside the time this page itself waited
  return apart(ticks, Math.max(answer.from, sent), Math.min(answer.to, got)) ? "apart" : "empty";
}

/**
 * Whether the panel runs in a process of its own: rounds until one proves it, or enough empty
 * ones, spaced out, say it doesn't. A round without an answer, or in a hidden page, says nothing
 * and is tried again later. `run` identifies this sequence; a newer one or a closed window ends it.
 */
async function probe(w: Win, run: number): Promise<void> {
  const live = (): boolean => w.probeRun === run && !!w.frame;
  const rounds: Round[] = [];
  let unanswered = 0;
  while (live()) {
    const v = verdict(rounds);
    if (v !== "again") return health(w, v);
    if (document.hidden) {
      await visible();
      continue;
    }
    const r = await round(w);
    if (!live()) return;
    rounds.push(r);
    if (r === "unanswered") {
      if (document.hidden) continue;
      if (unanswered >= UNANSWERED_PAUSES_MS.length) return;
      await sleep(UNANSWERED_PAUSES_MS[unanswered++]);
    } else if (r === "empty" && verdict(rounds) === "again") await sleep(EMPTY_PAUSES_MS[Math.min(rounds.filter((x) => x === "empty").length, EMPTY_PAUSES_MS.length) - 1]);
  }
}

function render(w: Win, p: PanelState): void {
  w.dialog.setTitle(`${p.title} — ${p.by === "agent" ? `by ${agentName()}` : "panel"}`);
  // A stopped panel's status text says why
  const state = p.statusText && (p.state === "stopped" || p.state === "error") ? "" : { starting: "Starting…", ready: "", "not-responding": "Not responding", stopped: "Stopped", error: "Stopped" }[p.state];
  const parts = [state, p.statusText, p.errors ? `${p.errors} error${p.errors === 1 ? "" : "s"}${app.state?.agent.attached ? ` sent to ${agentName()}` : ""}` : "", p.isolated === false ? "not isolated: may slow WireBuddy down" : ""].filter(Boolean);
  setText(w.footer, parts.join(" · "));
  w.footer.className = `pn-status ${p.state}${p.errors ? " has-errors" : ""}`;
  w.footer.title = p.control ? "This panel may set the display filter after you click in it" : "";
}
