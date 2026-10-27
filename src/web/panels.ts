/**
 * Panel windows: an extension's page in a sandboxed frame on a one-time origin
 * of its own. The page watches each frame: one that stops answering is
 * stopped, one that navigates or floods the page is closed, and the agent
 * hears about it through the server. A panel's wb.select and wb.setFilter go
 * through here, only right after the user clicked or typed in it.
 */

import type { ExtensionList, PanelState, ViewState } from "../shared/api.ts";
import { errorText, get, HttpError, post } from "./api.ts";
import { agentName, app, bus } from "./app.ts";
import { Dialog } from "./dialog.ts";
import type { MenuItem } from "./menu.ts";
import { toast } from "./toast.ts";
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
  probing: ((done: boolean) => void) | null;
  footer: HTMLElement;
  maximized: boolean;
  /** When the pointer entered the frame, or 0 while it is outside. */
  pointerIn: number;
}

/** The last click or key press in this page itself (never one in a panel: those stay in its frame). */
let pageInput = 0;
/** How long a click or key press gives transient activation (Chrome: 5 s). */
const ACTIVATION_MS = 5000;

const wins = new Map<string, Win>();
/** Extensions with a panel, for the menus. */
let available: { name: string; title: string }[] = [];

export function initPanels(): void {
  bus.on("state", sync);
  window.addEventListener("message", onMessage);
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
    toast("error", `Opening the panel failed: ${errorText(e)}`);
  }
}

/** Hides a panel's offer in the status bar for this capture. */
export async function dismissOffer(name: string): Promise<void> {
  try {
    await post("api/panels/offers/dismiss", { name });
  } catch (e) {
    toast("error", errorText(e));
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
  for (const [name, w] of wins) {
    if (!live.has(name)) {
      wins.delete(name);
      w.dialog.close();
    }
  }
  for (const p of s.panels) {
    const w = wins.get(p.name);
    if (!w) open(p);
    else if (w.label !== p.label) restart(w, p);
    else render(wins.get(p.name)!, p);
  }
}

function open(p: PanelState): void {
  const geo = load<{ w: number; h: number } | null>(`panel:${p.name}`, null);
  const dialog = new Dialog(p.title, { width: geo?.w ?? p.size[0], height: geo?.h ?? p.size[1], cls: "dlg-panel", modal: false });
  const footer = h("span", { class: "pn-status" });
  dialog.footerLeft.append(footer);
  const w: Win = { name: p.name, label: p.label, dialog, frame: null, origin: "", loads: 0, lastPong: 0, seq: 0, ping: 0, messages: 0, second: 0, probing: null, footer, maximized: false, pointerIn: 0 };
  dialog.button("Reload", () => void post("api/panels/reload", { name: p.name }).catch((e) => toast("error", errorText(e))), { title: "Read the panel's files again and restart it" });
  const maxBtn = dialog.button("Maximize", () => {
    w.maximized = !w.maximized;
    dialog.win.classList.toggle("pn-max", w.maximized);
    maxBtn.textContent = w.maximized ? "Restore" : "Maximize";
  });
  dialog.button("Close", () => dialog.close(), { primary: true });
  dialog.onClose = () => {
    stopWatch(w);
    const r = dialog.win.getBoundingClientRect();
    if (!w.maximized) save(`panel:${p.name}`, { w: Math.round(r.width), h: Math.round(r.height) });
    // Closed here (Close, Esc): the server forgets it too
    if (wins.get(p.name) === w) {
      wins.delete(p.name);
      void closePanel(p.name);
    }
  };
  // A resize starts on the window's own edge
  dialog.win.addEventListener("pointerdown", (e) => {
    if (e.target === dialog.win) document.body.classList.add("dlg-moving");
  });
  wins.set(p.name, w);
  restart(w, p);
  dialog.show(null);
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
  w.probing?.(false);
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
    void probe(w);
  } else if (m.t === "pong") {
    w.lastPong = Date.now();
    if (w.dialog.win.classList.contains("pn-hung")) {
      w.dialog.win.classList.remove("pn-hung");
      health(w, "responding");
    }
  } else if (m.t === "probed") w.probing?.(true);
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

/**
 * Whether the panel runs in a process of its own: it busies itself for 60 ms
 * while this page's timer ticks; in a shared process the ticks stall.
 */
async function probe(w: Win): Promise<void> {
  if (!w.frame) return;
  let worst = 0;
  let last = performance.now();
  const ticker = window.setInterval(() => {
    const now = performance.now();
    worst = Math.max(worst, now - last);
    last = now;
  }, 10);
  const answered = await new Promise<boolean>((done) => {
    w.probing = done;
    w.frame?.contentWindow?.postMessage({ wb: 1, t: "probe", ms: 60 }, w.origin);
    window.setTimeout(() => done(false), 500);
  });
  w.probing = null;
  window.clearInterval(ticker);
  if (answered && !document.hidden) health(w, worst >= 45 ? "not-isolated" : "isolated");
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
