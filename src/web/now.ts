/** Now (live capture): the user flags a moment for the agent with a tap, or a span by holding the key or button. */

import type { NowResult } from "../shared/api.ts";
import { errorText, post } from "./api.ts";
import { agentName, app, bus } from "./app.ts";
import { toast } from "./toast.ts";

/** Held this long, a press flags a span. */
const HOLD_MS = 400;

/** The press under way: since when, and what holds it (a key's code, a pointer). */
let held: { since: number; by: string } | null = null;
let sending = 0;

/** While the view follows a running capture that stays in one file (new files drop edited comments). */
export function nowAvailable(): boolean {
  const s = app.state;
  return s?.capture.status === "running" && !s.capture.ring && !!s.file && s.file === s.capture.currentFile && !s.loading;
}

export function nowState(): "idle" | "held" | "sending" {
  return held ? "held" : sending ? "sending" : "idle";
}

export function pressNow(by: string): void {
  if (held || !nowAvailable()) return;
  held = { since: performance.now(), by };
  bus.emit("now");
}

/** Ends the press `by` holds (without `by`, any: the page lost the keys or the pointer) and sends it. */
export function releaseNow(by?: string): void {
  if (!held || (by !== undefined && by !== held.by)) return;
  const ms = performance.now() - held.since;
  held = null;
  void send(ms >= HOLD_MS ? Math.round(ms) : 0, Date.now());
}

/** From a menu or a keyboard click on the button. */
export function tapNow(): void {
  pressNow("tap");
  releaseNow("tap");
}

/** `at`: the release, as the server may get it later (the browser queues requests). */
async function send(heldMs: number, at: number): Promise<void> {
  sending++;
  bus.emit("now");
  const name = agentName();
  try {
    const r = await post<NowResult>("api/now", { heldMs, at });
    const span = r.held ? ` (${(heldMs / 1000).toFixed(1)} s)` : "";
    const reach = !r.agent ? "" : r.woken ? `, sent to ${name}` : `; ${name} gets it with its next step`;
    toast("info", `Now${span}: ${r.about}${reach}`);
  } catch (e) {
    // Not an error toast: with an agent attached those go to it instead
    toast("info", `Now didn't go through: ${errorText(e)}`);
  } finally {
    sending--;
    bus.emit("now");
  }
}
