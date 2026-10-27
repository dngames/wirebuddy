/** Interface traffic sparklines, like Wireshark's start page. Polled only while something shows them. */

import type { InterfaceActivity } from "../shared/api.ts";
import { get } from "./api.ts";
import { bus } from "./app.ts";
import { Emitter } from "./util.ts";

const SVG_NS = "http://www.w3.org/2000/svg";
const SAMPLES = 60;
const W = 72;
const H = 18;

let latest: InterfaceActivity | null = null;
let busy = false;
const watchers: Array<() => boolean> = [];

export const activityBus = new Emitter<{ update: [] }>();

/** Registers a view that shows sparklines while `visible()` is true. */
export function watchActivity(visible: () => boolean): void {
  watchers.push(visible);
}

/** Packets per second for `iface`, oldest first. */
export function activityOf(iface: string): number[] {
  return latest?.ifaces[iface] ?? [];
}

export async function pollActivity(): Promise<void> {
  if (busy || document.visibilityState !== "visible" || !watchers.some((w) => w())) return;
  busy = true;
  try {
    latest = await get<InterfaceActivity>("api/capture/activity");
    activityBus.emit("update");
  } catch {
    // Sparklines are decoration; a failed poll just leaves them as they are
  } finally {
    busy = false;
  }
}

bus.on("tick", () => void pollActivity());

export function activityTitle(values: number[]): string {
  if (latest?.error) return `Traffic statistics unavailable: ${latest.error}`;
  if (!values.length) return latest && Object.keys(latest.ifaces).length ? "No traffic statistics for this interface" : "Measuring traffic…";
  const avg = values.reduce((a, b) => a + b, 0) / values.length;
  return `${values[values.length - 1]} packets/s now · ${avg < 10 ? avg.toFixed(1) : Math.round(avg)} avg over ${values.length} s`;
}

/** A small line chart of the last minute, newest at the right, scaled to its own peak. */
export function sparkline(values: number[]): SVGSVGElement {
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("class", "spark");
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
  svg.setAttribute("width", String(W));
  svg.setAttribute("height", String(H));
  svg.setAttribute("aria-hidden", "true");
  const base = document.createElementNS(SVG_NS, "line");
  base.setAttribute("class", "spark-base");
  base.setAttribute("x1", "0");
  base.setAttribute("x2", String(W));
  base.setAttribute("y1", String(H - 0.5));
  base.setAttribute("y2", String(H - 0.5));
  svg.append(base);
  const v = values.slice(-SAMPLES);
  if (v.length >= 2) {
    const max = Math.max(1, ...v);
    const step = W / (SAMPLES - 1);
    const x0 = W - (v.length - 1) * step;
    const line = document.createElementNS(SVG_NS, "polyline");
    line.setAttribute("class", "spark-line");
    line.setAttribute("points", v.map((n, i) => `${(x0 + i * step).toFixed(1)},${(H - 1 - (n / max) * (H - 3)).toFixed(1)}`).join(" "));
    svg.append(line);
  }
  return svg;
}

/** Redraws `el` with the sparkline of `iface`, touching the tooltip only when it changes. */
export function paintSpark(el: HTMLElement, iface: string): void {
  const values = activityOf(iface);
  el.replaceChildren(sparkline(values));
  const title = activityTitle(values);
  if (el.title !== title) el.title = title;
}
