/**
 * Panels: an extension's web page in a window of WireBuddy's UI. Each opening
 * gets a one-time origin of its own, `p<label>.localhost:<port>`, so a panel
 * runs in its own process, can't reach WireBuddy's API or token, and is served
 * nothing but the files read (and checked) when it opened. What goes wrong in
 * it is reported to the agent.
 */

import { randomBytes } from "node:crypto";
import { EventEmitter } from "node:events";
import { existsSync, readFileSync } from "node:fs";
import type { IncomingMessage, ServerResponse } from "node:http";
import { join } from "node:path";
import type { PanelState } from "../shared/api.ts";
import type { Extensions, PanelFiles } from "./extensions.ts";
import type { EventLog } from "./events.ts";
import { ApiError, type PanelData, type PanelSource } from "./paneldata.ts";
import { printable } from "./text.ts";

/** Host of a panel: "p" and 26 base32 characters (130 bits), then the server's port. */
export const PANEL_HOST = /^p([a-z2-7]{26})\.localhost:(\d{1,5})$/;
const MAX_PANELS = 8;
const MAX_REPORT = 16 * 1024;
const MAX_ERRORS = 50;
const MAX_LOGS = 200;
/** Events one panel may send the agent per minute. */
const MAX_EVENTS_PER_MINUTE = 20;
const MAX_REQUEST = 64 * 1024;
/** Data requests of one panel at a time, and what it may get per minute. */
const MAX_IN_FLIGHT = 4;
const MAX_BYTES_PER_MINUTE = 512 * 1024 * 1024;
/** Panel answers being sent at once, over all panels. */
const MAX_SENDING = 128 * 1024 * 1024;
const MAX_FRAMES_PER_SECOND = 20;
/** View events at most this often; a comment keeps idle event streams open. */
const VIEW_EVERY_MS = 250;
const HEARTBEAT_MS = 15_000;
/** A file panels read raw is looked at this often for new packets; "packets" events at most this often. */
const TAIL_MS = 200;
const PACKETS_EVERY_MS = 200;
/** Changes a panel may make to the view, per second (after a click in it). */
const MAX_SELECTS_PER_SECOND = 5;
const MAX_FILTERS_PER_SECOND = 1;
/** What wb.storage keeps per extension, and how often a panel may write it. */
const MAX_STORAGE = 256 * 1024;
const MAX_STORAGE_WRITES_PER_SECOND = 4;
/** A snapshot's PNG at most, its longest side, and how long the page has to answer. */
const MAX_SNAPSHOT = 1536 * 1024;
const SNAPSHOT_SIDE = 1600;
const SNAPSHOT_WAIT_MS = 5000;

type Health = "not-responding" | "responding" | "stopped" | "navigated" | "isolated" | "not-isolated" | "flooding";

interface Instance {
  name: string;
  label: string;
  files: PanelFiles;
  by: "user" | "agent";
  /** The page document now allowed to report; an older one gets 409. */
  docNonce: string | null;
  state: PanelState["state"];
  title: string;
  statusText: string;
  errors: string[];
  errorCount: number;
  logs: string[];
  /** New since the agent last asked (panel action "status"). */
  unseenErrors: string[];
  unseenLogs: string[];
  isolated: boolean | null;
  openedAt: number;
  readyAt: number | null;
  /** What it shows, as the panel described itself when ready. */
  digest: string;
  events: number[];
  waiters: (() => void)[];
  /** Event streams of its page, and what they were sent last. */
  streams: Set<ServerResponse>;
  sent: { view: string; epoch: number; frames: number };
  /** The last "packets" event, and the count held back until PACKETS_EVERY_MS passed. */
  packetsAt: number;
  packetsTimer: NodeJS.Timeout | null;
  packetsDue: number;
  inFlight: number;
  /** Bytes sent per answer, for the per-minute quota. */
  transfers: { at: number; bytes: number }[];
  frameCalls: number[];
  /** Times of its changes to the view and of its storage writes, for their limits. */
  acts: { select: number[]; setFilter: number[] };
  storageWrites: number[];
  /** Snapshots asked of its page, by request id. */
  snapshots: Map<string, (s: Snapshot) => void>;
}

/** An image of a panel, or why there is none. */
export type Snapshot = { png: Buffer; width: number; height: number } | { none: string };

export interface PanelReport {
  name: string;
  state: PanelState["state"];
  readyMs: number | null;
  statusText: string;
  errors: string[];
  logs: string[];
  digest: string;
  isolated: boolean | null;
  stale: boolean;
}

export class Panels extends EventEmitter {
  private readonly open = new Map<string, Instance>();
  private readonly byLabel = new Map<string, Instance>();
  /** The server's port, set once it listens. */
  port = 0;
  private readonly runtime: Map<string, Buffer>;
  private source: PanelSource | null = null;
  private data: PanelData | null = null;
  private viewTimer: NodeJS.Timeout | null = null;
  private heartbeat: NodeJS.Timeout | null = null;
  private tailTimer: NodeJS.Timeout | null = null;
  private tailing = false;
  /** Bytes of panel answers being sent now. */
  private sending = 0;

  constructor(
    private readonly extensions: Extensions,
    private readonly events: EventLog,
    runtimeDir: string,
  ) {
    super();
    // The bridge every panel page loads first, and its base style
    this.runtime = new Map(
      ["bridge.js", "base.css"].filter((f) => existsSync(join(runtimeDir, f))).map((f) => [f, readFileSync(join(runtimeDir, f))] as [string, Buffer]),
    );
  }

  /** Where panels get the view and the capture's data from. */
  attach(source: PanelSource, data: PanelData): void {
    this.source = source;
    this.data = data;
  }

  list(): PanelState[] {
    return [...this.open.values()].map((i) => ({
      name: i.name,
      label: i.label,
      title: i.title,
      src: `http://p${i.label}.localhost:${this.port}/`,
      size: i.files.manifest.size,
      by: i.by,
      state: i.state,
      statusText: i.statusText,
      errors: i.errorCount,
      isolated: i.isolated,
      control: i.files.manifest.permissions.includes("control"),
    }));
  }

  isOpen(name: string): boolean {
    return this.open.has(name);
  }

  /** Opens (or reopens with fresh files) the panel of an extension. */
  openPanel(name: string, by: "user" | "agent"): void {
    if (!this.open.has(name) && this.open.size >= MAX_PANELS) throw new Error(`at most ${MAX_PANELS} panels can be open`);
    const files = this.extensions.panelFiles(name);
    this.drop(name, "reload");
    const inst: Instance = {
      name,
      label: base32(randomBytes(17)).slice(0, 26),
      files,
      by,
      docNonce: null,
      state: "starting",
      title: files.manifest.title,
      statusText: "",
      errors: [],
      errorCount: 0,
      logs: [],
      unseenErrors: [],
      unseenLogs: [],
      isolated: null,
      openedAt: Date.now(),
      readyAt: null,
      digest: "",
      events: [],
      waiters: [],
      streams: new Set(),
      sent: { view: "", epoch: 0, frames: 0 },
      packetsAt: 0,
      packetsTimer: null,
      packetsDue: 0,
      inFlight: 0,
      transfers: [],
      frameCalls: [],
      acts: { select: [], setFilter: [] },
      storageWrites: [],
      snapshots: new Map(),
    };
    this.open.set(name, inst);
    this.byLabel.set(inst.label, inst);
    this.data?.opened(inst.label);
    this.emit("change");
  }

  close(name: string): boolean {
    const had = this.drop(name);
    if (had) this.emit("change");
    return had;
  }

  closeAll(): void {
    for (const name of [...this.open.keys()]) this.drop(name);
    this.emit("change");
  }

  private drop(name: string, why = "closed"): boolean {
    const inst = this.open.get(name);
    if (!inst) return false;
    this.open.delete(name);
    this.byLabel.delete(inst.label);
    for (const wake of inst.waiters.splice(0)) wake();
    for (const answer of [...inst.snapshots.values()]) answer({ none: "the panel was closed" });
    this.endStreams(inst, why);
    if (inst.packetsTimer) clearTimeout(inst.packetsTimer);
    this.data?.closed(inst.label);
    return true;
  }

  /** Tells a panel's event streams why they end, and ends them. */
  private endStreams(inst: Instance, why: string): void {
    for (const res of inst.streams) {
      sse(res, "bye", { why });
      res.end();
    }
    inst.streams.clear();
  }

  /** The view changed: panels hear about it, at most every VIEW_EVERY_MS. */
  viewChanged(): void {
    if (this.viewTimer || ![...this.open.values()].some((i) => i.streams.size)) return;
    this.viewTimer = setTimeout(() => {
      this.viewTimer = null;
      this.pushView();
    }, VIEW_EVERY_MS);
  }

  private pushView(): void {
    if (!this.source) return;
    const view = this.source.view();
    const json = JSON.stringify(view);
    for (const inst of this.open.values()) {
      if (!inst.streams.size) continue;
      const sent = inst.sent;
      const reset = view.epoch !== sent.epoch;
      for (const res of inst.streams) {
        // A reset carries the new view: the page starts over from it
        if (reset) sse(res, "reset", { epoch: view.epoch, why: this.source.resetWhy(), view });
        else if (json !== sent.view) res.write(`event: view\ndata: ${json}\n\n`);
      }
      inst.sent = { view: json, epoch: view.epoch, frames: reset ? view.frames : sent.frames };
      if (reset) inst.packetsDue = view.frames;
      else this.packets(inst, view.frames);
    }
  }

  /** Tells a panel's page there are `frames` packets now (FrameStore may know more than the view), at most every PACKETS_EVERY_MS. */
  private packets(inst: Instance, frames: number): void {
    inst.packetsDue = Math.max(inst.packetsDue, frames);
    if (inst.packetsDue <= inst.sent.frames || !inst.streams.size || inst.packetsTimer) return;
    const wait = inst.packetsAt + PACKETS_EVERY_MS - Date.now();
    if (wait > 0) {
      inst.packetsTimer = setTimeout(() => {
        inst.packetsTimer = null;
        this.packets(inst, 0);
      }, wait);
      return;
    }
    inst.packetsAt = Date.now();
    inst.sent.frames = inst.packetsDue;
    for (const res of inst.streams) sse(res, "packets", { frames: inst.packetsDue, live: this.source?.live() ?? false });
  }

  /** Watches the file while a panel that reads it raw listens: its page hears of new packets within TAIL_MS. */
  private tail(): void {
    const wanted = (): boolean => [...this.open.values()].some((i) => i.streams.size && this.data?.tailing(i.label));
    if (this.tailTimer || !wanted()) return;
    this.tailTimer = setInterval(async () => {
      if (!wanted()) {
        clearInterval(this.tailTimer!);
        this.tailTimer = null;
        return;
      }
      if (this.tailing || !this.data) return;
      this.tailing = true;
      try {
        const frames = await this.data.tail().catch(() => null);
        if (frames !== null) for (const inst of this.open.values()) this.packets(inst, frames);
      } finally {
        this.tailing = false;
      }
    }, TAIL_MS);
    this.tailTimer.unref();
  }

  /** Waits until the panel is ready, failed, or `ms` passed; then what it reported. */
  async settle(name: string, ms: number): Promise<PanelReport> {
    const inst = this.open.get(name);
    if (inst && inst.state === "starting" && !inst.errorCount) {
      await new Promise<void>((done) => {
        const timer = setTimeout(done, ms);
        inst.waiters.push(() => {
          clearTimeout(timer);
          done();
        });
      });
    }
    return this.report(name);
  }

  /** What the panel did since the agent last asked; with `seen`, the agent has seen it then. */
  report(name: string, seen = true): PanelReport {
    const inst = this.open.get(name);
    if (!inst) throw new Error(`the panel "${name}" is not open`);
    const out: PanelReport = {
      name,
      state: inst.state,
      readyMs: inst.readyAt ? inst.readyAt - inst.openedAt : null,
      statusText: inst.statusText,
      errors: seen ? inst.unseenErrors.splice(0) : [...inst.unseenErrors],
      logs: seen ? inst.unseenLogs.splice(0) : [...inst.unseenLogs],
      digest: inst.digest,
      isolated: inst.isolated,
      stale: this.extensions.panelFingerprint(name) !== inst.files.fingerprint,
    };
    return out;
  }

  /**
   * Whether a panel may change the view now (wb.select, wb.setFilter):
   * setFilter needs the "control" permission, both need a click or key press
   * in the panel just before (`clicked`, which the page checks), and both are
   * rate limited. Refusals are told to the agent. Returns the manifest's
   * title (not the one the panel set).
   */
  allow(name: string, label: string, m: "select" | "setFilter", clicked: boolean): string {
    const inst = this.open.get(name);
    if (!inst || inst.label !== label) throw new ApiError(404, "gone", "the panel was closed");
    if (m === "setFilter" && !inst.files.manifest.permissions.includes("control")) {
      this.tell(inst, "WARNING", 'called wb.setFilter, which was refused: it needs "permissions": ["control"] in its extension.json');
      throw new ApiError(403, "denied", 'wb.setFilter needs "permissions": ["control"] in extension.json');
    }
    if (!clicked) {
      this.tell(inst, "WARNING", `called wb.${m}, which was refused: the user hadn't just clicked or typed in the panel (it only works right after that)`);
      throw new ApiError(403, "denied", `wb.${m} only works right after the user clicked or typed in the panel`);
    }
    const now = Date.now();
    const times = inst.acts[m].filter((t) => now - t < 1000);
    inst.acts[m] = times;
    const max = m === "select" ? MAX_SELECTS_PER_SECOND : MAX_FILTERS_PER_SECOND;
    if (times.length >= max) throw new ApiError(429, "busy", `wb.${m} at most ${max} times a second`, { retryMs: 1000 - (now - times[0]) });
    times.push(now);
    return inst.files.manifest.title;
  }

  /** What a panel did to the view, for the agent. */
  acted(name: string, text: string): void {
    const inst = this.open.get(name);
    if (inst) this.tell(inst, "INFO", `${text} (the user clicked in it)`);
  }

  /** Asks the panel's page for an image of it: a PNG, or why there is none. */
  snapshot(name: string, ms = SNAPSHOT_WAIT_MS): Promise<Snapshot> {
    const inst = this.open.get(name);
    if (!inst) throw new Error(`the panel "${name}" is not open`);
    if (!inst.streams.size) throw new Error(inst.state === "stopped" || inst.state === "error" ? `the panel is ${inst.state}: panel action "reload"` : "the panel's page isn't running: is the viewer open?");
    const id = base32(randomBytes(10));
    return new Promise((done) => {
      const timer = setTimeout(() => answer({ none: `the panel did not answer within ${ms / 1000} s` }), ms);
      const answer = (s: Snapshot): void => {
        clearTimeout(timer);
        inst.snapshots.delete(id);
        done(s);
      };
      inst.snapshots.set(id, answer);
      for (const res of inst.streams) sse(res, "request", { id, kind: "snapshot", max: SNAPSHOT_SIDE, bytes: MAX_SNAPSHOT });
    });
  }

  /** The page's watchdog about a panel's frame. */
  health(name: string, label: string, health: Health): void {
    const inst = this.open.get(name);
    if (!inst || inst.label !== label) return;
    const before = inst.state;
    switch (health) {
      case "responding":
        if (inst.state === "not-responding") inst.state = inst.readyAt ? "ready" : "starting";
        break;
      case "not-responding":
        inst.state = "not-responding";
        if (before !== "not-responding") this.tell(inst, "WARNING", "stopped responding (an endless loop, or out of memory?)");
        break;
      case "stopped":
        inst.state = "stopped";
        inst.statusText = "Stopped: it did not respond for 20 s";
        this.tell(inst, "ERROR", "was stopped: it did not respond for 20 s. Fix it, then panel action \"reload\"");
        break;
      case "navigated":
        inst.state = "error";
        inst.statusText = "Closed: panels must not navigate";
        this.tell(inst, "ERROR", "navigated away and was stopped: panels must not navigate");
        break;
      case "flooding":
        inst.state = "error";
        inst.statusText = "Stopped: it sent too many messages";
        this.tell(inst, "ERROR", "sent too many messages to WireBuddy's page and was stopped");
        break;
      case "isolated":
      case "not-isolated":
        inst.isolated = health === "isolated";
        if (!inst.isolated) this.tell(inst, "WARNING", "does not run in a process of its own in this browser: a slow panel slows WireBuddy down");
        break;
    }
    for (const wake of inst.state === "starting" ? [] : inst.waiters.splice(0)) wake();
    this.emit("change");
  }

  /** Adds an event for the agent about a panel, at most a few per minute. */
  private tell(inst: Instance, level: "INFO" | "WARNING" | "ERROR", text: string): void {
    const now = Date.now();
    inst.events = inst.events.filter((t) => now - t < 60_000);
    if (inst.events.length >= MAX_EVENTS_PER_MINUTE) return;
    inst.events.push(now);
    this.events.add(level, `Panel "${inst.name}" ${text}`);
  }

  /**
   * Serves a request for a panel's host; false when `host` isn't one (the
   * caller serves WireBuddy itself then).
   */
  async handle(req: IncomingMessage, res: ServerResponse, host: string): Promise<boolean> {
    const m = PANEL_HOST.exec(host.toLowerCase());
    if (!m) return false;
    const inst = Number(m[2]) === this.port ? this.byLabel.get(m[1]) : undefined;
    const send = (status: number, body: string | Buffer, type = "text/plain; charset=utf-8"): true => {
      res.writeHead(status, { "content-type": type, ...this.headers(inst) });
      res.end(body);
      return true;
    };
    if (!inst) return send(404, "not found");
    const fetchSite = req.headers["sec-fetch-site"];
    const dest = req.headers["sec-fetch-dest"];
    // Only a browser's own requests; never service workers
    if (!fetchSite || req.headers["service-worker"]) return send(403, "forbidden");
    const url = new URL(req.url ?? "/", `http://${host}`);
    const path = decodeURIComponent(url.pathname);
    const origin = `http://p${inst.label}.localhost:${this.port}`;
    if (req.method === "GET" && path === "/") {
      if (dest !== "iframe") return send(403, "only as a frame of WireBuddy");
      inst.docNonce = base32(randomBytes(15));
      // Only the newest page of a panel hears from WireBuddy
      this.endStreams(inst, "replaced");
      return send(200, this.page(inst), "text/html; charset=utf-8");
    }
    if (path.startsWith("/_wb/api/")) {
      if (req.method !== "POST" || req.headers.origin !== origin || fetchSite !== "same-origin") return send(403, "forbidden");
      if (!/^application\/json\b/i.test(req.headers["content-type"] ?? "")) return send(415, "JSON only");
      if (req.headers["x-wb-doc"] !== inst.docNonce) return this.apiError(res, inst, new ApiError(409, "replaced", "a newer page of this panel is open"));
      if (path === "/_wb/api/storage") return this.storage(req, res, inst);
      return this.api(req, res, inst, path.slice("/_wb/api/".length));
    }
    if (req.method === "GET" && path === "/_wb/events") {
      if (fetchSite !== "same-origin" || dest === "document" || dest === "iframe") return send(403, "forbidden");
      if (url.searchParams.get("doc") !== inst.docNonce) return send(409, "replaced");
      return this.eventStream(res, inst);
    }
    if (req.method === "POST" && path === "/_wb/report") {
      if (req.headers.origin !== origin || fetchSite !== "same-origin") return send(403, "forbidden");
      if (!/^application\/json\b/i.test(req.headers["content-type"] ?? "")) return send(415, "JSON only");
      if (req.headers["x-wb-doc"] !== inst.docNonce) return send(409, "replaced");
      // A snapshot asked for is larger than any other report
      const body = await readBody(req, inst.snapshots.size ? Math.ceil(MAX_SNAPSHOT / 3) * 4 + MAX_REPORT : MAX_REPORT);
      if (body === null) return send(413, "too large");
      try {
        this.onReport(inst, JSON.parse(body.toString("utf8")) as Record<string, unknown>, origin);
      } catch {
        return send(400, "bad report");
      }
      return send(200, '{"ok":true}', "application/json");
    }
    if (req.method !== "GET" || fetchSite !== "same-origin" || dest === "document" || dest === "iframe") return send(403, "forbidden");
    const runtime = path.startsWith("/_wb/") ? this.runtime.get(path.slice(5)) : undefined;
    if (runtime) return send(200, runtime, path.endsWith(".css") ? "text/css" : "text/javascript");
    const file = inst.files.files.get(path.slice(1));
    return file ? send(200, file.bytes, file.type) : send(404, "not found");
  }

  /** A data request of a panel's page, within its quotas. */
  private async api(req: IncomingMessage, res: ServerResponse, inst: Instance, method: string): Promise<true> {
    inst.inFlight++;
    try {
      return await this.apiQuota(req, res, inst, method);
    } finally {
      inst.inFlight--;
    }
  }

  private async apiQuota(req: IncomingMessage, res: ServerResponse, inst: Instance, method: string): Promise<true> {
    const now = Date.now();
    inst.transfers = inst.transfers.filter((t) => now - t.at < 60_000);
    const used = inst.transfers.reduce((a, t) => a + t.bytes, 0);
    if (inst.inFlight > MAX_IN_FLIGHT) return this.apiError(res, inst, new ApiError(429, "busy", `at most ${MAX_IN_FLIGHT} requests at a time`, { retryMs: 200 }));
    if (used >= MAX_BYTES_PER_MINUTE) return this.apiError(res, inst, new ApiError(429, "busy", "512 MiB a minute at most", { retryMs: 60_000 - (now - inst.transfers[0].at) }));
    if (this.sending >= MAX_SENDING) return this.apiError(res, inst, new ApiError(429, "busy", "WireBuddy is sending a lot already", { retryMs: 500 }));
    if (method === "frame") {
      inst.frameCalls = inst.frameCalls.filter((t) => now - t < 1000);
      if (inst.frameCalls.length >= MAX_FRAMES_PER_SECOND) return this.apiError(res, inst, new ApiError(429, "busy", `wb.frame at most ${MAX_FRAMES_PER_SECOND} times a second: wb.packets reads many`, { retryMs: 1000 - (now - inst.frameCalls[0]) }));
      inst.frameCalls.push(now);
    }
    const raw = await readBody(req, MAX_REQUEST);
    if (raw === null) return this.apiError(res, inst, new ApiError(413, "too-large", "the request is too large"));
    let body: unknown;
    try {
      body = JSON.parse(raw.toString("utf8") || "{}");
    } catch {
      return this.apiError(res, inst, new ApiError(400, "bad-args", "the body is not JSON"));
    }
    if (!body || typeof body !== "object" || Array.isArray(body)) return this.apiError(res, inst, new ApiError(400, "bad-args", "the body is not a JSON object"));
    if (!this.data) return this.apiError(res, inst, new ApiError(500, "internal", "no capture data here"));
    let answer;
    try {
      answer = await this.data.handle(inst.label, method, body as Record<string, unknown>);
    } catch (err) {
      return this.apiError(res, inst, err instanceof ApiError ? err : new ApiError(500, "internal", printable((err as Error).message)));
    }
    // Closed or reopened meanwhile: nothing for an old page
    if (this.byLabel.get(inst.label) !== inst) return this.apiError(res, inst, new ApiError(404, "gone", "the panel was closed"));
    const out = answer.kind === "json" ? Buffer.from(JSON.stringify(answer.body)) : answer.body;
    if (this.sending && this.sending + out.length > MAX_SENDING) return this.apiError(res, inst, new ApiError(429, "busy", "WireBuddy is sending a lot already", { retryMs: 500 }));
    // The quota again, now that the answer's size is known
    const since = Date.now() - 60_000;
    inst.transfers = inst.transfers.filter((t) => t.at > since);
    const sent = inst.transfers.reduce((a, t) => a + t.bytes, 0);
    if (sent && sent + out.length > MAX_BYTES_PER_MINUTE) return this.apiError(res, inst, new ApiError(429, "busy", "512 MiB a minute at most", { retryMs: inst.transfers[0].at - since }));
    const headers: Record<string, string> = { ...this.headers(inst), "content-length": String(out.length) };
    if (answer.kind === "json") headers["content-type"] = "application/json";
    else if (answer.kind === "page") headers["content-type"] = "application/vnd.wirebuddy.page";
    else {
      headers["content-type"] = "application/octet-stream";
      headers["x-wb-type"] = encodeURIComponent(cut(answer.type, 200));
      headers["x-wb-filename"] = encodeURIComponent(cut(answer.filename, 500));
      headers["content-disposition"] = "attachment";
      headers["content-security-policy"] = "sandbox; default-src 'none'";
    }
    inst.transfers.push({ at: Date.now(), bytes: out.length });
    this.sending += out.length;
    if (method === "packets") this.tail();
    let counted = true;
    const done = (): void => {
      if (counted) this.sending -= out.length;
      counted = false;
    };
    res.once("finish", done);
    res.once("close", done);
    res.writeHead(200, headers);
    res.end(out);
    return true;
  }

  /** wb.storage: JSON kept per extension, {op: "get"} or {op: "set", value}. */
  private async storage(req: IncomingMessage, res: ServerResponse, inst: Instance): Promise<true> {
    const raw = await readBody(req, MAX_STORAGE + 1024);
    if (raw === null) return this.apiError(res, inst, new ApiError(413, "too-large", `wb.storage keeps at most ${MAX_STORAGE / 1024} KiB`));
    let body: { op?: unknown; value?: unknown };
    try {
      body = JSON.parse(raw.toString("utf8")) as typeof body;
    } catch {
      return this.apiError(res, inst, new ApiError(400, "bad-args", "the body is not JSON"));
    }
    const answer = (body: unknown): true => {
      res.writeHead(200, { ...this.headers(inst), "content-type": "application/json" });
      res.end(JSON.stringify(body));
      return true;
    };
    try {
      if (body?.op === "get") {
        const json = this.extensions.panelStorage(inst.name);
        let value: unknown = null;
        try {
          value = json === null ? null : JSON.parse(json);
        } catch {
          // not ours any more: nothing kept
        }
        return answer({ value });
      }
      if (body?.op !== "set") return this.apiError(res, inst, new ApiError(400, "bad-args", 'op must be "get" or "set"'));
      const json = body.value === undefined || body.value === null ? null : JSON.stringify(body.value);
      if (json && Buffer.byteLength(json) > MAX_STORAGE) return this.apiError(res, inst, new ApiError(413, "too-large", `wb.storage keeps at most ${MAX_STORAGE / 1024} KiB of JSON`));
      const now = Date.now();
      inst.storageWrites = inst.storageWrites.filter((t) => now - t < 1000);
      if (inst.storageWrites.length >= MAX_STORAGE_WRITES_PER_SECOND) {
        return this.apiError(res, inst, new ApiError(429, "busy", `wb.storage.set at most ${MAX_STORAGE_WRITES_PER_SECOND} times a second`, { retryMs: 1000 - (now - inst.storageWrites[0]) }));
      }
      inst.storageWrites.push(now);
      this.extensions.setPanelStorage(inst.name, json);
      return answer({ ok: true });
    } catch (err) {
      return this.apiError(res, inst, new ApiError(500, "internal", `wb.storage failed: ${printable((err as Error).message)}`));
    }
  }

  private apiError(res: ServerResponse, inst: Instance, err: ApiError): true {
    const body = JSON.stringify({ error: err.message, code: err.code, ...err.extra });
    res.writeHead(err.status, { ...this.headers(inst), "content-type": "application/json" });
    res.end(body);
    return true;
  }

  /** The page's event stream: the view on connect and when it changes, packets, resets, and the end. */
  private eventStream(res: ServerResponse, inst: Instance): true {
    res.writeHead(200, { ...this.headers(inst), "content-type": "text/event-stream" });
    res.write("retry: 2000\n\n");
    const view = this.source?.view();
    if (view) {
      const json = JSON.stringify(view);
      res.write(`event: view\ndata: ${json}\n\n`);
      if (!inst.streams.size) [inst.sent, inst.packetsDue] = [{ view: json, epoch: view.epoch, frames: view.frames }, view.frames];
    }
    inst.streams.add(res);
    res.on("close", () => {
      inst.streams.delete(res);
      this.beat();
    });
    this.beat();
    this.tail();
    return true;
  }

  /** Keeps event streams open while there are any. */
  private beat(): void {
    const any = [...this.open.values()].some((i) => i.streams.size);
    if (any && !this.heartbeat) {
      this.heartbeat = setInterval(() => {
        for (const inst of this.open.values()) for (const res of inst.streams) res.write(": hb\n\n");
      }, HEARTBEAT_MS);
      this.heartbeat.unref();
    } else if (!any && this.heartbeat) {
      clearInterval(this.heartbeat);
      this.heartbeat = null;
    }
  }

  /** Every panel response: the panel may load only its own files and talk only to its own origin. */
  private headers(inst: Instance | undefined): Record<string, string> {
    const p = this.port;
    const wasm = inst?.files.manifest.wasm ? " 'wasm-unsafe-eval'" : "";
    return {
      "content-security-policy": [
        "default-src 'none'",
        `script-src 'self'${wasm}`,
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data: blob:",
        "media-src 'self' data: blob:",
        "font-src 'self' data:",
        "connect-src 'self'",
        "worker-src 'self' blob:",
        "frame-src 'none'",
        "object-src 'none'",
        "base-uri 'none'",
        "form-action 'none'",
        "manifest-src 'none'",
        `frame-ancestors http://127.0.0.1:${p} http://localhost:${p} http://[::1]:${p}`,
      ].join("; "),
      "permissions-policy":
        "camera=(), microphone=(), geolocation=(), display-capture=(), fullscreen=(), usb=(), serial=(), hid=(), bluetooth=(), midi=(), payment=(), clipboard-read=(), publickey-credentials-get=(), local-fonts=(), window-management=()",
      "x-content-type-options": "nosniff",
      "referrer-policy": "no-referrer",
      "cache-control": "no-store",
      "cross-origin-resource-policy": "same-origin",
      "x-dns-prefetch-control": "off",
    };
  }

  /** The page WireBuddy generates around the panel's own files. */
  private page(inst: Instance): string {
    const { manifest, files, body } = inst.files;
    const meta = (name: string, value: string) => `<meta name="${name}" content="${escapeHtml(value)}">`;
    return [
      '<!doctype html><html><head><meta charset="utf-8"><meta name="color-scheme" content="light dark">',
      meta("wb-doc", inst.docNonce ?? ""),
      meta("wb-params", JSON.stringify(manifest.params)),
      meta("wb-name", inst.name),
      meta("wb-view", JSON.stringify(this.source?.view() ?? null)),
      `<title>${escapeHtml(manifest.title)}</title>`,
      '<link rel="stylesheet" href="/_wb/base.css">',
      files.has("style.css") ? '<link rel="stylesheet" href="/style.css">' : "",
      '<script src="/_wb/bridge.js"></script><script type="module" src="/main.js"></script>',
      `</head><body>${body}</body></html>`,
    ].join("");
  }

  private onReport(inst: Instance, r: Record<string, unknown>, origin: string): void {
    const text = (v: unknown, max: number): string => printable(String(v ?? "")).slice(0, max);
    // Paths in the panel's origin are its files: say where they are on disk
    const where = (v: unknown, max: number): string => text(String(v ?? "").split(origin).join(join(inst.files.folder, "panel")), max);
    switch (r.kind) {
      case "ready":
        if (!inst.readyAt) inst.readyAt = Date.now();
        if (inst.state === "starting") inst.state = "ready";
        inst.digest = text(r.digest, 600);
        for (const wake of inst.waiters.splice(0)) wake();
        break;
      case "status":
        inst.statusText = text(r.text, 200);
        break;
      case "title":
        inst.title = text(r.text, 80) || inst.files.manifest.title;
        break;
      case "digest":
        inst.digest = text(r.digest, 600);
        break;
      case "snapshot": {
        const answer = inst.snapshots.get(String(r.id ?? ""));
        if (!answer) return;
        const png = typeof r.png === "string" ? Buffer.from(r.png, "base64") : null;
        if (!png) answer({ none: text(r.none, 300) || "the panel has nothing to show" });
        else if (png.length < 24 || !png.subarray(0, 8).equals(PNG_SIGNATURE)) answer({ none: "the panel's snapshot is not a PNG" });
        else if (png.length > MAX_SNAPSHOT) answer({ none: `the panel's snapshot is larger than ${MAX_SNAPSHOT / 1024 / 1024} MiB` });
        else answer({ png, width: png.readUInt32BE(16), height: png.readUInt32BE(20) });
        return;
      }
      case "error": {
        // The first place in the panel's own files, as path:line:column on disk
        const at = new RegExp(`${origin.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(/[^\\s):]+):(\\d+):(\\d+)`).exec(String(r.stack ?? ""));
        const msg = where(r.message, 300) + (at ? ` at ${printable(join(inst.files.folder, "panel", at[1]))}:${at[2]}:${at[3]}` : "");
        inst.errorCount++;
        push(inst.errors, msg, MAX_ERRORS);
        push(inst.unseenErrors, msg, MAX_ERRORS);
        this.tell(inst, "ERROR", `[panel output]: ${msg}`);
        for (const wake of inst.waiters.splice(0)) wake();
        break;
      }
      case "csp": {
        const msg = `blocked by the content security policy: ${text(r.directive, 40)} ${where(r.blocked, 200)} — ${cspHint(String(r.directive ?? ""), String(r.blocked ?? ""))}`;
        push(inst.unseenErrors, msg, MAX_ERRORS);
        this.tell(inst, "WARNING", msg);
        break;
      }
      case "log": {
        const line = `${text(r.level, 8)}: ${where(r.text, 300)}`;
        push(inst.logs, line, MAX_LOGS);
        push(inst.unseenLogs, line, MAX_LOGS);
        if (r.level === "error" || r.level === "warn") this.tell(inst, "WARNING", `[panel output] console.${text(r.level, 8)}: ${where(r.text, 300)}`);
        break;
      }
      default:
        throw new Error("unknown report");
    }
    this.emit("change");
  }
}

/** At most `max` characters, none of them half a surrogate pair (encodeURIComponent refuses those). */
function cut(s: string, max: number): string {
  const whole = s.slice(0, max * 2).replace(/[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/g, "\ufffd");
  return Array.from(whole).slice(0, max).join("");
}

const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

function sse(res: ServerResponse, event: string, data: unknown): void {
  res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
}

function push(ring: string[], line: string, max: number): void {
  // The same error again and again is one line
  if (ring[ring.length - 1] === line) return;
  ring.push(line);
  if (ring.length > max) ring.shift();
}

function cspHint(directive: string, blocked: string): string {
  if (directive.startsWith("connect-src")) return "panels have no network: get data with wb.packets, wb.follow or wb.objects";
  if (blocked === "inline" || directive.startsWith("script-src-attr")) return "no inline scripts or on*= attributes: put code into main.js";
  if (blocked === "eval") return "eval and new Function are blocked";
  if (blocked === "wasm-eval") return 'WebAssembly needs "wasm": true in the panel manifest';
  if (/^https?:/.test(blocked)) return "panels load only their own files: copy the library into panel/";
  return "panels load only their own files";
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}

function base32(bytes: Buffer): string {
  const abc = "abcdefghijklmnopqrstuvwxyz234567";
  let out = "";
  let bits = 0;
  let value = 0;
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += abc[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  return out;
}

function readBody(req: IncomingMessage, max: number): Promise<Buffer | null> {
  return new Promise((done, fail) => {
    const parts: Buffer[] = [];
    let size = 0;
    req.on("data", (c: Buffer) => {
      size += c.length;
      if (size > max) {
        req.destroy();
        done(null);
      } else parts.push(c);
    });
    req.on("end", () => done(Buffer.concat(parts)));
    req.on("error", fail);
  });
}
