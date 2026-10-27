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
import { printable } from "./text.ts";

/** Host of a panel: "p" and 26 base32 characters (130 bits), then the server's port. */
export const PANEL_HOST = /^p([a-z2-7]{26})\.localhost:(\d{1,5})$/;
const MAX_PANELS = 8;
const MAX_REPORT = 16 * 1024;
const MAX_ERRORS = 50;
const MAX_LOGS = 200;
/** Events one panel may send the agent per minute. */
const MAX_EVENTS_PER_MINUTE = 20;

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
}

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
    }));
  }

  isOpen(name: string): boolean {
    return this.open.has(name);
  }

  /** Opens (or reopens with fresh files) the panel of an extension. */
  openPanel(name: string, by: "user" | "agent"): void {
    if (!this.open.has(name) && this.open.size >= MAX_PANELS) throw new Error(`at most ${MAX_PANELS} panels can be open`);
    const files = this.extensions.panelFiles(name);
    this.drop(name);
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
    };
    this.open.set(name, inst);
    this.byLabel.set(inst.label, inst);
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

  private drop(name: string): boolean {
    const inst = this.open.get(name);
    if (!inst) return false;
    this.open.delete(name);
    this.byLabel.delete(inst.label);
    for (const wake of inst.waiters.splice(0)) wake();
    return true;
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
      return send(200, this.page(inst), "text/html; charset=utf-8");
    }
    if (req.method === "POST" && path === "/_wb/report") {
      if (req.headers.origin !== origin || fetchSite !== "same-origin") return send(403, "forbidden");
      if (!/^application\/json\b/i.test(req.headers["content-type"] ?? "")) return send(415, "JSON only");
      if (req.headers["x-wb-doc"] !== inst.docNonce) return send(409, "replaced");
      const body = await readBody(req, MAX_REPORT);
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
