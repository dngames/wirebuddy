import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { printable } from "./text.ts";

/** sharkd silently drops request lines of 8 KiB or more. */
const MAX_REQUEST_BYTES = 8190;
/** A request this slow means sharkd is wedged; it is restarted. */
const CALL_TIMEOUT_MS = 5 * 60 * 1000;
/** Of a stderr line without an end (a plugin writing on and on), only this much is kept. */
const MAX_PARTIAL_LINE = 64 * 1024;
/** Longest answer read, in characters: a longer one (a huge stream followed) is refused, below V8's string limit. */
const MAX_ANSWER = 256 * 1024 * 1024;
/** What sharkd writes to stderr in normal operation. */
const ROUTINE = /^(load: filename=|sharkd_session_|Hello in child\.)/;

export class SharkdError extends Error {
  constructor(
    message: string,
    readonly code: number,
  ) {
    super(message);
  }
}

/** sharkd died (crashed, or a plugin ended it), or hung and was killed. */
export class SharkdExit extends Error {}

/** sharkd's answer was too long to read; sharkd was restarted. */
export class SharkdTooLarge extends Error {}

/** What sharkd's Lua loading said while it started. */
export interface LuaReport {
  loaded: { name: string; protocols: string[] }[];
  /** What a failed extension registered before its error stays registered. */
  failed: { name: string; error: string; protocols: string[] }[];
  /** The extension it was loading when it died. */
  crashedIn?: string;
  /** Load errors of Lua plugins that aren't extensions. */
  other: string[];
}

/** An extension's dissector failed on a packet, as its first dissection reported it. `frame` 0: more errors than reported. */
export interface LuaError {
  file: string;
  frame: number;
  message: string;
}

interface Pending {
  method: string;
  resolve: (value: unknown) => void;
  reject: (error: Error) => void;
  timer: NodeJS.Timeout;
}

/**
 * One `sharkd -` process speaking JSON-RPC over stdio.
 *
 * sharkd answers requests strictly in order, so requests can be pipelined; a
 * `load` therefore only affects requests sent after it. A crashed process is
 * respawned on the next call, with preferences and the last loaded file restored.
 */
export class Sharkd {
  private proc: ChildProcessWithoutNullStreams | null = null;
  private nextId = 1;
  private pending = new Map<number, Pending>();
  private lastLoad: Record<string, unknown> | undefined;
  /** The file the last load was for, also while it is still loading. */
  private loadingFile = "";
  private readonly prefs = new Map<string, string>();
  /** Processes stopped on purpose: their exit is no crash. */
  private readonly stopped = new WeakSet<ChildProcessWithoutNullStreams>();
  private restartWhenIdle = false;
  /** Closed for good: calls fail instead of starting it again. */
  private disposed = false;
  private idleWaiters: (() => void)[] = [];
  private lua: LuaLog | null = null;
  /** The environment generation the running process started with. */
  private startedWith = 0;
  private luaReady: Promise<LuaReport | null> = Promise.resolve(null);
  /** Called when sharkd dies or hangs (it is respawned on the next call). */
  onFailure: (message: string) => void = () => {};
  /** Called once per start, when Lua loading is over (or killed sharkd). */
  onLua: (report: LuaReport) => void = () => {};
  /** Called for each packet an extension failed on while the file was read. */
  onLuaError: (error: LuaError) => void = () => {};
  /** Longest answer read, in characters. */
  maxAnswer = MAX_ANSWER;

  /** `generation` changes whenever `env` would give a different environment. */
  constructor(
    private readonly bin = "sharkd",
    private readonly profile?: string,
    private readonly env: () => NodeJS.ProcessEnv = () => process.env,
    private readonly generation: () => number = () => 0,
  ) {}

  private start(): ChildProcessWithoutNullStreams {
    // sharkd reads stdin without "-" too; "-C <profile> -" is refused
    const args = this.profile ? ["-C", this.profile] : ["-"];
    this.startedWith = this.generation();
    const proc = spawn(this.bin, args, { stdio: ["pipe", "pipe", "pipe"], env: this.env() });
    let ready: (report: LuaReport | null) => void = () => {};
    this.luaReady = new Promise((done) => (ready = done));
    const lua = new LuaLog((report) => {
      try {
        this.onLua(report);
      } catch (err) {
        this.onFailure(`Handling what sharkd's Lua loading reported failed: ${(err as Error).message}`);
      }
      ready(report);
    });
    this.lua = lua;
    // Buffers of this process alone: a killed one may still deliver half an answer
    let out = "";
    proc.stdout.setEncoding("utf8");
    proc.stdout.on("data", (chunk: string) => {
      if (this.proc !== proc) return;
      out = this.onData(out, chunk);
      if (out.length <= this.maxAnswer) return;
      // Answers come in order: the oldest request in flight asked for it; the rest are lost with the restart
      out = "";
      const mb = Math.round(this.maxAnswer / 1024 / 1024);
      const method = this.pending.values().next().value?.method ?? "?";
      this.stop(proc, new SharkdTooLarge(`sharkd's answer to "${method}" is longer than ${mb} MB and was refused`));
    });
    let err = "";
    // What sharkd said last, for the message when it dies: not WireBuddy's markers, nor sharkd's routine lines
    let said = "";
    const errLine = (line: string): void => {
      line = line.replace(/\r$/, "");
      if (line.trim() && !line.includes("WIREBUDDY-") && !ROUTINE.test(line)) said = line.trim();
      const at = line.indexOf("WIREBUDDY-LUA-ERROR\t");
      if (at < 0) return lua.line(line);
      const [, frame, message = ""] = line.slice(at).split("\t");
      if (this.proc === proc) this.onLuaError({ file: this.loadingFile, frame: Number(frame) || 0, message });
    };
    proc.stderr.setEncoding("utf8");
    proc.stderr.on("data", (chunk: string) => {
      // WireBuddy's markers start on a new line: cutting a long unfinished one loses none
      let start = 0;
      for (let nl = chunk.indexOf("\n"); nl >= 0; nl = chunk.indexOf("\n", start)) {
        errLine(start === 0 ? err + chunk.slice(0, nl) : chunk.slice(start, nl));
        start = nl + 1;
      }
      err = (start === 0 ? err + chunk : chunk.slice(start)).slice(-MAX_PARTIAL_LINE);
    });
    // Writing to a sharkd that just died raises EPIPE here instead of crashing the server
    proc.stdin.on("error", (e) => this.fail(proc, e));
    proc.on("error", (e) => {
      ready(null);
      this.fail(proc, e);
    });
    // "close", not "exit": only then has all of stderr been read
    proc.on("close", (code, signal) => {
      if (err) errLine(err);
      // An extension that killed it while loading is reported (and switched off) through onLua
      let blamed: string | undefined;
      if (this.stopped.has(proc)) ready(null);
      else blamed = lua.died();
      const detail = printable(said.slice(0, 300));
      const message = `sharkd exited (${signal ?? code})${detail ? ": " + detail : ""}`;
      // Still current: it died by itself, not by close() or a timeout kill
      if (this.proc === proc && !blamed) this.onFailure(message);
      this.fail(proc, new SharkdExit(message));
    });
    this.proc = proc;
    return proc;
  }

  private fail(proc: ChildProcessWithoutNullStreams, err: Error): void {
    if (this.proc !== proc) return;
    this.proc = null;
    proc.kill();
    for (const p of this.pending.values()) {
      clearTimeout(p.timer);
      p.reject(err);
    }
    this.pending.clear();
    this.settled();
  }

  /** After the last request in flight: restart if asked to, wake idle() waiters. */
  private settled(): void {
    if (this.pending.size) return;
    if (this.restartWhenIdle && this.proc) this.stop(this.proc, "sharkd restarted");
    for (const wake of this.idleWaiters.splice(0)) wake();
  }

  /** Resolves when no request is in flight, or after `maxMs`. */
  idle(maxMs: number): Promise<void> {
    if (!this.pending.size) return Promise.resolve();
    return new Promise((done) => {
      const timer = setTimeout(done, maxMs);
      this.idleWaiters.push(() => {
        clearTimeout(timer);
        done();
      });
    });
  }

  /** Splits a stdout chunk into answers; returns the unfinished line. */
  private onData(partial: string, chunk: string): string {
    // Only the new chunk is searched: an answer can be megabytes long
    let start = 0;
    let nl = chunk.indexOf("\n");
    while (nl >= 0) {
      this.onLine(start === 0 ? partial + chunk.slice(0, nl) : chunk.slice(start, nl));
      start = nl + 1;
      nl = chunk.indexOf("\n", start);
    }
    return start === 0 ? partial + chunk : chunk.slice(start);
  }

  private onLine(line: string): void {
    // A plugin's stray output may come first
    const at = line.indexOf('{"jsonrpc"');
    if (at < 0) return;
    let msg: { id?: number; result?: unknown; error?: { code: number; message: string } };
    try {
      msg = JSON.parse(line.slice(at));
    } catch {
      return;
    }
    if (msg.id === undefined) return;
    const p = this.pending.get(msg.id);
    if (!p) return;
    // sharkd answers only once its plugins are loaded
    this.lua?.settle();
    this.pending.delete(msg.id);
    clearTimeout(p.timer);
    if (msg.error) p.reject(new SharkdError(msg.error.message, msg.error.code));
    else p.resolve(msg.result);
    this.settled();
  }

  call<T = unknown>(method: string, params?: Record<string, unknown>): Promise<T> {
    if (this.disposed) return Promise.reject(new SharkdExit("sharkd was closed"));
    const id = this.nextId++;
    const request = JSON.stringify({ jsonrpc: "2.0", id, method, ...(params ? { params } : {}) });
    if (Buffer.byteLength(request) >= MAX_REQUEST_BYTES) {
      return Promise.reject(new SharkdError("request too long for sharkd (8 KiB limit); use a shorter filter", -32600));
    }
    if (this.restartWhenIdle && this.proc && !this.pending.size) this.stop(this.proc, "sharkd restarted");
    let proc = this.proc;
    if (!proc) {
      this.restartWhenIdle = false;
      proc = this.start();
      // A respawned sharkd starts with defaults; restore preferences and the last file first
      for (const [name, value] of this.prefs) if (method !== "setconf" || params?.name !== name) this.call("setconf", { name, value }).catch(() => {});
      // Not for a preference: a load follows it anyway
      if (method !== "load" && method !== "setconf" && this.lastLoad) this.call("load", this.lastLoad).catch(() => {});
    }
    if (method === "load") this.loadingFile = String(params?.file ?? "");
    const result = new Promise<T>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        this.settled();
        reject(new SharkdExit(`sharkd did not answer "${method}" within ${CALL_TIMEOUT_MS / 1000} s`));
        if (this.proc === proc) this.onFailure(`sharkd did not answer "${method}" within ${CALL_TIMEOUT_MS / 1000} s and was restarted`);
        this.stop(proc, "sharkd restarted after a timeout");
      }, CALL_TIMEOUT_MS);
      this.pending.set(id, { method, resolve: resolve as (v: unknown) => void, reject, timer });
      proc.stdin.write(request + "\n");
    });
    if (method !== "load") return result;
    return result.then((r) => {
      const status = (r as { status?: string; err?: number }) ?? {};
      if (status.status === "OK" || status.err === -12) this.lastLoad = params;
      return r;
    });
  }

  /** Sets a preference now and after every respawn (also one that interrupts this call). */
  async setPref(name: string, value: string): Promise<void> {
    const before = this.prefs.get(name);
    this.prefs.set(name, value);
    const r = await this.call<{ status?: string }>("setconf", { name, value });
    if (r?.status && r.status !== "OK") {
      if (before === undefined) this.prefs.delete(name);
      else this.prefs.set(name, before);
      throw new Error(`${name}: ${r.status}`);
    }
  }

  /**
   * Stops sharkd so the next call starts it with the environment of then;
   * `whenIdle` waits for the requests in flight.
   */
  restart(whenIdle = false): void {
    if (whenIdle && this.pending.size) this.restartWhenIdle = true;
    else if (this.proc) this.stop(this.proc, "sharkd restarted");
  }

  /** A respawn won't load the last file again (nobody looks at it any more). */
  forgetFile(): void {
    this.lastLoad = undefined;
  }

  /** Process id of the running sharkd, or null. */
  get pid(): number | null {
    return this.proc?.pid ?? null;
  }

  /** Running with an environment older than the current one. */
  outdated(): boolean {
    return this.proc !== null && this.startedWith !== this.generation();
  }

  /** What Lua loading said in the current (or last) start; null if it was stopped first. */
  luaLoaded(): Promise<LuaReport | null> {
    return this.luaReady;
  }

  private stop(proc: ChildProcessWithoutNullStreams, why: string | Error): void {
    this.stopped.add(proc);
    this.fail(proc, typeof why === "string" ? new Error(why) : why);
  }

  close(): void {
    const proc = this.proc;
    this.lastLoad = undefined;
    if (!proc) return;
    this.stop(proc, "sharkd closed");
    proc.stdin.end();
  }

  /** Closes it for good: later calls fail instead of starting sharkd again. */
  dispose(): void {
    this.disposed = true;
    this.close();
  }
}

/** The frames `filter` matches, read in pages: millions of them in one answer would be too long to read. */
export async function matchingFrames(engine: Sharkd, filter: string, pageRows = 1_000_000): Promise<Int32Array> {
  const parts: Int32Array[] = [];
  for (let skip = 0; ; skip += pageRows) {
    const rows = await engine.call<{ num: number }[]>("frames", { filter, ...(skip ? { skip } : {}), limit: pageRows, column0: "frame.number:0" });
    parts.push(Int32Array.from(rows, (r) => r.num));
    if (rows.length < pageRows) break;
  }
  if (parts.length === 1) return parts[0];
  const out = new Int32Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

/** Reads sharkd's startup stderr: WireBuddy's loader markers and Lua load errors. */
class LuaLog {
  private done = false;
  private loading: string | undefined;
  private otherError: string[] | null = null;
  private readonly report: LuaReport = { loaded: [], failed: [], other: [] };

  constructor(private readonly emit: (report: LuaReport) => void) {}

  /** sharkd died: reports the extension it was loading, if any, and returns its name. */
  died(): string | undefined {
    if (this.done) return undefined;
    this.endOther();
    this.report.crashedIn = this.loading;
    this.finish();
    return this.loading;
  }

  /** sharkd answered a request, so loading is over even if "Hello" was missed. */
  settle(): void {
    if (this.done) return;
    this.endOther();
    this.finish();
  }

  line(raw: string): void {
    if (this.done) return;
    // A plugin may have left half a line before a marker
    const at = raw.indexOf("WIREBUDDY-EXT-");
    const line = at > 0 ? raw.slice(at) : raw;
    const [marker, name = "", text = "", protos = ""] = line.split("\t");
    const protocols = (s: string): string[] => s.split(" ").filter(Boolean);
    if (marker.startsWith("WIREBUDDY-EXT-")) {
      this.endOther();
      if (marker === "WIREBUDDY-EXT-LOADING") this.loading = name;
      else if (marker === "WIREBUDDY-EXT-OK") this.report.loaded.push({ name, protocols: protocols(text) });
      else if (marker === "WIREBUDDY-EXT-ERROR") this.report.failed.push({ name, error: text.slice(0, 500), protocols: protocols(protos) });
      if (marker !== "WIREBUDDY-EXT-LOADING") this.loading = undefined;
    } else if (line.startsWith("sharkd: Lua: Error during loading")) {
      this.endOther();
      this.otherError = [];
    } else if (line.endsWith("Hello in child.")) {
      this.endOther();
      this.finish();
    } else if (this.otherError) {
      if (line.startsWith("stack traceback:")) this.endOther();
      else this.otherError.push(line.trim());
    }
  }

  private endOther(): void {
    if (this.otherError?.length) this.report.other.push(this.otherError.filter(Boolean).join(" | ").slice(0, 500));
    this.otherError = null;
  }

  private finish(): void {
    this.done = true;
    this.emit(this.report);
  }
}
