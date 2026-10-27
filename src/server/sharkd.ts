import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";

/** sharkd silently drops request lines of 8 KiB or more. */
const MAX_REQUEST_BYTES = 8190;
/** A request this slow means sharkd is wedged; it is restarted. */
const CALL_TIMEOUT_MS = 5 * 60 * 1000;

export class SharkdError extends Error {
  constructor(
    message: string,
    readonly code: number,
  ) {
    super(message);
  }
}

interface Pending {
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
  private buffer = "";
  private nextId = 1;
  private pending = new Map<number, Pending>();
  private stderrTail = "";
  private lastLoad: Record<string, unknown> | undefined;
  private readonly prefs = new Map<string, string>();
  /** Called when sharkd dies or hangs (it is respawned on the next call). */
  onFailure: (message: string) => void = () => {};

  constructor(
    private readonly bin = "sharkd",
    private readonly profile?: string,
  ) {}

  private start(): ChildProcessWithoutNullStreams {
    const args = this.profile ? ["-C", this.profile, "-"] : ["-"];
    const proc = spawn(this.bin, args, { stdio: ["pipe", "pipe", "pipe"] });
    proc.stdout.setEncoding("utf8");
    proc.stdout.on("data", (chunk: string) => this.onData(chunk));
    proc.stderr.setEncoding("utf8");
    proc.stderr.on("data", (chunk: string) => {
      this.stderrTail = (this.stderrTail + chunk).slice(-2000);
    });
    // Writing to a sharkd that just died raises EPIPE here instead of crashing the server
    proc.stdin.on("error", (err) => this.fail(proc, err));
    proc.on("error", (err) => this.fail(proc, err));
    proc.on("exit", (code, signal) => {
      const detail = this.stderrTail.trim().split("\n").pop() ?? "";
      const message = `sharkd exited (${signal ?? code})${detail ? ": " + detail : ""}`;
      // Still current: it died by itself, not by close() or a timeout kill
      if (this.proc === proc) this.onFailure(message);
      this.fail(proc, new Error(message));
    });
    this.proc = proc;
    return proc;
  }

  private fail(proc: ChildProcessWithoutNullStreams, err: Error): void {
    if (this.proc !== proc) return;
    this.proc = null;
    this.buffer = "";
    proc.kill();
    for (const p of this.pending.values()) {
      clearTimeout(p.timer);
      p.reject(err);
    }
    this.pending.clear();
  }

  private onData(chunk: string): void {
    this.buffer += chunk;
    let nl: number;
    while ((nl = this.buffer.indexOf("\n")) >= 0) {
      const line = this.buffer.slice(0, nl).trim();
      this.buffer = this.buffer.slice(nl + 1);
      if (!line.startsWith("{")) continue;
      let msg: { id?: number; result?: unknown; error?: { code: number; message: string } };
      try {
        msg = JSON.parse(line);
      } catch {
        continue;
      }
      if (msg.id === undefined) continue;
      const p = this.pending.get(msg.id);
      if (!p) continue;
      this.pending.delete(msg.id);
      clearTimeout(p.timer);
      if (msg.error) p.reject(new SharkdError(msg.error.message, msg.error.code));
      else p.resolve(msg.result);
    }
  }

  call<T = unknown>(method: string, params?: Record<string, unknown>): Promise<T> {
    const id = this.nextId++;
    const request = JSON.stringify({ jsonrpc: "2.0", id, method, ...(params ? { params } : {}) });
    if (Buffer.byteLength(request) >= MAX_REQUEST_BYTES) {
      return Promise.reject(new SharkdError("request too long for sharkd (8 KiB limit); use a shorter filter", -32600));
    }
    let proc = this.proc;
    if (!proc) {
      proc = this.start();
      // A respawned sharkd starts with defaults; restore preferences and the last file first
      for (const [name, value] of this.prefs) if (method !== "setconf" || params?.name !== name) this.call("setconf", { name, value }).catch(() => {});
      if (method !== "load" && this.lastLoad) this.call("load", this.lastLoad).catch(() => {});
    }
    const result = new Promise<T>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`sharkd did not answer "${method}" within ${CALL_TIMEOUT_MS / 1000} s`));
        if (this.proc === proc) this.onFailure(`sharkd did not answer "${method}" within ${CALL_TIMEOUT_MS / 1000} s and was restarted`);
        this.fail(proc, new Error("sharkd restarted after a timeout"));
      }, CALL_TIMEOUT_MS);
      this.pending.set(id, { resolve: resolve as (v: unknown) => void, reject, timer });
      proc.stdin.write(request + "\n");
    });
    if (method !== "load") return result;
    return result.then((r) => {
      const status = (r as { status?: string; err?: number }) ?? {};
      if (status.status === "OK" || status.err === -12) this.lastLoad = params;
      return r;
    });
  }

  /** Sets a preference now and after every respawn. */
  async setPref(name: string, value: string): Promise<void> {
    const r = await this.call<{ status?: string }>("setconf", { name, value });
    if (r?.status && r.status !== "OK") throw new Error(`${name}: ${r.status}`);
    this.prefs.set(name, value);
  }

  close(): void {
    const proc = this.proc;
    this.lastLoad = undefined;
    if (!proc) return;
    this.fail(proc, new Error("sharkd closed"));
    proc.stdin.end();
  }
}
