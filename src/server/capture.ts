import { spawn, execFile, type ChildProcess } from "node:child_process";
import { EventEmitter } from "node:events";
import { mkdirSync, readdirSync } from "node:fs";
import { join } from "node:path";
import type { CaptureInterface, CaptureRequest, CaptureState, FilterCheck } from "../shared/api.ts";

function run(bin: string, args: string[], timeoutMs = 10000): Promise<{ stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    execFile(bin, args, { timeout: timeoutMs, maxBuffer: 8 * 1024 * 1024 }, (_err, stdout, stderr) =>
      resolve({ stdout: String(stdout), stderr: String(stderr) }),
    );
  });
}

function positiveInt(value: unknown, name: string): number | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  const n = Number(value);
  if (!Number.isInteger(n) || n <= 0) throw new Error(`${name} must be a positive integer`);
  return n;
}

/**
 * Records with dumpcap. Emits "change" whenever {@link state} changes and
 * "file" when dumpcap starts writing a new file.
 */
export class Capture extends EventEmitter {
  state: CaptureState;
  private proc: ChildProcess | null = null;
  private starting = false;
  private stopRequested = false;
  private killTimer: NodeJS.Timeout | null = null;
  private interfaceCache: { at: number; list: CaptureInterface[] } | null = null;

  constructor(
    dir: string,
    private readonly bin = "dumpcap",
  ) {
    super();
    this.state = {
      status: "idle",
      iface: null,
      filter: "",
      autostop: {},
      ring: null,
      currentFile: null,
      files: [],
      dir,
      startedAt: null,
      packets: 0,
      error: null,
    };
  }

  private update(patch: Partial<CaptureState>): void {
    this.state = { ...this.state, ...patch };
    this.emit("change", this.state);
  }

  async interfaces(): Promise<CaptureInterface[]> {
    if (this.interfaceCache && Date.now() - this.interfaceCache.at < 5000) return this.interfaceCache.list;
    const { stdout, stderr } = await run(this.bin, ["-D", "-M"]);
    let parsed: Record<string, { friendly_name: string | null; vendor_description: string | null; addrs: string[]; loopback: boolean; extcap: string }>[];
    try {
      parsed = JSON.parse(stdout);
    } catch {
      throw new Error(`dumpcap could not list interfaces: ${stderr.trim() || stdout.trim()}`);
    }
    const list = parsed.flatMap((entry) =>
      Object.entries(entry)
        .filter(([, info]) => !info.extcap)
        .map(([name, info]) => ({
          name,
          description: info.friendly_name ?? info.vendor_description ?? null,
          addresses: info.addrs ?? [],
          loopback: !!info.loopback,
        })),
    );
    this.interfaceCache = { at: Date.now(), list };
    return list;
  }

  private async requireInterface(iface: string): Promise<void> {
    const list = await this.interfaces();
    if (!list.some((i) => i.name === iface)) throw new Error(`unknown interface "${iface}"`);
  }

  /** Compiles the capture filter for the interface without capturing. */
  async checkFilter(iface: string, filter: string): Promise<FilterCheck> {
    if (!filter.trim()) return { ok: true };
    try {
      await this.requireInterface(iface);
    } catch (err) {
      return { ok: false, error: (err as Error).message };
    }
    const { stdout, stderr } = await run(this.bin, ["-i", iface, "-f", filter, "-d"], 5000);
    if (stdout.includes("(000)")) return { ok: true };
    const message = stderr
      .split("\n")
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith("Capturing on") && !l.startsWith("See the User"))
      .join(" ")
      .replace(/^dumpcap:\s*/, "");
    return { ok: false, error: message || "invalid capture filter" };
  }

  async start(req: CaptureRequest): Promise<void> {
    // Claimed before the first await so a double click cannot start two dumpcaps
    if (this.starting || this.proc) throw new Error("a capture is already running");
    this.starting = true;
    this.stopRequested = false;
    let args: string[];
    let settings: Pick<CaptureState, "iface" | "filter" | "autostop" | "ring">;
    try {
      ({ args, settings } = await this.prepare(req));
    } finally {
      this.starting = false;
    }
    if (this.stopRequested) {
      this.stopRequested = false;
      return;
    }

    this.update({
      ...settings,
      status: "starting",
      currentFile: null,
      files: [],
      startedAt: Date.now(),
      packets: 0,
      error: null,
    });

    const proc = spawn(this.bin, args, { stdio: ["ignore", "ignore", "pipe"] });
    this.proc = proc;
    let tail = "";
    let partial = "";
    // dumpcap separates progress updates with \r and messages with \n
    const onLine = (line: string) => {
      if (this.proc !== proc) return;
      const file = /File: (.+)$/.exec(line.trim());
      if (file && file[1] !== this.state.currentFile) {
        const status = this.stopRequested ? "stopping" : "running";
        this.update({ status, currentFile: file[1], files: [...this.state.files, file[1]] });
        this.emit("file", file[1]);
        // A SIGINT sent before dumpcap was capturing can get lost
        if (this.stopRequested) proc.kill("SIGINT");
      }
      const count = /Packets(?: captured)?: (\d+)/.exec(line);
      if (count) this.update({ packets: Number(count[1]) });
    };
    proc.stderr!.setEncoding("utf8");
    proc.stderr!.on("data", (chunk: string) => {
      tail = (tail + chunk).slice(-4000);
      const lines = (partial + chunk).split(/[\r\n]/);
      partial = lines.pop() ?? "";
      lines.forEach(onLine);
    });
    proc.on("error", (err) => {
      if (this.proc !== proc) return;
      this.proc = null;
      this.update({ status: "error", error: err.message, startedAt: null });
    });
    proc.on("exit", (code) => {
      if (this.proc !== proc) return;
      this.proc = null;
      if (this.killTimer) clearTimeout(this.killTimer);
      this.killTimer = null;
      const failed = code !== 0 && !this.stopRequested;
      this.stopRequested = false;
      const reason = tail
        .split(/[\r\n]/)
        .map((l) => l.trim())
        .filter((l) => l.startsWith("dumpcap:") || /error|denied|permission/i.test(l))
        .join(" ");
      this.update({
        status: failed ? "error" : "idle",
        error: failed ? reason || `dumpcap exited with code ${code}` : null,
        startedAt: null,
      });
      this.emit("stopped");
    });
  }

  /** Validates a request and builds the dumpcap command line. */
  private async prepare(req: CaptureRequest) {
    await this.requireInterface(req.iface);
    const filter = (req.filter ?? "").trim();
    if (filter) {
      const check = await this.checkFilter(req.iface, filter);
      if (!check.ok) throw new Error(`capture filter: ${check.error}`);
    }
    const autostop = {
      durationSec: positiveInt(req.autostop?.durationSec, "auto-stop duration"),
      filesizeKB: positiveInt(req.autostop?.filesizeKB, "auto-stop file size"),
      packets: positiveInt(req.autostop?.packets, "auto-stop packets"),
    };
    let ring: CaptureRequest["ring"] = null;
    if (req.ring) {
      ring = {
        files: positiveInt(req.ring.files, "ring buffer files") ?? 2,
        filesizeKB: positiveInt(req.ring.filesizeKB, "ring buffer file size"),
        durationSec: positiveInt(req.ring.durationSec, "ring buffer duration"),
      };
      if (!ring.filesizeKB && !ring.durationSec) throw new Error("ring buffer needs a file size or a duration per file");
      // dumpcap reads -a filesize as the ring's switch size, so it would never stop
      if (autostop.filesizeKB) throw new Error("auto-stop by file size cannot be combined with a ring buffer");
    }

    mkdirSync(this.state.dir, { recursive: true });
    const stamp = new Date().toISOString().replace(/[-:.Z]/g, "").replace("T", "_");
    const safeIface = req.iface.replace(/[^A-Za-z0-9_.-]/g, "_");
    let base = `wirebuddy_${safeIface}_${stamp}`;
    const taken = new Set(readdirSync(this.state.dir).map((f) => f.split(/_\d{5}_|\.pcapng$/)[0]));
    for (let i = 2; taken.has(base); i++) base = `wirebuddy_${safeIface}_${stamp}_${i}`;
    const target = join(this.state.dir, `${base}.pcapng`);

    const args = ["-i", req.iface, "-w", target];
    if (filter) args.push("-f", filter);
    if (autostop.durationSec) args.push("-a", `duration:${autostop.durationSec}`);
    if (autostop.filesizeKB) args.push("-a", `filesize:${autostop.filesizeKB}`);
    if (autostop.packets) args.push("-a", `packets:${autostop.packets}`);
    if (ring) {
      args.push("-b", `files:${ring.files}`);
      if (ring.filesizeKB) args.push("-b", `filesize:${ring.filesizeKB}`);
      if (ring.durationSec) args.push("-b", `duration:${ring.durationSec}`);
    }
    return { args, settings: { iface: req.iface, filter, autostop, ring } };
  }

  stop(): void {
    if (this.starting && !this.proc) {
      this.stopRequested = true;
      return;
    }
    const proc = this.proc;
    if (!proc) return;
    this.stopRequested = true;
    this.update({ status: "stopping" });
    proc.kill("SIGINT");
    this.killTimer ??= setTimeout(() => {
      if (this.proc === proc) proc.kill("SIGTERM");
    }, 3000);
  }

  get running(): boolean {
    return this.proc !== null || this.starting;
  }
}
