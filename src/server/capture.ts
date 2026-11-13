import { spawn, execFile, type ChildProcess } from "node:child_process";
import { EventEmitter } from "node:events";
import { mkdirSync, readdirSync, readFileSync } from "node:fs";
import { networkInterfaces } from "node:os";
import { join } from "node:path";
import type { CaptureInterface, CaptureRequest, CaptureState, FilterCheck, InterfaceActivity } from "../shared/api.ts";

const ACTIVITY_SAMPLES = 60;
/** dumpcap -S keeps running this long after the last activity request. */
const ACTIVITY_IDLE_MS = 10_000;

function run(bin: string, args: string[], timeoutMs = 10000): Promise<{ stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    execFile(bin, args, { timeout: timeoutMs, maxBuffer: 8 * 1024 * 1024 }, (_err, stdout, stderr) =>
      resolve({ stdout: String(stdout), stderr: String(stderr) }),
    );
  });
}

/**
 * Interface names and indexes, to notice when interfaces come, go or are
 * re-created. Where `netDir` (Linux's /sys/class/net) is missing, the names
 * the system lists alone.
 */
export function interfaceSignature(netDir = "/sys/class/net", listNames: () => string[] = () => Object.keys(networkInterfaces())): string {
  let names: string[];
  try {
    names = readdirSync(netDir);
  } catch {
    return listNames().sort().join(",");
  }
  return names
    .map((n) => {
      try {
        return `${n}:${readFileSync(join(netDir, n, "ifindex"), "utf8").trim()}`;
      } catch {
        return n;
      }
    })
    .sort()
    .join(",");
}

/**
 * BPF for the traffic between WireBuddy's page (or an agent) and its server:
 * TCP on its port between the loopback addresses it listens on. Only network
 * and transport primitives, which libpcap compiles for Ethernet (lo), Linux
 * cooked capture (any) and the null link of lo0 alike; the addresses keep
 * another host's traffic on that port, seen on a real interface of `any`.
 */
export function ownTrafficFilter(port: number): string {
  return `tcp port ${port} and ((src host 127.0.0.1 and dst host 127.0.0.1) or (src host ::1 and dst host ::1))`;
}

/** The capture filter dumpcap gets: the user's (in brackets) without WireBuddy's own traffic on `leaveOut`'s port; "" for no filter. */
export function captureFilter(user: string, leaveOut: number | null): string {
  user = user.trim();
  if (leaveOut === null) return user;
  return user ? `(${user}) and not (${ownTrafficFilter(leaveOut)})` : `not (${ownTrafficFilter(leaveOut)})`;
}

/** Whether a capture on `iface` records the loopback traffic WireBuddy's page makes: loopback interfaces (lo, lo0), and any, which includes them. */
export function seesLoopback(iface: Pick<CaptureInterface, "name" | "loopback">): boolean {
  return iface.loopback || iface.name === "any" || /^lo\d*$/.test(iface.name);
}

/** Files of a capture the state lists. */
const MAX_FILES_LISTED = 100;

function positiveInt(value: unknown, name: string): number | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  const n = Number(value);
  // dumpcap takes 32-bit numbers
  if (!Number.isInteger(n) || n <= 0 || n > 0x7fffffff) throw new Error(`${name} must be a positive integer`);
  return n;
}

/**
 * Records with dumpcap. Emits "change" whenever {@link state} changes and
 * "file" when dumpcap starts writing a new file.
 */
export class Capture extends EventEmitter {
  state: CaptureState;
  /** The port WireBuddy's own server listens on, set once it does: captures that see loopback traffic leave it out. */
  ownPort: number | null = null;
  private proc: ChildProcess | null = null;
  private starting = false;
  private stopRequested = false;
  private killTimer: NodeJS.Timeout | null = null;
  private interfaceCache: { at: number; list: CaptureInterface[] } | null = null;
  private statsProc: ChildProcess | null = null;
  private statsIdle: NodeJS.Timeout | null = null;
  private statsError: string | null = null;
  private statsFailedAt = 0;
  private statsSignature = "";
  private statsCheckedAt = 0;
  private readonly activityTotals = new Map<string, number>();
  private readonly activityHistory = new Map<string, number[]>();

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
      promiscuous: true,
      leftOutPort: null,
      currentFile: null,
      files: [],
      filesWritten: 0,
      dir,
      startedAt: null,
      packets: 0,
      error: null,
      startedBy: null,
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

  private async requireInterface(iface: string): Promise<CaptureInterface> {
    const info = (await this.interfaces()).find((i) => i.name === iface);
    if (!info) throw new Error(`unknown interface "${iface}"`);
    return info;
  }

  /** The port of WireBuddy's own traffic a capture on `iface` leaves out; null where there is none. */
  private leftOut(iface: CaptureInterface): number | null {
    return this.ownPort !== null && seesLoopback(iface) ? this.ownPort : null;
  }

  /** Compiles the capture filter for the interface without capturing. */
  async checkFilter(iface: string, filter: string): Promise<FilterCheck> {
    if (!filter.trim()) return { ok: true };
    try {
      return await this.checkGiven(await this.requireInterface(iface), filter.trim());
    } catch (err) {
      return { ok: false, error: (err as Error).message };
    }
  }

  /** Compiles what dumpcap gets for the user's `filter` (also none) on `iface`; an error of the user's own filter says so alone. */
  private async checkGiven(iface: CaptureInterface, filter: string): Promise<FilterCheck> {
    const given = captureFilter(filter, this.leftOut(iface));
    const check = await this.compile(iface.name, given);
    if (check.ok || given === filter) return check;
    const alone = filter ? await this.compile(iface.name, filter) : check;
    return alone.ok || !filter ? { ok: false, error: `WireBuddy's own traffic can't be left out of this capture: ${check.error}` } : alone;
  }

  private async compile(iface: string, filter: string): Promise<FilterCheck> {
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

  async start(req: CaptureRequest, by: "user" | "agent" = "user"): Promise<void> {
    // Claimed before the first await so a double click cannot start two dumpcaps
    if (this.starting || this.proc) throw new Error("a capture is already running");
    this.starting = true;
    this.stopRequested = false;
    let args: string[];
    let settings: Pick<CaptureState, "iface" | "filter" | "autostop" | "ring" | "promiscuous" | "leftOutPort">;
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
      filesWritten: 0,
      startedAt: Date.now(),
      packets: 0,
      error: null,
      startedBy: by,
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
        // The state goes to every page with each change: a capture in new files for days lists its newest
        this.update({ status, currentFile: file[1], files: [...this.state.files, file[1]].slice(-MAX_FILES_LISTED), filesWritten: this.state.filesWritten + 1 });
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
    const info = await this.requireInterface(req.iface);
    const filter = (req.filter ?? "").trim();
    const leftOutPort = this.leftOut(info);
    // What dumpcap gets, checked as such: the user's filter, and the exclusion of WireBuddy's own traffic
    const given = captureFilter(filter, leftOutPort);
    if (given) {
      const check = await this.checkGiven(info, filter);
      if (!check.ok) throw new Error(`capture filter: ${check.error}`);
    }
    const autostop = {
      durationSec: positiveInt(req.autostop?.durationSec, "auto-stop duration"),
      filesizeKB: positiveInt(req.autostop?.filesizeKB, "auto-stop file size"),
      packets: positiveInt(req.autostop?.packets, "auto-stop packets"),
      files: positiveInt(req.autostop?.files, "auto-stop files"),
    };
    let ring: CaptureRequest["ring"] = null;
    if (req.ring) {
      ring = {
        files: positiveInt(req.ring.files, "ring buffer files"),
        filesizeKB: positiveInt(req.ring.filesizeKB, "new file size"),
        durationSec: positiveInt(req.ring.durationSec, "new file duration"),
        packets: positiveInt(req.ring.packets, "new file packets"),
        intervalSec: positiveInt(req.ring.intervalSec, "new file interval"),
      };
      if (!ring.filesizeKB && !ring.durationSec && !ring.packets && !ring.intervalSec) throw new Error("a new file needs a size, a duration, a packet count or an interval");
      if (ring.files !== undefined && ring.files < 2) throw new Error("a ring buffer needs at least 2 files");
      // dumpcap reads -a filesize as the switch size of new files, so it would never stop
      if (autostop.filesizeKB) throw new Error("stopping after a size cannot be combined with new files");
    } else if (autostop.files) throw new Error("stopping after a number of files needs new files to be created automatically");

    // Captures can hold passwords and private traffic: only the user may read them
    mkdirSync(this.state.dir, { recursive: true, mode: 0o700 });
    const stamp = new Date().toISOString().replace(/[-:.Z]/g, "").replace("T", "_");
    const safeIface = req.iface.replace(/[^A-Za-z0-9_.-]/g, "_");
    let base = `wirebuddy_${safeIface}_${stamp}`;
    const taken = new Set(readdirSync(this.state.dir).map((f) => f.split(/_\d{5}_|\.pcapng$/)[0]));
    for (let i = 2; taken.has(base); i++) base = `wirebuddy_${safeIface}_${stamp}_${i}`;
    const target = join(this.state.dir, `${base}.pcapng`);

    const promiscuous = req.promiscuous !== false;
    const args = ["-i", req.iface, "-w", target];
    if (!promiscuous) args.push("-p");
    if (given) args.push("-f", given);
    if (autostop.durationSec) args.push("-a", `duration:${autostop.durationSec}`);
    if (autostop.filesizeKB) args.push("-a", `filesize:${autostop.filesizeKB}`);
    if (autostop.packets) args.push("-a", `packets:${autostop.packets}`);
    if (autostop.files) args.push("-a", `files:${autostop.files}`);
    if (ring) {
      if (ring.files) args.push("-b", `files:${ring.files}`);
      if (ring.filesizeKB) args.push("-b", `filesize:${ring.filesizeKB}`);
      if (ring.durationSec) args.push("-b", `duration:${ring.durationSec}`);
      if (ring.packets) args.push("-b", `packets:${ring.packets}`);
      if (ring.intervalSec) args.push("-b", `interval:${ring.intervalSec}`);
    }
    return { args, settings: { iface: req.iface, filter, autostop, ring, promiscuous, leftOutPort } };
  }

  /**
   * Packets per second per interface over the last minute. Keeps `dumpcap -S`
   * running while it is asked for and stops it once nobody asks any more.
   */
  activity(): InterfaceActivity {
    this.ensureStats();
    return {
      interval: 1,
      ifaces: Object.fromEntries(this.activityHistory),
      ...(this.statsError ? { error: this.statsError } : {}),
    };
  }

  private ensureStats(): void {
    if (this.statsIdle) clearTimeout(this.statsIdle);
    this.statsIdle = setTimeout(() => this.stopActivity(), ACTIVITY_IDLE_MS);
    this.statsIdle.unref();
    // dumpcap -S opens its interfaces once; restart it when they change (added, removed, re-plugged)
    if (this.statsProc && Date.now() - this.statsCheckedAt > 5000) {
      this.statsCheckedAt = Date.now();
      if (interfaceSignature() !== this.statsSignature) this.restartStats();
    }
    // A failing dumpcap is retried at most every 10 s
    if (this.statsProc || Date.now() - this.statsFailedAt < ACTIVITY_IDLE_MS) return;
    this.statsSignature = interfaceSignature();
    this.statsCheckedAt = Date.now();
    const proc = spawn(this.bin, ["-S", "-M"], { stdio: ["ignore", "pipe", "pipe"] });
    this.statsProc = proc;
    this.statsError = null;
    let partial = "";
    let errTail = "";
    proc.stdout!.setEncoding("utf8");
    proc.stdout!.on("data", (chunk: string) => {
      if (this.statsProc !== proc) return;
      const lines = (partial + chunk).split("\n");
      partial = lines.pop() ?? "";
      for (const line of lines) this.onStatsLine(line);
    });
    proc.stderr!.setEncoding("utf8");
    proc.stderr!.on("data", (chunk: string) => {
      errTail = (errTail + chunk).slice(-500);
    });
    const failed = (message: string) => {
      if (this.statsProc !== proc) return;
      this.statsProc = null;
      this.statsError = message;
      this.statsFailedAt = Date.now();
      // A respawned dumpcap counts from its own start; old values would show as current
      this.activityTotals.clear();
      this.activityHistory.clear();
    };
    proc.on("error", (err) => failed(err.message));
    proc.on("exit", (code) => failed(errTail.trim().split("\n").pop()?.replace(/^dumpcap:\s*/, "") || `dumpcap -S exited with code ${code}`));
  }

  /** One `name<TAB>received<TAB>dropped` line; counters are cumulative. */
  private onStatsLine(line: string): void {
    const [name, received] = line.split("\t");
    const total = Number(received);
    if (!name || !Number.isFinite(total)) return;
    const last = this.activityTotals.get(name);
    this.activityTotals.set(name, total);
    if (last === undefined) return;
    let delta = total - last;
    // pcap counters are 32 bits; a drop from below 2^31 is a reset, not a wrap
    if (delta < 0) {
      if (last < 2 ** 31) return;
      delta += 2 ** 32;
    }
    const history = this.activityHistory.get(name) ?? [];
    history.push(delta);
    if (history.length > ACTIVITY_SAMPLES) history.shift();
    this.activityHistory.set(name, history);
  }

  /** Replaces dumpcap -S, keeping the history; the new process's first block is only a baseline. */
  private restartStats(): void {
    const proc = this.statsProc;
    this.statsProc = null;
    proc?.kill();
    this.activityTotals.clear();
    this.statsFailedAt = 0;
  }

  stopActivity(): void {
    if (this.statsIdle) clearTimeout(this.statsIdle);
    this.statsIdle = null;
    const proc = this.statsProc;
    this.statsProc = null;
    proc?.kill();
    this.activityTotals.clear();
    this.activityHistory.clear();
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
