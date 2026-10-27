import { execFile, spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { closeSync, fstatSync, openSync, readSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

const run = promisify(execFile);

/** How long a new Wireshark is watched for a failed start. */
const STARTUP_MS = 1500;
/** Extra wait when its output already shows a fatal error. */
const CRASH_WAIT_MS = 4000;
const FATAL = /\b(ERROR|CRITICAL)\] -- /;

/** What a GUI program needs to reach the desktop session. */
const SESSION_VARS = ["DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS", "XDG_SESSION_TYPE"];

/**
 * Environment for Wireshark. MCP clients may start WireBuddy with a minimal
 * environment without a display, which makes Wireshark abort at startup, so
 * on Linux the desktop session's variables come from the systemd user manager.
 */
export async function desktopEnvironment(env: NodeJS.ProcessEnv = process.env): Promise<NodeJS.ProcessEnv> {
  if (process.platform !== "linux" || env.DISPLAY || env.WAYLAND_DISPLAY) return env;
  const out = { ...env };
  for (const [name, value] of await userManagerEnvironment(env)) if (SESSION_VARS.includes(name) && !out[name]) out[name] = value;
  if (!out.DISPLAY && !out.WAYLAND_DISPLAY) {
    throw new Error("no desktop session to show Wireshark in: WireBuddy runs without DISPLAY or WAYLAND_DISPLAY");
  }
  return out;
}

async function userManagerEnvironment(env: NodeJS.ProcessEnv): Promise<[string, string][]> {
  // systemctl finds the user manager through XDG_RUNTIME_DIR, which may be missing too
  const runtimeDir = env.XDG_RUNTIME_DIR || `/run/user/${process.getuid?.()}`;
  try {
    const { stdout: text } = await run("systemctl", ["--user", "show-environment"], {
      encoding: "utf8",
      timeout: 3000,
      env: { ...env, XDG_RUNTIME_DIR: runtimeDir },
    });
    // Values that need quoting come escaped as $'…'; the session variables never do
    return text
      .split("\n")
      .map((line) => /^([A-Z_][A-Z0-9_]*)=([^\s'"$\\]+)$/.exec(line))
      .filter((m): m is RegExpExecArray => m !== null)
      .map((m) => [m[1], m[2]]);
  } catch {
    return [];
  }
}

/**
 * Starts Wireshark detached and watches it briefly, so a failed start (no
 * display, unknown profile) is reported with Wireshark's own message.
 */
export async function launchWireshark(bin: string, args: string[]): Promise<void> {
  const env = await desktopEnvironment();
  const fd = openLog();
  try {
    const child = spawn(bin, args, { detached: true, stdio: ["ignore", "ignore", fd ?? "ignore"], env });
    await new Promise<void>((resolve, reject) => {
      const settle = (err?: Error) => {
        clearTimeout(timer);
        child.removeAllListeners("exit");
        if (err) reject(err);
        else resolve();
      };
      let extended = false;
      const watch = (): void => {
        // A crash reporter (apport) can hold a dying Wireshark for seconds: wait for it once
        if (!extended && fd !== null && FATAL.test(readTail(fd))) {
          extended = true;
          timer = setTimeout(watch, CRASH_WAIT_MS);
        } else settle();
      };
      let timer = setTimeout(watch, STARTUP_MS);
      // Stays for Wireshark's lifetime: an unhandled "error" would end WireBuddy
      child.on("error", (err) => settle(err));
      child.on("exit", (code, signal) => settle(code === 0 ? undefined : startupError(fd === null ? "" : readTail(fd), code, signal)));
    });
    child.unref();
  } finally {
    if (fd !== null) closeSync(fd);
  }
}

/** Startup log, unlinked at once; null when the temp folder is unusable (then without error text). */
function openLog(): number | null {
  // A file, not a pipe: Wireshark keeps logging after WireBuddy is gone
  const log = join(tmpdir(), `wirebuddy-wireshark-${randomBytes(6).toString("hex")}.log`);
  try {
    const fd = openSync(log, "w+", 0o600);
    // Gone from the directory at once; Wireshark and this process keep their handles
    rmSync(log, { force: true });
    return fd;
  } catch {
    return null;
  }
}

/** The last 64 KiB: a fatal message comes last. */
function readTail(fd: number): string {
  const size = fstatSync(fd).size;
  const start = Math.max(0, size - 64 * 1024);
  const buf = Buffer.alloc(size - start);
  const text = buf.subarray(0, readSync(fd, buf, 0, buf.length, start)).toString("utf8");
  // Starting mid-file: drop the cut-off first line
  return start > 0 ? text.slice(text.indexOf("\n") + 1) : text;
}

function startupError(output: string, code: number | null, signal: NodeJS.Signals | null): Error {
  const lines = output.split("\n").map((l) => l.trim()).filter(Boolean);
  // Wireshark's own errors first, e.g. "[GUI ERROR] -- …" or "wireshark: Configuration Profile …"
  const line = lines.find((l) => FATAL.test(l) || l.startsWith("wireshark: ")) ?? lines[lines.length - 1];
  const reason = line?.replace(/^\*\* \(wireshark:\d+\) [\d:.]+ \[[^\]]*\] -- |^wireshark: /, "");
  const how = signal ? `crashed (${signal})` : `exited with code ${code}`;
  return new Error(`Wireshark ${how} at startup${reason ? `: ${reason.slice(0, 300)}` : ""}`);
}
