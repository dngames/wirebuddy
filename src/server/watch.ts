/**
 * `wirebuddy --watch <instance file>`: waits for the running viewer's next
 * problem or question for the agent, prints it with what the user did since
 * the agent last looked, and exits. An agent runs it as a background command
 * to be woken when the user runs into trouble or asks it something.
 */

import { chmodSync, existsSync, lstatSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import type { ViewerEvent } from "../shared/api.ts";
import { eventLines } from "./events.ts";

/** One long-poll request; the watcher loops until a problem or question comes. */
const POLL_MS = 50_000;

interface Instance {
  url: string;
  pid: number;
}

/**
 * Where this server publishes its URL and token for the watcher: the user's
 * runtime folder, else a folder of the user's own in the shared temp folder.
 */
export function instanceFile(): string {
  const uid = process.getuid?.();
  const runtime = process.env.XDG_RUNTIME_DIR || (uid !== undefined && existsSync(`/run/user/${uid}`) ? `/run/user/${uid}` : null);
  const dir = runtime ? join(runtime, "wirebuddy") : join(tmpdir(), uid === undefined ? "wirebuddy" : `wirebuddy-${uid}`);
  return join(dir, `${process.pid}.json`);
}

/**
 * Writes the instance file so that only the user can read it: its folder must
 * be the user's own (no link, no one else's), and the file is made anew, so a
 * file or link someone left under its name is never written through.
 */
export function writeInstance(file: string, url: string): void {
  const dir = dirname(file);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const st = lstatSync(dir);
  const uid = process.getuid?.();
  if (!st.isDirectory()) throw new Error(`${dir} is not a folder`);
  if (uid !== undefined && st.uid !== uid) throw new Error(`${dir} belongs to another user`);
  if (uid !== undefined && st.mode & 0o077) chmodSync(dir, 0o700);
  rmSync(file, { force: true });
  writeFileSync(file, JSON.stringify({ url, pid: process.pid } satisfies Instance), { mode: 0o600, flag: "wx" });
}

export function removeInstance(file: string): void {
  rmSync(file, { force: true });
}

export async function watch(file: string, out: (line: string) => void = (l) => console.log(l)): Promise<number> {
  let instance: Instance;
  try {
    instance = JSON.parse(readFileSync(file, "utf8")) as Instance;
    process.kill(instance.pid, 0);
  } catch {
    out("WireBuddy is not running.");
    return 3;
  }
  const base = new URL(instance.url);
  const call = async <T>(path: string, init?: RequestInit): Promise<T> => {
    const res = await fetch(new URL(path, base.origin), {
      ...init,
      headers: { "X-WireBuddy-Token": base.searchParams.get("token") ?? "", "content-type": "application/json" },
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return (await res.json()) as T;
  };
  type Since = { events: ViewerEvent[]; last: number; taken: number };
  try {
    // From what the agent saw last: a problem or question since its last tool call wakes it at once
    let after = (await call<Since>(`/api/events?after=${Number.MAX_SAFE_INTEGER}`)).taken;
    for (;;) {
      const r = await call<Since>(`/api/events?after=${after}&wait=${POLL_MS}&problems=1`);
      if (r.events.length) {
        const { events } = await call<{ events: ViewerEvent[] }>("/api/events/take", { method: "POST", body: "{}" });
        for (const line of eventLines(events)) out(line);
        return 0;
      }
      after = r.last;
    }
  } catch {
    out("WireBuddy stopped running.");
    return 3;
  }
}
