/**
 * `wirebuddy --watch <instance file>`: waits for the running viewer's next
 * problem or question for the agent, prints it with what the user did since
 * the agent last looked, and exits. An agent runs it as a background command
 * to be woken when the user runs into trouble or asks it something.
 */

import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ViewerEvent } from "../shared/api.ts";
import { eventLines } from "./events.ts";

/** One long-poll request; the watcher loops until a problem or question comes. */
const POLL_MS = 50_000;

interface Instance {
  url: string;
  pid: number;
}

/** Where this server publishes its URL and token for the watcher (only the user can read it). */
export function instanceFile(): string {
  return join(process.env.XDG_RUNTIME_DIR || tmpdir(), "wirebuddy", `${process.pid}.json`);
}

export function writeInstance(file: string, url: string): void {
  mkdirSync(join(file, ".."), { recursive: true, mode: 0o700 });
  writeFileSync(file, JSON.stringify({ url, pid: process.pid } satisfies Instance), { mode: 0o600 });
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
