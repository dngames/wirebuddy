/**
 * The two sharkd instances the view reads with, and how a capture gets into
 * one: the active engine answers queries while the standby reads the file
 * again, then the Viewer swaps them. The session runs state-changing work one
 * at a time, loads a file with a fallback for a filter that no longer applies
 * and a rollback of the extensions when they crash sharkd, retries a load
 * after each extension that crashed it, and remembers the dissection
 * preferences every engine reads with. What happens on an engine (failures,
 * Lua reports and errors) goes to hooks the Viewer gives; when to load, into
 * which engine, and what a load means for the view is the Viewer's.
 */

import { basename } from "node:path";
import { matchingFrames, SharkdError, SharkdExit, type LuaError, type LuaReport, type Sharkd } from "./sharkd.ts";
import { printable } from "./text.ts";
import { refTimeFilter } from "./timerefs.ts";

/** Loads tried again after extensions crashed sharkd (each crash switches one off). */
const MAX_CRASH_RETRIES = 10;
/** How long requests in flight may finish before their sharkd restarts with new extensions. */
export const RESTART_WAIT_MS = 10_000;

/** How a load got past a sharkd crash: back to the extensions before their last change, or without any. */
export type RollBack = false | "reverted" | "suspended";

export interface SharkdStatus {
  frames: number;
  duration?: number;
  filesize?: number;
  columns: string[];
  /** Column formats: %m the number, %i Info, %Cus:<field>:... a field. */
  column_info?: { format: string }[];
}

/** What a load found: the status, the frames `filter` shows (null: all), the filter it applied, and how it got past a crash. */
export interface LoadResult {
  status: SharkdStatus;
  displayed: Int32Array | null;
  filter: string;
  rolledBack: RollBack;
}

/** What happens on each engine, for the Viewer to tell. */
export interface EngineHooks {
  /** sharkd died or hung (see Sharkd.onFailure). */
  onFailure(message: string): void;
  /** Lua loading is over; a report with `crashedIn` has counted as a crash already. */
  onLua(report: LuaReport): void;
  onLuaError(error: LuaError): void;
}

/** The extensions as a load that crashed sharkd goes back on them. */
export interface LoadExtensions<S = unknown> {
  any(): boolean;
  /** The loaded set as it is now, for restore(). */
  saved(): S;
  /** Back to before the last change; false if there is none. */
  revert(): boolean;
  /** Without any until they are reloaded. */
  suspend(): void;
  restore(saved: S): void;
}

/** What loading reads of the view, and where it tells what it did. */
export interface LoadContext {
  extensions: LoadExtensions;
  /** The view's columns count Cumulative Bytes (%B). */
  cumulativeBytes(): boolean;
  /** A load got past a crash by going back on the extensions. */
  problem(text: string): void;
}

export interface LoadOptions {
  /** A filter that doesn't compile (its protocol is gone) is dropped: the result's `filter` is "". */
  fallback?: boolean;
  /** The engine read the only copy, so a kill (SIGKILL) is the memory running out, not an extension. */
  inPlace?: boolean;
  /** Without it, a crash is rethrown at once, not blamed on the extensions. */
  rollback?: boolean;
}

export class EngineSession {
  private readonly engines: [Sharkd, Sharkd];
  private index = 0;
  private mutation: Promise<unknown> = Promise.resolve();
  /** sharkd starts an extension crashed; a load is retried after each. */
  private crashes = 0;
  /** Preferences WireBuddy set for dissection (TLS key log, Decode As), for every sharkd; one turned off holds "". */
  private readonly dissectPrefs = new Map<string, string>();

  /** `make` starts each of the two engines; `hooks` hears what happens on them. */
  constructor(
    make: () => Sharkd,
    hooks: EngineHooks,
    private readonly context: LoadContext,
  ) {
    this.engines = [make(), make()];
    for (const e of this.engines) {
      e.onFailure = (message) => hooks.onFailure(message);
      e.onLua = (report) => {
        if (report.crashedIn) this.crashes++;
        hooks.onLua(report);
      };
      e.onLuaError = (error) => hooks.onLuaError(error);
    }
  }

  /** The engine that answers the view's queries. */
  get active(): Sharkd {
    return this.engines[this.index];
  }

  /** The other one, free to read the file again. */
  get standby(): Sharkd {
    return this.engines[1 - this.index];
  }

  /** Makes `to` (by default the standby) the active engine. */
  swap(to: Sharkd = this.standby): void {
    const i = this.engines.indexOf(to);
    if (i < 0) throw new Error("not an engine of this session");
    this.index = i;
  }

  /** Runs state-changing work one at a time: `fn` after everything queued before it, whatever happened to those. */
  exclusive<T>(fn: () => Promise<T>): Promise<T> {
    const next = this.mutation.then(fn, fn);
    this.mutation = next.catch(() => {});
    return next;
  }

  /**
   * Loads `file` into `engine` and computes the displayed frames for `filter`
   * (frame.ref_time: the time references `refs`); see LoadOptions for
   * `fallback`, `inPlace` and `rollback`.
   */
  async load(engine: Sharkd, file: string, filter: string, refs: readonly number[], { fallback = false, inPlace = false, rollback = true }: LoadOptions = {}): Promise<LoadResult> {
    const extensions = this.context.extensions;
    const memory = (err: unknown): boolean => inPlace && err instanceof SharkdExit && err.signal === "SIGKILL";
    const once = (dropFilter: boolean) =>
      this.crashRetries(async (): Promise<LoadResult> => {
        await this.current(engine, true);
        const load = await engine.call<{ status: string; err?: number }>("load", { file });
        // A file still being written ends mid-packet; sharkd reports that but keeps what it read.
        if (load.status !== "OK" && load.err !== -12) throw new Error(load.status);
        const status = await engine.call<SharkdStatus>("status");
        if (!filter) return { status, displayed: null, filter, rolledBack: false };
        try {
          return { status, displayed: await matchingFrames(engine, refTimeFilter(filter, refs)), filter, rolledBack: false };
        } catch (err) {
          if (!(err instanceof SharkdError) || !dropFilter) throw err;
          return { status, displayed: null, filter: "", rolledBack: false };
        }
      });
    try {
      return await once(fallback);
    } catch (err) {
      if (!(err instanceof SharkdExit) || !rollback || !extensions.any() || memory(err)) throw err;
      // Without the extensions' last change, then without any; if it still dies, they weren't the cause
      const before = extensions.saved();
      const steps: [RollBack, () => boolean, string][] = [
        ["reverted", () => extensions.revert(), "without the last change to the extensions"],
        ["suspended", () => (extensions.suspend(), true), "without extensions until they are reloaded"],
      ];
      for (const [kind, step, how] of steps) {
        if (!step()) continue;
        try {
          // A filter on a protocol that went with the extensions would fail every later reload
          const result = await once(true);
          const cleared = result.filter !== filter ? `; the display filter "${filter}" was cleared` : "";
          this.context.problem(`sharkd crashed reading ${basename(file)} with the extensions (${printable(err.message)}), so it reads it ${how}${cleared}. Test the extensions to find the one at fault (extensions action "test")`);
          return { ...result, rolledBack: kind };
        } catch (again) {
          if (!(again instanceof SharkdExit) || memory(again)) {
            extensions.restore(before);
            throw again;
          }
        }
      }
      extensions.restore(before);
      throw err;
    }
  }

  /** Runs `fn` again after each extension that crashed sharkd while loading (it is off then). */
  async crashRetries<T>(fn: () => Promise<T>): Promise<T> {
    for (let attempt = 0; ; attempt++) {
      const crashes = this.crashes;
      try {
        return await fn();
      } catch (err) {
        if (this.crashes === crashes || attempt >= MAX_CRASH_RETRIES) throw err;
      }
    }
  }

  /**
   * Restarts an engine that runs other extensions than the current ones, or
   * (`load`: before it reads a capture) one that would count Cumulative
   * Bytes on from the capture it read before; once its requests are done.
   */
  async current(engine: Sharkd, load = false): Promise<void> {
    if (!engine.outdated() && !(load && engine.loaded && this.context.cumulativeBytes())) return;
    await engine.idle(RESTART_WAIT_MS);
    engine.restart();
  }

  /** Remembers a dissection preference for every engine and sets it in both. */
  async setPref(name: string, value: string): Promise<void> {
    this.dissectPrefs.set(name, value);
    await Promise.all(this.engines.map((e) => e.setPref(name, value)));
  }

  /** The dissection preferences set so far, for engines started elsewhere. */
  prefs(): ReadonlyMap<string, string> {
    return this.dissectPrefs;
  }

  /** A restarted engine needn't read the closed file again. */
  forgetFile(): void {
    for (const e of this.engines) e.forgetFile();
  }

  close(): void {
    for (const e of this.engines) e.close();
  }
}
