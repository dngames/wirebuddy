/**
 * What happens in the viewer, for the agent rather than the user: problems
 * (failed requests, live reload and capture errors, page errors), what the
 * user does there and the questions the user asks it. The agent gets the
 * events it has not seen with every tool result, and `wirebuddy --watch`
 * waits for the next problem or question in the background to wake it.
 */

import type { ViewerEvent } from "../shared/api.ts";
import { printable } from "./text.ts";

const MAX_EVENTS = 500;
/** Events per tool result; older ones are summarised. */
const MAX_TAKE = 30;
/** The same event again within this time counts up the first one. */
const REPEAT_MS = 30_000;
/** A watcher between two long polls still counts as watching for this long. */
const WATCH_GAP_MS = 3_000;
/** Unseen questions the log keeps beyond MAX_EVENTS. */
const MAX_KEPT_QUESTIONS = 100;

/** An error the agent already heard about as an event: its request's failure isn't logged again. */
export class ReportedError extends Error {}

export class EventLog {
  private events: (ViewerEvent & { at: number })[] = [];
  private seq = 0;
  /** Seq of the last event the agent has seen. */
  private seen = 0;
  private waiters = new Set<() => void>();
  /** Waiting `--watch` long polls, and when the last one timed out. */
  private watchers = 0;
  private watchedAt = 0;
  private watching = false;

  /**
   * `onProblems(count)` gets the number of problems the agent has not seen
   * yet, `onWatching(on)` whether a `--watch` waits for the next problem or
   * question.
   */
  constructor(
    private readonly onProblems: (count: number) => void = () => {},
    private readonly onWatching: (on: boolean) => void = () => {},
  ) {}

  get last(): number {
    return this.seq;
  }

  get taken(): number {
    return this.seen;
  }

  add(level: ViewerEvent["level"], text: string, details?: Record<string, unknown>): void {
    // One line each: a file name can't pose as another event
    text = printable(text);
    const now = Date.now();
    const prev = this.events[this.events.length - 1];
    // Questions stay apart: the same words may be about other packets
    if (prev && level !== "QUESTION" && prev.text === text && prev.level === level && now - prev.at < REPEAT_MS && prev.seq > this.seen) {
      prev.repeated = (prev.repeated ?? 1) + 1;
      prev.at = now;
      if (details) prev.details = details;
    } else {
      this.events.push({ seq: ++this.seq, time: new Date(now).toISOString(), level, text, details, at: now });
      let drop = this.events.length - MAX_EVENTS;
      // The newest unseen questions stay until the agent takes them
      if (drop > 0) {
        const kept = new Set(
          this.events
            .filter((e) => e.level === "QUESTION" && e.seq > this.seen)
            .slice(-MAX_KEPT_QUESTIONS)
            .map((e) => e.seq),
        );
        this.events = this.events.filter((e) => {
          if (drop === 0 || kept.has(e.seq)) return true;
          drop--;
          return false;
        });
      }
    }
    for (const wake of this.waiters) wake();
    if (isProblem(level)) this.onProblems(this.pending());
  }

  /**
   * Events after `after`, waiting up to `waitMs` for one (only problems and
   * questions with `wakersOnly`, which is how `--watch` waits); `signal` ends
   * the wait when the request goes away.
   */
  async since(after: number, waitMs: number, wakersOnly: boolean, signal?: AbortSignal): Promise<{ events: ViewerEvent[]; last: number }> {
    const find = () => this.events.filter((e) => e.seq > after && (!wakersOnly || e.level !== "INFO")).map(publicEvent);
    let found = find();
    // A watcher that finds something at once exits with it
    if (found.length && wakersOnly && waitMs > 0) {
      this.watchedAt = 0;
      this.updateWatching();
    }
    if (!found.length && waitMs > 0 && !signal?.aborted) {
      if (wakersOnly) {
        this.watchers++;
        this.updateWatching();
      }
      await new Promise<void>((resolve) => {
        const done = (why: "timeout" | "event" | "gone"): void => {
          clearTimeout(timer);
          this.waiters.delete(check);
          signal?.removeEventListener("abort", gone);
          if (wakersOnly) {
            this.watchers--;
            // One that timed out polls again at once; a woken one exits, a gone one is gone
            if (why === "timeout") {
              this.watchedAt = Date.now();
              setTimeout(() => this.updateWatching(), WATCH_GAP_MS + 50).unref();
            } else this.watchedAt = 0;
            this.updateWatching();
          }
          resolve();
        };
        const check = (): void => {
          if (find().length) done("event");
        };
        const gone = (): void => done("gone");
        const timer = setTimeout(() => done("timeout"), waitMs);
        this.waiters.add(check);
        signal?.addEventListener("abort", gone, { once: true });
      });
      found = find();
    }
    return { events: found, last: this.seq };
  }

  /** The events the agent has not seen (the newest MAX_TAKE and every question), marked seen. */
  take(): ViewerEvent[] {
    let found = this.events.filter((e) => e.seq > this.seen).map(publicEvent);
    this.seen = this.seq;
    this.onProblems(0);
    if (found.length > MAX_TAKE) {
      const skipped = found.slice(0, -MAX_TAKE);
      const questions = skipped.filter((e) => e.level === "QUESTION");
      const problems = skipped.filter((e) => isProblem(e.level)).length;
      const others = skipped.length - questions.length;
      const note: ViewerEvent = { seq: 0, time: skipped[skipped.length - 1].time, level: "INFO", text: `${others} earlier events not shown (${problems} problems)` };
      found = [...(others ? [note] : []), ...questions, ...found.slice(-MAX_TAKE)];
    }
    return found;
  }

  /** Problems the agent has not seen. */
  pending(): number {
    return this.events.filter((e) => e.seq > this.seen && isProblem(e.level)).length;
  }

  /** Whether a `--watch` is waiting, so the next problem or question wakes the agent at once. */
  watched(): boolean {
    return this.watchers > 0 || Date.now() - this.watchedAt < WATCH_GAP_MS;
  }

  private updateWatching(): void {
    const on = this.watched();
    if (on === this.watching) return;
    this.watching = on;
    this.onWatching(on);
  }
}

function isProblem(level: ViewerEvent["level"]): boolean {
  return level === "WARNING" || level === "ERROR";
}

function publicEvent(e: ViewerEvent & { at: number }): ViewerEvent {
  const { at: _at, ...rest } = e;
  return rest;
}

/** Events as lines for the agent: "12:01:02 ERROR Opening failed: … (2×)". */
export function eventLines(events: ViewerEvent[]): string[] {
  return events.map((e) => {
    const time = e.time.slice(11, 19);
    const details = e.details && Object.keys(e.details).length ? ` ${JSON.stringify(e.details)}` : "";
    return `${time} ${e.level} ${e.text}${e.repeated ? ` (${e.repeated}×)` : ""}${details}`;
  });
}
