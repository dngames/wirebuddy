/**
 * What happens in the viewer, for the agent rather than the user: problems
 * (failed requests, live reload and capture errors, page errors) and what the
 * user does there. The agent gets the events it has not seen with every tool
 * result, and `wirebuddy --watch` waits for the next problem in the
 * background to wake it.
 */

import type { ViewerEvent } from "../shared/api.ts";

const MAX_EVENTS = 500;
/** Events per tool result; older ones are summarised. */
const MAX_TAKE = 30;
/** The same event again within this time counts up the first one. */
const REPEAT_MS = 30_000;

export class EventLog {
  private events: (ViewerEvent & { at: number })[] = [];
  private seq = 0;
  /** Seq of the last event the agent has seen. */
  private seen = 0;
  private waiters = new Set<() => void>();

  /** `onProblems(count)` gets the number of problems the agent has not seen yet. */
  constructor(private readonly onProblems: (count: number) => void = () => {}) {}

  get last(): number {
    return this.seq;
  }

  get taken(): number {
    return this.seen;
  }

  add(level: ViewerEvent["level"], text: string, details?: Record<string, unknown>): void {
    const now = Date.now();
    const prev = this.events[this.events.length - 1];
    if (prev && prev.text === text && prev.level === level && now - prev.at < REPEAT_MS && prev.seq > this.seen) {
      prev.repeated = (prev.repeated ?? 1) + 1;
      prev.at = now;
      if (details) prev.details = details;
    } else {
      this.events.push({ seq: ++this.seq, time: new Date(now).toISOString(), level, text, details, at: now });
      this.events.splice(0, Math.max(0, this.events.length - MAX_EVENTS));
    }
    for (const wake of this.waiters) wake();
    if (level !== "INFO") this.onProblems(this.pending());
  }

  /** Events after `after`, waiting up to `waitMs` for one (only problems with `problemsOnly`). */
  async since(after: number, waitMs: number, problemsOnly: boolean): Promise<{ events: ViewerEvent[]; last: number }> {
    const find = () => this.events.filter((e) => e.seq > after && (!problemsOnly || e.level !== "INFO")).map(publicEvent);
    let found = find();
    if (!found.length && waitMs > 0) {
      await new Promise<void>((resolve) => {
        const done = (): void => {
          clearTimeout(timer);
          this.waiters.delete(check);
          resolve();
        };
        const check = (): void => {
          if (find().length) done();
        };
        const timer = setTimeout(done, waitMs);
        this.waiters.add(check);
      });
      found = find();
    }
    return { events: found, last: this.seq };
  }

  /** The events the agent has not seen (the newest MAX_TAKE), marked seen. */
  take(): ViewerEvent[] {
    let found = this.events.filter((e) => e.seq > this.seen).map(publicEvent);
    this.seen = this.seq;
    this.onProblems(0);
    if (found.length > MAX_TAKE) {
      const skipped = found.slice(0, -MAX_TAKE);
      const problems = skipped.filter((e) => e.level !== "INFO").length;
      const note: ViewerEvent = { seq: 0, time: skipped[skipped.length - 1].time, level: "INFO", text: `${skipped.length} earlier events not shown (${problems} problems)` };
      found = [note, ...found.slice(-MAX_TAKE)];
    }
    return found;
  }

  pending(): number {
    return this.events.filter((e) => e.seq > this.seen && e.level !== "INFO").length;
  }
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
