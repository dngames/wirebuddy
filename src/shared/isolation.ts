/**
 * Whether a panel runs in a process of its own. Frames of one process share one main thread, so
 * while the panel busy-loops, a page in the same process runs no task at all: a page task that
 * ran inside the panel's busy window proves separate processes. No such task proves nothing
 * (the page may have been busy itself), so only repeated empty rounds count against isolation.
 */

/** Slack at both ends of the busy window, for clock coarsening and message timing. */
export const MARGIN_MS = 5;
/** Answered rounds without a task inside the window that make "not isolated". */
export const EMPTY_ROUNDS = 3;

/** apart: a page task ran inside the window; empty: answered, none did; unanswered: no usable answer (timeout, hidden page). */
export type Round = "apart" | "empty" | "unanswered";
export type Verdict = "isolated" | "not-isolated" | "again";

/** Whether one of the page's task times (ms, wall clock) lies inside [from + margin, to - margin]. */
export function apart(ticks: readonly number[], from: number, to: number, margin = MARGIN_MS): boolean {
  const lo = from + margin;
  const hi = to - margin;
  return lo <= hi && ticks.some((t) => t >= lo && t <= hi);
}

/** What the rounds so far say: one apart is enough; unanswered rounds count for nothing. */
export function verdict(rounds: readonly Round[]): Verdict {
  if (rounds.includes("apart")) return "isolated";
  return rounds.filter((r) => r === "empty").length >= EMPTY_ROUNDS ? "not-isolated" : "again";
}
