import type { ProvisionalTail } from "./api.ts";

/**
 * Seconds until provisional packets turn exact with the next full read, at
 * `now` (epoch ms): the rest of the read under way, else a whole read. A
 * read that takes longer than the last one did has no estimate (null).
 */
export function secondsToExact(t: Pick<ProvisionalTail, "readMs" | "readingSince">, now: number): number | null {
  if (t.readingSince === null) return Math.max(1, Math.round(t.readMs / 1000));
  const left = t.readMs - (now - t.readingSince);
  return left > 500 ? Math.round(left / 1000) || 1 : null;
}
