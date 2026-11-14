import type { Question } from "./api.ts";

/**
 * The base name of the capture a question's packets belong to when it isn't
 * the open one (its frame numbers are other packets now); null for a question
 * about the open capture, or about no packets.
 */
export function otherCapture(q: Pick<Question, "file" | "frame" | "count">, open: string | null): string | null {
  if (q.file === null || q.frame === null || q.count <= 0 || q.file === open) return null;
  return q.file.split(/[\\/]/).pop() || q.file;
}

/** Where questions without an answer stand, for the page: "not seen by Agent yet", "seen · waiting for the answer", or how many of several are not seen. */
export function waitingState(open: readonly Pick<Question, "seenAt">[], agent: string): string {
  const unseen = open.filter((q) => q.seenAt === null).length;
  if (!unseen) return "seen · waiting for the answer";
  return unseen === open.length ? `not seen by ${agent} yet` : `${unseen} not seen by ${agent} yet`;
}
