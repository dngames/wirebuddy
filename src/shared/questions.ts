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
