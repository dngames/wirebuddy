/**
 * What Wireshark's own message for a display filter can't tell. The
 * members of a set take commas: with spaces, it blames the second member
 * ("430" was unexpected in this context), not the missing comma.
 */
export function setHint(filter: string): string {
  // A quoted string, else a set (which may hold quoted strings)
  for (const m of filter.matchAll(/"(?:\\.|[^"\\])*"|\{((?:"(?:\\.|[^"\\])*"|[^{}"])*)\}/g)) {
    if (m[1] === undefined) continue;
    // Members and commas; a range may have spaces around its dots
    const tokens = m[1].replace(/\s*\.\.\s*/g, "..").match(/"(?:\\.|[^"\\])*"|,|[^\s,"]+/g) ?? [];
    const members = tokens.filter((t) => t !== ",");
    if (tokens.some((t, i) => i && t !== "," && tokens[i - 1] !== ",")) return ` (separate the members of a set with commas: {${members.join(", ")}})`;
  }
  return "";
}
