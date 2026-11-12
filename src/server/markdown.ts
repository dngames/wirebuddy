/**
 * Escaping for text that comes from captures, notes and comments when it is
 * written into a Markdown file: it must read as the text it is, never render
 * as a link, an image, HTML, a heading, a list, a table break or a code fence.
 * Pure functions, so the format can be pinned by tests.
 */

import { printable } from "./text.ts";

/**
 * `text` as an inline code span on one line: control characters (newlines
 * included) become "?" as in tool results, and the backtick fence is longer
 * than any run of backticks inside, so nothing inside can close it. A span
 * that starts or ends with a backtick, or with a space at both ends, is padded
 * with one space on each side, which Markdown strips again. `inTable`: "|" is
 * written "\|" so it can't end a table cell (a table cell code span reads
 * "\|" as "|"). A table takes a "|" as escaped when an odd number of
 * backslashes stands before it, so backslashes the text has right before a
 * "|" are doubled first: with the one added their number is odd whatever it
 * was (the cell then shows them doubled). Empty text gives "" (an empty span
 * isn't one).
 */
export function codeSpan(text: string, inTable = false): string {
  let t = printable(text);
  if (inTable) t = t.replace(/(\\*)\|/g, (_all, slashes: string) => `${slashes}${slashes}\\|`);
  if (!t) return "";
  let longest = 0;
  for (const run of t.match(/`+/g) ?? []) longest = Math.max(longest, run.length);
  const fence = "`".repeat(longest + 1);
  const pad = t.startsWith("`") || t.endsWith("`") || (t.startsWith(" ") && t.endsWith(" ") && t.trim() !== "") ? " " : "";
  return `${fence}${pad}${t}${pad}${fence}`;
}

/** A table cell holding `text`: a code span with "|" made safe. */
export function cell(text: string): string {
  return codeSpan(text, true);
}

/**
 * Characters Markdown may read as syntax, and "<" and "&" (HTML): a backslash
 * before any of them gives the character itself. ":" only before "/" (no
 * "http://" can be a link), "." and "@" always (no "www." or address links,
 * no "1." lists), "-", "+", "=", "#", ">" and the fence and table characters
 * anywhere (so a line can't start a list, rule, setext heading, heading,
 * quote, fence or table).
 */
const SPECIAL = /[\\`*_{}[\]()#+\-.!|~<>&=@]|:(?=\/)/g;

/** One line of text with Markdown's special characters backslash-escaped; control characters become "?", a tab a space. */
export function escapeLine(line: string): string {
  return printable(line.replace(/\t/g, " ")).replace(SPECIAL, "\\$&");
}

/** A blockquote of `text`, every line escaped (empty lines stay in the quote), line breaks of any kind ending a line. */
export function quote(text: string): string {
  return text
    .split(/\r\n|\r|\n/)
    .map((line) => (line ? `> ${escapeLine(line)}` : ">"))
    .join("\n");
}

/** Longest summary a report takes, in bytes. */
export const MAX_SUMMARY_BYTES = 16 * 1024;

/**
 * The caller's own Markdown, to go into a report as given: refuses control
 * characters but newline and tab (a NUL, a carriage return, an escape
 * sequence) and more than MAX_SUMMARY_BYTES. Returns it without trailing
 * whitespace, or "" when nothing is left.
 */
export function checkSummary(summary: string): string {
  if (/[\u0000-\u0008\u000b-\u001f]/.test(summary)) throw new Error("the summary may not contain control characters other than newline and tab");
  if (Buffer.byteLength(summary) > MAX_SUMMARY_BYTES) throw new Error(`the summary is longer than ${MAX_SUMMARY_BYTES / 1024} KiB`);
  return summary.trimEnd();
}
