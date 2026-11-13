/**
 * Packet comments as the view shows them: the ones edited here in place of
 * the capture file's, read for the frames asked about, merged into the list's
 * rows and into a packet's details as Wireshark's "Packet comments" node.
 */

import { toRanges } from "./export.ts";
import type { LiveTail, RowView } from "./livetail.ts";
import { page, type Sharkd } from "./sharkd.ts";
import type { SharkdRow } from "./viewer.ts";
import type { PacketRow, TreeNode } from "../shared/api.ts";
import { hasFrame } from "../shared/ranges.ts";

/** Lines of a comment the details list, as Wireshark's frame.max_comment_lines. */
const COMMENT_LINES = 30;
/** Ranges of frames whose comments are read one by one, however big the capture. */
const COMMENT_READS = 20;
/** Frames a search for the commented ones costs about as much as reading one range's comments. */
const COMMENT_READ_FRAMES = 100;
/** Comments the list's rows carry, and characters of each. */
const ROW_COMMENTS = 5;
const ROW_COMMENT = 300;
/** Wireshark's longest item label, in bytes. */
const ITEM_LABEL_LENGTH = 240;

/**
 * A packet's comments as edited in the viewer, in place of the file's: the
 * first `own` of `list` are the file's own ones, all of them, unchanged (-1:
 * they aren't).
 */
export interface EditedComments {
  list: string[];
  own: number;
}

/** The comments edited here, and the last frame whose comments were all dropped (frames up to it have none). */
export interface Edited {
  comments: ReadonlyMap<number, EditedComments>;
  cleared: number;
}

/** What reading comments needs of the viewer. */
export interface CommentsView {
  /** Frames read in full. */
  totalFrames(): number;
  /** Whether the frames with comments in the file are known for the full read now. */
  fileCommentsKnown(): boolean;
  fileCommented(): Promise<Int32Array>;
  engine(): Sharkd;
  listedTail(): LiveTail | null;
  rowView(): Promise<RowView>;
}

/** The comments `frames` (frames the view knows, ascending) have now: as edited here, else the file's. */
export async function commentsOf(v: CommentsView, edits: Edited, frames: number[]): Promise<Map<number, EditedComments>> {
  const out = new Map<number, EditedComments>();
  const file = (f: number, list: string[]): void => void out.set(f, { list, own: list.length });
  const read = v.totalFrames();
  const exact: number[] = [];
  const later: number[] = [];
  for (const f of frames) {
    const edited = edits.comments.get(f);
    if (edited) out.set(f, edited);
    else if (f <= edits.cleared) out.set(f, { list: [], own: 0 });
    else (f <= read ? exact : later).push(f);
  }
  let ranges = toRanges(exact);
  // Many ranges of a small capture: only the frames with comments are read
  if (ranges.length > COMMENT_READS && (v.fileCommentsKnown() || ranges.length * COMMENT_READ_FRAMES > read)) {
    const commented = await v.fileCommented();
    for (const f of exact) file(f, []);
    ranges = toRanges(exact.filter((f) => hasFrame(commented, f)));
  }
  const engine = v.engine();
  for (const [a, b] of ranges) {
    for (const r of await engine.call<SharkdRow[]>("frames", { ...page(a - 1, b - a + 1), column0: "frame.number:0" })) file(r.num, r.comments ?? []);
  }
  const tail = v.listedTail();
  if (later.length && tail) for (const r of await tail.rowsOf(later, await v.rowView())) file(r.num, r.cm ?? []);
  return out;
}

/** The comments edited here in place of frame `num`'s, or null. */
function editedOf(edits: Edited, num: number): string[] | null {
  return edits.comments.get(num)?.list ?? (num <= edits.cleared ? [] : null);
}

/** `rows` with their comments as edited here; `short`: as the list's rows carry them. */
export function withComments(rows: PacketRow[], edits: Edited, short = false): PacketRow[] {
  if (!edits.comments.size && !edits.cleared && !short) return rows;
  return rows.map((r) => {
    const { cm: file, ...row } = r;
    const cm = editedOf(edits, r.num) ?? file;
    if (!cm?.length) return row;
    return { ...row, cm: short ? cm.slice(0, ROW_COMMENTS).map((c) => (c.length > ROW_COMMENT ? `${c.slice(0, ROW_COMMENT - 1)}…` : c)) : cm };
  });
}

/** Frame `num`'s `tree` with its comments as edited here, in Wireshark's "Packet comments" node. */
export function withCommentNode(num: number, tree: TreeNode[], edits: Edited, ett: { node: number; item: number }): TreeNode[] {
  const node = tree.find((n) => n.fn === "pkt_comment");
  // As sharkd's own comment nodes expand
  if (node?.e !== undefined) ett.node = node.e;
  const item = node?.n?.find((n) => n.e !== undefined);
  if (item?.e !== undefined) ett.item = item.e;
  const cm = editedOf(edits, num);
  if (!cm) return tree;
  const rest = tree.filter((n) => n !== node);
  return cm.length ? [commentTree(cm, ett), ...rest] : rest;
}

/**
 * Wireshark's "Packet comments" node: a comment of several lines shows its
 * first line, and each line under it. `ett`: the expansion ids of the node
 * and of its comments.
 */
export function commentTree(comments: string[], ett: { node: number; item: number }): TreeNode {
  const line = (text: string): TreeNode => ({ l: labelText(text), f: `frame.comment == ${filterString(text)}`, fn: "frame.comment" });
  const comment = (text: string): TreeNode => {
    const lines = text.split("\n");
    if (lines.length === 1) return { ...line(text), s: "Comment", e: ett.item, n: [] };
    if (lines[lines.length - 1] === "") lines.pop();
    const n = lines.slice(0, COMMENT_LINES).map(line);
    if (lines.length > COMMENT_LINES) n.push({ l: `[comment truncated at ${COMMENT_LINES} lines]`, f: 'frame.comment == ""', fn: "frame.comment" });
    return { ...line(lines[0]), l: labelText(`${lines[0]} [...]`), s: "Comment", e: ett.item, n };
  };
  return { l: "Packet comments", t: "proto", f: "pkt_comment", fn: "pkt_comment", s: "Comment", e: ett.node, n: comments.map(comment) };
}

/** Escapes of control characters, as Wireshark writes them. */
const ESCAPES: Record<string, string> = { "\u0007": "a", "\b": "b", "\f": "f", "\n": "n", "\r": "r", "\t": "t", "\v": "v" };

/**
 * `text` as sharkd labels it: control characters escaped (\t, \x01, \u0085),
 * and cut to Wireshark's label length as proto.c does, behind "[…] ".
 */
function labelText(text: string): string {
  const label = text.replace(/[\u0000-\u001f\u007f-\u009f]/g, (c) => {
    const code = c.charCodeAt(0);
    return `\\${ESCAPES[c] ?? `${code < 0x80 ? "x" : "u00"}${code.toString(16).toUpperCase().padStart(2, "0")}`}`;
  });
  const bytes = Buffer.from(label);
  if (bytes.length < ITEM_LABEL_LENGTH) return label;
  // The mark goes first, and the last character in the buffer, whole or not, goes
  const cut = Buffer.concat([Buffer.from("[…] "), bytes.subarray(0, ITEM_LABEL_LENGTH - 6)]);
  let end = ITEM_LABEL_LENGTH - 1;
  while (end > 0 && (cut[end] & 0xc0) === 0x80) end--;
  return cut.subarray(0, end).toString();
}

/** `text` as a display filter string, escaped as Wireshark does. */
function filterString(text: string): string {
  return `"${text.replace(/[\u0007\b\f\n\r\t\v\\"]/g, (c) => `\\${ESCAPES[c] ?? c}`)}"`;
}
