/**
 * What the user and the agent lay over a capture and keep with it: marks,
 * time references and packet comments edited in the viewer. Marks and time
 * references live in the view's state; the functions here work out their
 * next values from a request. The comments edited here live in Edits: it
 * stands them in for the file's, counts what an export to pcapng hasn't
 * written yet, runs their edits one at a time and drops them with their
 * capture. What a change means for the view's state comes back as a patch
 * for the viewer to apply; what Edits needs to read (the file's own
 * comments, the frames the view knows) is handed to it.
 */

import type { Edited, EditedComments } from "./comments.ts";
import type { FrameComments } from "./export.ts";
import type { Investigation, InvestigationLimits } from "./investigation.ts";
import { StaleGenerationError } from "./stale.ts";
import { printable } from "./text.ts";
import { MAX_TIME_REFS, refsUpTo } from "./timerefs.ts";
import type { Mark, TimeRefsChange, TreeNode, ViewState } from "../shared/api.ts";
import { countRanges, hasFrame, inRanges, type Ranges } from "../shared/ranges.ts";

export const MAX_MARKS = 10000;
/** Characters of a mark's note. */
export const MAX_NOTE = 200;
/** Packets whose comments the viewer holds edited. */
export const MAX_COMMENTED = 10_000;
/** Characters of a comment written in the viewer. */
export const MAX_COMMENT = 2000;
/** What an investigation read back may hold: what the view can. */
export const EDIT_LIMITS: InvestigationLimits = { marks: MAX_MARKS, note: MAX_NOTE, timeRefs: MAX_TIME_REFS, commented: MAX_COMMENTED, comment: MAX_COMMENT };

const byFrame = (a: Mark, b: Mark): number => a.frame - b.frame;
const tooManyMarks = (): Error => new Error(`at most ${MAX_MARKS} frames can be marked`);
const tooManyRefs = (): Error => new Error(`at most ${MAX_TIME_REFS} frames can be time references`);

const FRAME_NUMBER = /"(?:\\.|[^"\\])*"|(?<![\w.-])frame\.number(?![\w.-])/g;

/** Whether `filter` tests frame.number (outside quotes): it names packets of the capture it was written for. */
export function usesFrameNumber(filter: string): boolean {
  return [...filter.matchAll(FRAME_NUMBER)].some((m) => !m[0].startsWith('"'));
}

/** Frame numbers for a sentence: the first `max`, then "..." */
export function frameList(frames: number[], max = 20): string {
  return frames.slice(0, max).join(", ") + (frames.length > max ? ", ..." : "");
}

/**
 * `marks` with the frames of `frames` the view knows (up to `known`) marked
 * with `note`, replacing marks they had; the frames that exist, the note
 * as marks keep it, and the frames whose mark by the user an agent replaced.
 */
export function marksWith(marks: readonly Mark[], frames: number[], note: string, by: Mark["by"], known: number): { marks: Mark[]; frames: number[]; note: string; replaced: number[] } {
  // Notes become packet comments on export, where editcap takes no control characters
  note = printable(note).slice(0, MAX_NOTE);
  const valid = [...new Set(frames)].filter((f) => Number.isInteger(f) && f >= 1 && f <= known);
  const marked = new Set(valid);
  const keep = marks.filter((m) => !marked.has(m.frame));
  if (keep.length + valid.length > MAX_MARKS) throw tooManyMarks();
  const added: Mark[] = valid.map((frame) => ({ frame, note, by }));
  const replaced = by === "agent" ? marks.filter((m) => marked.has(m.frame) && m.by === "user").map((m) => m.frame) : [];
  return { marks: [...keep, ...added].sort(byFrame), frames: valid, note, replaced };
}

/**
 * The first line of a marked packet's details, as the packet list's tooltip
 * words it. It has no field or filter: no filter, export or column reads it.
 */
export function markNode(mark: Mark, agentName: string): TreeNode {
  return { l: `${mark.by === "agent" ? `Marked by ${agentName}` : "Marked"}${mark.note ? `: ${mark.note}` : ""}`, t: "proto" };
}

/** `marks` without the ones on `frames`; without any when `frames` is left out. */
export function marksWithout(marks: readonly Mark[], frames?: number[]): Mark[] {
  const drop = frames && new Set(frames);
  return drop ? marks.filter((m) => !drop.has(m.frame)) : [];
}

/** Wireshark's Mark/Unmark Packet(s): `marks` with the mark of each of `frames` flipped. */
export function toggledMarks(marks: readonly Mark[], frames: Ranges, by: Mark["by"]): Mark[] {
  const removed = marks.filter((m) => inRanges(frames, m.frame)).length;
  if (marks.length - removed + countRanges(frames) - removed > MAX_MARKS) throw tooManyMarks();
  const had = new Set(marks.map((m) => m.frame));
  const added: Mark[] = [];
  for (const [a, b] of frames) for (let f = a; f <= b; f++) if (!had.has(f)) added.push({ frame: f, note: "", by });
  return [...marks.filter((m) => !inRanges(frames, m.frame)), ...added].sort(byFrame);
}

/**
 * Wireshark's Mark All Displayed (`on`) / Unmark All Displayed: `marks` with
 * every row of the list marked, or none of them; existing marks keep their
 * notes. `list`: its number of rows, whether it shows a frame, and the frames
 * of rows.
 */
export function displayedMarks(marks: readonly Mark[], on: boolean, by: Mark["by"], list: { rows: number; shown: (frame: number) => boolean; frames: (rows: Ranges) => Ranges }): Mark[] {
  if (!on) return marks.filter((m) => !list.shown(m.frame));
  const n = list.rows;
  if (marks.length + n - marks.filter((m) => list.shown(m.frame)).length > MAX_MARKS) throw tooManyMarks();
  const had = new Set(marks.map((m) => m.frame));
  const added: Mark[] = [];
  for (const [a, b] of n ? list.frames([[0, n - 1]]) : []) {
    for (let frame = a; frame <= b; frame++) if (!had.has(frame)) added.push({ frame, note: "", by });
  }
  return [...marks, ...added].sort(byFrame);
}

/** Time references `refs` with (`on`) or without the frames of `frames` the view knows (up to `known`). */
export function refsWith(refs: readonly number[], frames: number[], on: boolean, known: number): number[] {
  const given = new Set(frames.filter((f) => Number.isInteger(f) && f >= 1 && f <= known));
  if (!on) return refs.filter((f) => !given.has(f));
  const all = new Set([...refs, ...given]);
  if (all.size > MAX_TIME_REFS) throw tooManyRefs();
  return [...all].sort((a, b) => a - b);
}

/** Wireshark's Set/Unset Time Reference: `refs` with the reference of each of `frames` flipped. */
export function toggledRefs(refs: readonly number[], frames: Ranges): number[] {
  const removed = refs.filter((f) => inRanges(frames, f)).length;
  if (refs.length - 2 * removed + countRanges(frames) > MAX_TIME_REFS) throw tooManyRefs();
  const had = new Set(refs);
  const added: number[] = [];
  for (const [a, b] of frames) for (let f = a; f <= b; f++) if (!had.has(f)) added.push(f);
  return [...refs.filter((f) => !inRanges(frames, f)), ...added].sort((a, b) => a - b);
}

/** What going from time references `before` to `after` did. */
export function refsChange(before: readonly number[], after: readonly number[]): TimeRefsChange {
  const had = new Set(before);
  const now = new Set(after);
  return { set: after.filter((f) => !had.has(f)), unset: before.filter((f) => !now.has(f)) };
}

/** A packet comment as editcap writes it: lines end in "\n", other control characters become "?". */
export function commentText(text: string): string {
  if (text.length > MAX_COMMENT) throw new Error(`a packet comment holds at most ${MAX_COMMENT} characters`);
  return text.replace(/\r\n?/g, "\n").replace(/[\u0000-\u0009\u000b-\u001f\u007f-\u009f\u2028\u2029]/g, "?");
}

/** `index`, a comment `frame` has now (`comments`), as long as it still reads `old`. */
export function commentAt(comments: string[], frame: number, index: number, old: string): number {
  if (!Number.isInteger(index) || index < 0 || index >= comments.length) throw new Error(`frame ${frame} has no comment ${index + 1}`);
  if (comments[index] !== old) throw new StaleGenerationError(`comment ${index + 1} of frame ${frame} changed meanwhile`);
  return index;
}

/** What Edits needs of the viewer. */
export interface EditsView {
  /** Throws unless a capture is open. */
  requireFile(): void;
  /** The state's commentRevision, which each change of the comments counts up. */
  revision(): number;
}

/** The edits an export started with (see Edits.checkpoint). */
export interface Checkpoint {
  readonly capture: number;
  readonly edit: number;
}

/** What the comments edited in the viewer say of the view's state. */
type CommentsState = Pick<ViewState, "commentEdits" | "commentsEdited" | "commentRevision">;

export class Edits {
  /** Packet comments edited in the viewer, by frame: they stand for the file's. */
  private readonly comments = new Map<number, EditedComments>();
  /** Frames up to this one lost the file's comments (Delete All Packet Comments), unless edited since. */
  private cleared = 0;
  /** The frames that had comments then. */
  private clearedFrames = new Int32Array(0);
  /** The edit that cleared them, until every packet was exported to pcapng since; else 0. */
  private clearedEdit = 0;
  /** Frames changed since every packet was last exported to pcapng, with the edit that changed them last. */
  private readonly unexported = new Map<number, number>();
  private commentEdit = 0;
  /** Edits of comments run one at a time, each from what the frames have then. */
  private commenting: Promise<unknown> = Promise.resolve();
  /** Changes when the edited comments go with their capture: edits read before go too. */
  private commentsFile = 0;
  /** Frames of the file with comments, as the full read `loads` found them. */
  private commentedFrames: { loads: number; frames: Int32Array } | null = null;
  /** Packets whose comments were edited and not exported in the capture the view left last, if they weren't kept; else 0. */
  private droppedEdits = 0;

  constructor(private readonly v: EditsView) {}

  /** The capture the edited comments are of, as a number that changes when they go with it. */
  capture(): number {
    return this.commentsFile;
  }

  /** Whether the edited comments are still of `capture`. */
  isCapture(capture: number): boolean {
    return capture === this.commentsFile;
  }

  /** Refuses to edit comments once their capture is gone. */
  sameCapture(capture: number): void {
    if (capture !== this.commentsFile) throw new StaleGenerationError("the capture was closed or another one opened meanwhile");
  }

  /** Runs `fn` after the edits of comments before it, if a capture is open and its comments are still of `capture`. */
  queue<T>(capture: number, fn: () => Promise<T>): Promise<T> {
    const run = (): Promise<T> => {
      this.v.requireFile();
      this.sameCapture(capture);
      return fn();
    };
    const next = this.commenting.then(run, run);
    this.commenting = next.catch(() => {});
    return next;
  }

  /** The comments edited here, as comments.ts reads them; they change with the edits. */
  edited(): Edited {
    return { comments: this.comments, cleared: this.cleared };
  }

  /** Frames read in full that have comments in the file: as full read `loads` found them, else what `read` finds. */
  async fileCommented(loads: number, read: () => Promise<Int32Array>): Promise<Int32Array> {
    if (this.commentedFrames?.loads === loads) return this.commentedFrames.frames;
    const frames = await read();
    this.commentedFrames = { loads, frames };
    return frames;
  }

  /** Whether the frames with comments in the file are known for full read `loads`. */
  fileCommentsKnown(loads: number): boolean {
    return this.commentedFrames?.loads === loads;
  }

  /**
   * Packet comments edited in the viewer: the packets whose comments differ
   * from the file's, the frames Delete All went up to (0: none), and the
   * frames edited since, the first `max` with their comments.
   */
  summary(max: number): { packets: number; cleared: number; frames: number; list: [number, string[]][] } {
    const frames = [...this.comments.keys()].sort((a, b) => a - b);
    const both = frames.filter((f) => hasFrame(this.clearedFrames, f)).length;
    const list = frames.slice(0, max).map((f): [number, string[]] => [f, this.comments.get(f)!.list]);
    return { packets: frames.length + this.clearedFrames.length - both, cleared: this.cleared, frames: frames.length, list };
  }

  /** Packets whose comments read otherwise than the capture file's, as edited here (exported or not). */
  editedPackets(): number {
    return this.summary(0).packets;
  }

  /** The packets with comments as the view shows them, ascending: edited here, else the file's (`fileCommented`). */
  async commented(fileCommented: () => Promise<Int32Array>): Promise<number[]> {
    const frames = new Set<number>();
    for (const [f, e] of this.comments) if (e.list.length) frames.add(f);
    for (const f of await fileCommented()) if (f > this.cleared && !this.comments.has(f)) frames.add(f);
    return [...frames].sort((a, b) => a - b);
  }

  /** The comments edited here of the frames in `ranges`, as an export to pcapng writes them, and how many packets they change. */
  forExport(ranges: Ranges): { comments: Map<number, FrameComments>; edited: number } {
    const comments = new Map<number, FrameComments>();
    let edited = 0;
    for (const [f, e] of this.comments) {
      if (!inRanges(ranges, f)) continue;
      comments.set(f, { own: e.own < 0 ? false : e.own ? true : undefined, texts: e.list.slice(Math.max(e.own, 0)) });
      edited++;
    }
    for (const f of this.clearedFrames) if (!this.comments.has(f) && inRanges(ranges, f)) edited++;
    return { comments, edited };
  }

  /**
   * Gives each of `frames` the comments `change` makes of the ones it has
   * (`now`, as read for them); returns the frames whose comments changed, and
   * what the state says then (null: nothing changed).
   */
  edit(frames: number[], now: ReadonlyMap<number, EditedComments>, change: (now: string[], frame: number) => string[]): { frames: number[]; patch: CommentsState | null } {
    const lists = new Map<number, EditedComments>();
    for (const f of frames) {
      const was = now.get(f) ?? { list: [], own: 0 };
      const list = change(was.list, f);
      if (list.length === was.list.length && list.every((c, i) => c === was.list[i])) continue;
      // While the file's own comments lead, exports keep them and add the rest
      const own = was.own >= 0 && was.list.slice(0, was.own).every((c, i) => c === list[i]) ? was.own : -1;
      lists.set(f, { list, own });
    }
    if (!lists.size) return { frames: [], patch: null };
    let added = 0;
    for (const f of lists.keys()) if (!this.comments.has(f)) added++;
    if (this.comments.size + added > MAX_COMMENTED) {
      throw new Error(`the viewer holds the comments of at most ${MAX_COMMENTED} packets; export the capture to pcapng and open that file to change more`);
    }
    const edit = ++this.commentEdit;
    for (const [f, e] of lists) {
      this.comments.set(f, e);
      this.unexported.set(f, edit);
    }
    return { frames: [...lists.keys()], patch: this.told() };
  }

  /**
   * Wireshark's Delete All Packet Comments, of the `known` frames the view
   * has, whose file has comments on `commented`: returns the frames that had
   * comments, and what the state says then (null: none had).
   */
  clearAll(commented: Int32Array, known: number): { frames: number[]; patch: CommentsState | null } {
    const shown = (f: number): boolean => (this.comments.get(f)?.list.length ?? (f > this.cleared ? 1 : 0)) > 0;
    const gone = commented.filter((f) => f <= known && shown(f));
    const added = [...this.comments.keys()].filter((f) => shown(f) && !hasFrame(commented, f));
    if (!gone.length && !added.length) return { frames: [], patch: null };
    const edit = ++this.commentEdit;
    for (const f of added) this.unexported.set(f, edit);
    this.clearedFrames = this.cleared ? Int32Array.from(new Set([...this.clearedFrames, ...gone])).sort() : gone;
    this.clearedEdit = edit;
    this.cleared = known;
    this.comments.clear();
    return { frames: [...gone, ...added].sort((a, b) => a - b), patch: this.told() };
  }

  /** The edits made until now, for exported() once an export of them is written. */
  checkpoint(): Checkpoint {
    return { capture: this.commentsFile, edit: this.commentEdit };
  }

  /**
   * Every packet was exported to pcapng with the edits made until `at`:
   * those are kept in a file. Returns the packets changed since (the
   * state's commentEdits), or null when the capture changed meanwhile.
   */
  exported(at: Checkpoint): number | null {
    if (at.capture !== this.commentsFile) return null;
    for (const [f, e] of this.unexported) if (e <= at.edit) this.unexported.delete(f);
    if (this.clearedEdit <= at.edit) this.clearedEdit = 0;
    return this.editCount();
  }

  /** The marks, time references and edited comments past frame `last` go; what the state says then. */
  prune(last: number, marks: readonly Mark[], timeRefs: number[]): Partial<ViewState> {
    return { marks: marks.filter((m) => m.frame <= last), timeRefs: refsUpTo(timeRefs, last), ...this.pruneComments(last) };
  }

  /** Every mark, time reference and edited comment goes with the capture, and edits under way with them; what the state says then. */
  dropAll(): Partial<ViewState> {
    this.commentsFile++;
    this.commentedFrames = null;
    this.clearedEdit = 0;
    return { marks: [], timeRefs: [], ...this.pruneComments(0) };
  }

  /** As dropAll, for Forget: the capture's packets read as its file has them again; what the state says then of marks and comments. */
  forget(): Pick<ViewState, "marks"> & CommentsState {
    this.dropAll();
    return { marks: [], commentEdits: this.editCount(), commentsEdited: 0, commentRevision: this.v.revision() + 1 };
  }

  /** After dropAll: the marks, time references and comments kept in `inv`, as the edits that made them left them; what the state says then. */
  restore(inv: Investigation): Partial<ViewState> {
    const c = inv.comments;
    // Only which edits came after the last export of every packet matters, not their order
    const edit = ++this.commentEdit;
    for (const e of c.edited) this.comments.set(e.frame, { list: [...e.list], own: e.own });
    for (const f of c.unexported) this.unexported.set(f, edit);
    this.cleared = c.cleared;
    this.clearedFrames = Int32Array.from(c.clearedFrames);
    this.clearedEdit = c.clearedUnexported ? edit : 0;
    return { marks: inv.marks, timeRefs: inv.timeRefs, ...this.told() };
  }

  /** The view's `marks`, `timeRefs` and the comments edited here, as investigation.ts keeps them. */
  snapshot(marks: Mark[], timeRefs: number[]): Investigation {
    const ascending = (frames: Iterable<number>): number[] => [...new Set(frames)].sort((a, b) => a - b);
    return {
      marks,
      timeRefs,
      comments: {
        edited: ascending(this.comments.keys()).map((frame) => ({ frame, list: this.comments.get(frame)!.list, own: this.comments.get(frame)!.own })),
        cleared: this.cleared,
        clearedFrames: ascending(this.clearedFrames),
        unexported: ascending(this.unexported.keys()),
        clearedUnexported: this.clearedEdit > 0,
      },
    };
  }

  /** The view leaves its capture, whose comments are edited in `unexported` packets since its last export: lost unless `kept`. */
  left(kept: boolean, unexported: number): void {
    this.droppedEdits = kept ? 0 : unexported;
  }

  /** Packets whose edited comments were lost with the capture the view left last (neither exported nor kept); else 0. */
  dropped(): number {
    return this.droppedEdits;
  }

  /** Drops the comments edited for frames after `last`; what the state says then. */
  private pruneComments(last: number): Partial<CommentsState> {
    let gone = 0;
    for (const f of this.comments.keys()) {
      if (f <= last) continue;
      this.comments.delete(f);
      gone++;
    }
    for (const f of this.unexported.keys()) if (f > last) this.unexported.delete(f);
    if (this.cleared > last) {
      this.cleared = last;
      this.clearedFrames = this.clearedFrames.filter((f) => f <= last);
      gone++;
    }
    return gone ? this.told() : {};
  }

  /** Packets whose comments changed since every packet was last exported to pcapng. */
  private editCount(): number {
    if (!this.clearedEdit) return this.unexported.size;
    let both = 0;
    for (const f of this.unexported.keys()) if (hasFrame(this.clearedFrames, f)) both++;
    return this.unexported.size + this.clearedFrames.length - both;
  }

  /** What the state says of the comments now: one change more. */
  private told(): CommentsState {
    return { commentEdits: this.editCount(), commentsEdited: this.editedPackets(), commentRevision: this.v.revision() + 1 };
  }
}
