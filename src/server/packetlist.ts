/**
 * The packet list's geometry: the frames the display filter shows, which row
 * a frame has and which frame a row, and what a selection of rows names. The
 * list is the exact rows (frames read in full that the filter shows) and then
 * the provisional ones of a live capture's tail. Nothing here asks sharkd;
 * what the state and the tail say comes in with each call as a ListView.
 */

import { countRanges, mergeRanges, type Ranges } from "../shared/ranges.ts";
import type { ViewState } from "../shared/api.ts";

/** Row ranges a selection may consist of. */
const MAX_ROW_RANGES = 10000;
/** Most rows a page of the list holds. */
const MAX_PAGE_ROWS = 500;

/** What the list needs of the live tail when it lists it. */
export interface ListTail {
  /** Frames the tail knows beyond those read in full. */
  readonly frames: number;
  readonly filter: string;
  /** Why the filter can't be applied to slices, if so. */
  readonly held: string | null;
  /** Provisional rows. */
  listed(): number;
  /** Provisional row of `frame`, or -1. */
  indexOf(frame: number): number;
  /** The frame of provisional row `i`. */
  frameAt(i: number): number;
  /** Whether `frame` is not checked against the filter yet. */
  unchecked(frame: number): boolean;
}

/** What the list reads of the view's state, and the tail it lists (null: none). */
export interface ListView {
  totalFrames: number;
  displayedFrames: number;
  tail: ListTail | null;
}

/** The row at `index` alone, or no rows for -1. */
export function rowOf(index: number): Ranges {
  return index >= 0 ? [[index, index]] : [];
}

export function rowSelection(rows: Ranges): Pick<ViewState, "selectedRows" | "selectedCount"> {
  return { selectedRows: rows, selectedCount: countRanges(rows) };
}

/** Cuts merged `ranges` to 0..n-1. */
export function clipRanges(ranges: Ranges, n: number): Ranges {
  return ranges.filter(([a]) => a < n).map(([a, b]) => [a, Math.min(b, n - 1)]);
}

/** Whether every row of `before` shows the same frame in `after` (a growing live capture). */
export function startsWith(after: { length: number; at: (i: number) => number }, before: { length: number; at: (i: number) => number }): boolean {
  if (after.length < before.length) return false;
  for (let i = 0; i < before.length; i++) if (before.at(i) !== after.at(i)) return false;
  return true;
}

/** The list a dialog was opened on: its capture alone when it names its packets by frame number, which no display filter changes. */
export type AboutView = { file: string; filter: string; generation?: number } | { file: string; filter?: undefined; generation?: undefined };

/** Whether a request made for `view` (a list the page showed) is for a list the view has replaced or changed in place since. */
export function listChanged(view: { file: string; filter: string; generation?: number }, now: { file: string | null; filter: string; rowsSince: number }): boolean {
  return view.file !== now.file || view.filter !== now.filter || (view.generation ?? Infinity) < now.rowsSince;
}

export class PacketList {
  private displayed: Int32Array | null = null;

  /** The frames the display filter shows, ascending; null: all of them. */
  setDisplayed(frames: Int32Array | null): void {
    this.displayed = frames;
  }

  /** The frames the filter shows, or null for all. */
  shown(): Int32Array | null {
    return this.displayed;
  }

  /** Frames the view knows: read in full, then provisional ones. */
  known(v: ListView): number {
    return v.totalFrames + (v.tail?.frames ?? 0);
  }

  /** Rows of the list: exact ones, then provisional ones. */
  length(v: ListView): number {
    return v.displayedFrames + (v.tail?.listed() ?? 0);
  }

  /** The row of `frame`, or -1 when the list has none. */
  indexOf(frame: number | null, v: ListView): number {
    if (frame === null) return -1;
    if (frame > v.totalFrames) {
      const i = v.tail?.indexOf(frame) ?? -1;
      return i < 0 ? -1 : v.displayedFrames + i;
    }
    if (!this.displayed) return frame >= 1 && frame <= v.totalFrames ? frame - 1 : -1;
    let lo = 0;
    let hi = this.displayed.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      const x = this.displayed[mid];
      if (x === frame) return mid;
      if (x < frame) lo = mid + 1;
      else hi = mid - 1;
    }
    return -1;
  }

  /** The list's rows as frame numbers, copied: exact rows (of `exact` frames read in full), then provisional ones. */
  rowFrames(v: ListView): { exact: number; length: number; at: (i: number) => number } {
    const displayed = this.displayed;
    const n = v.displayedFrames;
    const tail = v.tail;
    const listed = tail?.listed() ?? 0;
    const matches = tail?.filter ? Int32Array.from({ length: listed }, (_, i) => tail.frameAt(i)) : null;
    const base = v.totalFrames;
    return { exact: base, length: n + listed, at: (i) => (i < n ? (displayed ? displayed[i] : i + 1) : matches ? matches[i - n] : base + 1 + i - n) };
  }

  /** `count` rows from `start` as a page: how many there are, and how many of them are exact rows. */
  page(start: number, count: number, v: ListView): { count: number; exact: number } {
    count = Math.max(0, Math.min(count, MAX_PAGE_ROWS, this.length(v) - start));
    return { count, exact: Math.max(0, Math.min(count, v.displayedFrames - start)) };
  }

  /** Checks row ranges against the displayed list and merges them. */
  checkRows(rows: Ranges, v: ListView): Ranges {
    if (rows.length > MAX_ROW_RANGES) throw new Error(`at most ${MAX_ROW_RANGES} row ranges can be selected`);
    const n = this.length(v);
    for (const [a, b] of rows) {
      if (!Number.isInteger(a) || !Number.isInteger(b) || a < 0 || a > b || b >= n) throw new Error(`invalid row range [${a}, ${b}] (${n} rows are displayed)`);
    }
    return mergeRanges(rows);
  }

  /** Frame ranges of displayed rows, provisional ones too. */
  framesOfRows(rows: Ranges, v: ListView): Ranges {
    const displayed = this.displayed;
    const n = v.displayedFrames;
    const tail = v.tail;
    // Without a filter, row i is frame i + 1 throughout
    if (!displayed && !tail?.filter) return rows.map(([a, b]) => [a + 1, b + 1]);
    const out: Ranges = [];
    for (const [a, b] of rows) {
      for (let i = a; i <= b; i++) {
        const frame = i < n ? (displayed ? displayed[i] : i + 1) : tail!.frameAt(i - n);
        const last = out[out.length - 1];
        if (last && frame === last[1] + 1) last[1] = frame;
        else out.push([frame, frame]);
      }
    }
    return out;
  }

  /** Frame ranges of the user's selected rows. */
  selectedFrames(selectedRows: Ranges, v: ListView): Ranges {
    return this.framesOfRows(clipRanges(selectedRows, this.length(v)), v);
  }

  /** Frames of the selected rows, else the selected frame. */
  selectedOrCurrent(sel: Pick<ViewState, "selectedCount" | "selectedRows" | "selected">, v: ListView): Ranges {
    if (sel.selectedCount) return this.selectedFrames(sel.selectedRows, v);
    const frame = sel.selected;
    return frame === null ? [] : [[frame, frame]];
  }

  /**
   * The selection that makes `frame` the current packet: its row, and the
   * rows `rows` name (checked), else its row alone. Refuses a frame the view
   * doesn't know.
   */
  select(frame: number | null, rows: Ranges | undefined, v: ListView): { selectedIndex: number; selectedRows: Ranges } {
    if (frame !== null && (!Number.isInteger(frame) || frame < 1 || frame > this.known(v))) {
      throw new Error(`no frame ${frame}`);
    }
    const selectedIndex = this.indexOf(frame, v);
    const selectedRows = rows ? this.checkRows(rows, v) : rowOf(selectedIndex);
    return { selectedIndex, selectedRows };
  }

  /** Why the list has no row for `frame`, a frame the view knows: "hidden by the current display filter", or why it isn't listed yet. */
  unlisted(frame: number, v: ListView): string {
    const tail = v.tail;
    if (tail && frame > v.totalFrames) {
      if (tail.held) return `listed once read in full, as ${tail.held}`;
      if (tail.unchecked(frame)) return "not checked against the display filter yet";
    }
    return "hidden by the current display filter";
  }
}
