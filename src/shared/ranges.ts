/** Inclusive [first, last] integer ranges, sorted and merged: row selections and frame sets. */

export type Ranges = [number, number][];

/** Sorts and merges overlapping or adjacent ranges into a new array. */
export function mergeRanges(ranges: Ranges): Ranges {
  const sorted = ranges.map(([a, b]) => [a, b] as [number, number]).sort((x, y) => x[0] - y[0]);
  const out: Ranges = [];
  for (const [a, b] of sorted) {
    const last = out[out.length - 1];
    if (last && a <= last[1] + 1) last[1] = Math.max(last[1], b);
    else out.push([a, b]);
  }
  return out;
}

export function countRanges(ranges: Ranges): number {
  return ranges.reduce((n, [a, b]) => n + b - a + 1, 0);
}

/** Whether `i` lies in merged `ranges`. */
export function inRanges(ranges: Ranges, i: number): boolean {
  let lo = 0;
  let hi = ranges.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (i < ranges[mid][0]) hi = mid - 1;
    else if (i > ranges[mid][1]) lo = mid + 1;
    else return true;
  }
  return false;
}

/** Adds `i` to merged `ranges`, or removes it if present (Ctrl+click). */
export function toggleInRanges(ranges: Ranges, i: number): Ranges {
  if (!inRanges(ranges, i)) return mergeRanges([...ranges, [i, i]]);
  const out: Ranges = [];
  for (const [a, b] of ranges) {
    if (i < a || i > b) out.push([a, b]);
    else {
      if (a < i) out.push([a, i - 1]);
      if (i < b) out.push([i + 1, b]);
    }
  }
  return out;
}

/** "frame.number in {3, 7..9}" for frame `ranges`, or null once it would exceed `maxLength`. */
export function framesFilter(ranges: Ranges, maxLength: number): string | null {
  let set = "";
  for (const [a, b] of ranges) {
    set += `${set ? ", " : ""}${a === b ? a : `${a}..${b}`}`;
    if (set.length > maxLength) return null;
  }
  return `frame.number in {${set}}`;
}
