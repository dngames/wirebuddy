/**
 * Time references, as Wireshark's Edit › Set/Unset Time Reference makes
 * them: frames the time columns count from. sharkd keeps none; it takes them
 * with each request ("frames" `refs`, "frame" `ref_frame`), and its display
 * filters never see them, so WireBuddy spells frame.ref_time out as their
 * frame numbers.
 */

import { MAX_REQUEST_BYTES, SharkdError } from "./sharkd.ts";
import { framesFilter, mergeRanges } from "../shared/ranges.ts";

/** Time references a view keeps. */
export const MAX_TIME_REFS = 10_000;
/** Longest display filter frame.ref_time is spelled out in: requests need room for their other params too. */
const MAX_REF_FILTER = 4096;
/** frame.ref_time as a field, or a string (left as it is). */
const REF_TIME = /"(?:\\.|[^"\\])*"|(?<![\w.-])frame\.ref_time(?![\w.-])/g;

/** How many of `refs` (ascending) are at or before `frame`. */
function upTo(refs: readonly number[], frame: number): number {
  let lo = 0;
  let hi = refs.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (refs[mid] <= frame) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}

/** The nearest of `refs` (ascending) at or before `frame`, or 0. */
export function refBefore(refs: readonly number[], frame: number): number {
  const n = upTo(refs, frame);
  return n ? refs[n - 1] : 0;
}

/**
 * The references rows of `frames` (ascending) count from: the nearest at or
 * before each, once. sharkd counts each row from the nearest it is given, so
 * these read as all of them do.
 */
export function refsOf(refs: readonly number[], frames: ArrayLike<number>): number[] {
  const out: number[] = [];
  if (!refs.length || !frames.length) return out;
  let i = upTo(refs, frames[0]) - 1;
  for (let k = 0; k < frames.length; k++) {
    while (i + 1 < refs.length && refs[i + 1] <= frames[k]) i++;
    if (i >= 0 && out[out.length - 1] !== refs[i]) out.push(refs[i]);
  }
  return out;
}

/** `refs` up to `frame`: the same array when none comes after it. */
export function refsUpTo(refs: number[], frame: number): number[] {
  return refs.length && refs[refs.length - 1] > frame ? refs.filter((f) => f <= frame) : refs;
}

/** sharkd's `refs` for a "frames" request: `refs` (ascending) as a list it reads; undefined for none (it never answers ""). */
export function refsParam(refs: readonly number[]): string | undefined {
  let out = "";
  let last = 0;
  for (const r of refs) {
    // Anything but ascending frame numbers gets no answer at all
    if (!Number.isSafeInteger(r) || r <= last) continue;
    out += out ? `,${r}` : String(r);
    last = r;
  }
  return out || undefined;
}

/** The time references rows from..to-1 of a "frames" request count from (see refsOf). */
export type RowRefs = (from: number, to: number) => number[];

/**
 * The rows `read` gets for a "frames" request with `params` (limit, skip),
 * counting time from the references `refs` names for them; `extra`: params
 * `read` adds to a request of its own. When the references make a request
 * too long for sharkd, the rows come in parts, each with the references its
 * own rows count from.
 */
export async function framesWithRefs<T>(
  params: Record<string, unknown>,
  refs: RowRefs,
  read: (params: Record<string, unknown>) => Promise<T[]>,
  extra: Record<string, unknown> = {},
): Promise<T[]> {
  const limit = Number(params.limit);
  const ref = refsParam(refs(0, limit));
  if (!ref) return read(params);
  const all = { ...params, refs: ref };
  // One row too long even so: sharkd.call refuses it, saying why
  if (!(limit > 1) || fits({ ...all, ...extra })) return read(all);
  const skip = Number(params.skip ?? 0);
  const half = Math.ceil(limit / 2);
  const [a, b] = await Promise.all([
    framesWithRefs({ ...params, limit: half }, refs, read, extra),
    framesWithRefs({ ...params, skip: skip + half, limit: limit - half }, (from, to) => refs(half + from, half + to), read, extra),
  ]);
  return [...a, ...b];
}

/** Whether a "frames" request with `params` is short enough for sharkd, whatever its id. */
function fits(params: Record<string, unknown>): boolean {
  return Buffer.byteLength(JSON.stringify({ jsonrpc: "2.0", id: Number.MAX_SAFE_INTEGER, method: "frames", params })) < MAX_REQUEST_BYTES;
}

/** Whether `filter` uses frame.ref_time, which sharkd never matches. */
export function usesRefTime(filter: string): boolean {
  return [...filter.matchAll(REF_TIME)].some((m) => !m[0].startsWith('"'));
}

/**
 * `filter` as sharkd can match it: frame.ref_time spelled out as the
 * references' frame numbers, or as no frame without any. Throws when that is
 * too long for sharkd.
 */
export function refTimeFilter(filter: string, refs: readonly number[]): string {
  if (!usesRefTime(filter)) return filter;
  const set = refs.length ? framesFilter(mergeRanges(refs.map((f) => [f, f])), MAX_REF_FILTER) : "frame.number == 0";
  const out = set === null ? null : filter.replace(REF_TIME, (m) => (m.startsWith('"') ? m : `(${set})`));
  if (out === null || Buffer.byteLength(out) > MAX_REF_FILTER) throw new Error(`frame.ref_time stands for the ${refs.length} time references, which makes the display filter too long for sharkd; unset some of them`);
  return out;
}

/** Whether the display filter frame.ref_time can stand for `refs`, spelled out (see refTimeFilter). */
export function refTimeFits(refs: readonly number[]): boolean {
  try {
    refTimeFilter("frame.ref_time", refs);
    return true;
  } catch {
    return false;
  }
}

/**
 * Why sharkd, which takes `filter`, can't match it once frame.ref_time is
 * spelled out (in a function, with # or @); null when it can. `check` throws
 * a SharkdError for a filter sharkd refuses.
 */
export async function refTimeError(filter: string, check: (filter: string) => Promise<unknown>): Promise<string | null> {
  if (!usesRefTime(filter)) return null;
  try {
    await check(refTimeFilter(filter, []));
    return null;
  } catch (err) {
    if (!(err instanceof SharkdError)) throw err;
    return "WireBuddy matches frame.ref_time by the time references' frame numbers, so it only works as a test of its own (frame.ref_time, !frame.ref_time), not in a function or with # or @";
  }
}

/** "set the time reference on frame 5", "unset time references on 3 frames", or both; "" for no change. */
export function changeText(change: { set: readonly number[]; unset: readonly number[] }): string {
  const did = (verb: string, frames: readonly number[]): string =>
    !frames.length ? "" : frames.length === 1 ? `${verb} the time reference on frame ${frames[0]}` : `${verb} time references on ${frames.length} frames`;
  return [did("set", change.set), did("unset", change.unset)].filter(Boolean).join(" and ");
}
