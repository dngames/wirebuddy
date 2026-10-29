import { execFile } from "node:child_process";
import { randomBytes } from "node:crypto";
import { chmodSync, mkdtempSync, renameSync, rmSync, statSync } from "node:fs";
import { dirname, extname, isAbsolute, join } from "node:path";
import { inRanges, mergeRanges, type Ranges } from "../shared/ranges.ts";

/** editcap refuses more than 512 selections per run. */
const SELECTIONS_PER_RUN = 500;
/** Bytes of packet comment arguments per editcap run, well within what a command line may hold. */
const COMMENT_BYTES_PER_RUN = 512 * 1024;

function run(bin: string, args: string[]): Promise<void> {
  return new Promise((resolve, reject) => {
    execFile(bin, args, { timeout: 300_000, maxBuffer: 4 * 1024 * 1024 }, (err, _stdout, stderr) => {
      // editcap reports too many selections on stderr with exit code 0
      const problem = String(stderr).trim();
      if (err || /out of room/i.test(problem)) reject(new Error(problem || (err as Error).message));
      else resolve();
    });
  });
}

/** Parses "1-10,25,30-" into sorted, merged [from, to] ranges within 1..total. */
export function parseRange(spec: string, total: number): Ranges {
  const ranges: Ranges = [];
  // Spaces may sit anywhere, e.g. "20 - 30, 40"
  for (const part of spec.split(",").map((p) => p.replace(/\s+/g, "")).filter(Boolean)) {
    const m = /^(\d+)?(?:(-)(\d+)?)?$/.exec(part);
    if (!m || (!m[1] && !m[3])) throw new Error(`invalid range "${part}"`);
    const from = m[1] ? Number(m[1]) : 1;
    const to = m[2] ? (m[3] ? Number(m[3]) : total) : from;
    if (from < 1 || to > total || from > to) throw new Error(`range "${part}" is outside 1-${total}`);
    ranges.push([from, to]);
  }
  if (!ranges.length) throw new Error("the range is empty");
  return mergeRanges(ranges);
}

/** Collapses sorted or unsorted frame numbers into merged [from, to] ranges. */
export function toRanges(frames: Iterable<number>): Ranges {
  return mergeRanges([...frames].map((f) => [f, f] as [number, number]));
}

/**
 * Checks an export target and returns its file format. `protectedFiles` (the
 * open capture, files being recorded) are compared by identity, so another
 * spelling of the same path can't replace them.
 */
export function checkTarget(path: string, protectedFiles: string[], overwrite: boolean): "pcapng" | "pcap" {
  if (!isAbsolute(path)) throw new Error("the export path must be absolute");
  const ext = extname(path).toLowerCase();
  if (ext !== ".pcapng" && ext !== ".pcap") throw new Error("the export file must end in .pcapng or .pcap");
  if (!statSync(dirname(path), { throwIfNoEntry: false })?.isDirectory()) throw new Error(`no such directory: ${dirname(path)}`);
  const existing = statSync(path, { throwIfNoEntry: false });
  if (!existing) return ext === ".pcap" ? "pcap" : "pcapng";
  if (!existing.isFile()) throw new Error(`${path} exists and is not a file`);
  for (const file of protectedFiles) {
    const st = statSync(file, { throwIfNoEntry: false });
    if (st && st.dev === existing.dev && st.ino === existing.ino) throw new Error("can't export over the open capture or a file being recorded");
  }
  if (!overwrite) throw new Error(`${path} already exists`);
  return ext === ".pcap" ? "pcap" : "pcapng";
}

/**
 * Splits `ranges` into one list per editcap run: at most SELECTIONS_PER_RUN
 * ranges, and commented frames (sorted, each with the bytes of its comment
 * argument) up to COMMENT_BYTES_PER_RUN, but at least one.
 */
export function splitRuns(ranges: Ranges, commented: [number, number][]): Ranges[] {
  const out: Ranges[] = [[]];
  let bytes = 0;
  let c = 0;
  const fits = (k: number) => bytes === 0 || bytes + commented[k][1] <= COMMENT_BYTES_PER_RUN;
  for (const range of ranges) {
    let a = range[0];
    const b = range[1];
    while (a <= b) {
      while (c < commented.length && commented[c][0] < a) c++;
      if (out[out.length - 1].length === SELECTIONS_PER_RUN || (c < commented.length && commented[c][0] === a && !fits(c))) {
        out.push([]);
        bytes = 0;
      }
      let k = c;
      for (; k < commented.length && commented[k][0] <= b && fits(k); k++) bytes += commented[k][1];
      // A full run ends before the next commented frame
      const end = k < commented.length && commented[k][0] <= b ? commented[k][0] - 1 : b;
      out[out.length - 1].push([a, end]);
      c = k;
      a = end + 1;
    }
  }
  return out;
}

/**
 * A frame's packet comments in an export: its own ones if `own`, then
 * `texts`; `own` undefined: it has none.
 */
export interface FrameComments {
  own?: boolean;
  texts: string[];
}

/**
 * editcap arguments that write `comments` into a run of `part` (input frame
 * numbers), one pass after the other: editcap writes one comment per frame a
 * pass, and keeps or replaces the frames' own ones all alike. The first pass
 * reads the input, drops the frames' own comments if `discard`, and replaces
 * them if some frame loses its own ones; each later pass appends the next
 * comment, by the frame's place in what the first one wrote. Empty comments
 * are left out: editcap can't write them.
 */
export function commentPasses(part: Ranges, comments: Map<number, FrameComments>, discard = false): { first: string[]; later: string[][] } {
  const frames = [...comments].filter(([f]) => inRanges(part, f)).sort((x, y) => x[0] - y[0]);
  const replace = !discard && frames.some(([, c]) => c.own === false);
  const first: string[] = [];
  const later: string[][] = [];
  for (const [f, c] of frames) {
    let texts = c.texts;
    // Replacing comments, frames that keep their own ones get all of theirs later
    if (!replace || !c.own) {
      if (texts[0] || (replace && c.own === false)) first.push("-a", `${f}:${texts[0] ?? ""}`);
      texts = texts.slice(1);
    }
    let k = 0;
    for (const text of texts) {
      if (!text) continue;
      (later[k++] ??= []).push("-a", `${placeIn(part, f)}:${text}`);
    }
  }
  const mode = discard ? ["--discard-packet-comments"] : replace || !first.length ? [] : ["--preserve-packet-comments"];
  return { first: [...mode, ...first], later };
}

/** Position of frame `f` among the frames of `ranges`, from 1. */
function placeIn(ranges: Ranges, f: number): number {
  let n = 0;
  for (const [a, b] of ranges) {
    if (f <= b) return n + f - a + 1;
    n += b - a + 1;
  }
  return n;
}

/**
 * Writes the frames in `ranges` of `input` to `output` with editcap, splitting
 * large selections into several runs joined by mergecap. `comments` (by input
 * frame number) are the packet comments of the frames they name, and frames
 * up to `cleared` lose their own ones; pcap can't hold them. The result
 * appears atomically.
 */
export async function exportFrames(opts: {
  editcap: string;
  mergecap: string;
  input: string;
  output: string;
  format: "pcapng" | "pcap";
  ranges: Ranges;
  comments?: Map<number, FrameComments>;
  cleared?: number;
}): Promise<number> {
  const { editcap, mergecap, input, output, format, ranges } = opts;
  const comments = format === "pcapng" ? (opts.comments ?? new Map<number, FrameComments>()) : new Map<number, FrameComments>();
  const cleared = format === "pcapng" ? (opts.cleared ?? 0) : 0;
  const partial = `${output}.partial-${randomBytes(6).toString("hex")}`;
  const sel = (r: [number, number]) => (r[0] === r[1] ? String(r[0]) : `${r[0]}-${r[1]}`);
  const commented = [...comments]
    .map(([f, c]): [number, number] => [f, c.texts.reduce((n, text) => n + Buffer.byteLength(`${f}:${text}`) + 4, c.own ? 0 : Buffer.byteLength(`${f}:`) + 4)])
    .filter(([, bytes]) => bytes > 0)
    .sort((x, y) => x[0] - y[0]);
  // Runs of cleared frames drop their own comments, runs of the others keep them
  const runs = [
    ...splitRuns(clip(ranges, 1, cleared), commented).map((part) => ({ part, discard: true })),
    ...splitRuns(clip(ranges, cleared + 1, Infinity), commented).map((part) => ({ part, discard: false })),
  ].filter(({ part }) => part.length);
  // Each later pass rewrites what the run wrote so far
  const write = async ({ part, discard }: { part: Ranges; discard: boolean }, to: string, fmt: string): Promise<void> => {
    const { first, later } = commentPasses(part, comments, discard);
    await run(editcap, ["-F", fmt, ...first, "-r", input, to, ...part.map(sel)]);
    for (const add of later) {
      const next = `${to}.next`;
      try {
        await run(editcap, ["-F", fmt, "--preserve-packet-comments", ...add, to, next]);
        renameSync(next, to);
      } finally {
        rmSync(next, { force: true });
      }
    }
  };
  try {
    if (runs.length === 1) await write(runs[0], partial, format);
    else {
      // Next to the export, where there is room for it, rather than a small tmpfs
      const dir = mkdtempSync(join(dirname(output), ".wirebuddy-export-"));
      try {
        const parts: string[] = [];
        for (const part of runs) {
          const file = join(dir, `part${String(parts.length).padStart(5, "0")}.pcapng`);
          await write(part, file, "pcapng");
          parts.push(file);
        }
        // Parts are in frame order; -a concatenates instead of merging by time
        if (format === "pcap") await run(mergecap, ["-a", "-F", "pcap", "-w", partial, ...parts]);
        else {
          const merged = join(dir, "merged.pcapng");
          await run(mergecap, ["-a", "-F", "pcapng", "-w", merged, ...parts]);
          // mergecap names the parts in a capture comment
          await run(editcap, ["-F", "pcapng", "--discard-capture-comment", merged, partial]);
        }
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    }
    // As private as the captures it comes from
    chmodSync(partial, 0o600);
    renameSync(partial, output);
  } catch (err) {
    rmSync(partial, { force: true });
    throw err;
  }
  return statSync(output).size;
}

/** The parts of merged `ranges` from `a` to `b`. */
function clip(ranges: Ranges, a: number, b: number): Ranges {
  return ranges.filter(([x, y]) => x <= b && y >= a).map(([x, y]) => [Math.max(x, a), Math.min(y, b)]);
}
