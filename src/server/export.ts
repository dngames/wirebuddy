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
 * Writes the frames in `ranges` of `input` to `output` with editcap, splitting
 * large selections into several runs joined by mergecap. `comments` (by input
 * frame number) become packet comments next to the ones the frames have; pcap
 * can't hold them. The result appears atomically.
 */
export async function exportFrames(opts: {
  editcap: string;
  mergecap: string;
  input: string;
  output: string;
  format: "pcapng" | "pcap";
  ranges: Ranges;
  comments?: Map<number, string>;
}): Promise<number> {
  const { editcap, mergecap, input, output, format, ranges } = opts;
  const comments = format === "pcapng" ? (opts.comments ?? new Map<number, string>()) : new Map<number, string>();
  const partial = `${output}.partial-${randomBytes(6).toString("hex")}`;
  const sel = (r: [number, number]) => (r[0] === r[1] ? String(r[0]) : `${r[0]}-${r[1]}`);
  const commented = [...comments].map(([f, text]): [number, number] => [f, Buffer.byteLength(`${f}:${text}`) + 4]).sort((x, y) => x[0] - y[0]);
  const runs = splitRuns(ranges, commented);
  const args = (part: Ranges, to: string, fmt: string): string[] => {
    const add = [...comments].filter(([f]) => inRanges(part, f)).flatMap(([f, text]) => ["-a", `${f}:${text}`]);
    return ["-F", fmt, ...(add.length ? ["--preserve-packet-comments", ...add] : []), "-r", input, to, ...part.map(sel)];
  };
  try {
    if (runs.length === 1) await run(editcap, args(runs[0], partial, format));
    else {
      // Next to the export, where there is room for it, rather than a small tmpfs
      const dir = mkdtempSync(join(dirname(output), ".wirebuddy-export-"));
      try {
        const parts: string[] = [];
        for (const part of runs) {
          const file = join(dir, `part${String(parts.length).padStart(5, "0")}.pcapng`);
          await run(editcap, args(part, file, "pcapng"));
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
