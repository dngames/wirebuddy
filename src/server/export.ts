import { execFile } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtempSync, renameSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, extname, isAbsolute, join } from "node:path";

/** editcap refuses more than 512 selections per run. */
const SELECTIONS_PER_RUN = 500;

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
export function parseRange(spec: string, total: number): [number, number][] {
  const ranges: [number, number][] = [];
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
export function toRanges(frames: Iterable<number>): [number, number][] {
  return mergeRanges([...frames].map((f) => [f, f] as [number, number]));
}

function mergeRanges(ranges: [number, number][]): [number, number][] {
  ranges.sort((a, b) => a[0] - b[0]);
  const out: [number, number][] = [];
  for (const [a, b] of ranges) {
    const last = out[out.length - 1];
    if (last && a <= last[1] + 1) last[1] = Math.max(last[1], b);
    else out.push([a, b]);
  }
  return out;
}

export function countFrames(ranges: [number, number][]): number {
  return ranges.reduce((n, [a, b]) => n + b - a + 1, 0);
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
 * Writes the frames in `ranges` of `input` to `output` with editcap, splitting
 * large selections into several runs joined by mergecap. The result appears
 * atomically.
 */
export async function exportFrames(opts: {
  editcap: string;
  mergecap: string;
  input: string;
  output: string;
  format: "pcapng" | "pcap";
  ranges: [number, number][];
}): Promise<number> {
  const { editcap, mergecap, input, output, format, ranges } = opts;
  const partial = `${output}.partial-${randomBytes(6).toString("hex")}`;
  const sel = (r: [number, number]) => (r[0] === r[1] ? String(r[0]) : `${r[0]}-${r[1]}`);
  try {
    if (ranges.length <= SELECTIONS_PER_RUN) await run(editcap, ["-F", format, "-r", input, partial, ...ranges.map(sel)]);
    else {
      const dir = mkdtempSync(join(tmpdir(), "wirebuddy-export-"));
      try {
        const parts: string[] = [];
        for (let i = 0; i < ranges.length; i += SELECTIONS_PER_RUN) {
          const part = join(dir, `part${String(parts.length).padStart(5, "0")}.pcapng`);
          await run(editcap, ["-F", "pcapng", "-r", input, part, ...ranges.slice(i, i + SELECTIONS_PER_RUN).map(sel)]);
          parts.push(part);
        }
        // Parts are in frame order; -a concatenates instead of merging by time
        await run(mergecap, ["-a", "-F", format, "-w", partial, ...parts]);
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    }
    renameSync(partial, output);
  } catch (err) {
    rmSync(partial, { force: true });
    throw err;
  }
  return statSync(output).size;
}
