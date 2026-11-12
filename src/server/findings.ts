/** The findings report: one Markdown file stating what an investigation found. */

import { chmodSync, closeSync, constants, copyFileSync, fsyncSync, linkSync, lstatSync, openSync, renameSync, rmSync, statSync, writeSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { dirname, extname, isAbsolute, join } from "node:path";
import { TargetExists } from "./export.ts";
import { cell, codeSpan, quote } from "./markdown.ts";

/** Marked packets and commented packets a report lists; more are counted in one line. */
export const MAX_LISTED = 2000;
/** Largest report written. */
export const MAX_REPORT_BYTES = 4 * 1024 * 1024;

/** What the packet list shows of a packet. */
export interface RowSummary {
  time: string;
  source: string;
  destination: string;
  protocol: string;
  info: string;
}

export interface MarkedPacket {
  frame: number;
  note: string;
  by: "agent" | "user";
  /** Provisional: a live capture's packet not read in full yet. */
  provisional: boolean;
  row: RowSummary | null;
}

export interface CommentedPacket {
  frame: number;
  comments: string[];
  provisional: boolean;
  row: RowSummary | null;
}

export interface Findings {
  /** The capture's file name and absolute path. */
  name: string;
  path: string;
  packets: number;
  bytes: number;
  /** Seconds. */
  duration: number;
  /** The capture is still being recorded. */
  live: boolean;
  filter: string;
  /** Decode As entries as text ("udp.port 50000 → rtp"). */
  decodeAs: string[];
  timeRefs: number[];
  version: string;
  at: Date;
  /** The caller's Markdown, checked (see checkSummary); "" for none. */
  summary: string;
  /** In frame order; only the first MAX_LISTED are written. */
  marks: MarkedPacket[];
  commented: CommentedPacket[];
  /** Marked and commented packets beyond those given. */
  moreMarks?: number;
  moreCommented?: number;
}

const plural = (n: number, one: string, many = `${one}s`): string => `${n} ${n === 1 ? one : many}`;

/** The packet's place in a heading or cell: its number, "provisional" when a live capture hasn't read it in full. */
const place = (p: { frame: number; provisional: boolean }): string => `${p.frame}${p.provisional ? " (provisional)" : ""}`;

/** The report as text: Markdown ending in a newline. Capture text and notes are written escaped (see markdown.ts). */
export function buildFindings(f: Findings): string {
  const out: string[] = [`# Findings: ${codeSpan(f.name)}`, ""];
  const summary = f.summary.trimEnd();
  if (summary) out.push(summary, "");
  out.push("## Capture", `- File: ${codeSpan(f.path)}`);
  out.push(`- ${plural(f.packets, "packet")}, ${f.bytes} bytes, ${f.duration.toFixed(3)} s${f.live ? " (live capture, still running)" : ""}`);
  if (f.filter) out.push(`- Display filter: ${codeSpan(f.filter)}`);
  if (f.decodeAs.length) out.push(`- Decode As: ${f.decodeAs.map((e) => codeSpan(e)).join(", ")}`);
  if (f.timeRefs.length) out.push(`- Time references: ${f.timeRefs.length === 1 ? "packet" : "packets"} ${f.timeRefs.join(", ")}`);
  out.push(`- Written by WireBuddy ${f.version} on ${f.at.toISOString().replace(/\.\d+Z$/, "Z")}`);

  const marks = f.marks.slice(0, MAX_LISTED);
  const moreMarks = (f.moreMarks ?? 0) + f.marks.length - marks.length;
  if (marks.length || moreMarks) {
    out.push("", "## Marked packets", "", "| Packet | Time | Source | Destination | Protocol | Info | Note | By |", "| --- | --- | --- | --- | --- | --- | --- | --- |");
    for (const m of marks) {
      const r = m.row;
      out.push(`| ${place(m)} | ${cell(r?.time ?? "")} | ${cell(r?.source ?? "")} | ${cell(r?.destination ?? "")} | ${cell(r?.protocol ?? "")} | ${cell(r?.info ?? "")} | ${cell(m.note)} | ${m.by} |`);
    }
    if (moreMarks) out.push("", `${plural(moreMarks, "more marked packet")} not listed.`);
  }

  const commented = f.commented.slice(0, MAX_LISTED);
  const moreCommented = (f.moreCommented ?? 0) + f.commented.length - commented.length;
  if (commented.length || moreCommented) {
    out.push("", "## Packet comments");
    for (const c of commented) {
      const r = c.row;
      // "Packet 3: TCP 10.0.0.1 → 10.0.0.2"
      const ends = r && (r.source || r.destination) ? `${codeSpan(r.source)} → ${codeSpan(r.destination)}`.replace(/^ → | → $/, "") : "";
      const heading = r ? [codeSpan(r.protocol), ends].filter(Boolean).join(" ") : "";
      out.push("", `### Packet ${place(c)}${heading ? `: ${heading}` : ""}`);
      const info = r ? codeSpan(r.info) : "";
      if (info) out.push(info);
      // A bare ">" line keeps the comments apart: lines of one quote paragraph would run together
      out.push(c.comments.map(quote).join("\n>\n"));
    }
    if (moreCommented) out.push("", `${plural(moreCommented, "more packet")} with comments not listed.`);
  }
  return `${out.join("\n")}\n`;
}

/**
 * Checks where a report goes: as for an export of packets, an absolute path
 * in a directory that exists, ending in .md, naming no file of `protectedFiles`
 * (by identity), and a file that exists only with `overwrite`.
 */
export function checkReportTarget(path: string, protectedFiles: string[], overwrite: boolean): void {
  if (!isAbsolute(path)) throw new Error("the report path must be absolute");
  if (extname(path).toLowerCase() !== ".md") throw new Error("the report file must end in .md");
  if (!statSync(dirname(path), { throwIfNoEntry: false })?.isDirectory()) throw new Error(`no such directory: ${dirname(path)}`);
  const existing = statSync(path, { throwIfNoEntry: false });
  if (!existing) return;
  if (!existing.isFile()) throw new Error(`${path} exists and is not a file`);
  for (const file of protectedFiles) {
    const st = statSync(file, { throwIfNoEntry: false });
    if (st && st.dev === existing.dev && st.ino === existing.ino) throw new Error("can't write the report over the open capture or a file being recorded");
  }
  if (!overwrite) throw new TargetExists(`${path} already exists`);
}

/**
 * Writes `text` to `path` (checked by checkReportTarget): a new file only
 * readable by the user, written under a temporary name in the same folder and
 * put in place whole. A new file is linked into place, which fails if
 * anything, a link included, appeared there meanwhile; with `overwrite` the
 * file is replaced by renaming (never written through), unless it is a link.
 */
export function writeReport(path: string, text: string, overwrite: boolean): number {
  const bytes = Buffer.byteLength(text);
  if (bytes > MAX_REPORT_BYTES) throw new Error(`the report would be ${(bytes / 1024 / 1024).toFixed(1)} MiB, more than the ${MAX_REPORT_BYTES / 1024 / 1024} MiB allowed`);
  const tmp = join(dirname(path), `.wirebuddy-findings-${randomBytes(8).toString("hex")}.tmp`);
  try {
    const fd = openSync(tmp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), 0o600);
    try {
      writeSync(fd, text);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    if (overwrite) {
      if (lstatSync(path, { throwIfNoEntry: false })?.isSymbolicLink()) throw new Error(`${path} is a link`);
      renameSync(tmp, path);
    } else {
      try {
        linkSync(tmp, path);
      } catch (err) {
        const code = (err as NodeJS.ErrnoException).code;
        if (code === "EEXIST") throw new TargetExists(`${path} already exists`);
        // A file system without hard links: copied instead, which also fails when anything is there
        if (code !== "EPERM" && code !== "ENOTSUP" && code !== "EOPNOTSUPP" && code !== "ENOSYS") throw err;
        try {
          copyFileSync(tmp, path, constants.COPYFILE_EXCL);
        } catch (copyErr) {
          if ((copyErr as NodeJS.ErrnoException).code === "EEXIST") throw new TargetExists(`${path} already exists`);
          throw copyErr;
        }
        chmodSync(path, 0o600);
      }
    }
  } finally {
    rmSync(tmp, { force: true });
  }
  return bytes;
}
