/**
 * An investigation kept with its capture: the marks, time references and
 * packet comments edited in the viewer, in a file of WireBuddy's own data
 * folder (never next to the capture, where another user could put one). The
 * file is named after a SHA-256 of the capture's first bytes, so a copy of
 * the capture finds it too. What is read back is checked whole: one field
 * that is off, and nothing of it is used.
 */

import { createHash } from "node:crypto";
import { chmodSync, closeSync, constants, fstatSync, lstatSync, mkdirSync, openSync, readdirSync, readSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import type { Mark } from "../shared/api.ts";

/** The version of the file's format this WireBuddy reads and writes. */
export const FORMAT_VERSION = 1;
/** How many first bytes of a capture name its investigation: the head the viewer keeps of the file. */
export const INVESTIGATION_HEAD = 4096;
/** Largest file written or read: every mark with a full note fits, with room for many comments. */
export const MAX_INVESTIGATION_BYTES = 4 * 1024 * 1024;
/** Investigation files kept: the ones changed last. */
export const MAX_INVESTIGATIONS = 200;
/** pcapng holds a comment of at most this many bytes, so a file's own comments that edited packets keep fit. */
export const MAX_FILE_COMMENT = 65_535;

const KEY = /^[0-9a-f]{64}$/;
const FILE = /^[0-9a-f]{64}\.json$/;
/** A file this WireBuddy couldn't read, set aside before it wrote anew: never read, pruned like the others. */
const SET_ASIDE = /^[0-9a-f]{64}\.unreadable$/;
/** Written last by a server that died while writing it. */
const TEMP = /^\.[0-9a-f]{64}\.\d+\.tmp$/;
const TEMP_AGE_MS = 60_000;
/** Characters a comment written in the viewer can't hold (see the viewer's commentText). */
const NOT_COMMENT = /[\u0000-\u0009\u000b-\u001f\u007f-\u009f\u2028\u2029]/;
const NOT_PRINTABLE = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/;

/** The caps the viewer holds its marks, time references and comments to. */
export interface InvestigationLimits {
  marks: number;
  note: number;
  timeRefs: number;
  /** Packets with edited comments. */
  commented: number;
  /** A comment written in the viewer. */
  comment: number;
}

/** A packet's comments as edited, in place of the file's: the first `own` of `list` are all of the file's own ones (-1: they aren't). */
export interface KeptComments {
  frame: number;
  list: string[];
  own: number;
}

/** What the viewer keeps of a capture. */
export interface Investigation {
  marks: Mark[];
  timeRefs: number[];
  comments: {
    edited: KeptComments[];
    /** Frames up to this one lost the file's comments (Delete All Packet Comments), unless edited since. */
    cleared: number;
    /** The frames that had comments then. */
    clearedFrames: number[];
    /** Frames whose comments changed since every packet was last exported to pcapng. */
    unexported: number[];
    /** Delete All Packet Comments came after that export, or there was none. */
    clearedUnexported: boolean;
  };
}

/** The capture an investigation was saved for, for information and pruning. */
export interface CaptureInfo {
  path: string;
  size: number;
  frames: number;
}

/** WireBuddy's folder of investigations: in `$XDG_DATA_HOME`, else `~/.local/share`. */
export function investigationDir(env: NodeJS.ProcessEnv = process.env): string {
  return join(env.XDG_DATA_HOME || join(homedir(), ".local/share"), "wirebuddy/investigations");
}

/** The name of a capture's investigation, from its first bytes. */
export function investigationKey(head: Buffer): string {
  return createHash("sha256").update(head).digest("hex");
}

/** Whether there is nothing to keep: no marks or time references, and every packet's comments read as the file's. */
export function nothingToKeep(inv: Investigation): boolean {
  const c = inv.comments;
  return !inv.marks.length && !inv.timeRefs.length && !c.clearedFrames.length && c.edited.every((e) => e.own === e.list.length);
}

/** What is kept, without when and for which file: the same for the same investigation. */
export function investigationContent(inv: Investigation): string {
  const { marks, timeRefs, comments: c } = inv;
  return JSON.stringify({
    marks: marks.map(({ frame, note, by }) => ({ frame, note, by })),
    timeRefs,
    comments: { edited: c.edited.map(({ frame, list, own }) => ({ frame, list, own })), cleared: c.cleared, clearedFrames: c.clearedFrames, unexported: c.unexported, clearedUnexported: c.clearedUnexported },
  });
}

/** "3 marks, 1 time reference and the edited comments of 2 packets"; "" for none of them. */
export function keptSummary(marks: number, timeRefs: number, packets: number): string {
  const plural = (n: number, what: string): string => `${n} ${what}${n === 1 ? "" : "s"}`;
  const parts = [marks ? plural(marks, "mark") : "", timeRefs ? plural(timeRefs, "time reference") : "", packets ? `the edited comments of ${plural(packets, "packet")}` : ""].filter(Boolean);
  return parts.length > 1 ? `${parts.slice(0, -1).join(", ")} and ${parts[parts.length - 1]}` : (parts[0] ?? "");
}

/** The file's text for `inv`. */
export function serializeInvestigation(inv: Investigation, capture: CaptureInfo, saved = new Date()): string {
  const content = JSON.parse(investigationContent(inv)) as object;
  return JSON.stringify({ version: FORMAT_VERSION, capture: { path: capture.path, size: capture.size, frames: capture.frames }, saved: saved.toISOString(), ...content });
}

/** A file that can't be used, and why. */
export class InvalidInvestigation extends Error {}

/** `text` as an investigation, checked against `limits`; throws InvalidInvestigation naming the first problem. */
export function parseInvestigation(text: string, limits: InvestigationLimits): Investigation {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    throw new InvalidInvestigation("it is not JSON");
  }
  const top = record(raw, "the file", ["version", "capture", "saved", "marks", "timeRefs", "comments"]);
  if (top.version !== FORMAT_VERSION) throw new InvalidInvestigation(`it is of another version (${typeof top.version === "number" ? top.version : "none"}), not ${FORMAT_VERSION}`);
  const capture = record(top.capture, "capture", ["path", "size", "frames"]);
  if (typeof capture.path !== "string" || capture.path.length > 4096) invalid("capture.path");
  count(capture.size, "capture.size");
  count(capture.frames, "capture.frames");
  if (typeof top.saved !== "string" || top.saved.length > 64) invalid("saved");

  const marks = list(top.marks, "marks", limits.marks).map((m, i): Mark => {
    const r = record(m, `marks[${i}]`, ["frame", "note", "by"]);
    const note = r.note;
    if (typeof note !== "string" || note.length > limits.note || NOT_PRINTABLE.test(note)) invalid(`marks[${i}].note`);
    if (r.by !== "user" && r.by !== "agent") invalid(`marks[${i}].by`);
    return { frame: frame(r.frame, `marks[${i}].frame`), note, by: r.by };
  });
  ascending(marks.map((m) => m.frame), "marks");
  const timeRefs = list(top.timeRefs, "timeRefs", limits.timeRefs).map((f, i) => frame(f, `timeRefs[${i}]`));
  ascending(timeRefs, "timeRefs");

  const c = record(top.comments, "comments", ["edited", "cleared", "clearedFrames", "unexported", "clearedUnexported"]);
  const edited = list(c.edited, "comments.edited", limits.commented).map((e, i): KeptComments => {
    const r = record(e, `comments.edited[${i}]`, ["frame", "list", "own"]);
    const texts = list(r.list, `comments.edited[${i}].list`, Infinity);
    const own = r.own;
    if (typeof own !== "number" || !Number.isInteger(own) || own < -1 || own > texts.length) invalid(`comments.edited[${i}].own`);
    texts.forEach((t, k) => {
      // Comments written in the viewer, after the file's own ones; the file's may be longer and hold any character
      const written = own >= 0 && k >= own;
      if (typeof t !== "string" || t.length > (written ? limits.comment : MAX_FILE_COMMENT) || (written && (!t || NOT_COMMENT.test(t)))) invalid(`comments.edited[${i}].list[${k}]`);
    });
    return { frame: frame(r.frame, `comments.edited[${i}].frame`), list: texts as string[], own };
  });
  ascending(edited.map((e) => e.frame), "comments.edited");
  const cleared = count(c.cleared, "comments.cleared");
  const clearedFrames = list(c.clearedFrames, "comments.clearedFrames", Infinity).map((f, i) => frame(f, `comments.clearedFrames[${i}]`));
  ascending(clearedFrames, "comments.clearedFrames");
  if (clearedFrames.length && clearedFrames[clearedFrames.length - 1] > cleared) invalid("comments.clearedFrames");
  const unexported = list(c.unexported, "comments.unexported", Infinity).map((f, i) => frame(f, `comments.unexported[${i}]`));
  ascending(unexported, "comments.unexported");
  if (typeof c.clearedUnexported !== "boolean") invalid("comments.clearedUnexported");
  return { marks, timeRefs, comments: { edited, cleared, clearedFrames, unexported, clearedUnexported: c.clearedUnexported } };
}

function invalid(what: string): never {
  throw new InvalidInvestigation(`${what} is not valid`);
}

/** `v` as an object with just the keys `keys`, all of them. */
function record(v: unknown, what: string, keys: string[]): Record<string, unknown> {
  if (!v || typeof v !== "object" || Array.isArray(v)) invalid(what);
  const r = v as Record<string, unknown>;
  const own = Object.keys(r);
  if (own.length !== keys.length || !keys.every((k) => Object.hasOwn(r, k))) throw new InvalidInvestigation(`${what} doesn't have just the fields ${keys.join(", ")}`);
  return r;
}

function list(v: unknown, what: string, max: number): unknown[] {
  if (!Array.isArray(v)) invalid(what);
  if (v.length > max) throw new InvalidInvestigation(`${what} has more than ${max} entries`);
  return v;
}

function count(v: unknown, what: string): number {
  if (typeof v !== "number" || !Number.isSafeInteger(v) || v < 0) invalid(what);
  return v;
}

function frame(v: unknown, what: string): number {
  if (typeof v !== "number" || !Number.isSafeInteger(v) || v < 1) throw new InvalidInvestigation(`${what} is not a frame number`);
  return v;
}

function ascending(frames: number[], what: string): void {
  for (let i = 1; i < frames.length; i++) if (frames[i] <= frames[i - 1]) throw new InvalidInvestigation(`${what} are not in ascending order of frames, each once`);
}

/**
 * Whether `dir` is there as a folder of the user's own, not a link; with
 * `create`, made (0700) when it is missing. Throws when it is something
 * else, or another user's. A folder others may open is closed to them.
 */
export function privateDir(dir: string, create: boolean): boolean {
  if (create) mkdirSync(dir, { recursive: true, mode: 0o700 });
  let st;
  try {
    st = lstatSync(dir);
  } catch (err) {
    // A file on the way (ENOTDIR) holds no folder either
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "ENOENT" || code === "ENOTDIR") return false;
    throw err;
  }
  if (!st.isDirectory()) throw new Error(`${dir} is not a folder`);
  const uid = process.getuid?.();
  if (uid !== undefined && st.uid !== uid) throw new Error(`${dir} belongs to another user`);
  if (uid !== undefined && st.mode & 0o077) chmodSync(dir, 0o700);
  return true;
}

function fileOf(dir: string, key: string): string {
  if (!KEY.test(key)) throw new Error(`not an investigation key: ${key}`);
  return join(dir, `${key}.json`);
}

/**
 * The investigation kept in `dir` under `key`, or null when there is none.
 * Throws InvalidInvestigation for a file that can't be used (left as it is),
 * and other errors for a folder that isn't the user's own.
 */
export function readInvestigation(dir: string, key: string, limits: InvestigationLimits): Investigation | null {
  const file = fileOf(dir, key);
  if (!privateDir(dir, false)) return null;
  let fd: number;
  try {
    // Never through a link in its name
    fd = openSync(file, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "ENOENT") return null;
    if (code === "ELOOP") throw new InvalidInvestigation("it is a link");
    throw err;
  }
  try {
    const st = fstatSync(fd);
    const uid = process.getuid?.();
    if (!st.isFile()) throw new InvalidInvestigation("it is not a file");
    if (uid !== undefined && st.uid !== uid) throw new InvalidInvestigation("it belongs to another user");
    if (st.size > MAX_INVESTIGATION_BYTES) throw new InvalidInvestigation(`it is bigger than ${MAX_INVESTIGATION_BYTES / 1024 / 1024} MiB`);
    const buf = Buffer.alloc(st.size);
    let n = 0;
    while (n < buf.length) {
      const got = readSync(fd, buf, n, buf.length - n, n);
      if (!got) break;
      n += got;
    }
    return parseInvestigation(buf.subarray(0, n).toString("utf8"), limits);
  } finally {
    closeSync(fd);
  }
}

/** Keeps `text` in `dir` under `key`: a new file (0600) renamed over the old one, never half written, never through a link. */
export function writeInvestigation(dir: string, key: string, text: string): void {
  const file = fileOf(dir, key);
  if (Buffer.byteLength(text) > MAX_INVESTIGATION_BYTES) throw new Error(`bigger than ${MAX_INVESTIGATION_BYTES / 1024 / 1024} MiB`);
  privateDir(dir, true);
  const tmp = join(dir, `.${key}.${process.pid}.tmp`);
  try {
    rmSync(tmp, { force: true });
    writeFileSync(tmp, text, { mode: 0o600, flag: "wx" });
    renameSync(tmp, file);
  } finally {
    rmSync(tmp, { force: true });
  }
}

/**
 * Moves the file kept under `key` aside, to `<key>.unreadable` in the same
 * folder (in place of an older one), so that writing anew loses nothing of a
 * file this WireBuddy couldn't read (another version's, say); returns where
 * it went, or null when there was none.
 */
export function setAsideInvestigation(dir: string, key: string): string | null {
  const file = fileOf(dir, key);
  if (!privateDir(dir, false) || !lstatSync(file, { throwIfNoEntry: false })) return null;
  const aside = setAsideName(dir, key);
  renameSync(file, aside);
  return aside;
}

/** Where setAsideInvestigation puts the file of `key`. */
export function setAsideName(dir: string, key: string): string {
  return join(dir, `${key}.unreadable`);
}

/** Removes the investigation kept under `key`, if `dir` is the user's own. */
export function removeInvestigation(dir: string, key: string): void {
  const file = fileOf(dir, key);
  if (privateDir(dir, false)) rmSync(file, { force: true });
}

/** Keeps the `keep` investigations (also set-aside ones) changed last in `dir` and removes the others, and files a write left; returns how many went. */
export function pruneInvestigations(dir: string, keep = MAX_INVESTIGATIONS, now = Date.now()): number {
  if (!privateDir(dir, false)) return 0;
  const files: { name: string; mtime: number }[] = [];
  let gone = 0;
  for (const name of readdirSync(dir)) {
    const isFile = FILE.test(name) || SET_ASIDE.test(name);
    if (!isFile && !TEMP.test(name)) continue;
    const st = lstatSync(join(dir, name), { throwIfNoEntry: false });
    if (!st?.isFile()) continue;
    if (isFile) files.push({ name, mtime: st.mtimeMs });
    else if (now - st.mtimeMs > TEMP_AGE_MS) {
      rmSync(join(dir, name), { force: true });
      gone++;
    }
  }
  files.sort((a, b) => b.mtime - a.mtime);
  for (const f of files.slice(keep)) {
    rmSync(join(dir, f.name), { force: true });
    gone++;
  }
  return gone;
}
