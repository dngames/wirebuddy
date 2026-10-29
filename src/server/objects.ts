/**
 * Files carried in the traffic (Wireshark's File > Export Objects), saved for
 * the user or the agent. Names and contents come from the capture, so every
 * save goes into a new private folder that other users can't redirect, under
 * names of its own, never over an existing file and never where code is
 * loaded from.
 */

import { closeSync, mkdirSync, openSync, realpathSync, rmdirSync, rmSync, statSync, writeSync } from "node:fs";
import { extname, isAbsolute, join, resolve, sep } from "node:path";
import { rootTrust } from "./extensions.ts";
import { printable } from "./text.ts";
import type { ObjectKind, ObjectRow } from "../shared/api.ts";

export type { ObjectKind };
export const OBJECT_KINDS = ["http", "imf", "smb", "tftp", "dicom", "ftp-data"] as const satisfies readonly ObjectKind[];

/** One file sharkd found in the traffic; `token` downloads it. */
export interface CapturedObject extends ObjectRow {
  token: string;
}

const MAX_NAME = 100;
/** Folders or files tried with a counter before giving up. */
const MAX_TRIES = 1000;

/** "f12-big.txt": the frame, then the object's own name reduced to safe characters. */
export function objectFileName(frame: number, filename: string): string {
  const last = filename.split(/[\\/]/).pop() ?? "";
  const safe = last.replace(/[^A-Za-z0-9._-]+/g, "_").slice(0, MAX_NAME);
  return `f${frame}-${safe || "object"}`;
}

/** Why objects must not go into the real path `real`, or null. */
function placeProblem(real: string, codeFolders: string[]): string | null {
  // Hidden folders hold configuration (autostart, shells, ssh)
  if (real.split(sep).some((part) => part.startsWith("."))) return "is or lies in a hidden folder";
  for (const folder of codeFolders) {
    let code: string;
    try {
      code = realpathSync(folder);
    } catch {
      code = resolve(folder);
    }
    if (real === code || real.startsWith(code + sep)) return "is or lies in a folder Wireshark or WireBuddy loads code from";
  }
  return null;
}

/**
 * Checks a directory to save objects into and returns its real path.
 * `codeFolders`: folders whose files Wireshark or WireBuddy load as code.
 */
export function objectDir(dir: string, codeFolders: string[]): string {
  if (!isAbsolute(dir)) throw new Error("the directory must be an absolute path");
  if (!statSync(dir, { throwIfNoEntry: false })?.isDirectory()) throw new Error(`no such directory: ${dir}`);
  const real = realpathSync(dir);
  const problem = placeProblem(real, codeFolders);
  if (problem) throw new Error(`${printable(dir)} ${problem}; choose another directory`);
  return real;
}

/**
 * Creates a new private folder for one save in the checked real directory
 * `real` (e.g. "<real>/http-objects-2") and returns it. Every folder from /
 * down to it must be closed to other users, so none of them can swap it, or
 * a folder above it, for a link to somewhere else while files are written.
 */
export function newObjectFolder(real: string, kind: ObjectKind, codeFolders: string[]): string {
  for (let i = 1; i <= MAX_TRIES; i++) {
    const folder = join(real, `${kind}-objects${i > 1 ? `-${i}` : ""}`);
    try {
      mkdirSync(folder, { mode: 0o700 });
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "EEXIST") continue;
      throw err;
    }
    // The folder as made, not where a link swapped in for it leads
    const trust = rootTrust(folder, true);
    const problem = trust.real !== folder ? "was replaced while it was made" : (placeProblem(folder, codeFolders) ?? trust.problem);
    if (problem) {
      try {
        // rmdir never follows a link in its last part
        rmdirSync(folder);
      } catch {
        // Gone or swapped: nothing of the user's to clean up
      }
      throw new Error(`${printable(folder)} ${problem}; choose a directory that only you can change (/tmp works)`);
    }
    return folder;
  }
  throw new Error(`${printable(real)} already has ${MAX_TRIES} ${kind}-objects folders`);
}

/** Writes `data` as a new file named `name` (or "name-2.ext", …) in `folder`; returns the name used. */
export function writeObject(folder: string, name: string, data: Buffer): string {
  const ext = extname(name);
  const stem = name.slice(0, name.length - ext.length);
  for (let i = 1; i <= MAX_TRIES; i++) {
    const candidate = i > 1 ? `${stem}-${i}${ext}` : name;
    const path = join(folder, candidate);
    let fd: number;
    try {
      // "wx": never replaces or follows an existing file or link
      fd = openSync(path, "wx", 0o600);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "EEXIST") continue;
      throw err;
    }
    try {
      for (let off = 0; off < data.length; ) off += writeSync(fd, data, off);
    } catch (err) {
      // No cut-off file under a name that looks complete
      closeSync(fd);
      rmSync(path, { force: true });
      throw err;
    }
    closeSync(fd);
    return candidate;
  }
  throw new Error(`too many objects named ${name}`);
}
