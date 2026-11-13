/**
 * What WireBuddy keeps of its own between runs, apart from the investigations
 * of captures: the session token.
 * Small files in a folder of the user's own (`0700`, files `0600`, never
 * through a link), in the data folder next to the investigations. What is
 * read back is checked whole: a file that doesn't check out is ignored.
 */

import { randomBytes } from "node:crypto";
import { closeSync, constants, fstatSync, mkdirSync, openSync, readSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { privateDir } from "./investigation.ts";

/** Largest file written or read. */
const MAX_BYTES = 64 * 1024;
/** What WireBuddy makes a session token of: 128 random bits. */
const TOKEN = /^[0-9a-f]{32}$/;

/** WireBuddy's folder for what it keeps for the user: in `$XDG_DATA_HOME`, else `~/.local/share`. */
export function settingsDir(env: NodeJS.ProcessEnv = process.env): string {
  return join(env.XDG_DATA_HOME || join(homedir(), ".local/share"), "wirebuddy/state");
}

/**
 * The text of file `name` in `dir`, or null when there is none. Throws when
 * the folder or the file isn't the user's own, is a link or too big; with
 * `secret`, also when others can read the file.
 */
export function readSetting(dir: string, name: string, secret = false): string | null {
  if (!privateDir(dir, false)) return null;
  let fd: number;
  try {
    fd = openSync(join(dir, name), constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "ENOENT") return null;
    if (code === "ELOOP") throw new Error(`${name} is a link`);
    throw err;
  }
  try {
    const st = fstatSync(fd);
    const uid = process.getuid?.();
    if (!st.isFile()) throw new Error(`${name} is not a file`);
    if (uid !== undefined && st.uid !== uid) throw new Error(`${name} belongs to another user`);
    if (secret && uid !== undefined && st.mode & 0o077) throw new Error(`${name} can be read by other users`);
    if (st.size > MAX_BYTES) throw new Error(`${name} is bigger than ${MAX_BYTES / 1024} KiB`);
    const buf = Buffer.alloc(st.size);
    let n = 0;
    while (n < buf.length) {
      const got = readSync(fd, buf, n, buf.length - n, n);
      if (!got) break;
      n += got;
    }
    return buf.subarray(0, n).toString("utf8");
  } finally {
    closeSync(fd);
  }
}

/** Keeps `text` as file `name` in `dir`: a new file (0600) renamed over the old one, never half written, never through a link. */
export function writeSetting(dir: string, name: string, text: string): void {
  if (Buffer.byteLength(text) > MAX_BYTES) throw new Error(`${name} would be bigger than ${MAX_BYTES / 1024} KiB`);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  privateDir(dir, true);
  const tmp = join(dir, `.${name}.${process.pid}.tmp`);
  try {
    rmSync(tmp, { force: true });
    writeFileSync(tmp, text, { mode: 0o600, flag: "wx" });
    renameSync(tmp, join(dir, name));
  } finally {
    rmSync(tmp, { force: true });
  }
}

/**
 * The session token WireBuddy used last, kept in `dir` for the user alone, so
 * that a page open across a restart still holds the right one; a new random
 * one, kept in its place, when there is none or the file can't be trusted
 * (another user's, readable by others, not a token). `problem` says why
 * nothing could be kept: the token is good for this run all the same.
 */
export function keptToken(dir: string): { token: string; fresh: boolean; problem?: string } {
  let problem: string | undefined;
  try {
    const text = readSetting(dir, "token", true)?.trim();
    if (text !== undefined && TOKEN.test(text)) return { token: text, fresh: false };
  } catch (err) {
    problem = (err as Error).message;
  }
  const token = randomBytes(16).toString("hex");
  try {
    writeSetting(dir, "token", `${token}\n`);
  } catch (err) {
    return { token, fresh: true, problem: `${(err as Error).message}` };
  }
  return { token, fresh: true, ...(problem ? { problem: `${problem}; made a new one` } : {}) };
}
