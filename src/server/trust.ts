/**
 * Who besides the user could change a folder or a file: what keeps other
 * users' Lua out of sharkd and saved objects out of folders others could
 * redirect. On Linux it reads owners, modes, POSIX ACLs and the filesystem
 * type; on macOS owners, modes, ACLs as /bin/ls prints them and the volume's
 * entry in the mount table. Anything that can't be found out counts as
 * letting others in.
 */

import { execFileSync, spawnSync } from "node:child_process";
import { closeSync, constants, fstatSync, lstatSync, openSync, readFileSync, realpathSync, statfsSync, statSync, type Stats } from "node:fs";
import { userInfo } from "node:os";
import { join, sep } from "node:path";
import { printable } from "./text.ts";

/**
 * Whether others could change what is in a folder. `dev`: its filesystem;
 * `privateDev`: set below a folder of the user's that others can't enter,
 * for entries on that folder's filesystem.
 */
export interface RootTrust {
  problem: string | null;
  real: string;
  dev: number;
  privateDev: number | null;
}

/** Whether these checks exist here: elsewhere no folder is trusted with code. */
export function trustChecked(): boolean {
  return process.platform === "linux" || process.platform === "darwin";
}

let ownGroup: number | null | undefined;

/** The user's own group when nobody else is in it (Debian's user private groups), else null. */
function privateGid(): number | null {
  if (ownGroup !== undefined) return ownGroup;
  ownGroup = null;
  const gid = process.getgid?.();
  try {
    const [name, , , members] = execFileSync("getent", ["group", String(gid)], { encoding: "utf8", timeout: 5000 }).trim().split(":");
    if (gid !== undefined && name === userInfo().username && !members) ownGroup = gid;
  } catch {
    // no getent: a group-writable file counts as writable by others
  }
  return ownGroup;
}

const aclCache = new Map<string, boolean>();

/**
 * Whether a POSIX ACL lets named users or groups write (the group bits then
 * show the ACL mask). What can't be found out counts as letting them: getfacl
 * failing, or an ACL where there is no getfacl to read it with.
 */
function aclLetsOthersWrite(path: string, st: Stats): boolean {
  const key = `${st.dev}:${st.ino}:${st.ctimeMs}`;
  let result = aclCache.get(key);
  if (result !== undefined) return result;
  result = false;
  try {
    const acl = execFileSync("getfacl", ["--absolute-names", "--omit-header", "--", path], { encoding: "utf8", timeout: 5000 });
    for (const line of acl.split("\n")) {
      const [type, who, perms = ""] = line.split(":");
      if ((type === "user" || type === "group") && who && perms.slice(0, 3).includes("w")) result = true;
    }
  } catch (err) {
    // Not installed (the acl package): ACLs can be there all the same, restored or inherited
    result = (err as NodeJS.ErrnoException).code === "ENOENT" ? hasAcl(path) : true;
  }
  aclCache.set(key, result);
  return result;
}

let gnuLs: boolean | undefined;

/** Whether `path` has an ACL of its own or one for new entries, which GNU ls marks with "+" after the mode; true when ls can't tell. */
function hasAcl(path: string): boolean {
  try {
    gnuLs ??= execFileSync("ls", ["--version"], { encoding: "utf8", timeout: 5000 }).includes("GNU coreutils");
    if (!gnuLs) return true;
    const mode = execFileSync("ls", ["-ld", "--", path], { encoding: "utf8", timeout: 5000 }).split(/\s/)[0];
    // "." marks a security context alone
    return !/^[-a-zA-Z]{10}\.?$/.test(mode);
  } catch {
    return true;
  }
}

/** Rights in a macOS ACL entry that only read, or only say where the entry is inherited; any other one may change something. */
const MAC_READ_ONLY = new Set(["read", "list", "execute", "search", "readattr", "readextattr", "readsecurity", "synchronize", "file_inherit", "directory_inherit", "limit_inherit", "only_inherit"]);

/** What a macOS ACL allows users besides the user and root. */
export interface MacAcl {
  /** To change the entry, or for a folder what is in it. */
  change: boolean;
  /** Anything at all, entering a folder among it. */
  any: boolean;
}

/**
 * What the ACL in macOS's `ls -led` output allows others than `user` and
 * root, or null when the output isn't what that ls prints. Deny entries only
 * take rights away, so they never count (home folders deny everyone delete).
 * Every allowed right besides reading, for anyone else, counts as a change:
 * rights ls might name in a later macOS among them.
 */
export function macAcl(listing: string, user: string): MacAcl | null {
  const lines = listing.split("\n");
  if (lines.at(-1) === "") lines.pop();
  // The mode, then "+" for an ACL or "@" for extended attributes (an ACL is listed then all the same)
  const mode = /^[-a-zA-Z]{10}([ @+])/.exec(lines[0] ?? "");
  if (!mode) return null;
  const entries = lines.slice(1);
  if (mode[1] === "+" && !entries.length) return null;
  const out: MacAcl = { change: false, any: false };
  for (const [i, line] of entries.entries()) {
    // " 0: group:everyone deny delete", " 1: user:bob inherited allow read,write"
    const m = /^ (\d+): (.+) (allow|deny) ([a-z_,]*)$/.exec(line);
    // ls numbers the entries it skips too: a gap is one it couldn't read
    if (!m || Number(m[1]) !== i) return null;
    if (m[3] === "deny") continue;
    const who = m[2].replace(/ inherited$/, "");
    if (who === `user:${user}` || who === "user:root") continue;
    out.any = true;
    if (m[4].split(",").some((right) => right && !MAC_READ_ONLY.has(right))) out.change = true;
  }
  return out;
}

/**
 * Output of a macOS system tool, or null when it is missing, fails, takes too
 * long or says anything on stderr. By absolute path: those on the sealed system
 * volume, not the first ls or mount on PATH (GNU's from Homebrew reads no
 * macOS ACLs).
 */
function macTool(tool: string, args: string[]): string | null {
  const r = spawnSync(tool, args, { encoding: "utf8", timeout: 5000, stdio: ["ignore", "pipe", "pipe"] });
  return r.error || r.status !== 0 || r.stderr ? null : r.stdout;
}

const macAclCache = new Map<string, MacAcl>();

/** The ACL of `path` on macOS; one that can't be read lets others do anything. */
function macAclOf(path: string, st: Stats): MacAcl {
  const key = `${st.dev}:${st.ino}:${st.ctimeMs}`;
  const known = macAclCache.get(key);
  if (known) return known;
  // -d: the folder itself; -q: no line breaks from a name
  const listing = macTool("/bin/ls", ["-ledq", "--", path]);
  const acl = listing === null ? null : macAcl(listing, userInfo().username);
  if (!acl) return { change: true, any: true };
  macAclCache.set(key, acl);
  return acl;
}

/** Writable by someone besides the user (and root). */
function othersCanWrite(st: Stats, path: string): boolean {
  // macOS: the group is usually the shared "staff", and an ACL can let anyone in whatever the mode says
  if (process.platform === "darwin") return (st.mode & 0o022) !== 0 || macAclOf(path, st).change;
  if (st.mode & 0o002) return true;
  if (!(st.mode & 0o020)) return false;
  return st.gid !== privateGid() || aclLetsOthersWrite(path, st);
}

/** Whether an ACL lets others into a folder whose mode keeps them out: on macOS. A POSIX ACL can't, its mask is the group bits. */
function aclLetsOthersIn(st: Stats, path: string): boolean {
  return process.platform === "darwin" && macAclOf(path, st).any;
}

/** Whether a sticky folder keeps others from the user's entries: not on macOS when an ACL lets them change it. */
function stickyHolds(st: Stats, path: string): boolean {
  return process.platform !== "darwin" || !macAclOf(path, st).change;
}

/** Network and FUSE filesystems: the owners and modes they show don't say who can write. */
const UNCHECKABLE_FS = new Set([
  0x6969, 0x517b, 0xff534d42, 0xfe534d42, 0x65735546, 0x01021997, 0x00c36400, 0x5346414f, 0x73757245, 0x564c, 0x6b414653, 0x0bd00bd0, 0x47504653, 0x786f4256, 0x20030528,
  0x19830326,
]);

/** macOS volumes whose owners and modes are real. */
const MAC_OWNED_FS = new Set(["apfs", "hfs"]);
const MAC_NOT_OWNED = "it is on a network, FUSE or other volume whose owners and modes don't say who can write, or on one set to ignore ownership";
const MAC_NO_MOUNTS = "its volume can't be checked: the mount table didn't read as expected";

/**
 * Why the macOS volume with device `dev` can't be trusted, from `mount`'s
 * output, or null. It is found by device, not by path: /Users and other
 * firmlinks lead from / to the data volume. `devOf` stats a mount point; only
 * the local mounts are stat'ed, since a network one may not answer. Of those,
 * at least one must have the device, and every one that does (two mounts can
 * report the same number) must be an APFS or HFS+ volume that keeps ownership
 * ("noowners": every file shows as the viewer's), not a union mount and not
 * one another user mounted, and alone on its mount point.
 */
export function macMountProblem(table: string, dev: number, user: string, devOf: (point: string) => number | undefined): string | null {
  const mounts: { point: string; options: string[] }[] = [];
  for (const line of table.split("\n")) {
    if (!line) continue;
    // "/dev/disk3s5 on /System/Volumes/Data (apfs, local, journaled, nobrowse)"
    const m = /^(.+?) on (\/.*) \(([^()]*)\)$/.exec(line);
    if (!m) return MAC_NO_MOUNTS;
    mounts.push({ point: m[2], options: m[3].split(", ") });
  }
  if (!mounts.length) return MAC_NO_MOUNTS;
  const owned = (o: string[]): boolean =>
    MAC_OWNED_FS.has(o[0]) && o.includes("local") && !o.includes("noowners") && !o.includes("union") && o.every((x) => !x.startsWith("mounted by ") || x === `mounted by ${user}`);
  // Different mounts can share a device number (/ and the data volume do), so all of them must be trustworthy
  const holding = mounts.filter((m) => m.options.includes("local") && devOf(m.point) === dev);
  // Another volume mounted over one shows its own files at that point
  if (!holding.length || !holding.every((h) => owned(h.options) && mounts.filter((m) => m.point === h.point).length === 1)) return MAC_NOT_OWNED;
  return null;
}

/** How long the mount table is taken as read: volumes come and go. */
const MOUNTS_FOR_MS = 5000;
let mountTable: { text: string; at: number } | null = null;

function macFilesystemProblem(dev: number): string | null {
  if (!mountTable || Date.now() - mountTable.at > MOUNTS_FOR_MS) {
    const text = macTool("/sbin/mount", []);
    if (text === null) return MAC_NO_MOUNTS;
    mountTable = { text, at: Date.now() };
  }
  const devOf = (point: string): number | undefined => {
    try {
      return statSync(point).dev;
    } catch {
      return undefined;
    }
  };
  return macMountProblem(mountTable.text, dev, userInfo().username, devOf);
}

/** Why the filesystem holding `real` (device `dev`) can't say who can write, or null. */
function filesystemProblem(real: string, dev: number): string | null {
  if (process.platform === "darwin") return macFilesystemProblem(dev);
  return UNCHECKABLE_FS.has(Number(statfsSync(real).type)) ? "it is on a network or FUSE filesystem, where WireBuddy can't check who can write" : null;
}

/**
 * Whether others could change what is in `root`: every folder from / down to
 * it must belong to root or the user and be closed to other writers, except
 * sticky ones (like /tmp), below which only the user's own entries count. A
 * folder of the user's that others can't enter makes everything below it on
 * the same filesystem private, unless `strict`: then every folder is checked,
 * since one below may be a bind mount of a shared folder.
 */
export function rootTrust(root: string, strict = false): RootTrust {
  const fail = (problem: string): RootTrust => ({ problem, real: root, dev: -1, privateDev: null });
  let real: string;
  try {
    real = realpathSync(root);
  } catch {
    return fail("it can't be read");
  }
  const uid = process.getuid!();
  let path: string = sep;
  let sticky = false;
  let privateDev: number | null = null;
  let dev = -1;
  try {
    const parts = ["", ...real.split(sep).filter(Boolean)];
    for (const [i, part] of parts.entries()) {
      path = join(path, part);
      const st = statSync(path);
      dev = st.dev;
      // The folder itself counts even below a private one: it may be a bind mount of a shared folder
      if (i === parts.length - 1) {
        if (st.uid !== uid && st.uid !== 0) return fail("another user owns it");
        if (othersCanWrite(st, path)) return fail("others can write to it");
      }
      if (!strict && privateDev !== null && st.dev === privateDev) continue;
      // Another filesystem mounted below the private folder: check it from here
      privateDev = null;
      if (st.uid !== uid && (st.uid !== 0 || sticky)) return fail("another user owns it or a folder above it");
      if (st.uid === uid && st.isDirectory() && (st.mode & 0o011) === 0 && !aclLetsOthersIn(st, path)) {
        privateDev = st.dev;
        sticky = false;
        continue;
      }
      sticky = othersCanWrite(st, path) && (st.mode & 0o1000) !== 0 && stickyHolds(st, path);
      if (othersCanWrite(st, path) && !sticky) return fail("others can write to it or a folder above it");
    }
    const fs = filesystemProblem(real, dev);
    if (fs) return fail(fs);
  } catch {
    return fail("it can't be read");
  }
  if (sticky) return fail("others can write to it");
  return { problem: null, real, dev, privateDev };
}

/** Why something with these stats in a trusted root could have been changed by others, or null. */
function statProblem(st: Stats, path: string, kind: "folder" | "file", trust: RootTrust): string | null {
  if (st.isSymbolicLink()) return "is a symbolic link";
  if (kind === "folder" ? !st.isDirectory() : !st.isFile()) return kind === "file" ? "is not a regular file" : "is not a folder";
  if (st.dev !== trust.dev) return "is on another filesystem";
  // Root could change anything anyway
  if (st.uid !== process.getuid!() && st.uid !== 0) return "belongs to another user";
  // Another link to the file could be in a folder others can reach
  if (kind === "file" && st.nlink > 1) return "has other hard links";
  if (othersCanWrite(st, path)) return "can be written by others";
  return null;
}

/** Why an extension's folder or file could have been changed by others, or null. */
export function entryProblem(path: string, kind: "folder" | "file", trust: RootTrust, optional = false): string | null {
  const st = lstatSync(path, { throwIfNoEntry: false });
  if (!st) return optional ? null : `${printable(path)} is missing`;
  const problem = statProblem(st, path, kind, trust);
  return problem && `${printable(path)} ${problem}`;
}

/** Reads a file through a descriptor checked like entryProblem, so what was checked is what is read. */
export function readChecked(path: string, trust: RootTrust, max = Infinity): Buffer {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const st = fstatSync(fd);
    const problem = statProblem(st, path, "file", trust);
    if (problem) throw new Error(`${printable(path)} ${problem}`);
    if (st.size > max) throw new Error("too large");
    return readFileSync(fd);
  } finally {
    closeSync(fd);
  }
}
