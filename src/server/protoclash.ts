/**
 * Two Lua protocols can't have the same description or name: whichever
 * registers second fails to load. A Wireshark plugin of the user's and an
 * extension can clash that way, and then it is the plugin that fails, or the
 * extension. These find the clash from the error text and the Lua files.
 */

import { lstatSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

/** A protocol a Lua file declares, as written. */
export interface ProtoDecl {
  name: string;
  description: string;
}

/** What Wireshark says when a protocol repeats another's description or name: which of the two, else null. */
export function clashKind(error: string): "description" | "name" | null {
  const kind = /there cannot be two protocols with the same (description|name)/.exec(error)?.[1];
  return kind === "description" || kind === "name" ? kind : null;
}

const STRING = String.raw`(?:"((?:[^"\\\n]|\\.)*)"|'((?:[^'\\\n]|\\.)*)')`;
const DECLARATION = new RegExp(String.raw`\bProto(?:\.new)?\s*\(\s*${STRING}\s*,\s*${STRING}`, "g");

/** The `Proto("name", "description")` calls of Lua text with both as plain strings (a computed one isn't seen). */
export function protoDeclarations(lua: string): ProtoDecl[] {
  const out: ProtoDecl[] = [];
  for (const m of lua.matchAll(DECLARATION)) out.push({ name: m[1] ?? m[2], description: m[3] ?? m[4] });
  return out;
}

/** Whether any declaration of `a` has the description, or the name (as filters read it: in lower case), of one of `b`. */
export function sameProtocol(a: ProtoDecl[], b: ProtoDecl[]): boolean {
  return a.some((x) => b.some((y) => x.description === y.description || x.name.toLowerCase() === y.name.toLowerCase()));
}

/** The Lua files in `dirs`, a few levels down, at most `max` of them; folders that can't be read are left out. */
export function luaFilesBelow(dirs: string[], max = 500): string[] {
  const out: string[] = [];
  const walk = (dir: string, depth: number): void => {
    let names: string[];
    try {
      names = readdirSync(dir).sort();
    } catch {
      return;
    }
    for (const name of names) {
      if (out.length >= max) return;
      const path = join(dir, name);
      const st = lstatSync(path, { throwIfNoEntry: false });
      if (st?.isFile() && name.endsWith(".lua")) out.push(path);
      else if (st?.isDirectory() && depth < 3) walk(path, depth + 1);
    }
  };
  for (const dir of dirs) walk(dir, 0);
  return out;
}

/** The first of `files` that declares a protocol like one of `decls`; text over 1 MiB isn't looked into. */
export function clashingFile(files: string[], decls: ProtoDecl[]): string | null {
  if (!decls.length) return null;
  for (const file of files) {
    try {
      if (lstatSync(file).size > 1024 * 1024) continue;
      if (sameProtocol(decls, protoDeclarations(readFileSync(file, "utf8")))) return file;
    } catch {
      // unreadable: not it
    }
  }
  return null;
}
