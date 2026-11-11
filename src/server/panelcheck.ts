/** Static checks of a panel's files, for the agent before the panel runs: syntax and what the panel's policy blocks. */

import { spawn } from "node:child_process";
import { join } from "node:path";
import type { PanelFiles } from "./extensions.ts";

export interface PanelCheck {
  errors: string[];
  warnings: string[];
}

/** What may not work when it runs, found by its text alone (also in comments, strings and code that never runs): warnings only. */
const LINTS: [RegExp, string][] = [
  [/\bimport\b[^;\n]*["'`]https?:\/\//, "imports from the network: the panel's content security policy refuses them when they run (panels load only their own files; copy the library into panel/)"],
  [/\b(?:eval\s*\(|new\s+Function\s*\()/, "eval and new Function: the panel's content security policy refuses them when they run (fine in code that never runs, like a library's fallback)"],
  [/\b(?:fetch\s*\(|new\s+(?:WebSocket|XMLHttpRequest|EventSource)\b)/, "panels have no network: get data from wb (fetch, WebSocket and XMLHttpRequest only reach the panel's own files)"],
  [/\.(?:innerHTML|outerHTML)\s*=|\binsertAdjacentHTML\s*\(|\bdocument\.write\s*\(/, "HTML from strings: only for your own markup, never packet data (use wb.h or textContent)"],
  [/\b(?:alert|confirm|prompt)\s*\(/, "alert, confirm and prompt are blocked in panels"],
];

/** Checks a panel's files as read for opening it. */
export async function checkPanel(files: PanelFiles): Promise<PanelCheck> {
  const out: PanelCheck = { errors: [], warnings: [] };
  const where = (rel: string, line?: number): string => `${join(files.folder, "panel", rel)}${line ? `:${line}` : ""}`;
  for (const [rel, f] of files.files) {
    if (!/\.m?js$/.test(rel)) continue;
    const code = f.bytes.toString("utf8");
    const syntax = await nodeCheck(code);
    if (syntax) out.errors.push(`${where(rel, syntax.line)}: ${syntax.message}`);
    for (const [re, text] of LINTS) {
      const line = lineOf(code, re);
      if (line) out.warnings.push(`${where(rel, line)}: ${text}`);
    }
  }
  if (/<script\b/i.test(files.body)) out.errors.push(`${where("body.html")}: scripts in body.html don't run: put code into main.js`);
  if (/\son[a-z]+\s*=/i.test(files.body)) out.errors.push(`${where("body.html")}: on*= attributes don't run: add listeners in main.js`);
  if (/(?:src|href)\s*=\s*["']?https?:/i.test(files.body)) out.errors.push(`${where("body.html")}: links to the network don't load: copy what it needs into panel/`);
  return out;
}

function lineOf(code: string, re: RegExp): number | null {
  const m = re.exec(code);
  return m ? code.slice(0, m.index).split("\n").length : null;
}

/** Node's own parser on the module: "[stdin]:N" and the message, or null when it parses. */
function nodeCheck(code: string): Promise<{ line: number | undefined; message: string } | null> {
  return new Promise((done) => {
    const p = spawn(process.execPath, ["--check", "--input-type=module", "-"], { stdio: ["pipe", "ignore", "pipe"] });
    let err = "";
    const timer = setTimeout(() => p.kill(), 10_000);
    p.stderr.setEncoding("utf8");
    p.stderr.on("data", (d: string) => (err += d));
    p.on("error", () => done(null));
    p.on("close", (code) => {
      clearTimeout(timer);
      if (code === 0) return done(null);
      const line = /\[stdin\]:(\d+)/.exec(err)?.[1];
      const message = err.split("\n").find((l) => /^\w*Error\b/.test(l.trim()))?.trim() ?? "does not parse";
      done({ line: line ? Number(line) : undefined, message });
    });
    p.stdin.on("error", () => {});
    p.stdin.end(code);
  });
}
