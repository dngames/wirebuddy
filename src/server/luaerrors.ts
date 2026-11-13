/**
 * Lua errors the extensions report while a file is read: told to the agent
 * in batches, once they stop coming, with one example, never twice for the
 * same packet. The viewer is read through LuaErrorsView.
 */

import { basename } from "node:path";
import { printable } from "./text.ts";
import type { LuaError } from "./sharkd.ts";

/** What the batching needs of the viewer. */
export interface LuaErrorsView {
  /** The capture being shown, or null. */
  file(): string | null;
  /** Tells the agent of a problem. */
  report(text: string): void;
}

export class LuaErrors {
  /** Lua errors the extensions reported for the open file, told to the agent in batches. */
  private luaErrs = { file: "", frames: new Set<number>(), more: false, told: 0, example: null as LuaError | null, timer: null as NodeJS.Timeout | null, since: 0 };

  constructor(private readonly v: LuaErrorsView) {}

  /** An extension failed on a packet while a file was read: the agent hears about new ones in batches. */
  luaError(e: LuaError): void {
    const s = this.luaErrs;
    if (e.file !== s.file) {
      this.tellLuaErrors();
      this.forgetLuaErrors(e.file);
    }
    if (e.frame === 0) s.more = true;
    else if (!s.frames.has(e.frame) && s.frames.size < 100_000) {
      s.frames.add(e.frame);
      if (!s.example || e.frame < s.example.frame) s.example = e;
    }
    // Once they stop coming for 1.5 s (a looping dissector takes 1 s per packet), at most 8 s after the first
    if (s.timer) clearTimeout(s.timer);
    else s.since = Date.now();
    s.timer = setTimeout(() => this.tellLuaErrors(), Math.max(0, Math.min(1500, s.since + 8000 - Date.now())));
  }

  private tellLuaErrors(): void {
    const s = this.luaErrs;
    s.timer = null;
    const n = s.frames.size - s.told;
    if (n <= 0 || !s.example) return;
    const what = `${s.told ? `${n} more packet${n === 1 ? "" : "s"}` : `${n}${s.more ? "+" : ""} packet${n === 1 ? "" : "s"}`} of ${basename(s.file)}`;
    this.v.report(`Lua errors in ${what}, e.g. frame ${s.example.frame}: ${printable(s.example.message)} — fix the extension, check it with extensions(action "test"), then reload`);
    s.told = s.frames.size;
    s.example = null;
  }

  /** New code or another file: its errors are all new. */
  forgetLuaErrors(file = this.v.file() ?? ""): void {
    const s = this.luaErrs;
    if (s.timer) clearTimeout(s.timer);
    Object.assign(s, { file, frames: new Set<number>(), more: false, told: 0, example: null, timer: null });
  }
}
