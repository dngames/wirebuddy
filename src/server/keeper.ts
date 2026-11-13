/**
 * Keeping the open capture's investigation (see investigation.ts) while the
 * view changes: a second after a change at most once a second, at once on
 * request, and its file removed when nothing is left to keep. Problems with
 * the folder or the file go to the agent once each. What was kept is read
 * back when a capture opens. The viewer is read through KeeperView.
 */

import { basename, join } from "node:path";
import { fileHead } from "./capturefile.ts";
import {
  INVESTIGATION_HEAD,
  investigationContent,
  InvalidInvestigation,
  investigationKey,
  MAX_INVESTIGATION_BYTES,
  nothingToKeep,
  readInvestigation,
  removeInvestigation,
  serializeInvestigation,
  setAsideInvestigation,
  setAsideName,
  writeInvestigation,
  type Investigation,
  type InvestigationLimits,
} from "./investigation.ts";
import type { ViewState } from "../shared/api.ts";

/** How soon after a change the investigation is kept. */
const KEEP_MS = 1000;

/** What keeping needs of the viewer. */
export interface KeeperView {
  /** Where investigations are kept; null: nowhere. */
  dir(): string | null;
  state(): Pick<ViewState, "file" | "fileSize" | "totalFrames" | "marks" | "timeRefs" | "commentRevision" | "commentEdits" | "kept">;
  set(patch: Pick<ViewState, "kept">): void;
  /** The marks, time references and edited comments the view has. */
  investigation(): Investigation;
  /** The first bytes of the file read last. */
  loadedHead(): Buffer;
  /** Whether a running capture is still writing `file`. */
  growing(file: string): boolean;
  /** A WARNING for the agent. */
  warn(text: string): void;
}

/** What was read of the investigation kept for a capture: its key, the investigation, and why one that is there can't be used. */
export interface KeptRead {
  key: string;
  investigation: Investigation | null;
  problem: string | null;
}

export class Keeper {
  /** What the open capture's investigation file holds, as this server wrote or read it: its key, and its content ("" for none). */
  private kept: Readonly<{ key: string; content: string }> = { key: "", content: "" };
  private keepTimer: NodeJS.Timeout | null = null;
  /** What the last save looked at: a change to any of these is saved shortly after. */
  private keptOf: unknown[] = [];
  /** Problems with keeping investigations already told to the agent. */
  private readonly keepTold = new Set<string>();
  /** Keys whose file this server refused to read: set aside before anything is written over it. */
  private readonly refused = new Set<string>();

  constructor(private readonly v: KeeperView) {}

  /**
   * The investigation kept for `file` (whose first bytes are `head`), read
   * within `limits`; nothing for a file still growing into the bytes that
   * name it. A file that can't be read as one is set aside before anything
   * is kept over it.
   */
  read(file: string, head: Buffer, limits: InvestigationLimits): KeptRead {
    const dir = this.v.dir();
    if (!dir || !head.length || (head.length < INVESTIGATION_HEAD && this.v.growing(file))) return { key: "", investigation: null, problem: null };
    const key = investigationKey(head);
    try {
      return { key, investigation: readInvestigation(dir, key, limits), problem: null };
    } catch (err) {
      if (err instanceof InvalidInvestigation) this.refused.add(key);
      return { key, investigation: null, problem: (err as Error).message };
    }
  }

  /**
   * The view opened `file` with what read() brought back for it: its
   * investigation file holds what the view has now (nothing, if it couldn't
   * be used), and the view counts as kept if there is one. A problem reading
   * it goes to the agent.
   */
  adopt(file: string, { key, problem }: Pick<KeptRead, "key" | "problem">): void {
    const inv = this.v.investigation();
    this.kept = { key, content: key && !problem && !nothingToKeep(inv) ? investigationContent(inv) : "" };
    this.keptOf = this.keepingOf();
    // What the view has is what is kept: nothing, or what was read
    if (this.v.state().kept !== !!key) this.v.set({ kept: !!key });
    if (!problem) return;
    const dir = this.v.dir()!;
    const aside = this.refused.has(key) ? `; it stays as it is until something is kept for this capture, then it is moved to ${setAsideName(dir, key)}` : "";
    this.v.warn(`The marks, time references and packet comments kept for ${basename(file)} were not restored: ${problem} (${join(dir, `${key}.json`)})${aside}`);
  }

  /** The view left its capture: what an investigation file holds is known again once one opens. */
  leave(): void {
    this.kept = { key: "", content: "" };
  }

  /** What the open capture's investigation file holds, as this server last wrote or read it; another object once that changes. */
  held(): Readonly<{ key: string; content: string }> {
    return this.kept;
  }

  /** Whether the view changed since it was last kept. */
  changed(): boolean {
    return this.keepingOf().some((v, i) => v !== this.keptOf[i]);
  }

  /** The name of the open capture's investigation; null while a live capture still grows into the bytes that name it. */
  private captureKey(): string | null {
    const file = this.v.state().file;
    let head = this.v.loadedHead();
    if (!file || !head.length) return null;
    if (head.length < INVESTIGATION_HEAD) {
      if (this.v.growing(file)) return null;
      // A file that stopped growing: its first bytes as they are now, if they go on from the ones read
      const now = fileHead(file);
      if (!now.subarray(0, head.length).equals(head)) return null;
      head = now;
    }
    return investigationKey(head);
  }

  /** Keeps the investigation a second after a change, at most once a second. */
  keepSoon(): void {
    if (!this.v.dir() || this.keepTimer) return;
    this.keepTimer = setTimeout(() => {
      this.keepTimer = null;
      this.keepNow();
    }, KEEP_MS);
    this.keepTimer.unref();
  }

  /**
   * Keeps the open capture's marks, time references and edited comments
   * now, or removes its file when nothing is left to keep; returns whether
   * they are kept (or there is nothing to keep).
   */
  keepNow(): boolean {
    if (this.keepTimer) clearTimeout(this.keepTimer);
    this.keepTimer = null;
    const kept = this.keepNowIn();
    if (this.v.state().kept !== kept) this.v.set({ kept });
    return kept;
  }

  /** What changes make the view's investigation one to keep again. */
  private keepingOf(): unknown[] {
    const s = this.v.state();
    return [s.file, s.marks, s.timeRefs, s.commentRevision, s.commentEdits];
  }

  private keepNowIn(): boolean {
    const dir = this.v.dir();
    const file = this.v.state().file;
    this.keptOf = this.keepingOf();
    if (!dir || !file) return false;
    const key = this.captureKey();
    if (!key) return false;
    const inv = this.v.investigation();
    const content = nothingToKeep(inv) ? "" : investigationContent(inv);
    if (key === this.kept.key && content === this.kept.content) return true;
    try {
      // A file this server couldn't read goes aside first, not lost
      if (this.refused.has(key)) {
        setAsideInvestigation(dir, key);
        this.refused.delete(key);
      }
      if (!content) removeInvestigation(dir, key);
      else {
        const text = serializeInvestigation(inv, { path: file, size: this.v.state().fileSize, frames: this.v.state().totalFrames });
        if (Buffer.byteLength(text) > MAX_INVESTIGATION_BYTES) {
          this.keepProblem(`The marks, time references and packet comments of ${basename(file)} take more than ${MAX_INVESTIGATION_BYTES / 1024 / 1024} MiB, too much to keep: they stay only until the capture is closed or another one opened`, key);
          return false;
        }
        writeInvestigation(dir, key, text);
      }
      this.kept = { key, content };
      return true;
    } catch (err) {
      this.keepProblem(`Could not keep the marks, time references and packet comments of ${basename(file)} in ${dir}: ${(err as Error).message}`);
      return false;
    }
  }

  /** A WARNING for the agent, once for each problem (or `once` key). */
  keepProblem(text: string, once = text): void {
    if (this.keepTold.has(once)) return;
    this.keepTold.add(once);
    this.v.warn(text);
  }
}
