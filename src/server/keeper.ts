/**
 * Keeping the open capture's investigation (see investigation.ts) while the
 * view changes: a second after a change at most once a second, at once on
 * request, and its file removed when nothing is left to keep. Problems with
 * the folder or the file go to the agent once each. The viewer is read
 * through KeeperView.
 */

import { basename } from "node:path";
import { fileHead } from "./capturefile.ts";
import {
  INVESTIGATION_HEAD,
  investigationContent,
  investigationKey,
  MAX_INVESTIGATION_BYTES,
  nothingToKeep,
  removeInvestigation,
  serializeInvestigation,
  setAsideInvestigation,
  writeInvestigation,
  type Investigation,
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

export class Keeper {
  /** What the open capture's investigation file holds, as this server wrote or read it: its key, and its content ("" for none). */
  kept = { key: "", content: "" };
  private keepTimer: NodeJS.Timeout | null = null;
  /** What the last save looked at: a change to any of these is saved shortly after. */
  keptOf: unknown[] = [];
  /** Problems with keeping investigations already told to the agent. */
  private readonly keepTold = new Set<string>();
  /** Keys whose file this server refused to read: set aside before anything is written over it. */
  readonly refused = new Set<string>();

  constructor(private readonly v: KeeperView) {}

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
  keepingOf(): unknown[] {
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
