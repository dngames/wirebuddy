/**
 * The panels extensions offer for the open capture: each offer's filter is
 * checked, then whether a packet of the file (or of the live tail) matches
 * it. Matches show in the status bar until the user opens the panel or
 * dismisses the offer for the file. The viewer is read through OffersView.
 */

import { Superseded, type LiveTail } from "./livetail.ts";
import { ApiError } from "./paneldata.ts";
import { printable } from "./text.ts";
import type { FilterCheck, PanelOffer, ViewState } from "../shared/api.ts";

/** How often unmatched panel offers are checked again during a live capture. */
const OFFER_LIVE_MS = 30_000;

/** What the offers need of the viewer. */
export interface OffersView {
  state(): Pick<ViewState, "file" | "totalFrames" | "epoch" | "panelOffers">;
  set(patch: Pick<ViewState, "panelOffers">): void;
  /** The offers of enabled panels. */
  offers(): { name: string; label: string; filter: string; text: string }[];
  checkFilter(filter: string): Promise<FilterCheck>;
  warn(text: string): void;
  /** Whether a capture is running. */
  capturing(): boolean;
  followingCapture(): boolean;
  heldReason(filter: string): Promise<string | null>;
  liveTail(): LiveTail | null;
  tailWorked(tail: LiveTail): void;
  tailFailed(tail: LiveTail, err: Error): void;
  memoryShort(): boolean;
  anyMatch(filters: string[], release: boolean): Promise<{ matches: Map<string, boolean>; frames: number }>;
  isOpen(name: string): boolean;
}

export class PanelOffers {
  /** Panel offers for the open file: matched ones (with their filter), invalid filters, dismissed ones. */
  private offerFile: string | null = null;
  private readonly offerMatched = new Map<string, { offer: PanelOffer; filter: string }>();
  private readonly offerErrors = new Map<string, { filter: string; error: string }>();
  private readonly offerDismissed = new Set<string>();
  private offerSeq = 0;
  private offerRun: Promise<void> = Promise.resolve();
  private offerTimer: NodeJS.Timeout | null = null;
  /** Offer filters that matched no packet of the file up to a frame, for the file and epoch they were checked with. */
  private offerChecked = { file: "", epoch: -1, to: new Map<string, number>() };

  constructor(private readonly v: OffersView) {}

  /** The invalid-filter error of a panel's offer, if it has one. */
  errorOf(name: string): { filter: string; error: string } | undefined {
    return this.offerErrors.get(name);
  }

  /**
   * Checks the offers of enabled panels against the open capture (`all`: also
   * the ones matched already): each filter is checked, then whether a packet
   * matches it (see offerMatches). Matches show as panelOffers.
   */
  checkOffers(all: boolean): Promise<void> {
    const seq = ++this.offerSeq;
    if (this.offerTimer) clearTimeout(this.offerTimer);
    this.offerTimer = null;
    this.offerRun = this.offerPass(seq, all).catch((err) => {
      if (seq !== this.offerSeq) return;
      this.showOffers();
      // Another file or extensions meanwhile: the pass that follows checks again
      if (!(err instanceof ApiError && ["stale", "busy", "no-capture", "gone"].includes(err.code))) this.v.warn(`Checking the panels' offers failed: ${printable((err as Error).message)}`);
    });
    return this.offerRun;
  }

  private async offerPass(seq: number, all: boolean): Promise<void> {
    const file = this.v.state().file;
    if (file !== this.offerFile) {
      this.offerFile = file;
      this.offerMatched.clear();
      this.offerDismissed.clear();
      this.showOffers();
    }
    const offers = this.v.offers();
    // Offers gone or changed since are no offers any more
    for (const [name, m] of this.offerMatched) if (!offers.some((o) => o.name === name && o.filter === m.filter)) this.offerMatched.delete(name);
    for (const [name, e] of this.offerErrors) if (!offers.some((o) => o.name === name && o.filter === e.filter)) this.offerErrors.delete(name);
    const valid: typeof offers = [];
    for (const o of offers.filter((x) => all || !this.offerMatched.has(x.name))) {
      const check = await this.v.checkFilter(o.filter);
      if (seq !== this.offerSeq) return;
      if (check.ok) {
        this.offerErrors.delete(o.name);
        valid.push(o);
        continue;
      }
      const error = check.error ?? "invalid";
      if (this.offerErrors.get(o.name)?.error !== error) this.v.warn(`The offer filter "${o.filter}" of the panel "${o.name}" is invalid, so it is never offered: ${error}`);
      this.offerErrors.set(o.name, { filter: o.filter, error });
      this.offerMatched.delete(o.name);
    }
    if (file && this.v.state().totalFrames > 0 && valid.length) {
      const found = await this.offerMatches(file, valid.map((o) => o.filter), () => seq === this.offerSeq);
      if (seq !== this.offerSeq || this.v.state().file !== file) return;
      for (const o of valid) {
        // Not checked this time: as it was
        if (!found.has(o.filter)) continue;
        if (found.get(o.filter)) this.offerMatched.set(o.name, { offer: { name: o.name, label: o.label, text: o.text }, filter: o.filter });
        else this.offerMatched.delete(o.name);
      }
    }
    this.showOffers();
    // A live capture may bring matching packets later
    if (file && this.v.capturing() && this.v.followingCapture() && offers.some((o) => !this.offerMatched.has(o.name) && !this.offerErrors.has(o.name))) {
      this.offerTimer = setTimeout(() => {
        this.offerTimer = null;
        if (this.v.capturing() && this.v.followingCapture()) void this.checkOffers(false);
      }, OFFER_LIVE_MS);
      this.offerTimer.unref();
    }
  }

  /**
   * Which of `filters` match a packet of `file`. Of a live capture, from
   * slices of the live tail: each filter from the frame it was found in none
   * up to on. Without a tail, and for filters slices can't check (see
   * heldReason), by the panel engine reading the whole file, which waits
   * while memory is short during a capture. Only while `wanted`.
   */
  private async offerMatches(file: string, filters: string[], wanted: () => boolean): Promise<Map<string, boolean>> {
    const { epoch } = this.v.state();
    if (this.offerChecked.file !== file || this.offerChecked.epoch !== epoch) this.offerChecked = { file, epoch, to: new Map() };
    const checked = this.offerChecked.to;
    const found = new Map<string, boolean>();
    // Those found are checked from the start again: their match may lie before `to`
    const advance = (fs: string[], to: number): void => {
      if (this.offerChecked.to !== checked || !wanted()) return;
      for (const f of fs) if (!found.get(f)) checked.set(f, Math.max(checked.get(f) ?? 0, to));
    };
    const held = new Set<string>();
    for (const f of filters) if (await this.v.heldReason(f)) held.add(f);
    const live = this.v.liveTail();
    const tail = live?.file === file && !live.broken() ? live : null;
    const sliced = tail ? filters.filter((f) => !held.has(f)) : [];
    if (tail && sliced.length) {
      try {
        const r = await tail.anyMatch(sliced, (f) => (checked.get(f) ?? 0) + 1, wanted);
        this.v.tailWorked(tail);
        if (!wanted()) return found;
        for (const f of sliced) found.set(f, r.found.has(f));
        advance(sliced, r.to);
      } catch (err) {
        // The live tail went, broke or failed: the whole file says
        if (!(err instanceof Superseded)) this.v.tailFailed(tail, err as Error);
      }
    }
    const whole = filters.filter((f) => !found.has(f));
    if (whole.length && wanted() && !(this.v.capturing() && this.v.memoryShort())) {
      // Slices check them next time: the panel engine needn't keep the file
      const release = this.v.capturing() && whole.every((f) => !held.has(f));
      const { matches, frames } = await this.v.anyMatch(whole, release);
      for (const f of whole) found.set(f, matches.get(f) ?? false);
      advance(whole, frames);
    }
    return found;
  }

  /** The matched offers the user sees: not of open panels, not dismissed. */
  showOffers(): void {
    const offers = this.shownOffers();
    if (JSON.stringify(offers) !== JSON.stringify(this.v.state().panelOffers)) this.v.set({ panelOffers: offers });
  }

  private shownOffers(): PanelOffer[] {
    const offers = [...this.offerMatched.values()].map((m) => m.offer).filter((o) => !this.v.isOpen(o.name) && !this.offerDismissed.has(o.name));
    return offers.sort((a, b) => a.name.localeCompare(b.name));
  }

  /** The user dismissed a panel's offer: not offered again for this file. */
  dismissOffer(name: string): void {
    this.offerDismissed.add(name);
    this.showOffers();
  }

  /** Panels offered for the open capture, once a check that runs now is done (or after `ms`). */
  async matchedOffers(ms = 5000): Promise<PanelOffer[]> {
    let timer: NodeJS.Timeout | undefined;
    await Promise.race([this.offerRun, new Promise<void>((done) => (timer = setTimeout(done, ms)))]);
    clearTimeout(timer);
    return this.shownOffers();
  }
}
