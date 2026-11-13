/**
 * The state the viewer shows the page and the agent: the one place where it
 * is replaced. A change made with set() runs the rules registered with
 * after() and then tells the listener; merge() changes the state without
 * telling anyone, for changes that are told by the set() that follows.
 */

import { randomBytes } from "node:crypto";
import type { CaptureState, ViewState } from "../shared/api.ts";

/** What the state starts from. */
export function initialState({ capture, wiresharkAvailable, decodeAsUnavailable }: { capture: CaptureState; wiresharkAvailable: boolean; decodeAsUnavailable: string | null }): ViewState {
  return {
    file: null,
    fileSize: 0,
    loading: false,
    loadError: null,
    // Unique per process so a restarted server never reuses a generation the UI has cached
    generation: Date.now() % 1_000_000_000,
    instance: randomBytes(6).toString("hex"),
    columns: [],
    totalFrames: 0,
    displayedFrames: 0,
    duration: 0,
    filter: "",
    selected: null,
    selectedIndex: -1,
    selectedBy: null,
    selectSeq: 0,
    selectedRows: [],
    selectedCount: 0,
    rowsSince: 0,
    marks: [],
    timeRefs: [],
    timeRefsRevision: 0,
    commentEdits: 0,
    commentsEdited: 0,
    commentRevision: 0,
    kept: false,
    capture,
    agentNotice: null,
    agent: { attached: false, pending: 0, name: "Agent", watching: false },
    wiresharkAvailable,
    customColumns: [],
    tlsKeylog: null,
    decodeAs: { entries: [], unavailable: decodeAsUnavailable },
    extensions: { active: 0, failing: 0, revision: 0 },
    panels: [],
    panelOffers: [],
    epoch: 1,
    tail: null,
  };
}

export class ViewStore {
  private current: ViewState;
  private readonly rules: ((state: ViewState) => ViewState)[] = [];

  /** `tell` is called with the state after every set(). */
  constructor(
    initial: ViewState,
    private readonly tell: (state: ViewState) => void,
  ) {
    this.current = initial;
  }

  get state(): ViewState {
    return this.current;
  }

  /** Registers a rule run after each set(), in order: it gets the state with the patch applied and returns the state to keep (the same one if nothing changes). */
  after(rule: (state: ViewState) => ViewState): void {
    this.rules.push(rule);
  }

  /** Applies `patch`, runs the rules, and tells the listener. */
  set(patch: Partial<ViewState>): void {
    this.current = { ...this.current, ...patch };
    for (const rule of this.rules) this.current = rule(this.current);
    this.tell(this.current);
  }

  /** Applies `patch` without running the rules or telling anyone. */
  merge(patch: Partial<ViewState>): void {
    this.current = { ...this.current, ...patch };
  }
}
