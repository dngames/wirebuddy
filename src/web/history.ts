/** Packet history for Go > Back / Forward, like Wireshark's. */

import * as act from "./actions.ts";
import { app, bus } from "./app.ts";

const MAX = 500;

let frames: number[] = [];
let pos = -1;
let navigating = false;

export function canGoBack(): boolean {
  return pos > 0;
}

export function canGoForward(): boolean {
  return pos >= 0 && pos < frames.length - 1;
}

export function goHistory(dir: 1 | -1): void {
  const i = pos + dir;
  if (i < 0 || i >= frames.length) return;
  pos = i;
  navigating = true;
  try {
    act.jumpToFrame(frames[i]);
  } finally {
    navigating = false;
  }
}

bus.on("state", (s, prev) => {
  // Frame numbers of another file mean nothing here
  if (prev && (s.file !== prev.file || s.instance !== prev.instance)) {
    frames = [];
    pos = -1;
  }
});

bus.on("selection", () => {
  const f = app.selFrame;
  if (navigating || f === null || frames[pos] === f) return;
  frames = frames.slice(0, pos + 1);
  frames.push(f);
  if (frames.length > MAX) frames.shift();
  pos = frames.length - 1;
});
