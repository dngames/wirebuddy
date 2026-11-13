/** WebSocket for server pushes, reconnecting with exponential backoff. */

import type { ServerEvent, ViewState } from "../shared/api.ts";
import { get, HttpError, wsUrl } from "./api.ts";
import { applyState, markResync, noteWsState, refreshState } from "./actions.ts";
import { app, bus, type ConnState } from "./app.ts";
import { toast, toastRefused } from "./toast.ts";

let ws: WebSocket | null = null;
let attempt = 0;
let retryTimer = 0;
/** Number of the last push of this socket taken: its whole state, then each patch in turn; null before the state. */
let pushSeq: number | null = null;
/** Sockets in a row closed for a skipped number without a patch taken in order since. */
let skips = 0;

function setConn(c: ConnState): void {
  if (app.conn === c) return;
  app.conn = c;
  bus.emit("conn", c);
}

function open(): void {
  window.clearTimeout(retryTimer);
  setConn("connecting");
  let sock: WebSocket;
  try {
    sock = new WebSocket(wsUrl());
  } catch {
    schedule();
    return;
  }
  ws = sock;
  pushSeq = null;
  let opened = false;
  sock.onopen = () => {
    opened = true;
    attempt = 0;
    setUnauthorized(false);
    // The server may have restarted: the next state must not be diffed against the old one.
    markResync();
    setConn("open");
    void refreshState();
  };
  sock.onmessage = (ev: MessageEvent) => {
    let msg: ServerEvent;
    try {
      msg = JSON.parse(String(ev.data)) as ServerEvent;
    } catch {
      return;
    }
    if (msg.type === "state") {
      pushSeq = msg.seq;
      noteWsState();
      applyState(msg.state);
    } else if (msg.type === "patch") {
      // Without the state before it or with a number missing, what changed in between is unknown: a whole state comes with a new socket
      if (!app.state || pushSeq === null || msg.seq !== pushSeq + 1) {
        skipped(sock);
        return;
      }
      pushSeq = msg.seq;
      skips = 0;
      noteWsState();
      // The fields the patch leaves out keep their objects from the state before: applyState and the handlers rely on that to skip work
      applyState({ ...app.state, ...msg.patch });
    } else if (msg.type === "toast") {
      // The server logs an error it sends here for the agent itself
      if (msg.level === "error") toastRefused(msg.text);
      else toast("info", msg.text);
    }
  };
  sock.onclose = () => {
    if (ws !== sock) return;
    ws = null;
    // A socket refused before it opened says nothing of why: ask over HTTP whether the token is the reason
    if (!opened) void probe();
    schedule();
  };
  sock.onerror = () => {
    // onclose follows and schedules the retry
  };
}

function setUnauthorized(on: boolean): void {
  if (app.unauthorized === on) return;
  app.unauthorized = on;
  bus.emit("conn", app.conn);
}

/** Whether the server refuses the page's token: a restarted WireBuddy has a new one unless the old was kept, and the page can't hear 403 from the socket. */
async function probe(): Promise<void> {
  try {
    await get<ViewState>("api/state");
    setUnauthorized(false);
  } catch (err) {
    // Refused to connect (status 0) or any other trouble: just offline
    setUnauthorized(err instanceof HttpError && (err.status === 401 || err.status === 403));
  }
  // A socket that opened meanwhile has the final word
  if (app.conn === "open") setUnauthorized(false);
}

/** A push is missing: reconnect for a whole state, at once the first time, then with the backoff so that a server that keeps doing this is not hammered. */
function skipped(sock: WebSocket): void {
  ws = null;
  sock.onmessage = null;
  sock.close();
  if (skips++ === 0) {
    open();
    return;
  }
  attempt = skips - 2;
  schedule();
}

function schedule(): void {
  const delay = Math.min(10000, 500 * 2 ** attempt) * (0.8 + Math.random() * 0.4);
  attempt = Math.min(attempt + 1, 10);
  app.reconnectAt = Date.now() + delay;
  setConn("closed");
  bus.emit("conn", "closed");
  retryTimer = window.setTimeout(open, delay);
}

/** Retry right away (status bar click, network back online). */
export function reconnectNow(): void {
  if (ws) return;
  attempt = 0;
  open();
}

export function connectWs(): void {
  open();
  window.addEventListener("online", reconnectNow);
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible" && !ws) reconnectNow();
  });
}
