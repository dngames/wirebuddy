/** WebSocket for server pushes, reconnecting with exponential backoff. */

import type { ServerEvent } from "../shared/api.ts";
import { wsUrl } from "./api.ts";
import { applyState, markResync, noteWsState, refreshState } from "./actions.ts";
import { app, bus, type ConnState } from "./app.ts";
import { toast } from "./toast.ts";

let ws: WebSocket | null = null;
let attempt = 0;
let retryTimer = 0;

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
  sock.onopen = () => {
    attempt = 0;
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
      noteWsState();
      applyState(msg.state);
    } else if (msg.type === "toast") {
      toast(msg.level === "error" ? "error" : "info", msg.text);
    }
  };
  sock.onclose = () => {
    if (ws !== sock) return;
    ws = null;
    schedule();
  };
  sock.onerror = () => {
    // onclose follows and schedules the retry
  };
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
