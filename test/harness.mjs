// What the test suites share: the check runner, sleep, starting the server, and headless Chrome over the DevTools protocol.

import { spawn } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { WebSocket } from "ws";

const main = join(dirname(fileURLToPath(import.meta.url)), "..", "dist/server/main.js");

export const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * The runner of a suite: `check(name, fn)` prints `ok   name` or `FAIL name: message` and counts failures;
 * `finish()` prints the summary and exits 1 on failures, else 0 (`cleanup` runs after the summary, before the exit).
 * `timed`: each ok line ends in the check's seconds. `notes`: a check may return text, printed in parentheses
 * after ok, or {skip: reason}, printed as a skip line and counted in the summary.
 */
export function suite({ timed = false, notes = false } = {}) {
  let failures = 0;
  let skipped = 0;
  async function check(name, fn) {
    const t0 = Date.now();
    try {
      const note = await fn();
      if (notes && note?.skip) {
        skipped++;
        console.log(`skip ${name}: ${note.skip}`);
      } else console.log(`ok   ${name}${timed ? ` (${Math.round((Date.now() - t0) / 1000)} s)` : ""}${notes && note ? ` (${note})` : ""}`);
    } catch (err) {
      failures++;
      console.log(`FAIL ${name}: ${err.message}`);
    }
  }
  function finish(cleanup) {
    console.log(failures ? `${failures} check(s) failed` : `all checks passed${skipped ? ` (${skipped} skipped)` : ""}`);
    cleanup?.();
    process.exit(failures ? 1 : 0);
  }
  return { check, finish };
}

/** The server on a port of its own with `token` (and `args` after it); `stdio` and `env` as spawn takes them. */
export function spawnServer({ token, args = [], env, stdio = ["ignore", "pipe", "inherit"] }) {
  return spawn(process.execPath, [main, "--port", "0", "--token", token, ...args], { stdio, env });
}

/** Where a spawned server's UI is, once it says so; rejects if it exits first. */
export function serverUrl(proc) {
  return new Promise((resolve, reject) => {
    proc.stdout.setEncoding("utf8");
    proc.stdout.on("data", (d) => {
      const m = /UI at (http:\/\/[^/]+)\//.exec(d);
      if (m) resolve(m[1]);
    });
    proc.on("exit", (code) => reject(new Error(`server exited with ${code}`)));
  });
}

/** A server and its URL, once it is up. */
export async function startServer(options) {
  const proc = spawnServer(options);
  return { proc, base: await serverUrl(proc) };
}

/** A request to the server's API: GET, or POST of `body` as JSON, with the token; the fetch response. */
export function apiFetch(base, token, path, body) {
  return fetch(base + path, {
    method: body === undefined ? "GET" : "POST",
    headers: { "X-WireBuddy-Token": token, "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

/** Headless Chrome with a profile folder of its own, a DevTools port of its choosing, and `flags`. */
export function startChrome(bin, profile, flags) {
  return spawn(bin, ["--headless=new", "--remote-debugging-port=0", `--user-data-dir=${profile}`, ...flags, "about:blank"], { stdio: "ignore" });
}

/** The DevTools port Chrome wrote to its profile folder; undefined if it did not within `ms`. */
export async function chromePort(profile, ms = 30_000) {
  let port;
  // A busy machine may take a while to start it
  for (const end = Date.now() + ms; !port && Date.now() < end; await sleep(100)) {
    if (existsSync(join(profile, "DevToolsActivePort"))) port = readFileSync(join(profile, "DevToolsActivePort"), "utf8").split("\n")[0];
  }
  return port;
}

/** An open DevTools connection to Chrome's first page. */
export async function pageSocket(port) {
  const targets = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
  const ws = new WebSocket(targets.find((t) => t.type === "page").webSocketDebuggerUrl);
  await new Promise((resolve, reject) => (ws.once("open", resolve), ws.once("error", reject)));
  return ws;
}

/** `cdp(method, params)` on `ws`: the whole answer message, error or not. */
export function rawCdp(ws) {
  let id = 0;
  const pending = new Map();
  ws.on("message", (m) => {
    const d = JSON.parse(m);
    pending.get(d.id)?.(d);
    pending.delete(d.id);
  });
  return (method, params = {}) => new Promise((resolve) => (pending.set(++id, resolve), ws.send(JSON.stringify({ id, method, params }))));
}

/** Chrome started on `bin`, its page connected, and `cdp` (see rawCdp); kills Chrome and throws if it never gets a DevTools port. */
export async function launchChrome(bin, profile, flags) {
  const chrome = startChrome(bin, profile, flags);
  const port = await chromePort(profile);
  if (!port) {
    chrome.kill();
    throw new Error("Chrome did not start its DevTools server in 30 s");
  }
  const ws = await pageSocket(port);
  return { chrome, ws, cdp: rawCdp(ws) };
}

/**
 * A WebSocket to the server's UI feed, followed the way the page does: `state` is taken whole, a `patch` is applied
 * when its number is the one after the last, and a skipped number is an error (thrown by `state`, `seq` and `until`).
 * Resolves once the first message (the whole state) is in. `messages` lists what came as {type, seq, bytes, patch?}
 * (the state message has no patch), `toasts` the texts of toasts, `until(describe, ms, pred)` the state once `pred(state)` is truthy.
 */
export async function followState(base, token) {
  const ws = new WebSocket(`${base.replace("http", "ws")}/ws?token=${token}`);
  const messages = [];
  const toasts = [];
  let state = null;
  let seq = null;
  let failure = null;
  const woken = new Set();
  ws.on("message", (raw) => {
    const m = JSON.parse(String(raw));
    if (m.type === "toast") return void toasts.push(m.text);
    messages.push({ type: m.type, seq: m.seq, bytes: Buffer.byteLength(String(raw)), patch: m.patch });
    if (m.type === "state") state = m.state;
    else if (m.type === "patch" && state !== null && m.seq === seq + 1) state = { ...state, ...m.patch };
    else failure = new Error(`push ${m.seq} after ${seq}${state === null ? " (no state yet)" : ""}: a number was skipped`);
    seq = m.seq;
    for (const wake of woken) wake();
  });
  await new Promise((resolve, reject) => (ws.once("open", resolve), ws.once("error", reject)));
  const until = (what, ms, pred) =>
    new Promise((resolve, reject) => {
      const timer = setTimeout(() => (woken.delete(look), reject(new Error(`gave up waiting for ${what}`))), ms);
      const look = () => {
        if (failure) return clearTimeout(timer), woken.delete(look), reject(failure);
        if (state !== null && pred(state)) return clearTimeout(timer), woken.delete(look), resolve(state);
      };
      woken.add(look);
      look();
    });
  await until("the first state", 10_000, () => true);
  return {
    ws,
    messages,
    toasts,
    until,
    get state() {
      if (failure) throw failure;
      return state;
    },
    get seq() {
      if (failure) throw failure;
      return seq;
    },
    close: () => ws.close(),
  };
}
