// The page across a restart of WireBuddy, in headless Chrome: a restart that keeps the session token is picked up by the
// open page by itself (it shows the new state); a plain offline server dims what is on screen; a server that refuses the
// page's token (another one, as after a restart with --token) makes the page say so plainly and keep trying, and it recovers
// when the token works again.
// Screenshots of the notice go to the folder named by SHOTS, if set.
// Usage: node test/browser-restart.mjs   (after npm run build; skipped without Chrome)
import { spawn } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import net from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import { chromeOrSkip } from "./chrome.mjs";
import { apiFetch, launchChrome, sleep, suite } from "./harness.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const chromeBin = chromeOrSkip();
if (!chromeBin) process.exit(0);

const work = mkdtempSync(join(tmpdir(), "wirebuddy-restart-"));
const home = join(work, "home");
mkdirSync(home);
const fixture = join(root, "test/fixtures/http.pcapng");

/** A port nothing listens on: the restarted servers use the same one, as a restart of the agent's server does. */
const port = await new Promise((resolve) => {
  const s = net.createServer().listen(0, "127.0.0.1", () => {
    const { port } = s.address();
    s.close(() => resolve(port));
  });
});

/** A server on `port` and the home of this test, without --token unless `args` gives one: its token, API and stop. */
async function start(args = []) {
  const proc = spawn(process.execPath, [join(root, "dist/server/main.js"), "--port", String(port), ...args], {
    env: { ...process.env, HOME: home, XDG_CONFIG_HOME: join(home, ".config"), XDG_DATA_HOME: join(home, ".local/share"), XDG_RUNTIME_DIR: join(home, "run"), WIREBUDDY_EXTENSIONS: "", WIREBUDDY_TOKEN: "" },
    stdio: ["ignore", "pipe", "ignore"],
  });
  const exited = new Promise((done) => proc.on("exit", done));
  const url = await new Promise((resolve, reject) => {
    proc.stdout.setEncoding("utf8");
    proc.stdout.on("data", (d) => /UI at (\S+)/.exec(d) && resolve(new URL(/UI at (\S+)/.exec(d)[1])));
    proc.on("exit", (code) => reject(new Error(`server exited with ${code}`)));
  });
  assert.equal(Number(url.port), port, "the server took the port it was asked for");
  const token = url.searchParams.get("token");
  const api = async (path, body) => {
    const r = await apiFetch(url.origin, token, path, body);
    return { status: r.status, json: await r.json() };
  };
  return { url, token, api, stop: async () => (proc.kill("SIGTERM"), await exited) };
}

const { check, finish } = suite({ timed: true });
const until = async (what, fn, ms = 10_000) => {
  for (const end = Date.now() + ms; Date.now() < end; await sleep(100)) if (await fn()) return;
  throw new Error(`timed out waiting for ${what}`);
};

let server = null;
let browser = null;
try {
  browser = await launchChrome(chromeBin, mkdtempSync(join(work, "chrome-")), ["--window-size=1280,760", "--no-first-run", "--no-default-browser-check", "--disable-gpu"]);
  const { cdp: raw } = browser;
  const cdp = async (method, params = {}) => {
    const d = await raw(method, params);
    if (d.error) throw new Error(`${method}: ${d.error.message}`);
    return d.result;
  };
  const evaluate = async (expression) => (await cdp("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true })).result.value;
  const shot = async (name) => {
    if (!process.env.SHOTS) return;
    mkdirSync(process.env.SHOTS, { recursive: true });
    writeFileSync(join(process.env.SHOTS, name), Buffer.from((await cdp("Page.captureScreenshot", { format: "png" })).data, "base64"));
  };
  const connOpen = () => evaluate("!!document.querySelector('.sb-conn.open')");
  const noticeShown = () => evaluate("(() => { const n = document.querySelector('.offline-notice'); return !!n && !n.hidden && getComputedStyle(n).display !== 'none'; })()");
  const mainOpacity = () => evaluate("Number(getComputedStyle(document.querySelector('.main')).opacity)");

  server = await start();
  const kept = server.token;
  assert.equal((await server.api("/api/open", { path: fixture })).status, 200);
  await cdp("Page.navigate", { url: server.url.href });
  await until("the page's rows", async () => (await connOpen()) && (await evaluate("document.querySelectorAll('.pl-row').length")) > 3, 30_000);

  await check("a server that went away: the page keeps what it shows, dims it after a few seconds, offers no notice about a token", async () => {
    await server.stop();
    await until("Offline", () => evaluate("!!document.querySelector('.sb-conn.closed')"));
    assert.equal(await noticeShown(), false);
    assert.ok((await evaluate("document.querySelectorAll('.pl-row').length")) > 3, "the rows stay");
    assert.equal(await evaluate("document.body.classList.contains('wb-offline')"), true);
    // Not at once: a reconnect within a moment must not flicker
    await until("the dimmed list", async () => (await mainOpacity()) < 0.8, 8000);
    assert.equal(await noticeShown(), false);
  });

  await check("a restart that keeps the token: the open page reconnects by itself and shows the new state", async () => {
    server = await start();
    assert.equal(server.token, kept, "the same token as before the restart");
    await until("the page to reconnect by itself", connOpen, 30_000);
    // The new process has no capture: the page shows the welcome page, not the old packets
    await until("the new state", () => evaluate("!document.querySelector('.welcome').hidden"), 5000);
    assert.equal(await evaluate("document.querySelector('.panes').hidden"), true);
    await until("the list undimmed", async () => (await mainOpacity()) > 0.95, 3000);
    assert.equal(await evaluate("document.body.classList.contains('wb-offline')"), false);
    assert.equal(await noticeShown(), false);
    assert.equal((await server.api("/api/open", { path: fixture })).status, 200);
    await until("the capture in the page", () => evaluate("document.querySelectorAll('.pl-row').length > 3"));
  });

  await check("a restart with another token: the page says plainly that it belongs to a session that ended, keeps trying, and recovers when the token works again", async () => {
    await server.stop();
    await until("Offline", () => evaluate("!!document.querySelector('.sb-conn.closed')"));
    server = await start(["--token", "another-token-0123456789"]);
    assert.notEqual(server.token, kept);
    await until("the notice", noticeShown, 40_000);
    const text = await evaluate("document.querySelector('.offline-notice').textContent");
    assert.match(text, /no longer connected to WireBuddy/);
    assert.match(text, /session that has ended or has another token/);
    assert.match(text, /viewer_url/);
    assert.match(text, /terminal WireBuddy runs in/);
    assert.match(text, /keeps trying/);
    // Over the page, and the page behind it looks out of date
    assert.equal(await evaluate("document.querySelector('.offline-notice').getBoundingClientRect().height > 60"), true);
    await until("the dimmed list", async () => (await mainOpacity()) < 0.8, 8000);
    for (const scheme of ["light", "dark"]) {
      await cdp("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: scheme }] });
      await sleep(300);
      await shot(`notice-${scheme}.png`);
    }
    await cdp("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: "light" }] });
    // Quietly: it tries again by itself, and Try again now does it at once
    assert.equal(await evaluate("[...document.querySelectorAll('.offline-notice button')].map((b) => b.textContent).join()"), "Try again now");
    // The token works again: the kept one, from a server without --token
    await server.stop();
    server = await start();
    assert.equal(server.token, kept);
    await evaluate("[...document.querySelectorAll('.offline-notice button')][0].click()");
    await until("the page to recover", async () => (await connOpen()) && !(await noticeShown()), 40_000);
    await until("the list undimmed", async () => (await mainOpacity()) > 0.95, 3000);
  });
} finally {
  browser?.ws.close();
  browser?.chrome.kill();
  await server?.stop().catch(() => {});
  await sleep(500);
  // Chrome may still be writing its profile as it ends
  finish(() => rmSync(work, { recursive: true, force: true, maxRetries: 5 }));
}
