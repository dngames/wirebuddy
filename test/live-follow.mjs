// The packet list following a big live capture in headless Chrome: its end shows rows, never a
// screen of placeholders, with or without a display filter; a click on a row still loading selects
// it; Go to Packet says why a provisional packet isn't listed; a selected provisional packet gets
// its row once the filter lists it; and the mouse wheel turns auto-scroll off in a list too long
// for the browser's scroll range. dumpcap is test/fake-dumpcap.mjs, which writes generated traffic.
// Usage: node test/live-follow.mjs   (after npm run build; skipped without Chrome, CHROME=<path>)
import { spawn } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { WebSocket } from "ws";

const chromeBin = process.env.CHROME ?? "/usr/bin/google-chrome";
if (!existsSync(chromeBin)) {
  console.log(`skip: no Chrome at ${chromeBin} (set CHROME)`);
  process.exit(0);
}
const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const work = mkdtempSync(join(tmpdir(), "wirebuddy-live-follow-"));
const home = join(work, "home");
const bin = join(work, "bin");
mkdirSync(home);
mkdirSync(bin);
writeFileSync(join(bin, "dumpcap"), `#!/bin/sh\nexec "${process.execPath}" "${join(root, "test/fake-dumpcap.mjs")}" "$@"\n`);
chmodSync(join(bin, "dumpcap"), 0o755);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const listLength = (s) => s.displayedFrames + (s.tail?.displayed ?? 0);

/** A WireBuddy server with an MCP client, capturing into a folder of its own; `env` adds to its environment. */
async function server(name, env = {}) {
  const captureDir = join(work, name);
  const client = new Client({ name: "live-follow", version: "0" });
  await client.connect(
    new StdioClientTransport({
      command: process.execPath,
      args: [join(root, "dist/server/main.js"), "--mcp", "--port", "0", "--capture-dir", captureDir],
      env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, HOME: home, XDG_CONFIG_HOME: join(home, ".config"), XDG_DATA_HOME: join(home, ".local/share"), WIREBUDDY_EXTENSIONS: "", ...env },
      stderr: "ignore",
    }),
  );
  const tool = async (tool, args = {}) => (await client.callTool({ name: tool, arguments: args })).content.map((c) => c.text).join("\n");
  const ui = new URL((await tool("viewer_url")).trim());
  const api = async (path, body) => {
    const res = await fetch(ui.origin + path, {
      method: body === undefined ? "GET" : "POST",
      headers: { "X-WireBuddy-Token": ui.searchParams.get("token"), "content-type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const json = await res.json();
    if (!res.ok) throw Object.assign(new Error(`${path}: ${res.status} ${JSON.stringify(json)}`), { status: res.status });
    return json;
  };
  const state = () => api("/api/state");
  return {
    captureDir,
    ui,
    api,
    state,
    /** Rows start..start+count-1 of the list as it is now; `start` may be a function of the state. */
    async rows(start, count) {
      for (;;) {
        const s = await state();
        const from = typeof start === "function" ? start(s) : start;
        try {
          return { s, rows: (await api(`/api/rows?gen=${s.generation}&start=${from}&count=${count}`)).rows };
        } catch (err) {
          if (err.status !== 409) throw err;
        }
      }
    },
    async until(what, ms, test) {
      const end = Date.now() + ms;
      for (;;) {
        const s = await state();
        if (test(s)) return s;
        if (Date.now() > end) throw new Error(`timed out waiting for ${what}: ${JSON.stringify({ totalFrames: s.totalFrames, tail: s.tail, capture: s.capture.status })}`);
        await sleep(200);
      }
    },
    async close() {
      await api("/api/capture/stop", {}).catch(() => {});
      await client.close();
      rmSync(captureDir, { recursive: true, force: true });
    },
  };
}

/** Headless Chrome on `url`, driven over the DevTools protocol. */
async function openBrowser(url, name) {
  const profile = join(work, `chrome-${name}`);
  const chrome = spawn(chromeBin, ["--headless=new", "--remote-debugging-port=0", `--user-data-dir=${profile}`, "--window-size=1280,820", "--no-first-run", "--no-default-browser-check", "--disable-gpu", "about:blank"], { stdio: "ignore" });
  let port;
  // A busy machine may take a while to start it
  for (const end = Date.now() + 30_000; !port && Date.now() < end; await sleep(100)) {
    if (existsSync(join(profile, "DevToolsActivePort"))) port = readFileSync(join(profile, "DevToolsActivePort"), "utf8").split("\n")[0];
  }
  if (!port) {
    chrome.kill();
    throw new Error("Chrome did not start its DevTools server in 30 s");
  }
  const targets = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
  const ws = new WebSocket(targets.find((t) => t.type === "page").webSocketDebuggerUrl);
  await new Promise((resolve, reject) => (ws.once("open", resolve), ws.once("error", reject)));
  let id = 0;
  const pending = new Map();
  ws.on("message", (m) => {
    const d = JSON.parse(m);
    pending.get(d.id)?.(d);
    pending.delete(d.id);
  });
  const cdp = (method, params = {}) => new Promise((resolve) => (pending.set(++id, resolve), ws.send(JSON.stringify({ id, method, params }))));
  await cdp("Page.navigate", { url: url.href });
  const evaluate = async (expression) => (await cdp("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true })).result?.result?.value;
  const mouse = (type, x, y, extra = {}) => cdp("Input.dispatchMouseEvent", { type, x, y, ...extra });
  const key = async (key, code, keyCode, modifiers = 0) => {
    await cdp("Input.dispatchKeyEvent", { type: "rawKeyDown", key, code, windowsVirtualKeyCode: keyCode, modifiers });
    await cdp("Input.dispatchKeyEvent", { type: "keyUp", key, code, windowsVirtualKeyCode: keyCode, modifiers });
  };
  return {
    evaluate,
    async click(x, y) {
      await mouse("mouseMoved", x, y);
      await mouse("mousePressed", x, y, { button: "left", clickCount: 1 });
      await mouse("mouseReleased", x, y, { button: "left", clickCount: 1 });
    },
    wheel: (x, y, deltaY) => mouse("mouseWheel", x, y, { deltaX: 0, deltaY }),
    /** Go to Packet (Ctrl+G) `n`; its toast, or what the page shows instead. */
    async goTo(n) {
      await evaluate("document.querySelectorAll('.toast').forEach((t) => t.remove())");
      const open = () => evaluate("!!document.querySelector('.goto-in')");
      // Its own toast, not another notice that came meanwhile
      const own = "[...document.querySelectorAll('.toast .toast-text')].map((t) => t.textContent).find((t) => t.startsWith('Packet ')) ?? null";
      // A busy page may miss the shortcut, or not know packet n yet (its refusal goes to the agent): asked again
      for (let tries = 0; tries < 10; tries++) {
        if (!(await open())) {
          await key("g", "KeyG", 71, 2);
          for (let k = 0; k < 40 && !(await open()); k++) await sleep(50);
          if (!(await open())) continue;
        }
        await evaluate(`(() => { const i = document.querySelector('.goto-in'); i.value = '${n}'; i.focus(); })()`);
        await key("Enter", "Enter", 13);
        for (let k = 0; k < 30; k++, await sleep(100)) {
          const text = await evaluate(own);
          if (text) return text;
        }
      }
      return `no toast; the dialog: ${await evaluate("document.querySelector('.dlg-goto')?.textContent ?? 'closed'")}`;
    },
    close: () => (ws.close(), chrome.kill()),
  };
}

/** The packet list's rows on screen: how many, how many still loading, the first and last index, the last frame shown. */
const SCREEN = `JSON.stringify((() => {
  const box = document.querySelector('.pl-scroll').getBoundingClientRect();
  const rows = [...document.querySelectorAll('.pl-row')].filter((r) => {
    if (r.style.display === 'none') return false;
    const b = r.getBoundingClientRect();
    return b.bottom > box.top + 1 && b.top < box.bottom - 1;
  });
  const shown = rows.filter((r) => !r.classList.contains('pending'));
  return { rows: rows.length, pending: rows.length - shown.length, first: Number(rows[0]?.dataset.i), last: Number(rows.at(-1)?.dataset.i), num: Number(shown.at(-1)?.querySelector('.pl-cell')?.textContent) };
})())`;
const AUTO_SCROLL = `document.querySelector('button[aria-label="Auto Scroll in Live Capture"]').getAttribute('aria-pressed')`;

let failures = 0;
async function check(name, fn) {
  const t0 = Date.now();
  try {
    await fn();
    console.log(`ok   ${name} (${Math.round((Date.now() - t0) / 1000)} s)`);
  } catch (err) {
    failures++;
    console.log(`FAIL ${name}: ${err.message}`);
  }
}
const report = [];

/** Samples the followed end for `ms`: screens of placeholders once rows showed, and how far the newest frame shown moved. */
async function follow(browser, wb, ms) {
  let blank = 0;
  let samples = 0;
  let shown = false;
  let from = 0;
  let to = 0;
  const behind = [];
  for (const end = Date.now() + ms; Date.now() < end; await sleep(100)) {
    const s = await wb.state();
    const p = JSON.parse(await browser.evaluate(SCREEN));
    if (!p.rows) continue;
    if (p.pending < p.rows) {
      shown = true;
      from ||= p.num;
      to = p.num;
      behind.push(listLength(s) - 1 - p.last);
    }
    if (!shown) continue;
    samples++;
    if (p.pending === p.rows) blank++;
  }
  behind.sort((a, b) => a - b);
  return { samples, blank, from, to, behind: behind[behind.length >> 1] ?? null };
}

const servers = [];
let browser = null;
try {
  const wb = await server("captures");
  servers.push(wb);
  browser = await openBrowser(wb.ui, "follow");
  await sleep(1500);
  await wb.api("/api/capture/start", { iface: "lo", filter: "burst 300000 rate 3000", autostop: {}, ring: null });
  await wb.until("provisional packets", 90_000, (s) => s.totalFrames > 250_000 && s.tail?.frames > 0);
  await sleep(2000);

  await check("the followed end of a big live capture shows rows, never a screen of placeholders", async () => {
    const plain = await follow(browser, wb, 8000);
    report.push(`no filter: ${plain.blank} of ${plain.samples} screens blank, the newest row shown ${plain.from} -> ${plain.to}, a median ${plain.behind} rows behind the list's end`);
    assert.equal(plain.blank, 0, `${plain.blank} of ${plain.samples} screens of placeholders`);
    assert.ok(plain.to - plain.from >= 8000, `the end moved from ${plain.from} to ${plain.to} in 8 s`);
    await wb.api("/api/filter", { filter: "dns" });
    await wb.until("provisional matches", 30_000, (s) => s.tail?.displayed > 0);
    const dns = await follow(browser, wb, 8000);
    report.push(`filter dns: ${dns.blank} of ${dns.samples} screens blank, the newest row shown ${dns.from} -> ${dns.to}, a median ${dns.behind} rows behind the list's end`);
    assert.equal(dns.blank, 0, `with a filter, ${dns.blank} of ${dns.samples} screens of placeholders`);
    assert.ok(dns.to > dns.from, `the end stayed at ${dns.from}`);
    await wb.api("/api/filter", { filter: "" });
  });

  await check("a click on a row still loading selects it once its page comes, though the list moved on", async () => {
    await browser.evaluate(`document.querySelector('button[aria-label="Auto Scroll in Live Capture"]').click()`);
    assert.equal(await browser.evaluate(AUTO_SCROLL), "false");
    // Pages arrive after the list's generation has moved on
    await browser.evaluate(`(() => { const f = window.fetch; window.fetch = (u, o) => f(u, o).then((r) => (/api\\/rows/.test(String(u)) ? new Promise((done) => setTimeout(() => done(r), 3000)) : r)); })()`);
    const s = await wb.state();
    await browser.evaluate(`(() => { const sc = document.querySelector('.pl-scroll'); sc.scrollTop = Math.round(sc.scrollHeight * ${(s.totalFrames / 2) / listLength(s)}); })()`);
    await sleep(300);
    const row = JSON.parse(await browser.evaluate(`JSON.stringify((() => { const r = [...document.querySelectorAll('.pl-row.pending')].find((r) => r.style.display !== 'none' && r.getBoundingClientRect().top > 150); const b = r.getBoundingClientRect(); return { i: Number(r.dataset.i), x: b.left + 100, y: b.top + b.height / 2 }; })())`));
    await browser.click(row.x, row.y);
    // Out of view before its page comes
    await browser.evaluate("document.querySelector('.pl-scroll').scrollTop = 0");
    const at = await wb.until("the click's selection", 15_000, (s) => s.selected !== null);
    assert.deepEqual([at.selected, at.selectedIndex], [row.i + 1, row.i]);
  });
  await wb.close();
  servers.pop();
  browser.close();
  browser = null;

  // Full reads wait for memory: the provisional packets pile up, and a list of over 400,000 rows
  const lean = await server("lean", { WIREBUDDY_MEM_AVAILABLE: "1" });
  servers.push(lean);
  browser = await openBrowser(lean.ui, "lean");
  await sleep(1500);
  await lean.api("/api/capture/start", { iface: "lo", filter: "burst 420000 rate 3000", autostop: {}, ring: null });
  const big = await lean.until("a list too long for the browser's scroll range", 120_000, (s) => s.tail?.paused && listLength(s) > 410_000);

  await check("in a list too long for the browser's scroll range, the mouse wheel up turns auto-scroll off", async () => {
    await sleep(2000);
    assert.equal(await browser.evaluate(AUTO_SCROLL), "true");
    const box = JSON.parse(await browser.evaluate("JSON.stringify(document.querySelector('.pl-scroll').getBoundingClientRect())"));
    assert.ok(JSON.parse(await browser.evaluate(SCREEN)).last >= listLength(big) - 200, "the view follows the end");
    for (let k = 0; k < 10; k++) await browser.wheel(box.left + 200, box.top + 100, -400);
    await sleep(200);
    assert.equal(await browser.evaluate(AUTO_SCROLL), "false");
    const scrolled = JSON.parse(await browser.evaluate(SCREEN));
    const n = listLength(await lean.state());
    assert.ok(scrolled.last <= n - 150, `rows ${scrolled.first}-${scrolled.last} of ${n}`);
    // The list grows meanwhile; the view stays where the wheel left it
    await sleep(2500);
    assert.equal(JSON.parse(await browser.evaluate(SCREEN)).first, scrolled.first);
    await browser.evaluate(`document.querySelector('button[aria-label="Auto Scroll in Live Capture"]').click()`);
  });

  await check("a selected provisional packet gets its row once the display filter lists it", async () => {
    await sleep(3000);
    const { rows } = await lean.rows((s) => s.displayedFrames, 500);
    const dns = rows.find((r) => r.p && r.c[4] === "DNS");
    assert.ok(dns, "a provisional DNS packet");
    await lean.api("/api/select", { frame: dns.num });
    await lean.api("/api/filter", { filter: "dns" });
    let at = -1;
    for (const end = Date.now() + 30_000; at < 0 && Date.now() < end; await sleep(300)) {
      const { s, rows: listed } = await lean.rows((s) => s.displayedFrames, 500);
      const k = listed.findIndex((r) => r.num === dns.num);
      if (k >= 0) at = s.displayedFrames + k;
    }
    assert.ok(at >= 0, `frame ${dns.num} listed`);
    const s = await lean.state();
    assert.equal(s.selected, dns.num);
    assert.equal(s.selectedIndex, at);
    assert.deepEqual(s.selectedRows, [[at, at]]);
  });

  await check("Go to Packet says why a provisional packet isn't listed", async () => {
    await lean.api("/api/filter", { filter: "tcp.stream == 3" });
    let s = await lean.state();
    const held = await browser.goTo(s.totalFrames + s.tail.frames - 100);
    assert.match(held ?? "", /^Packet \d+ is listed once read in full, as the filter uses tcp\.stream$/);
    // A filter applied just now has checked none of the provisional packets: the newest wait seconds
    await lean.api("/api/filter", { filter: "dns" });
    s = await lean.state();
    assert.ok(s.tail.unfiltered > 10_000, `${s.tail.unfiltered} provisional packets unchecked`);
    const unchecked = await browser.goTo(s.totalFrames + s.tail.frames - 100);
    assert.match(unchecked ?? "", /^Packet \d+ isn't checked against the display filter yet$/);
  });
} finally {
  browser?.close();
  for (const s of servers) await s.close().catch(() => {});
  rmSync(work, { recursive: true, force: true });
}
for (const line of report) console.log(`     ${line}`);
console.log(failures ? `${failures} check(s) failed` : "all checks passed");
process.exit(failures ? 1 : 0);
