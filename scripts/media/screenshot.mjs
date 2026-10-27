// Renders docs/screenshot.png: agent opens the fixture, marks and selects frames; headless Chrome captures the UI.
// Usage: node screenshot.mjs <wirebuddy-root> <out.png>
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createRequire } from "node:module";

const [root, out] = process.argv.slice(2);
const require = createRequire(join(root, "package.json"));
const { Client } = await import(require.resolve("@modelcontextprotocol/sdk/client/index.js"));
const { StdioClientTransport } = await import(require.resolve("@modelcontextprotocol/sdk/client/stdio.js"));
const WebSocket = require("ws");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const TOKEN = randomBytes(16).toString("hex");
// Empty home: no recent files or settings of the recording machine
const home = mkdtempSync(join(tmpdir(), "wb-shot-home-"));
const client = new Client({ name: "shot", version: "0" });
await client.connect(new StdioClientTransport({
  command: process.execPath,
  args: [join(root, "dist/server/main.js"), "--mcp", "--port", "8771", "--capture-dir", mkdtempSync(join(tmpdir(), "wb-shot-"))],
  env: { ...process.env, HOME: home, WIREBUDDY_TOKEN: TOKEN },
  stderr: "ignore",
}));
const call = (name, args = {}) => client.callTool({ name, arguments: args });

const profile = mkdtempSync(join(tmpdir(), "wb-chrome-"));
const chrome = process.env.CDP_PORT ? { kill() {} } : spawn(process.env.CHROME ?? "google-chrome", ["--headless=new", "--remote-debugging-port=9339", `--user-data-dir=${profile}`,
  "--window-size=1280,820", "--hide-scrollbars", "--force-device-scale-factor=1", "--no-first-run", "--no-default-browser-check", "--disable-gpu", "about:blank"], { stdio: "ignore" });
let targets;
for (let i = 0; i < 100 && !targets; i++) {
  await sleep(200);
  targets = await fetch(`http://127.0.0.1:${process.env.CDP_PORT ?? 9339}/json/list`).then((r) => r.json()).catch(() => null);
}
const page = targets.find((t) => t.type === "page");
const ws = new WebSocket(page.webSocketDebuggerUrl);
await new Promise((r) => ws.once("open", r));
let id = 0;
const pending = new Map();
ws.on("message", (m) => { const d = JSON.parse(m); pending.get(d.id)?.(d.result); pending.delete(d.id); });
const cdp = (method, params = {}) => new Promise((r) => { pending.set(++id, r); ws.send(JSON.stringify({ id, method, params })); });
const evaluate = (expression) => cdp("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true }).then((r) => r?.result?.value);

await cdp("Emulation.setDeviceMetricsOverride", { width: 1280, height: 820, deviceScaleFactor: 1, mobile: false });
await cdp("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: "light" }] });
await call("open_capture", { path: join(root, "test/fixtures/http.pcapng") });
await cdp("Page.navigate", { url: `http://127.0.0.1:8771/?token=${TOKEN}` });
await sleep(2500);
await call("mark_frames", { frames: [21, 25], note: "request for a missing file and its 404" });
await call("goto_frame", { frame: 25 });
await sleep(1500);
// Expand the HTTP node in the details tree and select its status line
console.log(await evaluate(`(() => {
  const label = [...document.querySelectorAll('[role=tree] *')].find((e) => e.childElementCount === 0 && e.textContent.trim() === 'Hypertext Transfer Protocol');
  if (!label) return 'http node not found';
  const row = label.closest('[role=treeitem]') ?? label.parentElement;
  row.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }));
  row.dispatchEvent(new MouseEvent('dblclick', { bubbles: true }));
  return 'expanded';
})()`));
await sleep(800);
console.log(await evaluate(`(() => {
  const label = [...document.querySelectorAll('[role=tree] *')].find((e) => e.childElementCount === 0 && e.textContent.trim().startsWith('HTTP/1.0 404'));
  if (!label) return 'status line not found';
  (label.closest('[role=treeitem]') ?? label.parentElement).dispatchEvent(new MouseEvent('mousedown', { bubbles: true }));
  return 'selected';
})()`));
await sleep(800);
const shot = await cdp("Page.captureScreenshot", { format: "png" });
writeFileSync(out, Buffer.from(shot.data, "base64"));
console.log(`wrote ${out}`);

ws.close();
chrome.kill();
await client.close();
await sleep(300);
rmSync(profile, { recursive: true, force: true });
rmSync(home, { recursive: true, force: true });
process.exit(0);
