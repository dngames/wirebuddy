// The example panels in a real browser, the way the agent works with them: each of
// examples/extensions copied into the extensions folder, tested on its fixture from
// test/media and opened over MCP in WireBuddy's UI in headless Chrome, then checked from
// inside its frame over the DevTools protocol.
// Usage: node test/browser.mjs [--verbose] [--shots <dir>]   (after npm run build; skipped without Chrome)
// CHROME=<path> picks the browser.
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { spawn } from "node:child_process";
import { accessSync, chmodSync, constants, cpSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import assert from "node:assert/strict";
import { writeHttpGallery } from "./media/http-gallery.mjs";
import { SCANS, writeLidarCapture } from "./media/lidar-wbpc.mjs";
import { writeRtpCapture } from "./media/rtp-h264.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const { values } = parseArgs({ options: { shots: { type: "string" }, verbose: { type: "boolean", default: false } } });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function findChrome() {
  if (process.env.CHROME) return process.env.CHROME;
  for (const name of ["google-chrome", "google-chrome-stable", "chromium", "chromium-browser"]) {
    for (const dir of (process.env.PATH ?? "").split(delimiter)) {
      try {
        accessSync(join(dir, name), constants.X_OK);
        return join(dir, name);
      } catch {
        // not here
      }
    }
  }
  return null;
}
const chromePath = findChrome();
if (!chromePath) {
  console.log("skipped: no Chrome or Chromium found (set CHROME to its path)");
  process.exit(0);
}

const home = mkdtempSync(join(tmpdir(), "wirebuddy-home-"));
const extDir = join(home, ".local/share/wirebuddy/extensions");
mkdirSync(extDir, { recursive: true, mode: 0o700 });
// Copies as the user would make them: not writable by others, or WireBuddy won't load them
const tighten = (p) => {
  const dir = statSync(p).isDirectory();
  chmodSync(p, dir ? 0o700 : 0o600);
  if (dir) for (const e of readdirSync(p)) tighten(join(p, e));
};
for (const name of ["http-gallery", "rtp-video", "lidar-wbpc"]) {
  cpSync(join(root, "examples/extensions", name), join(extDir, name), { recursive: true });
  tighten(join(extDir, name));
}
const fixtures = join(home, "fixtures");
mkdirSync(fixtures);
const files = writeHttpGallery(join(fixtures, "http-gallery.pcap"));
const streams = writeRtpCapture(join(fixtures, "rtp-h264.pcap"));
const scans = writeLidarCapture(join(fixtures, "lidar-wbpc.pcap"));

const client = new Client({ name: "browser-test", version: "0" });
await client.connect(
  new StdioClientTransport({
    command: process.execPath,
    args: [join(root, "dist/server/main.js"), "--mcp", "--port", "0"],
    env: { ...process.env, HOME: home, XDG_CONFIG_HOME: join(home, ".config"), XDG_DATA_HOME: join(home, ".local/share"), WIREBUDDY_EXTENSIONS: "" },
    stderr: "ignore",
  }),
);
/** An MCP tool's text; throws on a tool error. */
async function tool(name, args = {}) {
  const r = await client.callTool({ name, arguments: args });
  const text = r.content.map((c) => c.text).join("\n");
  if (values.verbose) console.log(`--- ${name} ${JSON.stringify(args)}\n${text}\n`);
  if (r.isError) throw new Error(`${name}: ${text}`);
  return text;
}
const ui = new URL(await tool("viewer_url"));
const token = ui.searchParams.get("token");

async function api(path, body) {
  const res = await fetch(new URL(path, ui.origin), {
    method: body === undefined ? "GET" : "POST",
    headers: { "X-WireBuddy-Token": token, "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const json = await res.json().catch(() => null);
  if (!res.ok) throw new Error(`${path}: ${res.status} ${JSON.stringify(json)}`);
  return json;
}

const profile = mkdtempSync(join(tmpdir(), "wirebuddy-chrome-"));
const chrome = spawn(
  chromePath,
  [
    "--headless=new",
    "--remote-debugging-port=0",
    `--user-data-dir=${profile}`,
    "--window-size=1280,900",
    "--force-device-scale-factor=1",
    "--hide-scrollbars",
    "--no-first-run",
    "--no-default-browser-check",
    "--mute-audio",
    // WebGL without a GPU
    "--use-angle=swiftshader",
    "--enable-unsafe-swiftshader",
    "about:blank",
  ],
  { stdio: "ignore" },
);

/** A DevTools connection to one target. */
async function connect(url) {
  const ws = new WebSocket(url);
  await new Promise((resolve, reject) => {
    ws.addEventListener("open", resolve, { once: true });
    ws.addEventListener("error", () => reject(new Error(`no DevTools connection to ${url}`)), { once: true });
  });
  let id = 0;
  const pending = new Map();
  ws.addEventListener("message", (e) => {
    const m = JSON.parse(e.data);
    const p = pending.get(m.id);
    if (!p) return;
    pending.delete(m.id);
    if (m.error) p.reject(new Error(m.error.message));
    else p.resolve(m.result);
  });
  const send = (method, params = {}) =>
    new Promise((resolve, reject) => {
      pending.set(++id, { resolve, reject });
      ws.send(JSON.stringify({ id, method, params }));
    });
  return {
    send,
    async evaluate(expression) {
      const r = await send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true });
      if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description ?? r.exceptionDetails.text);
      return r.result.value;
    },
    close: () => ws.close(),
  };
}

let failures = 0;
let skipped = 0;
async function check(name, fn) {
  try {
    const note = await fn();
    if (note?.skip) {
      skipped++;
      console.log(`skip ${name}: ${note.skip}`);
    } else console.log(`ok   ${name}${note ? ` (${note})` : ""}`);
  } catch (err) {
    failures++;
    console.log(`FAIL ${name}: ${err.message}`);
  }
}

/** Polls `fn` until its value is truthy and not {done: false}; the last value on timeout. */
async function until(fn, ms = 20000) {
  const end = Date.now() + ms;
  let last;
  while (Date.now() < end) {
    last = await fn().catch((e) => ({ error: e.message, done: false }));
    if (last && last.done !== false) return last;
    await sleep(250);
  }
  return last;
}

let page = null;
try {
  await check("the panel guide points at the examples", async () => {
    const guide = await tool("extensions", { action: "guide", topic: "panel" });
    assert.ok(guide.includes(`Examples to copy with your file tools: ${join(root, "examples/extensions")}/{http-gallery,rtp-video,lidar-wbpc}`), guide);
  });
  let cdpPort = 0;
  for (let i = 0; i < 100 && !cdpPort; i++) {
    await sleep(100);
    try {
      cdpPort = Number(readFileSync(join(profile, "DevToolsActivePort"), "utf8").split("\n")[0]);
    } catch {
      // not yet
    }
  }
  assert.ok(cdpPort, "Chrome did not start its DevTools server");
  const targets = () => fetch(`http://127.0.0.1:${cdpPort}/json/list`).then((r) => r.json());
  page = await connect((await targets()).find((t) => t.type === "page").webSocketDebuggerUrl);
  await page.send("Page.navigate", { url: ui.href });
  // The viewer is connected: panels the agent opens start in it
  const connected = await until(() => page.evaluate(`document.body?.innerText.includes("Connected") || null`));
  assert.ok(connected === true, "the viewer did not connect");

  /**
   * The agent's loop: open the capture, test the extension on it, open its panel. Returns
   * the test's text and a DevTools connection to the panel's frame.
   */
  async function open(name, fixture) {
    await tool("open_capture", { path: join(fixtures, fixture) });
    const test = await tool("extensions", { action: "test", name });
    assert.match(test, new RegExp(`Panel of "${name}": checks out`), test);
    assert.doesNotMatch(test, /warning:/, test);
    const opened = await tool("panel", { action: "open", name, wait_ms: 15000 });
    assert.match(opened, /ready after \d+ ms\. Isolated: yes\./, opened);
    assert.doesNotMatch(opened, /Errors \[panel output\]/, opened);
    const src = (await api("/api/state")).panels.find((x) => x.name === name).src;
    const frame = await until(async () => (await targets()).find((t) => t.type === "iframe" && t.url.startsWith(src)));
    assert.ok(frame?.webSocketDebuggerUrl, `no DevTools target for the frame of ${name}`);
    return { test, frame: await connect(frame.webSocketDebuggerUrl) };
  }

  async function finish(name, frame) {
    if (values.shots) {
      mkdirSync(values.shots, { recursive: true });
      const shot = await page.send("Page.captureScreenshot", { format: "png" });
      writeFileSync(join(values.shots, `${name}.png`), Buffer.from(shot.data, "base64"));
    }
    frame.close();
    const status = await tool("panel", { action: "status", name });
    await tool("panel", { action: "close", name });
    assert.doesNotMatch(status, /Errors \[panel output\]/, status);
  }

  await check("http-gallery: a tile for each image, the other files listed", async () => {
    const { frame } = await open("http-gallery", "http-gallery.pcap");
    const images = files.filter((f) => f.image).length;
    const got = await until(() =>
      frame.evaluate(`(() => {
        const tiles = document.querySelectorAll(".tile").length;
        const loaded = document.querySelectorAll(".tile.loaded").length;
        const others = document.querySelectorAll(".others tbody tr").length;
        return { tiles, loaded, others, done: tiles === loaded && tiles + others === ${files.length} };
      })()`),
    );
    assert.deepEqual([got.tiles, got.loaded, got.others], [images, images, files.length - images], JSON.stringify(got));
    // The full-size view shows where the picture came from
    const meta = await frame.evaluate(`(async () => {
      document.querySelector(".tile").click();
      for (let i = 0; i < 40 && !document.querySelector(".viewer img")?.complete; i++) await new Promise((r) => setTimeout(r, 50));
      return document.querySelector(".viewer dl")?.textContent ?? "";
    })()`);
    assert.match(meta, /Filesunrise\.png/);
    assert.match(meta, /Hostgallery\.example/);
    assert.match(meta, /SHA-1[0-9a-f]{40}/);
    const tiles = `(() => ({ tiles: document.querySelectorAll(".tile.loaded").length, text: document.body.innerText, viewer: !document.querySelector(".viewer").hidden }))()`;
    // No capture, then the capture again: it starts over
    await api("/api/close", {});
    const empty = await until(async () => {
      const t = await frame.evaluate(tiles);
      return { ...t, done: t.tiles === 0 && !t.viewer && /Open a capture/.test(t.text) };
    });
    assert.ok(empty.done, JSON.stringify(empty));
    await tool("open_capture", { path: join(fixtures, "http-gallery.pcap") });
    const again = await until(async () => {
      const t = await frame.evaluate(tiles);
      return { ...t, done: t.tiles === images };
    });
    assert.equal(again.tiles, images);
    await finish("http-gallery", frame);
    return `${got.tiles} images, ${got.others} other files`;
  });

  await check("rtp-video: plays the H.264 streams", async () => {
    const { test, frame } = await open("rtp-video", "rtp-h264.pcap");
    assert.match(test, /with it the capture decodes as:\n\s+frame > eth > ip > udp > rtp > h264: \d+ frames/, test);
    assert.match(test, /No Lua errors/);
    const progress = (min) =>
      until(() =>
        frame.evaluate(`(() => {
          const t = document.querySelector(".state")?.textContent ?? "";
          const decoded = Number(/(\\d+) decoded/.exec(t)?.[1] ?? 0);
          const unsupported = /no H\\.264 decoder/.test(document.body.textContent);
          const picked = document.querySelector("select").selectedOptions[0]?.textContent ?? "";
          return { text: t, decoded, unsupported, picked, streams: document.querySelectorAll("select option").length, done: unsupported || decoded >= ${min} };
        })()`),
      );
    const got = await progress(40);
    if (got.unsupported) {
      await finish("rtp-video", frame);
      return { skip: "this Chrome has no H.264 decoder" };
    }
    assert.equal(got.streams, streams.length, JSON.stringify(got));
    assert.match(got.picked, new RegExp(`SSRC 0x${streams[0].ssrc.toString(16)}`), "the stream with the most packets first");
    assert.ok(got.decoded >= 20, JSON.stringify(got));
    // The other stream, from the picker
    await frame.evaluate(`(() => {
      const s = document.querySelector("select");
      s.selectedIndex = [...s.options].findIndex((o) => o.textContent.includes("0x${streams[1].ssrc.toString(16)}"));
      s.dispatchEvent(new Event("change"));
    })()`);
    const other = await progress(20);
    assert.ok(other.decoded >= 20 && other.picked.includes(`0x${streams[1].ssrc.toString(16)}`), JSON.stringify(other));
    await finish("rtp-video", frame);
    return `${got.decoded} and ${other.decoded} pictures decoded`;
  });

  await check("lidar-wbpc: decodes the protocol and draws the point cloud", async () => {
    const { test, frame } = await open("lidar-wbpc", "lidar-wbpc.pcap");
    const packets = scans.reduce((a, s) => a + Math.ceil(s.length / 172), 0) + 1;
    assert.match(test, new RegExp(`^  wbpc: ${packets} packets, first 1$`, "m"), test);
    assert.match(test, /Scan: 100/);
    assert.match(test, /No Lua errors/);
    const got = await until(() =>
      frame.evaluate(`(() => {
        const c = document.querySelector("canvas");
        const gl = c?.getContext("webgl2");
        const nogl = /no WebGL2/.test(document.body.textContent);
        if (!gl) return { nogl, done: nogl };
        const px = new Uint8Array(c.width * c.height * 4);
        gl.readPixels(0, 0, c.width, c.height, gl.RGBA, gl.UNSIGNED_BYTE, px);
        let lit = 0;
        for (let i = 0; i < px.length; i += 4) if (px[i] !== px[0] || px[i + 1] !== px[1] || px[i + 2] !== px[2]) lit++;
        const scans = Number(/of (\\d+)/.exec(document.querySelector(".scan")?.textContent ?? "")?.[1] ?? 0);
        return { lit, size: c.width + "x" + c.height, scans, done: lit > 1000 && scans === ${SCANS} };
      })()`),
    );
    if (got.nogl) {
      await finish("lidar-wbpc", frame);
      return { skip: "no WebGL2 in this browser" };
    }
    assert.ok(got.lit > 1000, JSON.stringify(got));
    assert.equal(got.scans, SCANS, JSON.stringify(got));
    // The malformed packet is skipped, the next scan a click away
    const step = await frame.evaluate(`(() => {
      document.querySelector(".next").click();
      return document.querySelector(".scan").textContent;
    })()`);
    assert.match(step, new RegExp(`^scan 101 · 2 of ${SCANS} · ${scans[1].length} points`));
    assert.match(step, /1 bad packet skipped/);
    await finish("lidar-wbpc", frame);
    return `${got.lit} pixels lit of ${got.size}`;
  });
} finally {
  page?.close();
  chrome.kill();
  await client.close();
  await sleep(300);
  rmSync(profile, { recursive: true, force: true });
  rmSync(home, { recursive: true, force: true });
}
console.log(failures ? `${failures} check(s) failed` : `all checks passed${skipped ? ` (${skipped} skipped)` : ""}`);
process.exit(failures ? 1 : 0);
