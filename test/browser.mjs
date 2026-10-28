// The example panels in a real browser, the way the agent works with them: each of
// examples/extensions and the investigations' solutions (robot-arm, ct-archive) copied into the
// extensions folder, tested on its fixture from test/media and opened over MCP in WireBuddy's UI
// in headless Chrome, then checked from inside its frame over the DevTools protocol.
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
import { gzipSync } from "node:zlib";
import assert from "node:assert/strict";
import { writeCtCapture } from "./media/ct-archive.mjs";
import { writeHttpGallery } from "./media/http-gallery.mjs";
import { SCANS, writeLidarCapture } from "./media/lidar-wbpc.mjs";
import { writeArmCapture } from "./media/robot-arm.mjs";
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
cpSync(join(root, "examples/investigations/robot-arm/solution/armc"), join(extDir, "armc"), { recursive: true });
tighten(join(extDir, "armc"));
cpSync(join(root, "examples/investigations/ct-archive/solution/ctseries"), join(extDir, "ctseries"), { recursive: true });
tighten(join(extDir, "ctseries"));
const fixtures = join(home, "fixtures");
mkdirSync(fixtures);
const files = writeHttpGallery(join(fixtures, "http-gallery.pcap"));
const streams = writeRtpCapture(join(fixtures, "rtp-h264.pcap"));
const scans = writeLidarCapture(join(fixtures, "lidar-wbpc.pcap"));
const arm = writeArmCapture(join(fixtures, "robot-arm.pcap"));
const armFixed = writeArmCapture(join(fixtures, "robot-arm-fixed.pcap"), { fixed: true });
const ct = writeCtCapture(join(fixtures, "ct-archive.pcap"));
const ctFixed = writeCtCapture(join(fixtures, "ct-archive-fixed.pcap"), { fixed: true });
const ctThenFixed = writeCtCapture(join(fixtures, "ct-archive-then-fixed.pcap"), { thenFixed: true });

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
  for (let i = 0; i < 300 && !cdpPort; i++) {
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

  async function screenshot(name) {
    if (!values.shots) return;
    mkdirSync(values.shots, { recursive: true });
    const shot = await page.send("Page.captureScreenshot", { format: "png" });
    writeFileSync(join(values.shots, `${name}.png`), Buffer.from(shot.data, "base64"));
  }

  async function finish(name, frame) {
    await screenshot(name);
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
        // Thumbnails load as they come into view
        document.querySelector(".tile:not(.loaded)")?.scrollIntoView();
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

  await check("robot-arm: the armc solution decodes the arm, plots the delayed ACKs, then the fix", async () => {
    const { test, frame } = await open("armc", "robot-arm.pcap");
    assert.match(test, new RegExp(`^  armc: ${arm.armc} packets, first 1$`, "m"), test);
    assert.match(test, /No Lua errors/, test);
    let errors = "";
    /** The panel's status line, and its pixels: lit, and of the critical and the good status color. */
    const look = async () => {
      const s = await tool("panel", { action: "status", name: "armc" });
      if (/Errors \[panel output\]/.test(s)) errors += s;
      const m = /Status \[panel output, untrusted\]: "p50 ACK latency ([\d.]+) ms · (\d+) commands\/s"/.exec(s);
      const px = await frame.evaluate(`(() => {
        const c = document.querySelector("canvas");
        const d = c.getContext("2d").getImageData(0, 0, c.width, c.height).data;
        const near = (i, r, g, b) => Math.abs(d[i] - r) < 8 && Math.abs(d[i + 1] - g) < 8 && Math.abs(d[i + 2] - b) < 8;
        let lit = 0, red = 0, green = 0;
        for (let i = 0; i < d.length; i += 4) {
          if (d[i] !== d[0] || d[i + 1] !== d[1] || d[i + 2] !== d[2]) lit++;
          if (near(i, 0xd0, 0x3b, 0x3b)) red++;
          if (near(i, 0x0c, 0xa3, 0x0c)) green++;
        }
        return { lit, red, green, size: c.width + "x" + c.height };
      })()`);
      return { p50: m ? Number(m[1]) : NaN, rate: m ? Number(m[2]) : NaN, ...px, status: s.split("\n")[0] };
    };
    /** Whether it shows the numbers of the whole capture, rounded as the panel rounds them. */
    const all = (l, s) => l.p50 === Number(s.p50.toFixed(s.p50 < 1 ? 2 : 1)) && l.rate === Math.round(s.rate);
    const slow = await until(async () => {
      const l = await look();
      return { ...l, done: all(l, arm) && l.lit > 5000 };
    });
    assert.equal(errors, "");
    assert.ok(slow.p50 >= 30 && all(slow, arm), `${JSON.stringify(slow)}, generated ${arm.p50} ms, ${arm.rate}/s`);
    assert.ok(slow.lit > 5000 && slow.red > 1000 && slow.green < 200, JSON.stringify(slow));
    // A MOVE in the strip: its readout on hover, the packet it ends in selected on a click
    const src = (await api("/api/state")).panels.find((x) => x.name === "armc").src;
    const box = await page.evaluate(`(() => {
      const r = document.querySelector(${JSON.stringify(`iframe[src^="${src}"]`)}).getBoundingClientRect();
      return { x: r.left, y: r.top };
    })()`);
    const bar = await frame.evaluate(`(() => {
      const c = document.querySelector("canvas");
      const k = c.width / c.clientWidth;
      const y = Math.round(c.height - 30 * k);
      const row = c.getContext("2d").getImageData(0, y, c.width, 1).data;
      for (let x = Math.round(c.width / 2); x < c.width; x++) if (Math.abs(row[x * 4] - 0xd0) < 8 && Math.abs(row[x * 4 + 1] - 0x3b) < 8) return { x: x / k, y: y / k };
      return null;
    })()`);
    assert.ok(bar, "no MOVE bar in the strip");
    const at = { x: box.x + bar.x, y: box.y + bar.y };
    await page.send("Input.dispatchMouseEvent", { type: "mouseMoved", ...at });
    const tip = await until(() => frame.evaluate(`(() => { const r = document.querySelector(".readout"); return !r.hidden && r.textContent; })()`));
    assert.match(tip, /^MOVE seq=\d+ · frame \d+, began in \d+.*ACK in frame \d+, [\d.]+ ms after the first byte/, tip);
    await screenshot("armc-delayed");
    await page.send("Input.dispatchMouseEvent", { type: "mousePressed", ...at, button: "left", clickCount: 1 });
    await page.send("Input.dispatchMouseEvent", { type: "mouseReleased", ...at, button: "left", clickCount: 1 });
    const shown = Number(/^MOVE seq=\d+ · frame (\d+)/.exec(tip)[1]);
    assert.ok(arm.moveFrames.includes(shown), `frame ${shown} is no MOVE`);
    const selected = await until(async () => (await api("/api/state")).selected === shown || null);
    assert.ok(selected, `frame ${shown} was not selected`);
    // No capture, then the fixed app's: the panel starts over
    await api("/api/close", {});
    const empty = await until(async () => {
      const l = await look();
      const note = await frame.evaluate(`(() => { const n = document.querySelector(".note"); return n.hidden ? "" : n.textContent; })()`);
      return { ...l, note, done: l.lit === 0 && /^Open a capture with ARMC traffic/.test(note) };
    });
    assert.ok(empty.done, JSON.stringify(empty));
    await tool("open_capture", { path: join(fixtures, "robot-arm-fixed.pcap") });
    const fast = await until(async () => {
      const l = await look();
      return { ...l, done: all(l, armFixed) && l.green > 1000 };
    });
    assert.equal(errors, "");
    assert.ok(fast.p50 < 5 && all(fast, armFixed), `${JSON.stringify(fast)}, generated ${armFixed.p50} ms, ${armFixed.rate}/s`);
    assert.ok(fast.lit > 5000 && fast.green > 1000 && fast.red < 200, JSON.stringify(fast));
    // A compressed copy WireBuddy can't match in: read through the display filter instead
    writeFileSync(join(fixtures, "robot-arm.pcap.gz"), gzipSync(readFileSync(join(fixtures, "robot-arm.pcap"))));
    await tool("open_capture", { path: join(fixtures, "robot-arm.pcap.gz") });
    const gz = await until(async () => {
      const l = await look();
      return { ...l, done: all(l, arm) };
    });
    assert.ok(gz.done, `compressed: ${JSON.stringify(gz)}, generated ${arm.p50} ms, ${arm.rate}/s`);
    assert.equal(errors, "");
    await finish("armc", frame);
    return `p50 ${slow.p50} ms at ${slow.rate} commands/s, fixed ${fast.p50} ms at ${fast.rate}/s, ${slow.lit} pixels lit of ${slow.size}`;
  });

  await check("ct-archive: the ctseries solution shows the series as sent and as kept, the repeated UIDs, then the fix", async () => {
    // What the agent finds first: an export object per C-STORE, fewer UIDs than objects
    await tool("open_capture", { path: join(fixtures, "ct-archive.pcap") });
    const offered = await until(async () => (await api("/api/state")).panelOffers.some((o) => o.name === "ctseries") || null);
    assert.ok(offered, "the panel is not offered for the capture");
    const listing = await tool("export_objects", { kind: "dicom" });
    const uids = [...listing.matchAll(/^frame \d+: \d+-\d+-([\d.]+)\.dcm — /gm)].map((m) => m[1]);
    assert.equal(uids.length, ct.stores.length, listing.slice(0, 300));
    assert.equal(new Set(uids).size, ct.uids);
    const { frame } = await open("ctseries", "ct-archive.pcap");
    let errors = "";
    /** The panel's status line, its associations, its series buttons, and its pixels: lit, and of the collision red. */
    const look = async () => {
      const s = await tool("panel", { action: "status", name: "ctseries" });
      if (/Errors \[panel output\]/.test(s)) errors += s;
      const m = /Status \[panel output, untrusted\]: "(?:Association (\d+) of \d+ · )?(\d+) C-STOREs · (\d+) SOP Instance UIDs · (\d+|none) overwritten"/.exec(s);
      const px = await frame.evaluate(`(() => {
        const c = document.querySelector(".view canvas");
        const d = c.getContext("2d").getImageData(0, 0, c.width, c.height).data;
        let lit = 0, red = 0;
        for (let i = 0; i < d.length; i += 4) {
          if (d[i] !== d[0] || d[i + 1] !== d[1] || d[i + 2] !== d[2]) lit++;
          if (Math.abs(d[i] - 0xd0) < 8 && Math.abs(d[i + 1] - 0x3b) < 8 && Math.abs(d[i + 2] - 0x3b) < 8) red++;
        }
        const buttons = [...document.querySelectorAll(".series button")];
        const series = buttons.map((b) => b.textContent + (b.classList.contains("on") ? " *" : ""));
        const picker = document.querySelector(".association");
        return { lit, red, series, titles: buttons.map((b) => b.title), associations: picker.hidden ? 1 : picker.options.length, slice: document.querySelector(".slice").value };
      })()`);
      return { association: Number(m?.[1] ?? 1), stores: Number(m?.[2]), uids: Number(m?.[3]), overwritten: m?.[4] === "none" ? 0 : Number(m?.[4]), ...px, status: s.split("\n")[0] };
    };
    /** A snapshot over MCP: the PNG and how many of its pixels are not transparent. */
    const snapshot = async () => {
      const snap = await client.callTool({ name: "panel", arguments: { action: "snapshot", name: "ctseries" } });
      const png = Buffer.from(snap.content.find((c) => c.type === "image")?.data ?? "", "base64");
      assert.ok(!snap.isError && png.subarray(1, 4).toString() === "PNG", snap.content[0].text);
      const opaque = await page.evaluate(`(async () => {
        const bytes = Uint8Array.from(atob("${png.toString("base64")}"), (c) => c.charCodeAt(0));
        const image = await createImageBitmap(new Blob([bytes], { type: "image/png" }));
        const g = new OffscreenCanvas(image.width, image.height).getContext("2d");
        g.drawImage(image, 0, 0);
        const d = g.getImageData(0, 0, image.width, image.height).data;
        let n = 0;
        for (let i = 3; i < d.length; i += 4) if (d[i]) n++;
        return n;
      })()`);
      return { png, opaque };
    };
    const buggy = await until(async () => {
      const l = await look();
      return { ...l, done: l.stores === ct.stores.length && l.uids === ct.uids && l.series.length === 2 && l.lit > 50000 };
    }, 60000);
    assert.equal(errors, "");
    assert.ok(buggy.done && buggy.overwritten === ct.overwritten, `${JSON.stringify(buggy)}, generated ${ct.uids} UIDs`);
    assert.deepEqual(buggy.series, ["Series 2 · 5 mm", "Series 3 · 0.625 mm *"], "the thin series, with the lost images, first");
    assert.ok(buggy.red > 2000, JSON.stringify(buggy));
    const { png, opaque } = await snapshot();
    assert.ok(opaque > 50000, `${opaque} pixels in the snapshot`);
    if (values.shots) writeFileSync(join(values.shots, "ctseries-snapshot.png"), png);
    // An overwritten C-STORE in the strip: its readout on hover, its packet selected on a click
    const src = (await api("/api/state")).panels.find((x) => x.name === "ctseries").src;
    const box = await page.evaluate(`(() => {
      const r = document.querySelector(${JSON.stringify(`iframe[src^="${src}"]`)}).getBoundingClientRect();
      return { x: r.left, y: r.top };
    })()`);
    const tick = await frame.evaluate(`(() => {
      const c = document.querySelector(".view canvas");
      const k = c.width / c.clientWidth;
      const at = c.getBoundingClientRect();
      const y = Math.round(c.height - 35 * k);
      const row = c.getContext("2d").getImageData(0, y, c.width, 1).data;
      for (let x = 0; x < c.width; x++) if (Math.abs(row[x * 4] - 0xd0) < 8 && Math.abs(row[x * 4 + 1] - 0x3b) < 8) return { x: at.left + x / k + 1, y: at.top + y / k };
      return null;
    })()`);
    assert.ok(tick, "no red C-STORE in the strip");
    const at = { x: box.x + tick.x, y: box.y + tick.y };
    await page.send("Input.dispatchMouseEvent", { type: "mouseMoved", ...at });
    const tip = await until(() => frame.evaluate(`(() => { const r = document.querySelector(".readout"); return !r.hidden && r.textContent; })()`));
    assert.match(tip, /^C-STORE (\d+) · frame (\d+) · .*Same UID as C-STORE \d+ \(instance \d+, [\d.]+ mm\): overwritten/, tip);
    await screenshot("ctseries-collision");
    await page.send("Input.dispatchMouseEvent", { type: "mousePressed", ...at, button: "left", clickCount: 1 });
    await page.send("Input.dispatchMouseEvent", { type: "mouseReleased", ...at, button: "left", clickCount: 1 });
    const [, n, shown] = /^C-STORE (\d+) · frame (\d+)/.exec(tip).map(Number);
    const store = ct.stores[n - 1];
    assert.equal(shown, store.frame, `C-STORE ${n} ends in frame ${store.frame}`);
    const selected = await until(async () => (await api("/api/state")).selected === store.frame || null);
    assert.ok(selected, `frame ${store.frame} was not selected`);
    const picked = await until(async () => {
      const l = await look();
      return { ...l, done: l.slice === String(store.instance - 1) };
    });
    assert.ok(picked.done, `the panel does not show instance ${store.instance}: ${JSON.stringify(picked)}`);
    // No capture, then the fixed exporter's: the panel starts over
    await api("/api/close", {});
    const empty = await until(async () => {
      const l = await look();
      const note = await frame.evaluate(`(() => { const n = document.querySelector(".note"); return n.hidden ? "" : n.textContent; })()`);
      return { ...l, note, done: l.lit === 0 && /^Open a capture with DICOM/.test(note) };
    });
    assert.ok(empty.done, JSON.stringify(empty));
    await tool("open_capture", { path: join(fixtures, "ct-archive-fixed.pcap") });
    const fixed = await until(async () => {
      const l = await look();
      return { ...l, done: l.stores === ctFixed.stores.length && l.uids === ctFixed.uids && l.lit > 50000 };
    }, 60000);
    assert.equal(errors, "");
    assert.ok(fixed.done && fixed.overwritten === 0 && fixed.uids === fixed.stores, JSON.stringify(fixed));
    assert.equal(fixed.red, 0, "nothing red without repeated UIDs");
    await screenshot("ctseries-fixed");
    // Both exports in one capture: an association each, the latest shown, the other one picked
    await tool("open_capture", { path: join(fixtures, "ct-archive-then-fixed.pcap") });
    const [before, after] = ctThenFixed.exports;
    const latest = await until(async () => {
      const l = await look();
      return { ...l, done: l.association === 2 && l.stores === after.stores.length && l.uids === after.uids && l.lit > 50000 };
    }, 60000);
    assert.ok(latest.done && latest.associations === 2 && latest.overwritten === 0, JSON.stringify(latest));
    assert.deepEqual(latest.titles, ["Head 5.0: 24 images sent, 24 kept", "Head 0.625: 160 images sent, 160 kept"]);
    await frame.evaluate(`(() => {
      const p = document.querySelector(".association");
      p.value = "0";
      p.dispatchEvent(new Event("change"));
    })()`);
    const first = await until(async () => {
      const l = await look();
      return { ...l, done: l.association === 1 && l.uids === before.uids };
    });
    assert.ok(first.done && first.stores === before.stores.length && first.overwritten === before.overwritten, JSON.stringify(first));
    assert.deepEqual(first.titles, ["Head 5.0: 24 images sent, 24 kept", "Head 0.625: 160 images sent, 100 kept"]);
    // A C-STORE of the other association selected in WireBuddy: the panel goes there
    const later = after.stores[100];
    await tool("goto_frame", { frame: later.frame });
    const followed = await until(async () => {
      const l = await look();
      return { ...l, done: l.association === 2 && l.slice === String(later.instance - 1) };
    });
    assert.ok(followed.done, JSON.stringify(followed));
    assert.equal(errors, "");
    // Hidden, the panel gets no animation frames: a snapshot paints the canvas all the same
    await frame.evaluate(`(() => {
      window.requestAnimationFrame = () => 0;
      const c = document.querySelector(".view canvas");
      c.width = c.width;
    })()`);
    assert.equal((await look()).lit, 0, "the canvas is cleared");
    const hidden = await snapshot();
    assert.ok(hidden.opaque > 50000, `${hidden.opaque} pixels in the snapshot of the hidden panel`);
    await finish("ctseries", frame);
    return `${buggy.uids} SOP Instance UIDs in ${buggy.stores} C-STOREs, ${buggy.overwritten} overwritten; fixed ${fixed.uids}; ${buggy.lit} pixels lit`;
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
