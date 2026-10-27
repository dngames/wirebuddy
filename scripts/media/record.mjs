// Records the WireBuddy promo video: scripted chat + real MCP calls + real UI, captured with Chrome's screencast.
// Usage: CDP_PORT=<port of a running headless chrome> node record.mjs <wirebuddy-root> <outdir>
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { copyFileSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

const here = dirname(fileURLToPath(import.meta.url));
const [root, outdir] = process.argv.slice(2);
if (!process.env.CDP_PORT || !root || !outdir) {
  console.error("Usage: CDP_PORT=<port of a running headless chrome> node record.mjs <wirebuddy-root> <outdir>");
  process.exit(2);
}
const TOKEN = randomBytes(16).toString("hex");
const require = createRequire(join(root, "package.json"));
const { Client } = await import(require.resolve("@modelcontextprotocol/sdk/client/index.js"));
const { StdioClientTransport } = await import(require.resolve("@modelcontextprotocol/sdk/client/stdio.js"));
const WebSocket = require("ws");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const PORT = 8780;

// The stage must share the UI's origin to reach into its iframe
copyFileSync(join(here, "stage.html"), join(root, "dist/web/stage.html"));
const framesDir = join(outdir, "frames");
rmSync(framesDir, { recursive: true, force: true });
mkdirSync(framesDir, { recursive: true });
mkdirSync(join(outdir, "home"), { recursive: true });

const mcp = new Client({ name: "promo", version: "0" });
await mcp.connect(new StdioClientTransport({
  command: process.execPath,
  args: [join(root, "dist/server/main.js"), "--mcp", "--port", String(PORT), "--capture-dir", mkdtempSync(join(tmpdir(), "wb-video-"))],
  // Empty home: no recent-file history from the real Wireshark config can appear on screen
  env: { ...process.env, HOME: join(outdir, "home"), WIREBUDDY_TOKEN: TOKEN },
  stderr: "ignore",
}));
const tool = async (name, args = {}) => {
  const r = await mcp.callTool({ name, arguments: args });
  const text = r.content.map((c) => c.text).join("\n");
  if (r.isError) throw new Error(`${name}: ${text}`);
  return text;
};

// --- CDP plumbing
const targets = await fetch(`http://127.0.0.1:${process.env.CDP_PORT}/json/list`).then((r) => r.json());
const ws = new WebSocket(targets.find((t) => t.type === "page").webSocketDebuggerUrl);
await new Promise((r) => ws.once("open", r));
let nextId = 0;
const pending = new Map();
const frames = [];
ws.on("message", (raw) => {
  const m = JSON.parse(raw);
  if (m.id) {
    pending.get(m.id)?.(m.result ?? m.error);
    pending.delete(m.id);
  } else if (m.method === "Page.screencastFrame") {
    const { data, metadata, sessionId } = m.params;
    const file = join(framesDir, `f${String(frames.length).padStart(5, "0")}.jpg`);
    writeFileSync(file, Buffer.from(data, "base64"));
    frames.push({ file, t: metadata.timestamp });
    send("Page.screencastFrameAck", { sessionId });
  }
});
const send = (method, params = {}) => new Promise((r) => { pending.set(++nextId, r); ws.send(JSON.stringify({ id: nextId, method, params })); });
const js = async (expression) => {
  const r = await send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true });
  if (r?.exceptionDetails) throw new Error(`${expression.slice(0, 80)}: ${r.exceptionDetails.exception?.description ?? r.exceptionDetails.text}`);
  return r?.result?.value;
};
const stage = (call) => js(`window.stage.${call}`);

// Element helpers inside the WireBuddy iframe; coordinates are page coordinates
const APP = `document.getElementById("app")`;
const locate = (finder) => js(`(() => {
  const frame = ${APP}; const doc = frame.contentDocument; const off = frame.getBoundingClientRect();
  const el = (${finder})(doc);
  if (!el) return null;
  el.scrollIntoView({ block: "nearest" });
  const r = el.getBoundingClientRect();
  return { x: off.left + r.left + Math.min(r.width / 2, 60), y: off.top + r.top + r.height / 2 };
})()`);
const byText = (selector, text) => `(doc) => [...doc.querySelectorAll(${JSON.stringify(selector)})].find((e) => e.textContent.trim().startsWith(${JSON.stringify(text)}))`;
const byLabel = (label) => `(doc) => doc.querySelector('[aria-label=${JSON.stringify(label)}], [title=${JSON.stringify(label)}]')`;
async function click(finder, count = 1) {
  const p = await locate(finder);
  if (!p) throw new Error(`not found: ${finder}`);
  await send("Input.dispatchMouseEvent", { type: "mouseMoved", x: p.x, y: p.y });
  for (let i = 1; i <= count; i++) {
    await send("Input.dispatchMouseEvent", { type: "mousePressed", x: p.x, y: p.y, button: "left", clickCount: i });
    await send("Input.dispatchMouseEvent", { type: "mouseReleased", x: p.x, y: p.y, button: "left", clickCount: i });
  }
}
async function type(text, delay = 70) {
  for (const ch of text) {
    await send("Input.insertText", { text: ch });
    await sleep(delay);
  }
}
const key = async (k, code, vk, extra = {}) => {
  await send("Input.dispatchKeyEvent", { type: "keyDown", key: k, code, windowsVirtualKeyCode: vk, ...extra });
  await send("Input.dispatchKeyEvent", { type: "keyUp", key: k, code, windowsVirtualKeyCode: vk });
};
const enter = () => key("Enter", "Enter", 13, { text: "\r" });
const escape = () => key("Escape", "Escape", 27);
const selectAll = () => key("a", "KeyA", 65, { modifiers: 2 });

// --- recording
await send("Page.enable");
await send("Runtime.enable");
await send("Emulation.setDeviceMetricsOverride", { width: 1600, height: 900, deviceScaleFactor: 1, mobile: false });
await send("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: "light" }] });
await send("Page.navigate", { url: `http://127.0.0.1:${PORT}/stage.html` });
await sleep(1200);
await stage(`card("title", true)`);
await stage(`load("/?token=${TOKEN}")`);
await sleep(1500);
await send("Page.startScreencast", { format: "jpeg", quality: 88, maxWidth: 1600, maxHeight: 900, everyNthFrame: 1 });

// 1. Title
await sleep(3500);
await stage(`card("title", false)`);
await sleep(900);

// 2. The agent opens the capture and explains what it found
await stage(`user("Open test/fixtures/http.pcapng — why did the second download fail?")`);
await tool("open_capture", { path: join(root, "test/fixtures/http.pcapng") });
await sleep(400);
await stage(`reveal()`);
await stage(`tool("open_capture http.pcapng", "29 frames")`);
await stage(`caption("Your agent opens captures in the viewer you're looking at")`);
await sleep(1300);
await tool("capture_summary", {});
await stage(`tool("capture_summary", "TCP 29 · HTTP 4")`);
await sleep(700);
await tool("set_display_filter", { filter: "http" });
await stage(`tool("set_display_filter http", "4 of 29 shown")`);
await sleep(1300);
await tool("mark_frames", { frames: [21, 25], note: "request for a missing file and its 404" });
await stage(`tool("mark_frames 21, 25", "marked")`);
await sleep(800);
await tool("goto_frame", { frame: 25 });
const detail = await tool("inspect_frame", { frame: 25, protocols: ["http"] });
await stage(`tool("inspect_frame 25", ${JSON.stringify(/404 File not found/.test(detail) ? "HTTP 404" : "done")})`);
await stage(`caption("…filters, marks and selects packets so you see what it sees")`);
await stage(`agent("Frame 21 asks the server for /nothere, and frame 25 answers 404 File not found. I filtered to HTTP and marked both for you.")`);
await sleep(2600);

// 3. The user digs in, Wireshark-style
await stage(`caption("Dig in like in Wireshark: protocol tree, bytes, reassembly")`);
await click(byText("[role=tree] *", "Hypertext Transfer Protocol"), 2);
await sleep(900);
await click(byText("[role=tree] *", "HTTP/1.0 404"), 2);
await sleep(800);
await click(byText("[role=tree] *", "Status Code: 404"));
await sleep(2200);
await stage(`caption("Follow streams like in Wireshark: the list shows just that conversation")`);
await key("T", "KeyT", 84, { modifiers: 1 | 2 | 8 });
await sleep(3200);
await click(byText("button", "Back"));
await sleep(900);
await stage(`caption("Capture-filter syntax by mistake? It suggests the display filter")`);
await click(byLabel("Display filter"));
await selectAll();
await type("tcp port 18080");
await sleep(1600);
await click(`(doc) => doc.querySelector(".fb-suggest")`);
await sleep(700);
await enter();
await sleep(400);
await escape();
await sleep(2000);

// 4. Live capture: started by the user, analysed together
await stage(`caption("Live capture: you press Start, then analyse it with your agent")`);
await click(byLabel("Clear display filter"));
await sleep(600);
// Recording pauses while the bar opens, so no frame shows another interface's addresses
await send("Page.stopScreencast");
if (frames.length) frames[frames.length - 1].pausedAfter = true;
// The bar remembers being open in the browser profile: open it only when it is closed
const barShown = () => js(`!!${APP}.contentDocument.querySelector(".capturebar")?.offsetParent`);
if (!(await barShown())) await click(byLabel("Options…"));
await sleep(500);
const picked = await js(`(() => {
  const s = ${APP}.contentDocument.querySelector("select.cb-iface");
  s.value = "lo";
  s.dispatchEvent(new Event("change", { bubbles: true }));
  return s.value;
})()`);
if (picked !== "lo") throw new Error("could not select lo");
await sleep(500);
if (!(await barShown())) throw new Error("capture bar did not open");
await send("Page.startScreencast", { format: "jpeg", quality: 88, maxWidth: 1600, maxHeight: 900, everyNthFrame: 1 });
await sleep(400);
await click(`(doc) => doc.querySelector(".capturebar .cb-filter")`);
// Options persist in the browser profile: replace what an earlier run left
await selectAll();
// Pings only: other loopback ICMP (resolver port-unreachables) has no place in the video
await type("icmp and icmp[0] != 3", 70);
await sleep(900);
const ping = spawn("ping", ["-i", "0.1", "-c", "140", "127.0.0.1"], { stdio: "ignore" });
// The capture filter is checked as it is typed: wait for the verdict
const ready = await js(`new Promise((done) => {
  const t0 = Date.now();
  const tick = () => {
    const b = ${APP}.contentDocument.querySelector(".cb-start");
    if (b && !b.disabled) return done("ready");
    if (Date.now() - t0 > 6000) return done(b ? b.title : "missing");
    setTimeout(tick, 100);
  };
  tick();
})`);
if (ready !== "ready") throw new Error(`capture can't start: ${ready}`);
await click(`(doc) => doc.querySelector(".cb-start")`);
await sleep(3500);
await stage(`user("Anything unusual in the live traffic?")`);
await tool("get_view_state", {});
const requests = await tool("query_packets", { filter: "icmp.type == 8", limit: 1 });
const replies = await tool("query_packets", { filter: "icmp.type == 0", limit: 1 });
const nReq = Number(/^(\d+) frames match/.exec(requests)?.[1] ?? 0);
const nRep = Number(/^(\d+) frames match/.exec(replies)?.[1] ?? 0);
await stage(`tool("get_view_state", "capturing on lo")`);
await stage(`tool("query_packets icmp.type == 8 / == 0", "${nReq} / ${nRep}")`);
await stage(`agent(${JSON.stringify(`Just pings on loopback so far: ${nReq} echo requests and ${nRep} replies, ${Math.abs(nReq - nRep) <= 1 ? "every request answered" : `${Math.abs(nReq - nRep)} unanswered`}. Nothing unusual.`)})`);
await sleep(2500);
await click(byLabel("Stop the running capture"));
ping.kill();
await sleep(1500);

// 5. Hand-off to the real Wireshark (highlighted, not launched)
await js(`(() => {
  const doc = ${APP}.contentDocument;
  const b = [...doc.querySelectorAll("button")].find((e) => /Open in Wireshark/.test(e.textContent));
  const st = doc.createElement("style");
  st.textContent = "@keyframes wbpulse{0%,100%{box-shadow:0 0 0 0 rgba(139,92,246,.9)}50%{box-shadow:0 0 0 10px rgba(139,92,246,0)}}";
  doc.head.append(st);
  b.style.animation = "wbpulse 1s ease-in-out 4";
  b.style.outline = "4px solid #8b5cf6"; b.style.outlineOffset = "2px";
})()`);
await stage(`caption("One click to the real Wireshark: same file, filter and packet")`);
await sleep(3200);
await stage(`caption("")`);

// 6. End card
await stage(`card("end", true)`);
await sleep(4200);
await send("Page.stopScreencast");
await sleep(300);

// Frame list with real timings for ffmpeg's concat demuxer
const lines = [];
for (let i = 0; i < frames.length; i++) {
  const gap = i + 1 < frames.length ? frames[i + 1].t - frames[i].t : 0.5;
  // Cut the recording pause down to a short beat
  const dur = gap > 0.8 && frames[i].pausedAfter ? 0.3 : gap;
  lines.push(`file '${frames[i].file}'`, `duration ${Math.max(dur, 0.001).toFixed(4)}`);
}
lines.push(`file '${frames[frames.length - 1].file}'`);
writeFileSync(join(outdir, "frames.txt"), lines.join("\n") + "\n");
console.log(`${frames.length} frames, ${(frames[frames.length - 1].t - frames[0].t).toFixed(1)} s`);

ws.close();
await mcp.close();
rmSync(join(root, "dist/web/stage.html"), { force: true });
process.exit(0);
