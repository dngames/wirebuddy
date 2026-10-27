// Records the WireBuddy demo video: an agent investigates the stuttering robot arm of
// examples/investigations/robot-arm with real MCP calls, real loopback captures and the real UI,
// captured with Chrome's screencast. The chat is scripted; every tool call and result is real.
// Usage: CDP_PORT=<port of a running headless chrome> node record.mjs <wirebuddy-root> <outdir>
//        WATCH=1 node record.mjs <wirebuddy-root> <outdir>   (no recording: prints the viewer's URL
//        and waits for SIGUSR1 before each step, to follow the story in a browser)
import { execFileSync, spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { chmodSync, copyFileSync, cpSync, mkdirSync, mkdtempSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

const here = dirname(fileURLToPath(import.meta.url));
const [root, outdir] = process.argv.slice(2);
const WATCH = !!process.env.WATCH;
if ((!process.env.CDP_PORT && !WATCH) || !root || !outdir) {
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
const ARM = 7700;
const TELEMETRY = 7701;
const example = join(root, "examples/investigations/robot-arm");

// The app runs from a copy, so the fix never touches the repository
mkdirSync(outdir, { recursive: true });
const work = mkdtempSync(join(tmpdir(), "wb-arm-"));
for (const f of ["device.mjs", "app.mjs", "PROTOCOL.md"]) copyFileSync(join(example, f), join(work, f));
const home = join(outdir, "home");
rmSync(home, { recursive: true, force: true });
const extensions = join(home, ".local/share/wirebuddy/extensions");
mkdirSync(extensions, { recursive: true, mode: 0o700 });
const device = spawn(process.execPath, [join(work, "device.mjs"), "--port", String(ARM), "--telemetry", String(TELEMETRY)], { stdio: "ignore" });
process.on("exit", () => device.kill());

const mcp = new Client({ name: "demo", version: "0" });
await mcp.connect(new StdioClientTransport({
  command: process.execPath,
  args: [join(root, "dist/server/main.js"), "--mcp", "--port", String(PORT), "--capture-dir", mkdtempSync(join(tmpdir(), "wb-video-"))],
  // Empty home: no recent-file history from the real Wireshark config can appear on screen
  env: { ...process.env, HOME: home, XDG_CONFIG_HOME: join(home, ".config"), XDG_DATA_HOME: join(home, ".local/share"), WIREBUDDY_EXTENSIONS: "", WIREBUDDY_TOKEN: TOKEN },
  stderr: "ignore",
}));
const tool = async (name, args = {}) => {
  const r = await mcp.callTool({ name, arguments: args });
  const text = r.content.filter((c) => c.type === "text").map((c) => c.text).join("\n");
  if (WATCH) console.log(`\n> ${name} ${JSON.stringify(args)}\n${text.split("\nWireBuddy events")[0].slice(0, 1500)}`);
  if (r.isError) throw new Error(`${name}: ${text}`);
  return text;
};

/** The control app, run as the agent would run it: its report. Not blocking, so the recording goes on meanwhile. */
async function runApp(seconds) {
  const app = spawn(process.execPath, [join(work, "app.mjs"), "--port", String(ARM), "--telemetry", String(TELEMETRY), "--seconds", String(seconds)], { stdio: ["ignore", "pipe", "inherit"] });
  let out = "";
  app.stdout.setEncoding("utf8");
  app.stdout.on("data", (d) => (out += d));
  const code = await new Promise((done) => app.on("close", done));
  if (code !== 0) throw new Error(`app.mjs exited with ${code}`);
  if (WATCH) console.log(out);
  const rate = /([\d.]+)\/s achieved/.exec(out)?.[1];
  const p50 = /ACK latency\s+p50 ([\d.]+) ms/.exec(out)?.[1];
  const missed = /deadlines missed\s+(\d+)/.exec(out)?.[1];
  const err = /tracking error\s+max ([\d.]+)°/.exec(out)?.[1];
  return { rate, p50, missed, err };
}

/** The agent writes its dissector and panel: here, the example's solution. */
function writeExtension() {
  const to = join(extensions, "armc");
  cpSync(join(example, "solution/armc"), to, { recursive: true });
  const modes = (p) => {
    for (const e of readdirSync(p)) {
      const f = join(p, e);
      if (statSync(f).isDirectory()) {
        chmodSync(f, 0o700);
        modes(f);
      } else chmodSync(f, 0o600);
    }
  };
  chmodSync(to, 0o700);
  modes(to);
}

/** Frame numbers from query_packets with fields: the first value of each row. */
const framesOf = (text) => [...text.matchAll(/^\s*(\d+)\s*\|\s*(\d+)/gm)].map((m) => Number(m[2]));

// --- the browser: Chrome over CDP, or nothing in WATCH mode
let send = async () => ({});
let js = async () => null;
const frames = [];
let ws = null;
if (!WATCH) {
  // The stage must share the UI's origin to reach into its iframe
  copyFileSync(join(here, "stage.html"), join(root, "dist/web/stage.html"));
  const framesDir = join(outdir, "frames");
  rmSync(framesDir, { recursive: true, force: true });
  mkdirSync(framesDir, { recursive: true });
  const targets = await fetch(`http://127.0.0.1:${process.env.CDP_PORT}/json/list`).then((r) => r.json());
  ws = new WebSocket(targets.find((t) => t.type === "page").webSocketDebuggerUrl);
  await new Promise((r) => ws.once("open", r));
  let nextId = 0;
  const pending = new Map();
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
  send = (method, params = {}) => new Promise((r) => { pending.set(++nextId, r); ws.send(JSON.stringify({ id: nextId, method, params })); });
  js = async (expression) => {
    const r = await send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true });
    if (r?.exceptionDetails) throw new Error(`${expression.slice(0, 80)}: ${r.exceptionDetails.exception?.description ?? r.exceptionDetails.text}`);
    return r?.result?.value;
  };
}
const stage = async (call) => (WATCH ? console.log(`[stage] ${call}`) : js(`window.stage.${call}`));
/** A beat for the viewer; in WATCH mode, the next step waits for SIGUSR1. */
const beat = (ms) => (WATCH ? new Promise((r) => process.once("SIGUSR1", r)) : sleep(ms));

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
async function click(finder, count = 1) {
  if (WATCH) return;
  const p = await locate(finder);
  if (!p) return;
  await send("Input.dispatchMouseEvent", { type: "mouseMoved", x: p.x, y: p.y });
  for (let i = 1; i <= count; i++) {
    await send("Input.dispatchMouseEvent", { type: "mousePressed", x: p.x, y: p.y, button: "left", clickCount: i });
    await send("Input.dispatchMouseEvent", { type: "mouseReleased", x: p.x, y: p.y, button: "left", clickCount: i });
  }
}

/**
 * Reveals the UI once it shows a capture: WireBuddy's start page lists the
 * machine's interfaces with their addresses, which must never be in the video.
 */
async function revealCapture() {
  if (WATCH) return;
  for (let i = 0; i < 150; i++) {
    const ready = await js(`(() => {
      const doc = ${APP}.contentDocument;
      const list = doc?.querySelector(".wl-ifaces");
      return !!doc && (!list || list.offsetParent === null) && !!doc.querySelector(".pl-row");
    })()`);
    if (ready) return stage("reveal()");
    await sleep(100);
  }
  throw new Error("the viewer never showed the capture");
}

// --- the story
if (WATCH) console.log(`viewer: http://127.0.0.1:${PORT}/?token=${TOKEN}\nwaiting for SIGUSR1 (kill -USR1 ${process.pid}) before each step`);
else {
  await send("Page.enable");
  await send("Runtime.enable");
  await send("Emulation.setDeviceMetricsOverride", { width: 1600, height: 900, deviceScaleFactor: 1, mobile: false });
  await send("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: "light" }] });
  await send("Page.navigate", { url: `http://127.0.0.1:${PORT}/stage.html` });
  await sleep(1200);
  await stage(`card("title", true)`);
  await stage(`load("/?token=${TOKEN}")`);
  await sleep(1500);
  // Notes if the start page with the interface list is ever on screen while the UI is revealed
  await js(`setInterval(() => {
    const frame = ${APP};
    const list = frame.contentDocument?.querySelector(".wl-ifaces");
    if (frame.classList.contains("on") && list && list.offsetParent !== null) window.__startPageShown = true;
  }, 20) && true`);
  await send("Page.startScreencast", { format: "jpeg", quality: 88, maxWidth: 1600, maxHeight: 900, everyNthFrame: 1 });
}

// 1. Title
await beat(3500);
await stage(`card("title", false)`);
await sleep(900);

// 2. The problem, and a capture the agent starts itself
await stage(`user("Our robot arm stutters. The control app should send 50 MOVE commands a second but gets about 22 through, yet the vendor says the controller answers in under a millisecond. Capture the traffic while the app runs and find out why.")`);
await beat(500);
const filter = `tcp port ${ARM} or udp port ${TELEMETRY}`;
await tool("start_capture", { interface: "lo", filter });
await stage(`tool("start_capture lo · ${filter}", "capturing")`);
const running = runApp(4);
await revealCapture();
await stage(`caption("Your agent starts the capture and runs the app")`);
const before = await running;
await stage(`tool("node app.mjs", ${JSON.stringify(`${before.rate} commands/s · ACK p50 ${before.p50} ms`)})`);
await tool("stop_capture", {});
await stage(`tool("stop_capture", "done")`);
await beat(1800);

// 3. A vendor protocol Wireshark doesn't know: the agent teaches it
await tool("capture_summary", {});
await stage(`tool("capture_summary", "TCP ${ARM} and UDP ${TELEMETRY}: undecoded data")`);
await stage(`caption("Unknown protocol? The agent writes a dissector from the vendor's spec")`);
await beat(1500);
writeExtension();
await stage(`tool("write armc.lua from PROTOCOL.md", "MOVE, ACK, telemetry")`);
const tested = await tool("extensions", { action: "test", name: "armc" });
await stage(`tool("extensions test armc", ${JSON.stringify(/armc: (\d+) packets/.exec(tested)?.[0] ?? "decodes")})`);
await tool("extensions", { action: "reload" });
await stage(`tool("extensions reload", "the view decodes ARMC")`);
await beat(2200);

// 4. Where the time goes: a time-delta column on the controller's connection
await tool("set_display_filter", { filter: `tcp.port == ${ARM}` });
await tool("set_columns", { columns: [{ field: "frame.time_delta_displayed", title: "Δt" }, { field: "tcp.len", title: "TCP len" }] });
await stage(`tool("set_columns Δt, TCP len · tcp.port == ${ARM}", "shown")`);
// A MOVE's header alone: 8 bytes that aren't a whole ARMC message yet
const headers = framesOf(await tool("query_packets", { filter: `tcp.dstport == ${ARM} && tcp.len == 8 && !armc`, fields: ["frame.number"], limit: 40 }));
const h = headers[Math.min(20, headers.length - 1)] ?? headers[0];
const [ack] = framesOf(await tool("query_packets", { filter: `tcp.srcport == ${ARM} && tcp.len == 0 && frame.number > ${h}`, fields: ["frame.number"], limit: 1 }));
const [payload] = framesOf(await tool("query_packets", { filter: `tcp.dstport == ${ARM} && tcp.len > 8 && frame.number > ${h}`, fields: ["frame.number"], limit: 1 }));
// The header first, so the list shows it with the ACK and the payload below; then the payload's details
await tool("goto_frame", { frame: h });
await tool("goto_frame", { frame: payload });
await tool("mark_frames", { frames: [h, ack, payload], note: "MOVE header, the controller's ACK 40 ms later, then the payload" });
await stage(`tool("mark_frames ${h}, ${ack}, ${payload}", "header · ACK · payload")`);
await stage(`caption("Δt shows it: every command's payload waits 40 ms for the ACK of its header")`);
await click(byText("[role=tree] *", "ARMC"), 2);
await beat(2600);
const expert = await tool("expert_info", {});
const split = /Message split over frames[^\n]*: (\d+)\s+\[/.exec(expert)?.[1];
await stage(`tool("expert_info", ${JSON.stringify(split ? `${split}× message split over frames` : "split messages")})`);
await stage(`agent("The controller answers in microseconds; the 40 ms come before it. app.mjs writes each MOVE's header and payload separately. With Nagle on, the payload waits for the ACK of the header, and the controller's TCP holds that ACK back 40 ms. One write per message fixes it.")`);
await beat(3200);

// 5. What it means for the arm
await tool("panel", { action: "open", name: "armc", wait_ms: 10_000 });
await stage(`tool("panel open armc", "trajectory plot")`);
await stage(`caption("…and a panel it wrote shows what that does to the arm")`);
await beat(4200);

// 6. The fix, checked with a second capture
execFileSync("git", ["apply", "-p4", join(example, "solution/fix.diff")], { cwd: work });
await stage(`tool("edit app.mjs: one write per message", "1 line")`);
await tool("start_capture", { interface: "lo", filter });
await stage(`tool("start_capture", "capturing")`);
const after = await runApp(4);
await stage(`tool("node app.mjs", ${JSON.stringify(`${after.rate} commands/s · ACK p50 ${after.p50} ms`)})`);
await tool("stop_capture", {});
await stage(`caption("Fixed: a command every 20 ms, and the arm moves smoothly")`);
await beat(2500);
await stage(`agent(${JSON.stringify(`Fixed: ${after.rate} commands/s, each acknowledged in ${after.p50} ms, no deadline missed. The new capture has one segment per command, and the arm follows its path smoothly.`)})`);
await beat(4000);
await stage(`caption("")`);

// 7. End card
await stage(`card("end", true)`);
await beat(4200);

if (!WATCH) {
  await send("Page.stopScreencast");
  await sleep(300);
  if (await js("window.__startPageShown === true")) throw new Error("the start page with the machine's interfaces was on screen: the frames must not be used");
  // Frame list with real timings for ffmpeg's concat demuxer
  const lines = [];
  for (let i = 0; i < frames.length; i++) {
    const gap = i + 1 < frames.length ? frames[i + 1].t - frames[i].t : 0.5;
    lines.push(`file '${frames[i].file}'`, `duration ${Math.max(gap, 0.001).toFixed(4)}`);
  }
  lines.push(`file '${frames[frames.length - 1].file}'`);
  writeFileSync(join(outdir, "frames.txt"), lines.join("\n") + "\n");
  console.log(`${frames.length} frames, ${(frames[frames.length - 1].t - frames[0].t).toFixed(1)} s`);
  ws.close();
  rmSync(join(root, "dist/web/stage.html"), { force: true });
}
console.log(`before: ${JSON.stringify(before)}\nafter:  ${JSON.stringify(after)}`);
await mcp.close();
device.kill();
rmSync(work, { recursive: true, force: true });
process.exit(0);
