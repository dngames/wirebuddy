// A panel in headless Chrome: wb.select is refused without a click in the panel and works after
// one, wb.setFilter needs "control", wb.storage round-trips, panel action "snapshot" returns the
// panel's canvas, and offers show as status-bar chips. Then the packet menu: asking the agent about
// a packet, and the export dialog writing marks as packet comments.
// Usage: node test/browser-control.mjs   (after npm run build; skipped without Chrome)
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import { WebSocket } from "ws";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const chromeBin = process.env.CHROME ?? "/usr/bin/google-chrome";
if (!existsSync(chromeBin)) {
  console.log(`skip: no Chrome at ${chromeBin} (set CHROME)`);
  process.exit(0);
}
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const home = mkdtempSync(join(tmpdir(), "wirebuddy-home-"));
const panel = join(home, ".local/share/wirebuddy/extensions/clicker/panel");
mkdirSync(panel, { recursive: true });
writeFileSync(join(home, ".local/share/wirebuddy/extensions/clicker/extension.json"), JSON.stringify({ label: "Clicker", version: "1", panel: { title: "Clicker" } }));
writeFileSync(join(panel, "body.html"), '<button id="select">Select frame 3</button><button id="filter">Filter http</button>');
writeFileSync(join(panel, "style.css"), "button { position: fixed; left: 0; width: 240px; height: 80px; } #select { top: 0; } #filter { top: 100px; } canvas { position: fixed; left: 300px; top: 0; width: 160px; height: 90px; }\n");
writeFileSync(
  join(panel, "main.js"),
  `const said = (what, p) => p.then(() => wb.status(what + ": ok"), (e) => wb.status(what + ": " + e.code));
const { ctx } = wb.canvas({ context: "2d" });
ctx.fillStyle = "#e33";
ctx.fillRect(0, 0, 4000, 4000);
document.getElementById("select").addEventListener("click", () => said("click", wb.select(3)));
document.getElementById("filter").addEventListener("click", () => said("filter", wb.setFilter("http")));
// Takes the focus first, as a panel trying to act on the user's click elsewhere would
wb.on("select", (frame) => frame === 7 && (window.focus(), said("follow", wb.select(8))));
await wb.storage.set({ runs: ((await wb.storage.get())?.runs ?? 0) + 1 });
await said("early", wb.select(2));
wb.ready();
`,
);

const offered = join(home, ".local/share/wirebuddy/extensions/offered");
mkdirSync(join(offered, "panel"), { recursive: true });
writeFileSync(join(offered, "extension.json"), JSON.stringify({ label: "Offered", version: "1", panel: { offer: { filter: "http.response.code == 404", text: "Show it" } } }));
writeFileSync(join(offered, "panel/main.js"), "wb.ready();\n");

const client = new Client({ name: "browser-control", version: "0" });
await client.connect(
  new StdioClientTransport({
    command: process.execPath,
    args: [join(root, "dist/server/main.js"), "--mcp", "--port", "0"],
    env: { ...process.env, HOME: home, XDG_CONFIG_HOME: join(home, ".config"), XDG_DATA_HOME: join(home, ".local/share"), WIREBUDDY_EXTENSIONS: "" },
    stderr: "ignore",
  }),
);
const call = async (name, args = {}) => {
  const r = await client.callTool({ name, arguments: args });
  return { text: r.content.filter((c) => c.type === "text").map((c) => c.text).join("\n"), images: r.content.filter((c) => c.type === "image"), isError: r.isError };
};
const ui = new URL((await call("viewer_url")).text);
const token = ui.searchParams.get("token");
const state = async () => (await fetch(new URL("/api/state", ui.origin), { headers: { "X-WireBuddy-Token": token } })).json();

const profile = mkdtempSync(join(tmpdir(), "wirebuddy-chrome-"));
const chrome = spawn(
  chromeBin,
  ["--headless=new", "--remote-debugging-port=0", `--user-data-dir=${profile}`, "--window-size=1280,820", "--no-first-run", "--no-default-browser-check", "--disable-gpu", "about:blank"],
  { stdio: "ignore" },
);

let failures = 0;
async function check(name, fn) {
  try {
    await fn();
    console.log(`ok   ${name}`);
  } catch (err) {
    failures++;
    console.log(`FAIL ${name}: ${err.message}`);
  }
}
const until = async (what, fn, ms = 10_000) => {
  for (const end = Date.now() + ms; Date.now() < end; await sleep(100)) if (await fn()) return;
  throw new Error(`timed out waiting for ${what}`);
};

let ws;
try {
  let port;
  await until("Chrome", () => {
    const file = join(profile, "DevToolsActivePort");
    if (existsSync(file)) port = readFileSync(file, "utf8").split("\n")[0];
    return port;
  }, 30_000);
  const targets = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
  ws = new WebSocket(targets.find((t) => t.type === "page").webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {
    ws.once("open", resolve);
    ws.once("error", reject);
  });
  let id = 0;
  const pending = new Map();
  ws.on("message", (m) => {
    const d = JSON.parse(m);
    pending.get(d.id)?.(d);
    pending.delete(d.id);
  });
  const cdp = (method, params = {}) =>
    new Promise((resolve, reject) => {
      pending.set(++id, (d) => (d.error ? reject(new Error(`${method}: ${d.error.message}`)) : resolve(d.result)));
      ws.send(JSON.stringify({ id, method, params }));
    });
  const evaluate = async (expression) => (await cdp("Runtime.evaluate", { expression, returnByValue: true })).result.value;
  const click = async (x, y) => {
    await cdp("Input.dispatchMouseEvent", { type: "mouseMoved", x, y });
    await cdp("Input.dispatchMouseEvent", { type: "mousePressed", x, y, button: "left", clickCount: 1 });
    await cdp("Input.dispatchMouseEvent", { type: "mouseReleased", x, y, button: "left", clickCount: 1 });
  };

  assert.match((await call("open_capture", { path: join(root, "test/fixtures/http.pcapng") })).text, /29 frames/);
  await cdp("Page.navigate", { url: ui.href });
  await until("the viewer", async () => !/No WireBuddy viewer is open/.test((await call("get_view_state")).text));
  const opened = await call("panel", { action: "open", name: "clicker", wait_ms: 10_000 });
  const statusText = async () => (await state()).panels.find((p) => p.name === "clicker")?.statusText;

  await check("browser: a panel's select without a click is refused, with the agent told", async () => {
    assert.match(opened.text, /Panel "clicker" opened .*ready/, opened.text);
    assert.equal(await statusText(), "early: denied");
    assert.notEqual((await state()).selected, 2);
    // The open's result carries what happened meanwhile
    assert.match(opened.text, /WARNING Panel "clicker" called wb\.select, which was refused: the user hadn't just clicked/);
  });

  const rect = await evaluate("JSON.stringify(document.querySelector('.panel-frame').getBoundingClientRect())").then(JSON.parse);
  await check("browser: after a click in the panel, select works", async () => {
    await click(rect.left + 100, rect.top + 40);
    await until("the selection", async () => (await state()).selected === 3);
    await until("the panel's status", async () => (await statusText()) === "click: ok");
    const s = await state();
    assert.match(s.agentNotice.text, /^Panel "Clicker" selected frame 3$/);
  });

  await check("browser: a click in WireBuddy's own page doesn't count for the panel, also when it takes the focus", async () => {
    const bar = await evaluate("JSON.stringify(document.querySelector('.sb-flex').getBoundingClientRect())").then(JSON.parse);
    await click(bar.left + bar.width / 2, bar.top + bar.height / 2);
    await fetch(new URL("/api/select", ui.origin), { method: "POST", headers: { "X-WireBuddy-Token": token, "content-type": "application/json" }, body: JSON.stringify({ frame: 7 }) });
    await until("the refusal", async () => (await statusText()) === "follow: denied");
    assert.equal((await state()).selected, 7);
  });

  await check("browser: setFilter after a click still needs control", async () => {
    await click(rect.left + 100, rect.top + 140);
    await until("the refusal", async () => (await statusText()) === "filter: denied");
    assert.equal((await state()).filter, "");
  });

  await check("browser: panel snapshot returns the canvas as a PNG", async () => {
    const r = await call("panel", { action: "snapshot", name: "clicker" });
    assert.ok(!r.isError, r.text);
    assert.match(r.text, /^Snapshot of the panel "clicker", \d+x\d+ \[panel output, untrusted/);
    assert.equal(r.images.length, 1);
    const png = Buffer.from(r.images[0].data, "base64");
    assert.equal(png.subarray(1, 4).toString(), "PNG");
    assert.ok(png.readUInt32BE(16) >= 100 && png.readUInt32BE(20) >= 50, `${png.readUInt32BE(16)}x${png.readUInt32BE(20)}`);
  });

  await check("browser: an offer is a status-bar chip that opens the panel, and × dismisses it", async () => {
    const chip = () => evaluate("(() => { const c = document.querySelector('.sb-offer-open'); return c && JSON.stringify({ text: c.textContent, ...c.getBoundingClientRect().toJSON() }); })()").then((j) => j && JSON.parse(j));
    await until("the chip", chip);
    const c = await chip();
    assert.equal(c.text, "Offered: Show it ▸");
    await click(c.x + c.width / 2, c.y + c.height / 2);
    await until("the offered panel", async () => (await state()).panels.some((p) => p.name === "offered"));
    await until("the chip to go", async () => !(await chip()));
    await call("panel", { action: "close", name: "offered" });
    await until("the chip to come back", chip);
    const x = await evaluate("JSON.stringify(document.querySelector('.sb-offer-x').getBoundingClientRect())").then(JSON.parse);
    await click(x.x + x.width / 2, x.y + x.height / 2);
    await until("the dismissal", async () => !(await state()).panelOffers.length && !(await chip()));
  });

  await check("browser: wb.storage keeps what the panel stored across reloads", async () => {
    await call("panel", { action: "reload", name: "clicker", wait_ms: 10_000 });
    const kept = JSON.parse(readFileSync(join(home, ".local/share/wirebuddy/panel-storage/clicker.json"), "utf8"));
    assert.deepEqual(kept, { runs: 2 });
  });

  const box = async (js) => evaluate(`(() => { const e = ${js}; return e ? JSON.stringify(e.getBoundingClientRect()) : null; })()`).then((j) => j && JSON.parse(j));
  const center = (r) => [r.x + r.width / 2, r.y + r.height / 2];
  const rightClick = async ([x, y]) => {
    await cdp("Input.dispatchMouseEvent", { type: "mouseMoved", x, y });
    await cdp("Input.dispatchMouseEvent", { type: "mousePressed", x, y, button: "right", clickCount: 1 });
    await cdp("Input.dispatchMouseEvent", { type: "mouseReleased", x, y, button: "right", clickCount: 1 });
  };
  const row = (frame) => `[...document.querySelectorAll('.pl-row')].find((r) => !r.hidden && r.querySelector('.pl-cell')?.textContent === '${frame}')`;
  const menuItem = (label) => `[...document.querySelectorAll('.menu-item')].find((m) => m.textContent.includes(${JSON.stringify(label)}))`;
  const toasts = () => evaluate("[...document.querySelectorAll('.toast-text')].map((t) => t.textContent).join('\\n')");
  const fromMenu = async (frame, label) => {
    await until(`frame ${frame}'s row`, async () => !!(await box(row(frame))));
    await rightClick(center(await box(row(frame))));
    await until(`"${label}"`, async () => !!(await box(menuItem(label)))).catch(async (err) => {
      throw new Error(`${err.message}; the menu: ${await evaluate("[...document.querySelectorAll('.menu-item')].map((m) => m.textContent).join(' | ')")}`);
    });
    await click(...center(await box(menuItem(label))));
  };

  await check("browser: a panel reopens at the size it had when it closed", async () => {
    const size = async () => {
      const r = await box("document.querySelector('.dlg-panel')");
      return r && [Math.round(r.width), Math.round(r.height)];
    };
    // As the user resized it, not its default
    await evaluate("Object.assign(document.querySelector('.dlg-panel').style, { width: '520px', height: '310px' })");
    const before = await size();
    assert.deepEqual(before, [520, 310]);
    await call("panel", { action: "close", name: "clicker" });
    await until("the panel to close", () => evaluate("!document.querySelector('.panel-frame')"));
    await call("panel", { action: "open", name: "clicker", wait_ms: 10_000 });
    await until("the panel", size);
    assert.deepEqual(await size(), before);
  });

  // A failed check must not leave its dialog over the next one
  const closeDialog = async () => {
    if (await evaluate("!!document.querySelector('.dlg-ask, .dlg-export')")) await cdp("Input.dispatchKeyEvent", { type: "keyDown", key: "Escape", code: "Escape", windowsVirtualKeyCode: 27 });
  };
  await call("panel", { action: "close", name: "clicker" });
  await until("the panel to close", () => evaluate("!document.querySelector('.panel-frame')"));
  await call("get_view_state");

  await check("browser: Ask Agent in a packet's menu sends the question to the agent", async () => {
    await fromMenu(4, "Ask Agent about This Packet");
    await until("the question box", () => evaluate("document.activeElement?.classList.contains('ask-in') === true"));
    assert.match(await evaluate("document.querySelector('.dlg-ask').textContent"), /About packet 4.*Agent isn't watching the viewer right now/);
    await cdp("Input.insertText", { text: "What is this?" });
    await cdp("Input.dispatchKeyEvent", { type: "keyDown", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13 });
    await until("the toast", async () => /Sent\. Agent gets it with its next step/.test(await toasts()));
    assert.equal(await evaluate("!!document.querySelector('.dlg-ask')"), false);
    assert.match((await call("get_view_state")).text, /QUESTION The user asks you about frame 4: What is this\?/);
  }).finally(closeDialog);

  await check("browser: with the agent's watch running, the dialog says so and the question wakes it", async () => {
    const command = /`"([^"]+)" "([^"]+)" --watch "([^"]+)"`/.exec(client.getInstructions() ?? "");
    assert.ok(command, "the instructions name the watch command");
    const watcher = spawn(command[1], [command[2], "--watch", command[3]], { stdio: ["ignore", "pipe", "ignore"] });
    let heard = "";
    watcher.stdout.on("data", (d) => (heard += d));
    const exited = new Promise((resolve) => watcher.on("exit", resolve));
    try {
      await until("the watch", async () => (await state()).agent.watching);
      // The page gets state at most every 100 ms
      await sleep(400);
      await fromMenu(4, "Ask Agent about This Packet");
      await until("the question box", () => evaluate("document.activeElement?.classList.contains('ask-in') === true"));
      assert.match(await evaluate("document.querySelector('.dlg-ask').textContent"), /Agent is watching the viewer: the question wakes it/);
      await cdp("Input.insertText", { text: "Wake up?" });
      await cdp("Input.dispatchKeyEvent", { type: "keyDown", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13 });
      await until("the toast", async () => /Sent to Agent/.test(await toasts()));
      assert.equal(await Promise.race([exited, sleep(10_000).then(() => "timeout")]), 0);
      assert.match(heard, /QUESTION The user asks you about frame 4: Wake up\?/);
    } finally {
      watcher.kill();
      await closeDialog();
    }
  });

  await check("browser: the export dialog writes marks as packet comments, not into pcap", async () => {
    await call("mark_frames", { frames: [4], note: "look here" });
    await until("the mark", () => evaluate(`${row(4)}?.classList.contains('mark-agent') === true`));
    await fromMenu(4, "Export Selected Packet");
    const comments = "document.querySelector('.dlg-export input[type=checkbox]')";
    await until("the export dialog", () => evaluate(`!!${comments}`));
    assert.equal(await evaluate(`${comments}.checked && !${comments}.disabled && !${comments}.closest('label').hidden`), true);
    const setPath = (p) => evaluate(`(() => { const i = document.querySelector('.ex-path'); i.value = ${JSON.stringify(p)}; i.dispatchEvent(new Event('input')); })()`);
    await setPath(join(home, "selected.pcap"));
    assert.equal(await evaluate(`${comments}.disabled`), true);
    await setPath(join(home, "selected.pcapng"));
    assert.equal(await evaluate(`${comments}.disabled`), false);
    await click(...center(await box("document.querySelector('.dlg-export button.primary')")));
    await until("the export toast", async () => /Exported 1 packet \([^)]*, 1 mark as comments\)/.test(await toasts())).catch(async (err) => {
      throw new Error(`${err.message}; toasts: ${await toasts()}; dialog: ${await evaluate("document.querySelector('.dlg-export')?.textContent")}`);
    });
    assert.ok(existsSync(join(home, "selected.pcapng")));
  });
} finally {
  ws?.close();
  chrome.kill();
  await client.close();
  await sleep(300);
  rmSync(profile, { recursive: true, force: true });
  rmSync(home, { recursive: true, force: true });
}
console.log(failures ? `${failures} check(s) failed` : "all checks passed");
process.exit(failures ? 1 : 0);
