// A panel in headless Chrome: wb.select is refused without a click in the panel and works after
// one, wb.setFilter needs "control", wb.storage round-trips, panel action "snapshot" returns the
// panel's canvas, and offers show as status-bar chips. Then the packet menu: asking the agent about
// a packet, the export dialog writing marks as packet comments, time references set there and in
// the Edit menu, and Decode As set there (its packet line on reassembled TCP too) and removed in the
// status bar. Last, File › Export Objects, also on a live capture from test/fake-dumpcap.mjs.
// Usage: node test/browser-control.mjs   (after npm run build; skipped without Chrome)
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { spawn } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import { WebSocket } from "ws";
import { writeOddPortsCapture } from "./oddports.mjs";

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

const bin = join(home, "bin");
mkdirSync(bin);
writeFileSync(join(bin, "dumpcap"), `#!/bin/sh\nexec "${process.execPath}" "${join(root, "test/fake-dumpcap.mjs")}" "$@"\n`);
chmodSync(join(bin, "dumpcap"), 0o755);

const client = new Client({ name: "browser-control", version: "0" });
await client.connect(
  new StdioClientTransport({
    command: process.execPath,
    args: [join(root, "dist/server/main.js"), "--mcp", "--port", "0"],
    env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, HOME: home, XDG_CONFIG_HOME: join(home, ".config"), XDG_DATA_HOME: join(home, ".local/share"), WIREBUDDY_EXTENSIONS: "" },
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

  await check("browser: Set/Unset Time Reference in a packet's menu and in the Edit menu, Ctrl+Alt+T unsets all: the rows show *REF* and count from them", async () => {
    const time = (frame) => evaluate(`${row(frame)}?.querySelectorAll('.pl-cell')[1]?.textContent`);
    const before = await time(9);
    await fromMenu(6, "Set/Unset Time Reference");
    await until("frame 6's *REF*", async () => (await time(6)) === "*REF*");
    assert.deepEqual((await state()).timeRefs, [6]);
    await until("frame 9 counting from it", async () => (await time(9)) !== before);
    // The Edit menu's acts on the selected packet; Ctrl+Alt+T is Unset All Time References
    await click(...center(await box(row(9))));
    await until("frame 9 selected", async () => (await state()).selected === 9);
    await click(...center(await box("[...document.querySelectorAll('.mb-title')].find((b) => b.textContent === 'Edit')")));
    await until("the Edit menu", async () => !!(await box(menuItem("Set/Unset Time Reference"))));
    await click(...center(await box(menuItem("Set/Unset Time Reference"))));
    await until("frame 9's *REF*", async () => (await time(9)) === "*REF*");
    assert.deepEqual((await state()).timeRefs, [6, 9]);
    // Its details, shown already, are read again
    const details = () => evaluate("[...document.querySelectorAll('.dt-label')].map((l) => l.textContent).join('\\n')");
    await cdp("Input.dispatchKeyEvent", { type: "keyDown", key: "ArrowRight", code: "ArrowRight", windowsVirtualKeyCode: 39, modifiers: 2 });
    await until("frame 9's details as a reference", async () => /Time since reference or first frame: 0\.000000000 seconds/.test(await details()));
    await cdp("Input.dispatchKeyEvent", { type: "keyDown", key: "t", code: "KeyT", windowsVirtualKeyCode: 84, modifiers: 3 });
    await until("no time references", async () => (await state()).timeRefs.length === 0);
    await until("frame 9's time from the first packet", async () => (await time(9)) === before);
    await until("frame 9's details from the first packet", async () => /Time since reference or first frame: (?!0\.000000000 )/.test(await details()));
  });

  await check("browser: the packet menu says how many packets get time references; the menus don't offer the browser's Ctrl+T", async () => {
    await click(...center(await box(row(2))));
    await until("frame 2 selected", async () => (await state()).selected === 2);
    const [x, y] = center(await box(row(4)));
    for (const type of ["mousePressed", "mouseReleased"]) await cdp("Input.dispatchMouseEvent", { type, x, y, button: "left", clickCount: 1, modifiers: 8 });
    await until("3 rows selected", async () => (await state()).selectedCount === 3);
    await fromMenu(3, "Set/Unset Time References on 3 Packets");
    await until("their references", async () => (await state()).timeRefs.length === 3);
    assert.deepEqual((await state()).timeRefs, [2, 3, 4]);
    await click(...center(await box("[...document.querySelectorAll('.mb-title')].find((b) => b.textContent === 'Edit')")));
    await until("the Edit menu", async () => !!(await box(menuItem("Set/Unset Time Reference"))));
    const entry = await evaluate(`${menuItem("Set/Unset Time Reference")}.textContent`);
    await cdp("Input.dispatchKeyEvent", { type: "keyDown", key: "Escape", code: "Escape", windowsVirtualKeyCode: 27 });
    assert.doesNotMatch(entry, /Ctrl\+T|⌘T/);
    await fetch(new URL("/api/timerefs/clear", ui.origin), { method: "POST", headers: { "X-WireBuddy-Token": token, "content-type": "application/json" }, body: "{}" });
    await until("no time references", async () => (await state()).timeRefs.length === 0);
  });

  await check("browser: rows asked for before the time references changed are asked for again", async () => {
    const time = (frame) => evaluate(`${row(frame)}?.querySelectorAll('.pl-cell')[1]?.textContent`);
    const timeRefs = (frames) => fetch(new URL("/api/timerefs", ui.origin), { method: "POST", headers: { "X-WireBuddy-Token": token, "content-type": "application/json" }, body: JSON.stringify({ frames, on: true }) });
    // The next page's answer waits until released
    await evaluate(`(() => {
      const f = window.fetch;
      window.__held = null;
      window.fetch = async (...a) => {
        const r = await f(...a);
        if (!String(a[0]).includes("api/rows") || window.__held) return r;
        await new Promise((resolve) => (window.__held = resolve));
        return r;
      };
    })()`);
    try {
      await timeRefs([6]);
      await until("a page in flight", () => evaluate("!!window.__held"));
      await timeRefs([10]);
      await until("the page asked for again", async () => (await time(10)) === "*REF*");
      await evaluate("window.__held()");
      await sleep(500);
      assert.equal(await time(10), "*REF*");
      assert.equal(await time(6), "*REF*");
    } finally {
      await evaluate("window.__held?.()");
      await fetch(new URL("/api/timerefs/clear", ui.origin), { method: "POST", headers: { "X-WireBuddy-Token": token, "content-type": "application/json" }, body: "{}" });
    }
  });

  const key = (k, code, keyCode, modifiers = 0) => cdp("Input.dispatchKeyEvent", { type: "keyDown", key: k, code, windowsVirtualKeyCode: keyCode, modifiers });
  // Ctrl is 2, Alt 1
  const saveComment = () => key("Enter", "Enter", 13, 2);
  const commentBox = (title) => evaluate(`document.querySelector('.dlg-comment .dlg-title-text')?.textContent === ${JSON.stringify(title)} && document.activeElement?.closest('.dlg-comment') !== null`);
  const viewState = async () => (await call("get_view_state")).text;
  const closeComment = async () => {
    if (await evaluate("!!document.querySelector('.dlg-comment, .dlg-export')")) await key("Escape", "Escape", 27);
  };
  /** Clicks `label` in the open menus; on failure names what they hold. */
  const pick = async (label) => {
    await until(`"${label}"`, async () => !!(await box(menuItem(label)))).catch(async (err) => {
      throw new Error(`${err.message}; the menus: ${await evaluate("[...document.querySelectorAll('.menu-item')].map((m) => m.textContent).join(' | ')")}`);
    });
    await click(...center(await box(menuItem(label))));
  };
  const fromMenuBar = async (title, ...labels) => {
    await click(...center(await box(`[...document.querySelectorAll('.mb-title')].find((b) => b.textContent === ${JSON.stringify(title)})`)));
    for (const label of labels) await pick(label);
  };
  const detailsRow = (text) => `[...document.querySelectorAll('.dt-row')].find((r) => r.querySelector('.dt-label')?.textContent === ${JSON.stringify(text)})`;

  await check("browser: page errors reach the agent, Chrome's ResizeObserver loop note doesn't", async () => {
    for (const message of ["ResizeObserver loop completed with undelivered notifications.", "a test bug"]) await evaluate(`window.dispatchEvent(new ErrorEvent("error", { message: ${JSON.stringify(message)} }))`);
    let seen = "";
    await until("the page error", async () => /Page error: a test bug/.test((seen += await viewState())));
    await sleep(300);
    seen += await viewState();
    assert.doesNotMatch(seen, /ResizeObserver/);
  });

  await check("browser: packet comments from the keyboard, the Edit menu, the packet list and the details; the row shows them", async () => {
    await click(...center(await box(row(6))));
    await until("frame 6 selected", async () => (await state()).selected === 6);
    await key("c", "KeyC", 67, 3);
    await until("Add Packet Comment", () => commentBox("Add Packet Comment"));
    await cdp("Input.insertText", { text: "first line\nsecond line" });
    await saveComment();
    await until("the commented row", () => evaluate(`${row(6)}?.classList.contains('commented') === true`));
    assert.equal(await evaluate(`getComputedStyle(${row(6)}.querySelector('.pl-cm')).display`), "block");
    assert.equal(await evaluate(`${row(6)}.title`), "Comment: first line\nsecond line");
    assert.equal(await evaluate("document.title"), "*http.pcapng — WireBuddy");
    // The details show it as Wireshark does; opened once, comments show open in the next packets too
    await until("the details' comment", () => evaluate(`!!(${detailsRow("Packet comments")})`));
    await click(...center(await box(`${detailsRow("Packet comments")}.querySelector('.dt-tog')`)));
    await until("the comment's first line", () => evaluate(`!!(${detailsRow("first line [...]")})`));
    // Edit "…" in the Edit menu, with the comment as Wireshark shows it there
    await fromMenuBar("Edit", "Packet Comments", 'Edit "first line second line"');
    await until("Edit Packet Comment", () => commentBox("Edit Packet Comment"));
    assert.equal(await evaluate("document.activeElement.value"), "first line\nsecond line");
    await evaluate("document.activeElement.select()");
    await cdp("Input.insertText", { text: "edited" });
    await saveComment();
    await until("the edit", async () => /^ {2}6: "edited"$/m.test(await viewState()));
    await until("the details read again", () => evaluate(`!!(${detailsRow("edited")})`));
    // The export dialog says where they go
    await fromMenu(6, "Export Selected Packet");
    await until("the export dialog", () => evaluate("!!document.querySelector('.dlg-export')"));
    const note = "[...document.querySelectorAll('.dlg-export .goto-hint')].at(-1)";
    assert.match(await evaluate(`${note}.textContent`), /^Packet comments go along as edited \(1 packet not exported yet\)/);
    await evaluate(`(() => { const i = document.querySelector('.ex-path'); i.value = ${JSON.stringify(join(home, "x.pcap"))}; i.dispatchEvent(new Event('input')); })()`);
    assert.match(await evaluate(`${note}.textContent`), /^pcap holds no packet comments/);
    await closeComment();
    // Delete "…" in the packet list's menu
    await fromMenu(6, "Packet Comments");
    await pick('Delete "edited"');
    await until("the row without comments", () => evaluate(`${row(6)}?.classList.contains('commented') === false`));
    assert.match(await viewState(), /^ {2}6: \(comments deleted\)$/m);
    // The details' menu of a comment edits and deletes it
    await fromMenu(6, "Packet Comments");
    await pick("Add New Comment");
    await until("Add Packet Comment", () => commentBox("Add Packet Comment"));
    await cdp("Input.insertText", { text: "in the details" });
    await saveComment();
    await until("the comment", () => evaluate(`!!(${detailsRow("in the details")})`));
    await rightClick(center(await box(detailsRow("in the details"))));
    await pick("Edit Comment…");
    await until("Edit Packet Comment", () => commentBox("Edit Packet Comment"));
    await evaluate("document.activeElement.select()");
    await cdp("Input.insertText", { text: "edited in the details" });
    await saveComment();
    await until("the edited comment", () => evaluate(`!!(${detailsRow("edited in the details")})`));
    await rightClick(center(await box(detailsRow("edited in the details"))));
    await pick("Delete Comment");
    await until("no comment node", () => evaluate(`!(${detailsRow("Packet comments")})`));
    assert.match(await viewState(), /INFO The user deleted comment 1 of frame 6/);
  }).finally(closeComment);

  await check("browser: the agent's comments show with a notice; editing one the agent changed meanwhile is refused; Delete All asks first; closing with unsaved comments asks too", async () => {
    const r = await call("packet_comments", { action: "add", frames: [2, 3], comment: "from the agent" });
    assert.match(r.text, /^Added the comment to 2 frame\(s\)/);
    assert.match((await state()).agentNotice.text, /^Added a packet comment to 2 frames: from the agent$/);
    await until("the agent's comments", () => evaluate(`${row(2)}?.classList.contains('commented') && ${row(3)}?.classList.contains('commented')`));
    // A comment the agent changes while the user edits it stays the agent's
    await click(...center(await box(row(2))));
    await until("frame 2's details", () => evaluate(`!!(${detailsRow("from the agent")})`));
    await fromMenuBar("Edit", "Packet Comments", 'Edit "from the agent"');
    await until("Edit Packet Comment", () => commentBox("Edit Packet Comment"));
    await call("packet_comments", { action: "replace", frames: [2], comment: "replaced by the agent" });
    await evaluate("document.activeElement.select()");
    await cdp("Input.insertText", { text: "the user's" });
    await saveComment();
    await until("the refusal", () => evaluate("document.querySelector('.dlg-comment .of-err')?.textContent === 'The comment changed meanwhile; close this and choose it again'"));
    await closeComment();
    assert.match(await viewState(), /^ {2}2: "replaced by the agent"$/m);
    // Within 300 ms of picking from the Edit menu, a press on it is taken for closing it
    await sleep(300);
    await fromMenuBar("Edit", "Delete All Packet Comments…");
    await until("the question", () => evaluate("/Are you sure you want to remove all packet comments\\?/.test(document.querySelector('.confirm-text')?.textContent ?? '')"));
    await click(...center(await box("document.querySelector('.dlg button.primary')")));
    await until("no comments", () => evaluate(`!document.querySelector('.pl-row.commented')`));
    assert.match(await viewState(), /^ {2}1-29: all comments deleted \(Delete All Packet Comments\)/m);
    // Unexported edits: File › Close asks, and Cancel keeps the capture
    assert.ok((await state()).commentEdits > 0);
    await fromMenuBar("File", "Close");
    await until("the warning", () => evaluate("/weren't exported: closing the capture discards them/.test(document.querySelector('.confirm-text')?.textContent ?? '')"));
    await key("Escape", "Escape", 27);
    await sleep(300);
    assert.ok((await state()).file, "the capture stays open");
  }).finally(closeComment);

  await check("browser: Decode As in a packet's menu decodes its port; the status bar lists the entries and removes them", async () => {
    const oddPorts = join(home, "odd-ports.pcap");
    writeOddPortsCapture(oddPorts);
    const protocol = (frame) => evaluate(`${row(frame)}?.querySelectorAll('.pl-cell')[4]?.textContent`);
    const seg = "document.querySelector('.sb-da')";
    try {
      await call("open_capture", { path: oddPorts });
      await until("frame 5 as UDP", async () => (await protocol(5)) === "UDP");
      await fromMenu(5, "Decode As");
      await pick("UDP Port 50000");
      await until("the dialog", () => evaluate("document.activeElement?.classList.contains('da-in') === true"));
      assert.equal(await evaluate("document.querySelector('.da-packet').textContent"), "This packet: UDP 30000 → 50000, decoded as Data now.");
      await cdp("Input.insertText", { text: "rtp" });
      await click(...center(await box("document.querySelector('.dlg-decodeas button.primary')")));
      await until("frame 5 as RTP", async () => (await protocol(5)) === "RTP");
      assert.match(await toasts(), /UDP port 50000 now decodes as RTP \(5 packets\)/);
      assert.equal(await evaluate(`${seg}.hidden ? "" : ${seg}.textContent`), "Decode As: 1");
      await click(...center(await box(seg)));
      await pick("Remove udp.port 50000 → rtp");
      await until("frame 5 as UDP again", async () => (await protocol(5)) === "UDP");
      await until("the segment to go", () => evaluate(`${seg}.hidden`));
    } finally {
      if (await evaluate("!!document.querySelector('.dlg-decodeas')")) await key("Escape", "Escape", 27);
      await call("decode_as", { action: "clear" });
      await call("open_capture", { path: join(root, "test/fixtures/http.pcapng") });
    }
  });

  await check("browser: Decode As names the protocol of a reassembled TCP message, and says a packet has no payload only when it has none", async () => {
    const scroller = "document.querySelector('.pl-scroll')";
    const packetLine = async (frame) => {
      await fromMenu(frame, "Decode As");
      await pick("TCP Port 18080");
      await until("the dialog", () => evaluate("!!document.querySelector('.da-packet')"));
      const text = await evaluate("document.querySelector('.da-packet').textContent");
      await key("Escape", "Escape", 27);
      await until("the dialog to close", () => evaluate("!document.querySelector('.dlg-decodeas')"));
      return text;
    };
    try {
      await until("http.pcapng's rows", async () => (await evaluate(`${row(5)}?.querySelectorAll('.pl-cell')[4]?.textContent`)) === "TCP");
      // Frame 5 is an ACK, 6 the first of the 4 segments of an HTTP response that 12 ends
      assert.equal(await packetLine(5), "This packet: TCP 18080 → 43748, has no payload of its own.");
      assert.equal(await packetLine(6), "This packet: TCP 18080 → 43748.");
      // Below the list's first screen
      await evaluate(`${scroller}.scrollTop = document.querySelector('.pl-row').offsetHeight * 9`);
      await until("the list to show frame 12 at the top", () => evaluate(`!${row(1)} && !!${row(12)}`));
      assert.equal(await packetLine(12), "This packet: TCP 18080 → 43748, decoded as Hypertext Transfer Protocol now.");
    } finally {
      if (await evaluate("!!document.querySelector('.dlg-decodeas')")) await key("Escape", "Escape", 27);
      await evaluate(`${scroller}.scrollTop = 0`);
    }
  });

  const rows = () => evaluate("document.querySelectorAll('.dlg-objects tbody tr').length");
  const type = (field, text) => evaluate(`(() => { const i = document.querySelector('.dlg-objects ${field}'); i.value = ${JSON.stringify(text)}; i.dispatchEvent(new Event('input')); })()`);
  const button = (label) => box(`[...document.querySelectorAll('.dlg-objects .dlg-footer button')].find((b) => b.textContent === ${JSON.stringify(label)})`);
  const listMsg = () => evaluate("document.querySelector('.dlg-objects .stat-msg')?.textContent ?? null");
  const footer = () => evaluate("document.querySelector('.dlg-objects .dlg-footer-left').textContent");
  const saveErr = () => evaluate("(() => { const e = document.querySelector('.dlg-objects .of-err'); return e && !e.hidden ? e.textContent : ''; })()");
  // Escape closes a modeless dialog only while it has the focus; toasts may cover the button
  const closeObjects = () => evaluate("[...document.querySelectorAll('.dlg-objects .dlg-footer button')].find((b) => b.textContent === 'Close')?.click()");

  await check("browser: File › Export Objects › HTTP… goes to a packet and saves the chosen object", async () => {
    // The default is the fixture's folder, in the source tree
    const out = mkdtempSync("/tmp/wirebuddy-objects-");
    try {
      await fromMenuBar("File", "Export Objects", "HTTP…");
      await until("the two objects", async () => (await rows()) === 2);
      await type(".ex-search", "big");
      await until("the filtered object", async () => (await rows()) === 1);
      await click(...center(await box("document.querySelector('.dlg-objects tbody tr')")));
      await until("frame 12 selected", async () => (await state()).selected === 12);
      const notice = (await state()).agentNotice?.id;
      await type(".ex-path", out);
      await click(...center(await button("Save")));
      await until("the saved note", async () => /^Saved 1 HTTP object to http-objects$/.test(await footer())).catch(async (err) => {
        throw new Error(`${err.message}; dialog: ${await evaluate("document.querySelector('.dlg-objects')?.textContent")}`);
      });
      assert.doesNotMatch(await toasts(), /Saved/, "a toast would cover the dialog's buttons");
      assert.equal(await evaluate("document.querySelector('.dlg-objects .dlg-footer-left').title"), join(realpathSync(out), "http-objects"));
      assert.deepEqual(readdirSync(join(out, "http-objects")), ["f12-big.txt"]);
      assert.match(await viewState(), /The user saved 1 HTTP object/);
      assert.equal((await state()).agentNotice?.id, notice);
      await type(".ex-search", "");
      await until("both objects", async () => (await rows()) === 2);
      await click(...center(await button("Save All")));
      await until("the second folder", () => existsSync(join(out, "http-objects-2")) && readdirSync(join(out, "http-objects-2")).length === 2);
      await until("its note", async () => /^Saved 2 HTTP objects to http-objects-2$/.test(await footer()));
      await type(".ex-search", "big");
      await until("the count again", async () => /^1 of 2 HTTP objects/.test(await footer()));
    } finally {
      await closeObjects();
      rmSync(out, { recursive: true, force: true });
    }
  });

  await check("browser: Export Objects fits long names, names at most 10,000 objects in a save, and lists nothing itself when a save is stale", async () => {
    // 10,001 objects with long names listed and every save refused as stale, each request noted
    await evaluate(`(() => {
      const f = window.fetch;
      const long = "-".repeat(200);
      const objects = Array.from({ length: 10001 }, (_, i) => ({ frame: 1, host: "h" + long, type: "text/plain" + long, filename: "f" + i + long, size: 1, sha1: "" }));
      const answer = (status, body) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
      window.__fetch = f;
      window.__asked = [];
      window.fetch = async (...a) => {
        const url = String(a[0]);
        if (!url.includes("api/objects")) return f(...a);
        window.__asked.push(url.includes("save") ? "save" : "list");
        return url.includes("save") ? answer(409, { error: "the capture changed; list the objects again" }) : answer(200, { objects, dir: "/tmp" });
      };
    })()`);
    try {
      await fromMenuBar("File", "Export Objects", "HTTP…");
      await until("the first 5,000 rows", async () => (await rows()) === 5000);
      assert.ok(await evaluate("(() => { const w = document.querySelector('.dlg-objects .stat-wrap'); return w.scrollWidth <= w.clientWidth; })()"), "the table is wider than the dialog");
      await type(".ex-search", "h");
      await until("all of them matching", async () => /^10,001 of 10,001 /.test(await evaluate("document.querySelector('.dlg-objects .dlg-footer-left').textContent")));
      // The toasts of the checks before cover the dialog's buttons
      await evaluate("document.querySelectorAll('.toast').forEach((t) => t.remove())");
      await click(...center(await button("Save All")));
      await until("the reason", saveErr);
      assert.match(await saveErr(), /clear the filter to save all$/);
      await click(...center(await box("document.querySelector('.dlg-objects tbody tr')")));
      await click(...center(await button("Save")));
      await until("the refusal", async () => /nothing was saved/.test(await saveErr()));
      // The state that changed the capture lists again
      await sleep(500);
      assert.deepEqual(await evaluate("window.__asked"), ["list", "save"]);
    } finally {
      await evaluate("window.fetch = window.__fetch");
      await closeObjects();
    }
  });

  // Last: the capture replaces the fixture
  await check("browser: Export Objects lists a live capture only on Refresh", async () => {
    const waiting = "Capturing: Refresh lists the HTTP objects";
    try {
      await fromMenuBar("File", "Export Objects", "HTTP…");
      await until("the two objects", async () => (await rows()) === 2);
      await call("start_capture", { interface: "lo", filter: "burst 2000 rate 500" });
      await until("the capture's file unlisted", async () => (await listMsg()) === waiting);
      await until("more packets", async () => (await state()).totalFrames > 3000);
      assert.equal(await listMsg(), waiting);
      await click(...center(await box("document.querySelector('.dlg-objects .ex-bar button')")));
      await until("the captured objects", async () => (await rows()) > 0);
    } finally {
      await call("stop_capture");
      await closeObjects();
    }
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
