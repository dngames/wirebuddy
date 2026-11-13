// A panel in headless Chrome: wb.select is refused without a click in the panel and works after
// one, wb.setFilter needs "control", wb.storage round-trips, panel action "snapshot" returns the
// panel's canvas, and offers show as status-bar chips. Then the packet menu: asking the agent about
// a packet, the export dialog writing marks as packet comments, time references set there and in
// the Edit menu, and Decode As set there (its packet line on reassembled TCP too) and removed in the
// status bar. Last, File › Export Objects, also on a live capture from test/fake-dumpcap.mjs, and
// Now in one: N tapped and the toolbar button held. Also errors in the page: shown there and heard by the agent once.
// Usage: node test/browser-control.mjs   (after npm run build; skipped without Chrome)
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { spawn } from "node:child_process";
import { chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import { chromeOrSkip } from "./chrome.mjs";
import { chromePort, pageSocket, rawCdp, sleep, startChrome, suite } from "./harness.mjs";
import { writeOddPortsCapture } from "./oddports.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const chromeBin = chromeOrSkip();
if (!chromeBin) process.exit(0);
// CDP key modifiers: Alt 1, Ctrl 2, Meta 4, Shift 8. The page's shortcut key is Command on a Mac, Ctrl elsewhere
const ALT = 1;
const MOD = process.platform === "darwin" ? 4 : 2;

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
const chrome = startChrome(chromeBin, profile, ["--window-size=1280,820", "--no-first-run", "--no-default-browser-check", "--disable-gpu"]);

const { check, finish } = suite();
const until = async (what, fn, ms = 10_000) => {
  for (const end = Date.now() + ms; Date.now() < end; await sleep(100)) if (await fn()) return;
  throw new Error(`timed out waiting for ${what}`);
};

let ws;
try {
  const port = await chromePort(profile);
  if (!port) throw new Error("timed out waiting for Chrome");
  ws = await pageSocket(port);
  const answer = rawCdp(ws);
  const cdp = async (method, params = {}) => {
    const d = await answer(method, params);
    if (d.error) throw new Error(`${method}: ${d.error.message}`);
    return d.result;
  };
  const evaluate = async (expression) => (await cdp("Runtime.evaluate", { expression, returnByValue: true })).result.value;
  const click = async (x, y) => {
    await cdp("Input.dispatchMouseEvent", { type: "mouseMoved", x, y });
    await cdp("Input.dispatchMouseEvent", { type: "mousePressed", x, y, button: "left", clickCount: 1 });
    await cdp("Input.dispatchMouseEvent", { type: "mouseReleased", x, y, button: "left", clickCount: 1 });
  };

  assert.match((await call("open_capture", { path: join(root, "test/fixtures/http.pcapng") })).text, /29 frames/);
  await cdp("Page.navigate", { url: ui.href });
  // The page's own word for it: tool results remind of a missing viewer only now and then
  await until("the viewer", () => evaluate("!!document.querySelector('.sb-conn.open')"), 30_000);
  const opened = await call("panel", { action: "open", name: "clicker", wait_ms: 10_000 });
  const statusText = async () => (await state()).panels.find((p) => p.name === "clicker")?.statusText;

  await check("browser: a panel's select without a click is refused, with the agent told", async () => {
    assert.match(opened.text, /Panel "clicker" opened .*ready/, opened.text);
    assert.equal(await statusText(), "early: denied");
    assert.notEqual((await state()).selected, 2);
    // The open's result carries what happened meanwhile
    assert.match(opened.text, /WARNING Panel "clicker" called wb\.select, which was refused: the user hadn't just clicked/);
  });

  const frameRect = () => evaluate("JSON.stringify(document.querySelector('.panel-frame').getBoundingClientRect())").then(JSON.parse);
  const panelAndSelection = async () => `the panel's status: ${JSON.stringify(await statusText())}, the page's selection: ${(await state()).selected}`;
  await evaluate("addEventListener('pointerdown', (e) => { if (e.isTrusted) window.pageClickAt = performance.now(); }, true)");
  /**
   * Clicks (`dx`, `dy`) into the panel's frame until the panel says it got the click: its status then starts with
   * `answer`, which its click handlers set whether the page allowed the action or not. A click into the frame a
   * moment after it opened can go to this page instead, while Chrome has not yet routed hits to the out-of-process
   * frame; the panel hears nothing then. Only a click the panel did not get is repeated. One this page got counts
   * as its own input for 5 s (a panel can take the focus right after the user clicked elsewhere), so the repeat
   * waits that out. A click the panel got and was refused for stays a failure.
   */
  const clickPanel = async (dx, dy, answer) => {
    for (let attempt = 0; attempt < 4; attempt++) {
      await evaluate("window.pageClickAt = 0");
      const r = await frameRect();
      await click(r.left + dx, r.top + dy);
      try {
        await until(`the panel to get the click (${attempt + 1})`, async () => (await statusText())?.startsWith(`${answer}:`), 1500);
        return;
      } catch {}
      const age = await evaluate("window.pageClickAt ? performance.now() - window.pageClickAt : -1");
      if (age >= 0) await sleep(Math.max(0, 5200 - age));
    }
    throw new Error(`timed out waiting for the panel to get a click; ${await panelAndSelection()}`);
  };
  await check("browser: after a click in the panel, select works", async () => {
    await clickPanel(100, 40, "click");
    await until("the selection", async () => (await state()).selected === 3).catch(async (err) => {
      throw new Error(`${err.message}; ${await panelAndSelection()}`);
    });
    await until("the panel's status", async () => (await statusText()) === "click: ok").catch(async (err) => {
      throw new Error(`${err.message}; ${await panelAndSelection()}`);
    });
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
    await clickPanel(100, 140, "filter");
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
  /** What the packet list holds: its rows' numbers, where it is scrolled to, what covers it, and the view's state. */
  const listed = async () => {
    const page = await evaluate(
      `(() => { const s = document.querySelector('.pl-scroll'), o = document.querySelector('.pl-overlay'); return JSON.stringify({ rows: [...document.querySelectorAll('.pl-row')].filter((r) => !r.hidden).map((r) => r.querySelector('.pl-cell')?.textContent).join(' '), scrollTop: s.scrollTop, height: s.clientHeight, overlay: o && !o.hidden ? o.textContent : null, dialogs: [...document.querySelectorAll('.dlg-title-text')].map((d) => d.textContent), menu: document.querySelectorAll('.menu-item').length }); })()`,
    );
    const { selected, filter, generation, totalFrames, displayedFrames, loading } = await state();
    return `the list: ${page}; the view: ${JSON.stringify({ selected, filter, generation, totalFrames, displayedFrames, loading })}`;
  };
  const fromMenu = async (frame, label) => {
    await until(`frame ${frame}'s row`, async () => !!(await box(row(frame)))).catch(async (err) => {
      throw new Error(`${err.message}; ${await listed()}`);
    });
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

  await check("browser: a panel restored after the window narrowed comes back into view", async () => {
    const pn = "document.querySelector('.dlg-panel')";
    const button = (label) => `[...${pn}.querySelectorAll('.dlg-footer button')].find((b) => b.textContent === '${label}')`;
    try {
      await click(...center(await box(button("Maximize"))));
      await until("the panel maximized", () => evaluate(`${pn}.classList.contains('pn-max')`));
      await cdp("Emulation.setDeviceMetricsOverride", { width: 600, height: 500, deviceScaleFactor: 1, mobile: false });
      await until("the narrower window", async () => (await evaluate("window.innerWidth")) === 600);
      await click(...center(await box(button("Restore"))));
      await until("the panel restored inside the window", async () => {
        const r = await box(pn);
        return !(await evaluate(`${pn}.classList.contains('pn-max')`)) && r.left >= 0 && r.right <= 600 && r.top >= 0 && r.bottom <= 500;
      });
    } finally {
      await cdp("Emulation.clearDeviceMetricsOverride");
      if (await evaluate(`${pn}?.classList.contains('pn-max')`)) await click(...center(await box(button("Restore"))));
    }
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
    // The mark is kept with the capture otherwise, and back each time a later check opens it
  }).finally(() => call("clear_marks", {}));

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
    await cdp("Input.dispatchKeyEvent", { type: "keyDown", key: "ArrowRight", code: "ArrowRight", windowsVirtualKeyCode: 39, modifiers: MOD });
    await until("frame 9's details as a reference", async () => /Time since reference or first frame: 0\.000000000 seconds/.test(await details()));
    await cdp("Input.dispatchKeyEvent", { type: "keyDown", key: "t", code: "KeyT", windowsVirtualKeyCode: 84, modifiers: MOD | ALT });
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
  const saveComment = () => key("Enter", "Enter", 13, MOD);
  const commentBox = (title) => evaluate(`document.querySelector('.dlg-comment .dlg-title-text')?.textContent === ${JSON.stringify(title)} && document.activeElement?.closest('.dlg-comment') !== null`);
  const viewState = async () => (await call("get_view_state")).text;
  const closeComment = async () => {
    if (await evaluate("!!document.querySelector('.dlg-comment, .dlg-export')")) await key("Escape", "Escape", 27);
  };
  /** What is at a point of the page: the element's tag, classes and text. */
  const elementAt = (x, y) =>
    evaluate(`(() => { const e = document.elementFromPoint(${x}, ${y}); return e ? e.tagName + "." + e.className + " " + JSON.stringify(e.textContent.slice(0, 80)) : "nothing"; })()`);
  /** Clicks `label` in the open menus; on failure names what they hold. A `seen` object gets the point clicked, what was there and the toasts then. */
  const pick = async (label, seen) => {
    await until(`"${label}"`, async () => !!(await box(menuItem(label)))).catch(async (err) => {
      throw new Error(`${err.message}; the menus: ${await evaluate("[...document.querySelectorAll('.menu-item')].map((m) => m.textContent).join(' | ')")}`);
    });
    const at = center(await box(menuItem(label)));
    if (seen) Object.assign(seen, { point: at.map(Math.round), hit: await elementAt(...at), toasts: await toasts() });
    await click(...at);
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

  await check("browser: a mark is the first line of the selected packet's details and changes with it; Go › Marked Packets shows a long note in full", async () => {
    const first = () => evaluate("document.querySelector('.dt-label')?.textContent");
    const who = (await state()).agent.name;
    const long = `a long note ${"that has to wrap ".repeat(9)}to the end`;
    await call("goto_frame", { frame: 4 });
    await until("frame 4's details", () => evaluate("document.querySelector('.dt-label')?.textContent.startsWith('Frame 4:') === true"));
    await call("mark_frames", { frames: [4], note: "short" });
    await until("the mark as the first line", async () => (await first()) === `Marked by ${who}: short`);
    await call("mark_frames", { frames: [4], note: long });
    await until("the new note", async () => (await first()) === `Marked by ${who}: ${long}`);
    await fromMenuBar("Go", "Marked Packets");
    await until("the note in the menu", async () => !!(await box(`[...document.querySelectorAll('.menu-detail')].find((d) => d.textContent === ${JSON.stringify(long)})`)));
    // Wrapped over lines, none of it cut off
    const detail = await evaluate(`(() => { const d = [...document.querySelectorAll('.menu-detail')].find((e) => e.textContent === ${JSON.stringify(long)}); return { lines: Math.round(d.getBoundingClientRect().height / parseFloat(getComputedStyle(d).lineHeight || '15')), cut: d.scrollWidth > d.clientWidth + 1 }; })()`);
    assert.ok(detail.lines >= 2 && !detail.cut, JSON.stringify(detail));
    await key("Escape", "Escape", 27);
    await key("Escape", "Escape", 27);
    await call("clear_marks", { frames: [4] });
    await until("no mark line", async () => /^Frame 4:/.test(await first()));
  }).finally(() => call("clear_marks", {}));

  await check("browser: with the agent attached, an error the user runs into shows in the page and the agent hears it once, whether the server refused the request or only the page knew", async () => {
    const gone = join(home, "gone.pcapng");
    copyFileSync(join(root, "test/fixtures/http.pcapng"), gone);
    const events = async (after) => (await (await fetch(new URL(`/api/events?after=${after}`, ui.origin), { headers: { "X-WireBuddy-Token": token } })).json());
    const { last } = await events(Number.MAX_SAFE_INTEGER);
    try {
      // A dialog left open would hold the menus back
      await closeComment();
      await until("no dialog", () => evaluate("!document.querySelector('.dlg-export, .dlg-comment')"));
      // Only the page knows: the request for View › Reload doesn't reach the server
      await evaluate("(() => { window.__realFetch = window.fetch; window.fetch = (u, ...a) => (String(u).includes('api/reload') ? Promise.reject(new TypeError('offline')) : window.__realFetch(u, ...a)); })()");
      await fromMenuBar("View", "Reload");
      await until("the page's toast", async () => /Reloading failed: Cannot reach/.test(await toasts()));
      await evaluate("window.fetch = window.__realFetch");
      // The server refuses it: File › Open Recent of a file that has stopped being a capture
      assert.match((await call("open_capture", { path: gone })).text, /29 frames/);
      assert.match((await call("open_capture", { path: join(root, "test/fixtures/http.pcapng") })).text, /29 frames/);
      writeFileSync(gone, "not a capture\n");
      // The page lists the recent files when it starts
      await cdp("Page.navigate", { url: ui.href });
      await until("the viewer", () => evaluate("!!document.querySelector('.sb-conn.open')"), 30_000);
      await fromMenuBar("File", "Open Recent", "gone.pcapng");
      await until("the page's toast", async () => /Can't open gone\.pcapng/.test(await toasts()));
      await sleep(500);
      const heard = (await events(last)).events;
      const count = (re) => heard.filter((e) => e.level === "ERROR" && re.test(e.text)).reduce((n, e) => n + (e.repeated ?? 1), 0);
      assert.equal(count(/^Reloading failed: Cannot reach/), 1, JSON.stringify(heard));
      assert.equal(count(/^Opening a file failed: .*gone\.pcapng/), 1, JSON.stringify(heard));
    } finally {
      rmSync(gone, { force: true });
      if (await evaluate("!!document.querySelector('.menu-item')")) await key("Escape", "Escape", 27);
      await evaluate("if (window.__realFetch) window.fetch = window.__realFetch");
      await evaluate("document.querySelectorAll('.toast').forEach((t) => t.remove())");
    }
  });

  await check("browser: packet comments from the keyboard, the Edit menu, the packet list and the details; the row shows them", async () => {
    await click(...center(await box(row(6))));
    await until("frame 6 selected", async () => (await state()).selected === 6);
    await key("c", "KeyC", 67, MOD | ALT);
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

  await check("browser: the agent's comments show with a notice; editing one the agent changed meanwhile is refused; Delete All asks first; closing keeps comments with the capture, opening it again says so, and File › Forget asks, then drops them", async () => {
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
    // Unexported edits kept with the capture: File › Close closes without asking, and they come back with it
    await call("packet_comments", { action: "add", frames: [2], comment: "kept" });
    await until("the comment kept", async () => (await state()).kept);
    // The page has the state that says so
    await sleep(300);
    await fromMenuBar("File", "Close");
    await until("the capture to close", async () => !(await state()).file);
    assert.equal(await evaluate("!!document.querySelector('.confirm-text')"), false);
    await call("open_capture", { path: join(root, "test/fixtures/http.pcapng") });
    await until("the restored toast", async () => /Restored the edited comments of 1 packet kept for this capture/.test(await toasts()));
    await until("the kept comment", () => evaluate(`${row(2)}?.classList.contains('commented') === true`));
    // File › Forget Kept Marks and Comments… asks, then the packets read as the file has them
    await call("mark_frames", { frames: [3], note: "to forget" });
    await sleep(300);
    await fromMenuBar("File", "Forget Kept Marks and Comments…");
    await until("the question", () => evaluate("/forgets the marks, time references and packet comments edited for this capture/.test(document.querySelector('.confirm-text')?.textContent ?? '')"));
    await click(...center(await box("document.querySelector('.dlg button.primary')")));
    await until("nothing edited", async () => {
      const s = await state();
      return !s.marks.length && !s.commentsEdited;
    });
    await until("no commented row", () => evaluate("!document.querySelector('.pl-row.commented')"));
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
      const clicked = {};
      await pick("Remove udp.port 50000 → rtp", clicked);
      // What the page held when the removal did not show, and what the click met
      const found = async () => {
        const view = (await viewState()).split("\n").filter((l) => /Decode As|ERROR|WARNING/.test(l)).join(" / ");
        return [
          `frame 5's protocol cell: ${JSON.stringify(await protocol(5))}`,
          `the status segment: ${await evaluate(`${seg}.hidden ? "hidden" : JSON.stringify(${seg}.textContent)`)}`,
          `toasts now: ${JSON.stringify(await toasts())}`,
          `the view state: ${view}`,
          `menu items open: ${await evaluate("[...document.querySelectorAll('.menu-item')].map((m) => m.textContent).join(' | ') || 'none'")}`,
          `the click at ${clicked.point} met ${clicked.hit}, toasts then: ${JSON.stringify(clicked.toasts)}`,
        ].join("; ");
      };
      await until("frame 5 as UDP again", async () => (await protocol(5)) === "UDP").catch(async (err) => {
        throw new Error(`${err.message}; ${await found()}`);
      });
      await until("the segment to go", () => evaluate(`${seg}.hidden`));
    } finally {
      if (await evaluate("!!document.querySelector('.dlg-decodeas')")) await key("Escape", "Escape", 27);
      await call("decode_as", { action: "clear" });
      await call("open_capture", { path: join(root, "test/fixtures/http.pcapng") });
    }
  });

  const innerWidth = () => evaluate("window.innerWidth");
  // Counted after the dialogs' own listener, so a count means it ran
  await evaluate("window.resizes = 0; addEventListener('resize', () => window.resizes++)");
  /** Emulates a window of `width` x `height` (none: the real one) and waits for the page's resize event. */
  const resizeTo = async (width, height) => {
    const seen = await evaluate("window.resizes");
    await (width ? cdp("Emulation.setDeviceMetricsOverride", { width, height, deviceScaleFactor: 1, mobile: false }) : cdp("Emulation.clearDeviceMetricsOverride"));
    await until("the resize", async () => (await evaluate("window.resizes")) > seen);
  };

  await check("browser: a dialog the narrowed window cuts off moves back into view; one dragged aside stays aside", async () => {
    const dlg = "document.querySelector('.dlg-tls')";
    try {
      await fromMenuBar("Tools", "TLS Keys…");
      await until("the dialog", () => evaluate(`!!${dlg}`));
      const wide = await box(dlg);
      await resizeTo(Math.round(wide.right) - 100, 600);
      const r = await box(dlg);
      assert.ok(r.left >= 0 && r.right <= (await innerWidth()) && r.top >= 0 && r.bottom <= 600, JSON.stringify(r));
      const decrypt = await box(`[...${dlg}.querySelectorAll('button')].find((b) => b.textContent === 'Decrypt')`);
      assert.ok(decrypt.right <= (await innerWidth()), JSON.stringify(decrypt));
      // A wider window moves nothing
      await resizeTo();
      assert.equal((await box(dlg)).left, r.left);
      // Dragged aside, as startDrag allows: it keeps its 40px strip
      const full = await innerWidth();
      await evaluate(`${dlg}.style.left = '${full - 40}px'`);
      await resizeTo(full - 200, 600);
      assert.equal(Math.round((await box(dlg)).left), full - 240);
      await resizeTo();
      assert.equal(Math.round((await box(dlg)).left), full - 240);
    } finally {
      await cdp("Emulation.clearDeviceMetricsOverride");
      if (await evaluate(`!!${dlg}`)) await key("Escape", "Escape", 27);
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

  const post = async (path, body = {}) => {
    const r = await fetch(new URL(path, ui.origin), { method: "POST", headers: { "X-WireBuddy-Token": token, "content-type": "application/json" }, body: JSON.stringify(body) });
    return { status: r.status, json: await r.json().catch(() => null) };
  };
  const get = async (path) => (await fetch(new URL(path, ui.origin), { headers: { "X-WireBuddy-Token": token } })).json();
  const dblclick = async (x, y) => {
    await click(x, y);
    await cdp("Input.dispatchMouseEvent", { type: "mousePressed", x, y, button: "left", clickCount: 2 });
    await cdp("Input.dispatchMouseEvent", { type: "mouseReleased", x, y, button: "left", clickCount: 2 });
  };
  const inDialog = (cls) => evaluate(`!!document.activeElement?.closest('.${cls}')`);
  /** The page's requests are logged in window.__reqs; answers to those whose URL matches a key of `delays` come after that many ms. */
  const spyFetch = (delays = {}) =>
    evaluate(`(() => {
      const f = window.fetch;
      (window.__spied ??= []).push(f);
      window.__reqs = [];
      window.__replied = [];
      window.fetch = async (url, init) => {
        const u = String(url);
        window.__reqs.push({ u, body: init?.body ?? null });
        const ms = Object.entries(${JSON.stringify(delays)}).find(([k]) => new RegExp(k).test(u))?.[1];
        const r = await f(url, init);
        if (ms) await new Promise((done) => setTimeout(done, ms));
        window.__replied.push(u);
        return r;
      };
    })()`);
  const unspyFetch = () => evaluate("window.__spied?.length && (window.fetch = window.__spied.pop())");
  const requests = (part) => evaluate(`JSON.stringify(window.__reqs.filter((r) => r.u.includes(${JSON.stringify(part)})))`).then(JSON.parse);
  const closeButton = (cls) => evaluate(`[...document.querySelectorAll('.${cls} .dlg-footer button')].find((b) => b.textContent === 'Close')?.click()`);

  await check("browser: with Go to Packet open, Tab and Shift+Tab stay in the dialog and focus sent behind it comes back", async () => {
    // As rawKeyDown and keyUp, which is what moves the focus
    const tab = async (modifiers = 0) => {
      await cdp("Input.dispatchKeyEvent", { type: "rawKeyDown", key: "Tab", code: "Tab", windowsVirtualKeyCode: 9, modifiers });
      await cdp("Input.dispatchKeyEvent", { type: "keyUp", key: "Tab", code: "Tab", windowsVirtualKeyCode: 9, modifiers });
    };
    try {
      // A menu left open by an earlier check would take the keys
      if (await evaluate("!!document.querySelector('.menu-item')")) await key("Escape", "Escape", 27);
      await evaluate("document.querySelector('.pl-scroll').focus()");
      await key("g", "KeyG", 71, MOD);
      await until("the dialog", () => inDialog("dlg-goto"));
      for (let n = 1; n <= 9; n++) {
        await tab();
        assert.equal(await inDialog("dlg-goto"), true, `Tab ${n} left the dialog`);
      }
      for (let n = 1; n <= 9; n++) {
        await tab(8);
        assert.equal(await inDialog("dlg-goto"), true, `Shift+Tab ${n} left the dialog`);
      }
      await evaluate("document.querySelector('.fb-input').focus()");
      assert.equal(await inDialog("dlg-goto"), true, "the focus stayed behind the dialog");
    } finally {
      if (await evaluate("!!document.querySelector('.dlg-goto')")) await key("Escape", "Escape", 27);
      await until("the dialog to close", () => evaluate("!document.querySelector('.dlg-goto')"));
    }
  });

  await check("browser: a click on a URL in the details opens nothing and a double-click opens it; a frame number link jumps on one click", async () => {
    const frameWithUrl = async () => {
      const hasUrl = (nodes) => (nodes ?? []).some((n) => (n.t === "url" && /^https?:/.test(n.url ?? "")) || hasUrl(n.n));
      for (let frame = 1; frame <= 29; frame++) if (hasUrl((await get(`/api/frame?num=${frame}`)).tree)) return frame;
      return 0;
    };
    // The details list holds only the rows in view and is filled again when the packet's details are: the link is looked for anew each time
    const findLink = async (selector) => {
      let at = null;
      await evaluate("document.querySelector('.vl.dt').scrollTop = 0");
      await until(selector, async () => {
        if (!(await box(selector))) {
          await evaluate("(() => { const v = document.querySelector('.vl.dt'); v.scrollTop = v.scrollTop + v.clientHeight >= v.scrollHeight ? 0 : v.scrollTop + 100; })()");
          return false;
        }
        await evaluate(`${selector}?.scrollIntoView({ block: 'center' })`);
        await sleep(200);
        at = await box(selector);
        return !!at;
      });
      return center(at);
    };
    await evaluate("window.__open = window.open; window.__opened = []; window.open = (url) => (window.__opened.push(url), null)");
    try {
      const frame = await frameWithUrl();
      assert.ok(frame, "the fixture has a frame with a URL field");
      await post("/api/select", { frame });
      await until("its details", () => evaluate(`document.querySelector('.dt-label')?.textContent.startsWith('Frame ${frame}:') === true`));
      await evaluate("document.querySelector('.vl.dt').focus()");
      // Ctrl+Right expands everything
      await key("ArrowRight", "ArrowRight", 39, MOD);
      const url = "document.querySelector('.dt-link[title^=\"Double-click to open\"]')";
      await click(...(await findLink(url)));
      await sleep(300);
      assert.deepEqual(await evaluate("window.__opened"), []);
      await dblclick(...(await findLink(url)));
      await until("the URL to open", () => evaluate("window.__opened.length === 1"));
      assert.match(await evaluate("window.__opened[0]"), /^https?:\/\//);
      // E.g. "Response in frame: N"
      const link = "document.querySelector('.dt-link[title^=\"Go to packet\"]')";
      const [x, y] = await findLink(link);
      const to = Number(await evaluate(`${link}.title.replace(/\\D+/g, '')`));
      await click(x, y);
      await until(`frame ${to} selected`, async () => (await state()).selected === to);
    } finally {
      await evaluate("window.open = window.__open");
    }
  });

  await check("browser: the export dialog says no such directory without asking to replace, asks only for a file that exists, names the packet it opened for, and says when the packet list changed", async () => {
    const exists = join(home, "exists.pcapng");
    writeFileSync(exists, "x");
    const setPath = (p) => evaluate(`(() => { const i = document.querySelector('.ex-path'); i.value = ${JSON.stringify(p)}; i.dispatchEvent(new Event('input')); })()`);
    const exportIt = async () => click(...center(await box("document.querySelector('.dlg-export button.primary')")));
    const err = () => evaluate("(() => { const e = document.querySelector('.dlg-export .of-err'); return e && !e.hidden ? e.textContent : ''; })()");
    const open = async () => {
      await post("/api/select", { frame: 4 });
      await until("frame 4 selected", async () => (await state()).selected === 4);
      await evaluate("document.querySelector('.pl-scroll').scrollTop = 0");
      // The page shows the selection before the row's menu is asked for: a right-click on a row it doesn't show as
      // selected selects it, and that selection would still be on its way when the filter changes below
      await until("frame 4's row selected in the page", () => evaluate(`${row(4)}?.classList.contains('sel') === true`));
      await fromMenu(4, "Export Selected Packet");
      await until("the export dialog", () => evaluate("!!document.querySelector('.dlg-export')"));
    };
    try {
      await open();
      await setPath(join(home, "nonexistent", "x.pcapng"));
      await exportIt();
      await until("the error", async () => !!(await err()));
      assert.match(await err(), /no such directory/);
      assert.equal(await evaluate("!!document.querySelector('.confirm-text')"), false, "asked to replace a file that isn't there");
      await setPath(exists);
      await exportIt();
      await until("the replace question", () => evaluate("document.querySelector('.confirm-text')?.textContent === 'exists.pcapng already exists. Replace it?'"));
      await key("Escape", "Escape", 27);
      await until("the question to close", () => evaluate("!document.querySelector('.confirm-text')"));
      // Another packet is selected meanwhile: the dialog exports the one it showed
      await post("/api/select", { frame: 9 });
      await until("frame 9 selected", async () => (await state()).selected === 9);
      await setPath(join(home, "sel.pcapng"));
      await spyFetch();
      await exportIt();
      await until("the export request", async () => (await requests("api/export")).length > 0);
      const sent = JSON.parse((await requests("api/export"))[0].body);
      assert.equal(sent.which, "selected");
      assert.equal(sent.about.frame, 4);
      assert.equal(sent.about.view.filter, "");
      await unspyFetch();
      // A successful export closes the dialog
      await sleep(500);
      if (!(await evaluate("!!document.querySelector('.dlg-export')"))) await open();
      await post("/api/filter", { filter: "tcp" });
      await until("the filter", async () => (await state()).filter === "tcp");
      await setPath(join(home, "sel2.pcapng"));
      await exportIt();
      await until("the packet list's change", async () => /The packet list changed since this opened/.test(await err())).catch(async (e) => {
        throw new Error(`${e.message}; error: ${await err()}; toasts: ${await toasts()}`);
      });
    } finally {
      if (await evaluate("!!document.querySelector('.confirm-text')")) await key("Escape", "Escape", 27);
      await closeDialog();
      await post("/api/filter", { filter: "" });
      await until("no filter", async () => (await state()).filter === "");
    }
  });

  await check("browser: text typed after Enter keeps its own state when the earlier filter apply comes back", async () => {
    const typeFilter = (text) => evaluate(`(() => { const i = document.querySelector('.fb-input'); i.focus(); i.value = ${JSON.stringify(text)}; i.dispatchEvent(new Event('input')); })()`);
    const classes = () => evaluate("document.querySelector('.fb-box').className");
    try {
      await spyFetch({ "api/filter$": 1500 });
      await typeFilter("tcp");
      await key("Enter", "Enter", 13);
      await until("the apply to be asked", async () => (await requests("api/filter")).some((r) => r.body?.includes("tcp")));
      await typeFilter("tcp.prt ==");
      await until("the apply to come back", () => evaluate("window.__replied.some((u) => /api\\/filter$/.test(u))"));
      await sleep(300);
      assert.match(await classes(), /st-error/);
      assert.doesNotMatch(await classes(), /busy/);
    } finally {
      await unspyFetch();
      await typeFilter("");
      await key("Enter", "Enter", 13);
      await until("no filter", async () => (await state()).filter === "" && !/busy/.test(await classes()));
    }
  });

  await check("browser: an I/O graph click selects a packet of its interval with a time reference set, asking with until=", async () => {
    try {
      assert.equal((await post("/api/timerefs", { frames: [2], on: true })).status, 200);
      await fromMenuBar("Statistics", "I/O Graphs");
      await until("the graph", () => evaluate("!!document.querySelector('.io-svg path.io-line, .io-svg circle')"), 15_000);
      const svg = await box("document.querySelector('.io-svg')");
      await spyFetch();
      let found = 0;
      // From the right, where the bars lie after the reference
      for (let x = svg.x + svg.width - 20; x > svg.x + 66 && !found; x -= 6) {
        const before = (await state()).selected;
        await click(x, svg.y + svg.height / 2);
        await sleep(350);
        const selected = (await state()).selected;
        if (selected !== before && selected > 2) found = selected;
      }
      const asked = await requests("api/frame-at");
      assert.ok(asked.length > 0 && asked.every((r) => /[?&]until=/.test(r.u)), `frame-at requests: ${asked.map((r) => r.u).join(" ")}`);
      assert.ok(found, "no click selected a packet after the reference");
    } finally {
      await unspyFetch();
      await closeButton("dlg-io");
      await post("/api/timerefs/clear");
      await until("no time references", async () => (await state()).timeRefs.length === 0);
    }
  });

  await check("browser: Follow Stream after another capture opened says the capture closed, selects nothing on a click and leaves the display filter on Back", async () => {
    const other = join(home, "other.pcapng");
    copyFileSync(join(root, "test/fixtures/http.pcapng"), other);
    const footerButton = (label) => `[...document.querySelectorAll('.dlg-follow .dlg-footer button')].find((b) => b.textContent === '${label}')`;
    try {
      await post("/api/select", { frame: 4 });
      await until("frame 4's details", () => evaluate("document.querySelectorAll('.dt-row').length > 3"));
      await sleep(400);
      await evaluate("document.querySelector('.pl-scroll').scrollTop = 0");
      await fromMenu(4, "Follow");
      await pick("TCP Stream");
      await until("the stream", () => evaluate("!!document.querySelector('.dlg-follow .fl-text span[data-frame]')"), 15_000);
      assert.match((await state()).filter, /tcp\.stream/);
      assert.match((await call("open_capture", { path: other })).text, /29 frames/);
      await until("the title", () => evaluate("document.querySelector('.dlg-follow .dlg-title-text').textContent.endsWith('[capture closed]')"));
      const before = await state();
      const span = await box("document.querySelector('.dlg-follow .fl-text span[data-frame]')");
      await click(span.x + 5, span.y + 5);
      await sleep(400);
      assert.equal((await state()).selected, before.selected);
      await evaluate(`${footerButton("Back")}.click()`);
      await until("the window to close", () => evaluate("!document.querySelector('.dlg-follow')"));
      await sleep(400);
      assert.equal((await state()).filter, before.filter);
    } finally {
      if (await evaluate("!!document.querySelector('.dlg-follow')")) await evaluate(`${footerButton("Back")}?.click()`);
      await call("open_capture", { path: join(root, "test/fixtures/http.pcapng") });
      await post("/api/filter", { filter: "" });
      await until("no filter", async () => (await state()).filter === "");
    }
  });

  await check("browser: Conversations with a tab clicked again while it computes sends one request for it", async () => {
    const tabButton = (label) => `[...document.querySelectorAll('.dlg-stats .tab')].find((t) => t.textContent.startsWith(${JSON.stringify(label)}))`;
    try {
      await spyFetch({ "api/stats/conv": 1000 });
      await fromMenuBar("Statistics", "Conversations");
      await until("the dialog", () => evaluate("!!document.querySelector('.dlg-stats .tabs')"));
      await click(...center(await box(tabButton("TCP"))));
      await click(...center(await box(tabButton("UDP"))));
      await click(...center(await box(tabButton("TCP"))));
      await until("the TCP table", () => evaluate(`/ · \\d+/.test(${tabButton("TCP")}.textContent) && !!document.querySelector('.dlg-stats .stat-table')`), 15_000);
      assert.equal((await requests("type=tcp")).length, 1);
    } finally {
      await unspyFetch();
      await closeButton("dlg-stats");
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

  await check("browser: File › Write Findings Report… writes the file at the chosen path and says so in a toast", async () => {
    const out = mkdtempSync("/tmp/wirebuddy-findings-");
    const file = join(out, "report.md");
    try {
      await fromMenuBar("File", "Write Findings Report…");
      await until("the dialog", async () => (await evaluate("!!document.querySelector('.dlg-findings .ex-path')")) === true);
      // The default is next to the capture, named after it
      assert.match(await evaluate("document.querySelector('.dlg-findings .ex-path').value"), /\/http-findings\.md$/);
      await evaluate(`(() => { const i = document.querySelector('.dlg-findings .ex-path'); i.value = ${JSON.stringify(file)}; i.dispatchEvent(new Event('input')); })()`);
      await evaluate(`(() => { const t = document.querySelector('.dlg-findings textarea'); t.value = "## Found\\n\\nA summary."; t.dispatchEvent(new Event('input')); })()`);
      // Toasts may cover the button
      await evaluate("document.querySelectorAll('.toast').forEach((t) => t.remove())");
      await click(...center(await box("[...document.querySelectorAll('.dlg-findings .dlg-footer button')].find((b) => b.textContent === 'Write')")));
      await until("the file", () => existsSync(file)).catch(async (err) => {
        throw new Error(`${err.message}; dialog: ${await evaluate("document.querySelector('.dlg-findings')?.textContent")}; toasts: ${await toasts()}`);
      });
      await until("the toast", async () => /Wrote the findings report report\.md/.test(await toasts()));
      assert.match(readFileSync(file, "utf8"), /^# Findings: `http\.pcapng`\n\n## Found\n\nA summary\.\n\n## Capture\n/);
      assert.equal(await evaluate("!!document.querySelector('.dlg-findings')"), false, "the dialog closes");
    } finally {
      // A click on File within 300 ms of the menu closing counts as the one that closed it
      await sleep(400);
      await evaluate("document.querySelectorAll('.toast').forEach((t) => t.remove())");
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

  await check("browser: Now in a live capture: N tapped and the button held flag packets with comments and wake the agent, also when the capture stops during the hold; not in captures in new files", async () => {
    const button = `document.querySelector('button[aria-label="Now"]')`;
    const command = /`"([^"]+)" "([^"]+)" --watch "([^"]+)"`/.exec(client.getInstructions() ?? "");
    assert.ok(command, "the instructions name the watch command");
    /** A --watch like the agent's; it exits with the next event. */
    const watch = async () => {
      const proc = spawn(command[1], [command[2], "--watch", command[3]], { stdio: ["ignore", "pipe", "ignore"] });
      const w = { proc, heard: "", exited: new Promise((resolve) => proc.on("exit", resolve)) };
      proc.stdout.on("data", (d) => (w.heard += d));
      await until("the watch", async () => (await state()).agent.watching);
      // The page gets state at most every 100 ms
      await sleep(400);
      return w;
    };
    const woke = async (w) => {
      assert.equal(await Promise.race([w.exited, sleep(15_000).then(() => "timeout")]), 0);
      return w.heard;
    };
    const comments = async () => (await call("get_view_state")).text;
    let w = null;
    try {
      // The capture before has stopped
      await until("Now off without a running capture", () => evaluate(`${button}.disabled`));
      await call("start_capture", { interface: "lo", filter: "burst 0 rate 200 realtime" });
      await until("Now", () => evaluate(`!${button}.disabled`));
      await until("some packets", async () => (await state()).totalFrames > 100);

      w = await watch();
      await evaluate("document.querySelector('.pl-scroll').focus()");
      await cdp("Input.dispatchKeyEvent", { type: "rawKeyDown", key: "n", code: "KeyN", windowsVirtualKeyCode: 78 });
      await cdp("Input.dispatchKeyEvent", { type: "keyUp", key: "n", code: "KeyN", windowsVirtualKeyCode: 78 });
      const tap = await woke(w);
      const [, tapped] = /QUESTION The user pressed Now in the live capture, without words: what happened just before\? Frame (\d+) is the newest packet then, with the packet comment "WireBuddy Now"\./.exec(tap) ?? [];
      assert.ok(tapped, tap);
      const [, filter] = /"filter":"(frame\.time_epoch >= \d+\.\d{3} && frame\.time_epoch <= \d+\.\d{3})"/.exec(tap) ?? [];
      assert.ok(filter, tap);
      await until("the tap's toast", async () => new RegExp(`Now: packet ${tapped}, sent to Agent`).test(await toasts()));
      assert.match(await comments(), new RegExp(`^  ${tapped}: "WireBuddy Now"$`, "m"));
      // The filter finds the packet, once the agent's tools read it
      await until("the filter to find it", async () => /^1 frames match/.test((await call("query_packets", { filter: `(${filter}) && frame.number == ${tapped}` })).text));
      // The agent shows it: the list stops following this capture, the setting stays
      const autoScroll = `document.querySelector('button[aria-label="Auto Scroll in Live Capture"]').getAttribute('aria-pressed') === 'true'`;
      const saved = "localStorage.getItem(Object.keys(localStorage).find((k) => k.endsWith('autoscroll')) ?? '')";
      const savedBefore = await evaluate(saved);
      assert.equal(await evaluate(autoScroll), true);
      await call("goto_frame", { frame: Number(tapped) });
      await until("auto-scroll paused", async () => !(await evaluate(autoScroll)));
      assert.equal(await evaluate(saved), savedBefore);

      // Held about 1.5 s, let go off the button
      w = await watch();
      const [x, y] = center(await box(button));
      await cdp("Input.dispatchMouseEvent", { type: "mouseMoved", x, y });
      await cdp("Input.dispatchMouseEvent", { type: "mousePressed", x, y, button: "left", clickCount: 1 });
      await until("the button held", () => evaluate(`${button}.classList.contains('holding')`));
      await sleep(1500);
      await cdp("Input.dispatchMouseEvent", { type: "mouseMoved", x: x + 200, y: y + 200, button: "left", buttons: 1 });
      await cdp("Input.dispatchMouseEvent", { type: "mouseReleased", x: x + 200, y: y + 200, button: "left", clickCount: 1 });
      const hold = await woke(w);
      const [, a, b] = /QUESTION The user held Now for 1\.\d s in the live capture, without words: what happened then\? Frames (\d+) to (\d+) came meanwhile, the first and last with packet comments\./.exec(hold) ?? [];
      assert.ok(a, hold);
      // 200 packets a second
      assert.ok(b - a > 200 && b - a < 400, `${a} to ${b}`);
      await until("the hold's toast", async () => new RegExp(`Now \\(1\\.\\d s\\): packets ${a}–${b}, sent to Agent`).test(await toasts()));
      const listed = await comments();
      assert.match(listed, new RegExp(`^  ${a}: "WireBuddy Now: held 1\\.\\d s from here"$`, "m"));
      assert.match(listed, new RegExp(`^  ${b}: "WireBuddy Now: held until here"$`, "m"));
      assert.equal(await evaluate(`${button}.classList.contains('holding') || ${button}.classList.contains('sending')`), false);

      // The capture stops during the hold: the release still counts
      w = await watch();
      await cdp("Input.dispatchMouseEvent", { type: "mouseMoved", x, y });
      await cdp("Input.dispatchMouseEvent", { type: "mousePressed", x, y, button: "left", clickCount: 1 });
      await until("the button held", () => evaluate(`${button}.classList.contains('holding')`));
      await sleep(500);
      await call("stop_capture");
      await until("the capture stopped", async () => (await state()).capture.status === "idle");
      await cdp("Input.dispatchMouseEvent", { type: "mouseReleased", x, y, button: "left", clickCount: 1 });
      assert.match(await woke(w), /QUESTION The user held Now for \d+\.\d s in the live capture, without words: what happened then\? Frames \d+ to \d+ came meanwhile, the first and last with packet comments\./);
      assert.equal(await evaluate(autoScroll), false, "the stop keeps the agent's packet in view");

      // New files would drop the comments
      await call("start_capture", { interface: "lo", filter: "burst 0 rate 200 realtime", new_file_after_packets: 1000000 });
      await until("auto-scroll back with the next capture", () => evaluate(autoScroll));
      await until("some packets", async () => (await state()).totalFrames > 100);
      assert.equal(await evaluate(`${button}.disabled`), true);
      const refused = await fetch(new URL("/api/now", ui.origin), { method: "POST", headers: { "X-WireBuddy-Token": token, "Content-Type": "application/json" }, body: JSON.stringify({ heldMs: 0 }) });
      assert.equal(refused.status, 400);
      assert.match((await refused.json()).error, /Now works in a capture that stays in one file/);
    } finally {
      w?.proc.kill();
      await call("stop_capture");
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
finish();
