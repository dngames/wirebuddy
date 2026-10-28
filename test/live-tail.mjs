// The live view of a big, busy capture: newer packets show provisionally within about two seconds
// while full reads of the file lag behind, become exact once the capture stops, and small captures
// never show provisional packets. With a display filter the newest rows keep coming; slices that
// can't be written leave the exact rows alone; and when memory is short, full reads wait, read in
// place, and a failed one lists the file from slices. dumpcap is test/fake-dumpcap.mjs, which
// writes generated traffic. The packet list's marking is checked in headless Chrome when there is
// one.
// Usage: node test/live-tail.mjs   (after npm run build; CHROME=<path> picks the browser)
import { spawn } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { WebSocket } from "ws";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const work = mkdtempSync(join(tmpdir(), "wirebuddy-live-tail-"));
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
  const client = new Client({ name: "live-tail", version: "0" });
  await client.connect(
    new StdioClientTransport({
      command: process.execPath,
      args: [join(root, "dist/server/main.js"), "--mcp", "--port", "0", "--capture-dir", captureDir],
      // A home of its own: the tester's Wireshark preferences and plugins don't apply
      env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, HOME: home, XDG_CONFIG_HOME: join(home, ".config"), XDG_DATA_HOME: join(home, ".local/share"), WIREBUDDY_EXTENSIONS: "", ...env },
      stderr: "ignore",
    }),
  );
  const tool = async (tool, args = {}) => {
    const r = await client.callTool({ name: tool, arguments: args });
    return { text: r.content.map((c) => c.text).join("\n"), error: !!r.isError };
  };
  const ui = new URL((await tool("viewer_url")).text.trim());
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
    tool,
    api,
    state,
    /** Rows start..start+count-1 (Infinity: the last ones; a function: of the state then) of the list as it is now. */
    async rows(start, count) {
      for (;;) {
        const s = await state();
        const from = start === Infinity ? Math.max(0, listLength(s) - count) : typeof start === "function" ? start(s) : start;
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
        if (Date.now() > end) throw new Error(`timed out waiting for ${what}: ${JSON.stringify({ totalFrames: s.totalFrames, tail: s.tail, capture: s.capture.status, loading: s.loading, loadError: s.loadError })}`);
        await sleep(200);
      }
    },
    async close() {
      await api("/api/capture/stop", {}).catch(() => {});
      await client.close();
    },
  };
}

/** The viewer in headless Chrome: evaluates an expression in its page; null without Chrome. */
async function openBrowser(url) {
  const bin = process.env.CHROME ?? "/usr/bin/google-chrome";
  if (!existsSync(bin)) return null;
  const profile = join(work, "chrome");
  const chrome = spawn(bin, ["--headless=new", "--remote-debugging-port=0", `--user-data-dir=${profile}`, "--window-size=1280,820", "--no-first-run", "--no-default-browser-check", "--disable-gpu", "about:blank"], { stdio: "ignore" });
  let port;
  for (const end = Date.now() + 10_000; !port && Date.now() < end; await sleep(100)) {
    if (existsSync(join(profile, "DevToolsActivePort"))) port = readFileSync(join(profile, "DevToolsActivePort"), "utf8").split("\n")[0];
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
  return {
    evaluate: async (expression) => (await cdp("Runtime.evaluate", { expression, returnByValue: true })).result?.result?.value,
    close: () => (ws.close(), chrome.kill()),
  };
}
let browser = null;

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

const servers = [];
try {
  const wb = await server("captures");
  servers.push(wb);
  const { api, state, tool, until } = wb;

  await check("a small capture never lists provisional packets", async () => {
    await api("/api/capture/start", { iface: "lo", filter: "burst 2000 rate 300", autostop: { durationSec: 4 }, ring: null });
    const s = await until("the capture to end", 15_000, (s) => {
      assert.equal(s.tail, null, "no provisional packets");
      return s.capture.status === "idle";
    });
    await sleep(1500);
    const end = await state();
    assert.equal(end.tail, null);
    assert.equal(end.totalFrames, s.capture.packets);
  });

  // Provisional rows seen during the capture, to compare once they are exact, and the packets there were then
  const seen = new Map();
  let knownThen = 0;
  let marked = 0;
  await check("a big capture: newer packets show within about 2 s while full reads lag", async () => {
    await api("/api/capture/start", { iface: "lo", filter: "burst 300000 rate 2000", autostop: {}, ring: null });
    await until("provisional packets", 30_000, (s) => s.tail !== null && s.tail.frames > 0 && s.totalFrames > 0);
    const latencies = [];
    let provisional = 0;
    for (let k = 0; k < 8; k++) {
      const t0 = Date.now();
      const written = (await state()).capture.packets;
      for (;;) {
        const { s, rows: last } = await wb.rows(Infinity, 1);
        if (last[0]?.num >= written) {
          latencies.push(Date.now() - t0);
          // Listed before a full read covered it
          if (last[0].p) provisional++;
          assert.equal(last[0].c[0], String(last[0].num));
          assert.equal(s.tail === null || s.tail.frames + s.totalFrames >= last[0].num, true);
          break;
        }
        assert.ok(Date.now() - t0 < 5000, `packet ${written} not listed after 5 s`);
        await sleep(50);
      }
      await sleep(400);
    }
    latencies.sort((a, b) => a - b);
    const s = await state();
    report.push(`newest packet listed after ${latencies.join(", ")} ms at ${s.capture.packets} packets; ${provisional} of 8 provisional; a full read takes ${s.tail?.readMs} ms`);
    assert.ok(latencies[latencies.length - 2] <= 2000, `latencies ${latencies}`);
    assert.ok(provisional >= 5, `only ${provisional} of 8 newest packets were listed before a full read covered them`);
    // A page of provisional rows, kept to compare
    const { s: at, rows: page } = await wb.rows((s) => s.displayedFrames, 400);
    assert.ok(page.length > 0 && page.every((r) => r.p === true), `${page.length} rows, ${page.filter((r) => r.p).length} provisional, tail ${JSON.stringify(at.tail)}`);
    for (const r of page) seen.set(r.num, r);
    knownThen = at.totalFrames + at.tail.frames;
  });

  await check("a provisional packet: details from its slice, selected and marked like any other", async () => {
    const [num] = [...seen.keys()].slice(-50);
    const d = await api(`/api/frame?num=${num}`);
    assert.equal(d.provisional, true);
    assert.equal(d.num, num);
    assert.match(d.tree[0].l, new RegExp(`^Frame ${num}:`));
    assert.ok(Buffer.from(d.bytes, "base64").length > 40);
    seen.get(num).bytes = d.bytes;
    await api("/api/select", { frame: num });
    await api("/api/marks", { frames: [num], note: "provisional" });
    const s = await state();
    assert.equal(s.selected, num);
    assert.equal(s.selectedIndex, s.displayedFrames + (num - s.totalFrames - 1));
    marked = num;
    // The agent: exact data only, and told what is still provisional
    const view = await tool("get_view_state");
    assert.match(view.text, /newer packets .* provisional/i);
    const inspect = await tool("inspect_frame", { frame: num });
    assert.ok(inspect.error && /arrived after the last full read/.test(inspect.text), inspect.text);
    const go = await tool("goto_frame", { frame: num });
    const at = await state();
    assert.match(go.text, new RegExp(`^Selected frame ${num} \\(row \\d+ of \\d+\\)`));
    const [, row, of] = /row (\d+) of (\d+)/.exec(go.text).map(Number);
    assert.ok(row <= of && of >= at.totalFrames, go.text);
    // Right after a full read lands nothing may be provisional for a moment
    let query;
    for (let k = 0; k < 10 && !/provisional/.test(query?.text ?? ""); k++) query = await tool("query_packets", { filter: "dns", limit: 1 });
    assert.match(query.text, /these results cover frames 1-\d+, read in full; \d+ newer packets are provisional/);
  });

  await check("the packet list marks provisional rows, the status bar counts them (headless Chrome)", async () => {
    browser = await openBrowser(wb.ui);
    if (!browser) return console.log("     skipped: no Chrome (set CHROME)");
    const page = async () => JSON.parse(await browser.evaluate(`JSON.stringify({ prov: [...document.querySelectorAll('.pl-row.prov')].filter((r) => r.style.display !== 'none').map((r) => r.title), live: document.querySelector('.sb-live')?.hidden ? '' : document.querySelector('.sb-live')?.textContent })`) ?? "{}");
    let seenPage = {};
    for (const end = Date.now() + 15_000; !(seenPage.prov?.length && seenPage.live) && Date.now() < end; await sleep(200)) seenPage = await page();
    assert.ok(seenPage.prov?.length, "provisional rows in the list");
    assert.match(seenPage.prov[0], /^Provisional: /);
    assert.match(seenPage.live, /^[\d,]+ provisional · exact after the next full read/);
  });

  await check("display filters: provisional matches, held for stream indices", async () => {
    try {
      await heldFilters();
    } finally {
      await api("/api/filter", { filter: "" });
      // goto_frame moved it
      await api("/api/select", { frame: marked });
    }
  });
  async function heldFilters() {
    assert.equal((await api("/api/filter", { filter: "dns" })).ok, true);
    const s = await until("provisional matches", 20_000, (s) => s.tail?.displayed > 0 && s.tail.held === null);
    const { rows: matches } = await wb.rows(s.displayedFrames, Math.min(50, s.tail.displayed));
    assert.ok(matches.every((r) => r.p && r.c[4] === "DNS"), JSON.stringify(matches[0]));
    assert.equal((await api("/api/filter", { filter: "tcp.stream == 3" })).ok, true);
    const held = await state();
    assert.match(held.tail.held, /tcp\.stream/);
    assert.equal(held.tail.displayed, 0);
    // The agent hears why a provisional packet isn't listed, and what an export left out
    let go;
    for (let k = 0; k < 5 && !/listed once read in full/.test(go?.text ?? ""); k++) {
      const s = await state();
      go = await tool("goto_frame", { frame: s.totalFrames + s.tail.frames });
    }
    assert.match(go.text, /but it is listed once read in full, as the filter uses tcp\.stream/);
    const exported = await tool("export_packets", { path: join(work, "held.pcapng"), which: "displayed" });
    assert.match(exported.text, /; \d+ newer packets? of the live capture, not read in full yet, (was|were) left out/);
  }

  await check("with a display filter the newest rows keep coming: requests for lists replaced since are dropped", async () => {
    try {
      await pileUp();
    } finally {
      await api("/api/filter", { filter: "" });
    }
  });
  async function pileUp() {
    assert.equal((await api("/api/filter", { filter: "tcp" })).ok, true);
    await until("provisional matches", 20_000, (s) => s.tail?.displayed > 0);
    // As the packet list does: the newest pages of each new list, without waiting for the ones before
    const answered = [];
    let dropped = 0;
    const pending = [];
    let generation = 0;
    for (const end = Date.now() + 20_000; Date.now() < end; await sleep(100)) {
      const s = await state();
      if (s.generation === generation) continue;
      generation = s.generation;
      const n = listLength(s);
      for (let start = Math.max(0, n - 600); start < n; start += 200) {
        const count = Math.min(200, n - start);
        const t0 = Date.now();
        pending.push(
          api(`/api/rows?gen=${generation}&start=${start}&count=${count}`).then(
            (r) => answered.push({ ms: Date.now() - t0, full: r.rows.length === count && r.rows.every((row) => row.c.length) }),
            (err) => {
              if (err.status !== 409) throw err;
              dropped++;
            },
          ),
        );
      }
    }
    await Promise.all(pending);
    const slowest = Math.max(...answered.map((a) => a.ms));
    report.push(`filter "tcp": ${answered.length} of the newest pages answered, the slowest in ${slowest} ms; ${dropped} for replaced lists dropped`);
    assert.ok(answered.filter((a) => a.full).length >= 3, `${answered.filter((a) => a.full).length} full pages of ${answered.length}`);
    // Requests for each list piled up before, each slower than the last
    assert.ok(slowest < 6000, `a page took ${slowest} ms`);
  }

  await check("TLS keys: provisional rows are decrypted too", async () => {
    assert.equal((await api("/api/filter", { filter: "ip.addr == 10.0.1.3 && http" })).ok, true);
    await api("/api/tls", { keylog: `${(await state()).file}.keys` });
    try {
      let found = null;
      for (const end = Date.now() + 30_000; !found && Date.now() < end; await sleep(300)) {
        const s = await state();
        if (!s.tail?.displayed) continue;
        const { rows } = await wb.rows(s.displayedFrames, Math.min(500, s.tail.displayed));
        found = rows.find((r) => r.p && r.c[4] === "HTTP");
      }
      assert.ok(found, "decrypted HTTP among the provisional rows");
    } finally {
      // The rows kept to compare at the end were read without keys
      await api("/api/tls", { keylog: null });
      await api("/api/filter", { filter: "" });
    }
  });

  await check("slices that can't be written: the exact rows still come, and newer packets wait for full reads after a few failures", async () => {
    const folder = join(wb.captureDir, readdirSync(wb.captureDir).find((n) => n.startsWith(".wirebuddy-slices-")));
    chmodSync(folder, 0o500);
    try {
      let s = await state();
      for (const end = Date.now() + 20_000; s.tail && Date.now() < end; s = await state()) {
        try {
          // A page across the last exact rows and the first provisional ones, then the newest page
          const across = await api(`/api/rows?gen=${s.generation}&start=${s.displayedFrames - 50}&count=100`);
          assert.ok(across.rows.length >= 50 && across.rows.slice(0, 50).every((row) => !row.p && row.c.length), `${across.rows.length} rows`);
          await api(`/api/rows?gen=${s.generation}&start=${listLength(s) - 100}&count=100`);
        } catch (err) {
          if (err.status !== 409) throw err;
        }
        await sleep(200);
      }
      assert.equal(s.tail, null);
      // Marks and the selection on provisional packets stay
      assert.equal(s.selected, marked);
      assert.ok(s.marks.some((m) => m.frame === marked));
      const view = await tool("get_view_state");
      assert.match(view.text, /listed only once read in full: reading them from slices failed 3 times in a row/);
    } finally {
      chmodSync(folder, 0o700);
    }
  });

  await check("after the stop: one full read, everything exact, as provisional rows showed it", async () => {
    await api("/api/capture/stop", {});
    const s = await until("the final full read", 60_000, (s) => s.capture.status === "idle" && s.tail === null && s.totalFrames === s.capture.packets);
    assert.equal(s.selected, marked);
    assert.equal(s.selectedIndex, marked - 1);
    assert.ok(s.marks.some((m) => m.frame === marked));
    const nums = [...seen.keys()];
    const { rows: exact } = await wb.rows(nums[0] - 1, nums.length);
    let diff = 0;
    const examples = [];
    for (const r of exact) {
      const p = seen.get(r.num);
      // A PDU that a packet written after the row was read completes: Wireshark couldn't tell then either
      const info = r.c[6].replace(/ \[TCP PDU reassembled in (\d+)\]$/, (all, n) => (Number(n) > knownThen ? "" : all));
      const same = [r.c, [...r.c.slice(0, 6), info, ...r.c.slice(7)]].some((c) => p.c.join("\t") === c.join("\t"));
      if (!same || (p.bg ?? "") !== (r.bg ?? "")) {
        diff++;
        if (examples.length < 4) examples.push(`${r.num}: ${r.c[6]} | ${p.c[6]}`);
      }
      assert.equal(r.p, undefined);
    }
    report.push(`${diff} of ${exact.length} provisional rows read differently once exact`);
    assert.equal(diff, 0, examples.join("\n"));
    const d = await api(`/api/frame?num=${marked}`);
    assert.equal(d.provisional, undefined);
    assert.equal(d.bytes, seen.get(marked).bytes);
    if (!browser) return;
    let left;
    for (const end = Date.now() + 10_000; left !== 0 && Date.now() < end; await sleep(200)) left = await browser.evaluate("document.querySelectorAll('.pl-row.prov').length + (document.querySelector('.sb-live').hidden ? 0 : 1)");
    assert.equal(left, 0, "no provisional rows or status once read in full");
  });
  browser?.close();
  browser = null;
  await wb.close();
  servers.pop();

  // Memory too short for any second copy of the capture
  const lean = await server("lean", { WIREBUDDY_MEM_AVAILABLE: "1" });
  servers.push(lean);
  await check("short of memory: full reads wait, View › Reload reads in place, a failed final read lists the file from slices", async () => {
    await lean.api("/api/capture/start", { iface: "lo", filter: "burst 200000 rate 3000", autostop: {}, ring: null });
    const paused = await lean.until("full reads to wait", 60_000, (s) => s.tail?.paused);
    assert.match(paused.tail.paused, /not enough free memory/);
    await sleep(2500);
    const later = await lean.state();
    assert.equal(later.totalFrames, paused.totalFrames, "no full read while they wait");
    assert.ok(later.tail.frames > paused.tail.frames);
    // View › Reload: in place of the copy there is
    await lean.api("/api/reload", {});
    const reread = await lean.state();
    assert.ok(reread.totalFrames > later.totalFrames && !reread.loading && reread.tail?.paused);
    const told = await lean.tool("get_view_state");
    assert.match(told.text, /reads it again in place of the one it has/);
    // The final read can't open the file
    chmodSync(reread.file, 0);
    try {
      await lean.api("/api/capture/stop", {});
      const failed = await lean.until("the final read to fail", 60_000, (s) => s.capture.status === "idle" && !s.loading && s.loadError);
      assert.match(failed.loadError, /in full failed .*listed provisionally from slices/);
      assert.equal(failed.totalFrames, 0);
      assert.equal(failed.tail.frames, failed.capture.packets);
      const { rows } = await lean.rows(Infinity, 100);
      assert.ok(rows.length === 100 && rows.every((r) => r.p && r.c.length), JSON.stringify(rows[0]));
      assert.equal(rows.at(-1).num, failed.capture.packets);
    } finally {
      chmodSync(reread.file, 0o600);
    }
    // Readable again: View › Reload reads it in full
    await lean.api("/api/reload", {});
    const done = await lean.state();
    assert.deepEqual([done.tail, done.loadError, done.totalFrames], [null, null, done.capture.packets]);
  });
} finally {
  browser?.close();
  for (const s of servers) await s.close().catch(() => {});
  rmSync(work, { recursive: true, force: true });
}
for (const line of report) console.log(`     ${line}`);
console.log(failures ? `${failures} check(s) failed` : "all checks passed");
process.exit(failures ? 1 : 0);
