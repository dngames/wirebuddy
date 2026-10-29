// The live view of a big, busy capture: newer packets show provisionally within about two seconds
// while full reads of the file lag behind, are read ahead only while a list shows its end, become
// exact once the capture stops, and small captures never show provisional packets. With a display
// filter the newest rows keep coming; slices that can't be written leave the exact rows alone; the
// profile's and custom columns read as in full, also after an extension changes a field; a final
// read that fails leaves newer packets provisional and says so; and when memory is short, full
// reads wait, matches that later packets change are listed anew, reads in place don't fail
// requests in flight, and one killed for memory lists the file from slices without blaming an
// extension. A full read that dies after the stop, with the final read still to come, leaves it to
// that one (test/holding-sharkd.mjs holds and kills it). A server ends on SIGHUP as on SIGTERM,
// also right as its URL is out, and removes slices killed ones left. A panel offer that only later
// packets match is checked from slices of them. Provisional rows and details count from time
// references, also one long before their slice. dumpcap is test/fake-dumpcap.mjs, which writes
// generated traffic. The packet list's marking is checked in headless Chrome when there is one.
// Usage: node test/live-tail.mjs   (after npm run build; CHROME=<path> picks the browser)
import { spawn } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, readlinkSync, rmSync, writeFileSync } from "node:fs";
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
const homeEnv = (dir) => ({ HOME: dir, XDG_CONFIG_HOME: join(dir, ".config"), XDG_DATA_HOME: join(dir, ".local/share"), XDG_RUNTIME_DIR: join(dir, "run") });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const listLength = (s) => s.displayedFrames + (s.tail?.displayed ?? 0);
/** What a tool result tells the agent about the live capture's packets after the last full read. */
const liveLine = (text) => /Live capture: [^\n\]]*/.exec(text)?.[0] ?? "";

/** A WireBuddy server with an MCP client, capturing into a folder of its own; `env` adds to its environment. */
async function server(name, env = {}, homeDir = home) {
  const captureDir = join(work, name);
  const client = new Client({ name: "live-tail", version: "0" });
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [join(root, "dist/server/main.js"), "--mcp", "--port", "0", "--capture-dir", captureDir],
    // A home of its own: the tester's Wireshark preferences and plugins don't apply
    env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, ...homeEnv(homeDir), WIREBUDDY_EXTENSIONS: "", ...env },
    stderr: "ignore",
  });
  await client.connect(transport);
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
    pid: transport.pid,
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

/** The sharkd processes of the server `pid` that have `file` open (they read it in full). */
function sharkdsReading(pid, file) {
  const out = [];
  for (const p of readdirSync("/proc").filter((n) => /^\d+$/.test(n))) {
    try {
      const m = /^\d+ \((.*)\) \S (\d+)/.exec(readFileSync(`/proc/${p}/stat`, "utf8"));
      if (m?.[1] !== "sharkd" || Number(m[2]) !== pid) continue;
      if (readdirSync(`/proc/${p}/fd`).some((fd) => readlinkSync(`/proc/${p}/fd/${fd}`) === file)) out.push(Number(p));
    } catch {
      // ended meanwhile
    }
  }
  return out;
}

/** The viewer in headless Chrome: evaluates an expression in its page; null without Chrome. */
async function openBrowser(url) {
  const bin = process.env.CHROME ?? "/usr/bin/google-chrome";
  if (!existsSync(bin)) return null;
  const profile = mkdtempSync(join(work, "chrome-"));
  const chrome = spawn(bin, ["--headless=new", "--remote-debugging-port=0", `--user-data-dir=${profile}`, "--window-size=1280,820", "--no-first-run", "--no-default-browser-check", "--disable-gpu", "about:blank"], { stdio: "ignore" });
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
/** Of a folder of slices this machine's servers make: what tells the machine. */
let sliceTag = null;

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
  let markedBytes = "";
  await check("a big capture: newer packets show within about 2 s, sooner than full reads would", async () => {
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
        assert.ok(Date.now() - t0 < 10_000, `packet ${written} not listed after 10 s`);
        await sleep(50);
      }
      await sleep(400);
    }
    latencies.sort((a, b) => a - b);
    const s = await state();
    report.push(`newest packet listed after ${latencies.join(", ")} ms at ${s.capture.packets} packets; ${provisional} of 8 provisional; a full read takes ${s.tail?.readMs} ms`);
    // A page of provisional rows, kept to compare (also when the timing below fails); a full read may just have caught up
    let at;
    let page;
    for (const end = Date.now() + 30_000; ; await sleep(200)) {
      ({ s: at, rows: page } = await wb.rows((s) => s.displayedFrames, 400));
      if (page.length > 0 && page.every((r) => r.p === true)) break;
      assert.ok(Date.now() < end, `${page.length} rows, ${page.filter((r) => r.p).length} provisional, tail ${JSON.stringify(at.tail)}`);
    }
    for (const r of page) seen.set(r.num, r);
    knownThen = at.totalFrames + at.tail.frames;
    // Sooner than full reads would show them: within half a full read more, 2 s at least
    const readMs = s.tail?.readMs ?? 0;
    assert.ok(latencies[latencies.length - 2] <= Math.max(2000, 1.5 * readMs), `latencies ${latencies}, a full read takes ${readMs} ms`);
    // Full reads quicker than 3 s cover many of the newest packets first
    assert.ok(provisional >= (readMs >= 3000 ? 5 : 1), `only ${provisional} of 8 newest packets were listed before a full read (${readMs} ms) covered them`);
  });

  await check("a provisional packet: details from its slice, selected and marked like any other", async () => {
    // A full read may cover the packet while this runs: then again with a newer one
    for (let attempt = 1; ; attempt++) {
      // Right after a full read lands nothing is provisional until the next tail tick
      const s = await until("newer packets", 10_000, (s) => s.tail?.frames > 10);
      const num = s.totalFrames + s.tail.frames - 10;
      try {
        await provisionalPacket(num);
        return;
      } catch (err) {
        if (attempt >= 5 || !err.overtaken) throw err;
      }
    }
  });

  await check("time references among provisional packets: *REF*, and rows and details count from the nearest one, also one long before them", async () => {
    try {
      for (let attempt = 1; ; attempt++) {
        const s = await until("newer packets", 10_000, (s) => s.tail?.frames > 50 && s.totalFrames > 1000);
        try {
          // One far from the slices' flows' first packets, and a provisional one
          await provisionalRefs(Math.floor(s.totalFrames / 2) + 7, s.totalFrames + s.tail.frames - 20);
          return;
        } catch (err) {
          if (attempt >= 5 || !err.overtaken) throw err;
        }
      }
    } finally {
      await tool("time_references", { action: "clear" });
    }
  });

  /** Sets the exact frame `early` and the provisional `ref` as time references and checks the rows and details around `ref`. */
  async function provisionalRefs(early, ref) {
    const set = await tool("time_references", { action: "set", frames: [early, ref] });
    assert.match(set.text, new RegExp(`^Set time references on 2 frames; 2 time reference\\(s\\): ${early}, ${ref}`), set.text);
    assert.equal((await state()).agentNotice.text, "Set time references on 2 frames");
    // No display filter: the row of frame n is n - 1
    const { rows } = await wb.rows(ref - 3, 5);
    await stillProvisional(ref, rows.length === 5 && rows.every((r) => r.p), `rows ${rows.map((r) => `${r.num}${r.p ? "p" : ""}`)}`);
    const row = new Map(rows.map((r) => [r.num, r]));
    assert.equal(row.get(ref).c[1], "*REF*");
    const UNITS = { day: 86400, hour: 3600, minute: 60, second: 1, millisecond: 1e-3, microsecond: 1e-6, nanosecond: 1e-9 };
    /** Nanoseconds since 1970, and seconds since the reference ("2 minutes, 9.984000000 seconds"), as the frame's details say. */
    const times = async (num) => {
      const d = await api(`/api/frame?num=${num}`);
      const node = (fn) => d.tree.find((n) => n.fn === "frame").n.find((n) => n.fn === fn)?.l ?? "";
      const parts = [...node("frame.time_relative").matchAll(/([\d.]+) (day|hour|minute|second|millisecond|microsecond|nanosecond)s?\b/g)];
      assert.ok(parts.length, node("frame.time_relative"));
      const [s, f = ""] = /: (\d+(?:\.\d+)?)/.exec(node("frame.time_epoch"))[1].split(".");
      return { provisional: !!d.provisional, ref: !!node("frame.ref_time"), epoch: BigInt(s) * 1_000_000_000n + BigInt(f.padEnd(9, "0")), since: parts.reduce((t, [, v, unit]) => t + Number(v) * UNITS[unit], 0) };
    };
    const [first, before, at, after] = await Promise.all([early, ref - 2, ref, ref + 1].map(times));
    await stillProvisional(ref, before.provisional && at.provisional && after.provisional, "details not provisional");
    assert.deepEqual([at.ref, at.since, after.ref], [true, 0, false]);
    const seconds = (ns) => Number(ns) / 1e9;
    for (const [what, t, from, num] of [["after it", after, at, ref + 1], [`before it, from frame ${early}`, before, first, ref - 2]]) {
      const want = seconds(t.epoch - from.epoch);
      assert.ok(Math.abs(t.since - want) < 2e-6, `${what}: details ${t.since}, want ${want}`);
      assert.ok(Math.abs(Number(row.get(num).c[1]) - want) < 2e-6, `${what}: row ${row.get(num).c[1]}, want ${want}`);
    }
  }

  /** Throws `message` unless `ok`; one a full read covering `num` by now explains may be tried again. */
  async function stillProvisional(num, ok, message) {
    if (ok) return;
    throw Object.assign(new Error(message), { overtaken: (await state()).totalFrames >= num });
  }

  /** Details, selection, marks, the agent's tools and export of `num`, while it is provisional. */
  async function provisionalPacket(num) {
    const d = await api(`/api/frame?num=${num}`);
    await stillProvisional(num, d.provisional === true, `frame ${num} is not provisional`);
    assert.equal(d.num, num);
    assert.match(d.tree[0].l, new RegExp(`^Frame ${num}:`));
    assert.ok(Buffer.from(d.bytes, "base64").length > 40);
    await api("/api/select", { frame: num });
    await api("/api/marks", { frames: [num], note: "provisional" });
    marked = num;
    markedBytes = d.bytes;
    const s = await state();
    assert.equal(s.selected, num);
    assert.equal(s.selectedIndex, s.displayedFrames + (num - s.totalFrames - 1));
    // The agent: exact data only, and told what is still provisional
    const view = await tool("get_view_state");
    await stillProvisional(num, /newer packets .* provisional/i.test(view.text), view.text);
    const inspect = await tool("inspect_frame", { frame: num });
    await stillProvisional(num, inspect.error && /arrived after the last full read/.test(inspect.text), inspect.text);
    const go = await tool("goto_frame", { frame: num });
    const at = await state();
    assert.match(go.text, new RegExp(`^Selected frame ${num} \\(row \\d+ of \\d+\\)`));
    const [, row, of] = /row (\d+) of (\d+)/.exec(go.text).map(Number);
    assert.ok(row <= of && of >= at.totalFrames, go.text);
    // Only what reads from the full read says which frames it covers
    assert.doesNotMatch(go.text, /these results cover/);
    // Right after a full read lands nothing may be provisional for a moment
    let query;
    for (let k = 0; k < 20 && !/provisional/.test(query?.text ?? ""); k++, await sleep(100)) query = await tool("query_packets", { filter: "dns", limit: 1 });
    assert.match(liveLine(query.text), /^Live capture: these results cover frames 1-\d+, read in full; \d+ newer packets \(\d+-\d+\) arrived after the last full read; the user's list shows all of them provisionally; your tools see them with the next full read/);
    // An export writes provisional packets as captured, and says how many
    let exported;
    for (let k = 0; k < 30 && !/; 2 of them are newer packets/.test(exported?.text ?? ""); k++, await sleep(100)) {
      const s = await state();
      if ((s.tail?.frames ?? 0) < 2) continue;
      rmSync(join(work, "across.pcapng"), { force: true });
      exported = await tool("export_packets", { path: join(work, "across.pcapng"), which: "range", range: `${s.totalFrames - 1}-${s.totalFrames + 2}` });
    }
    assert.match(exported?.text ?? "", /^Wrote 4 packets .*; 2 of them are newer packets of the live capture, not read in full yet/);
    assert.doesNotMatch(exported.text, /these results cover/);
  }

  await check("with no list showing its end, the rows it gains aren't read ahead: no slices are written", async () => {
    /** The number of the newest slice written so far. */
    const newest = () => {
      const folder = readdirSync(wb.captureDir).find((n) => n.startsWith(".wirebuddy-slices-"));
      return Math.max(0, ...(folder ? readdirSync(join(wb.captureDir, folder)).map((f) => parseInt(f) || 0) : []));
    };
    // A list that showed its end has them read ahead a few seconds more
    await sleep(5000);
    const before = newest();
    let after = before;
    // Full reads may catch up for a moment: newer packets must have come meanwhile
    let waiting = 0;
    for (const end = Date.now() + 4000; Date.now() < end; await sleep(50)) {
      after = Math.max(after, newest());
      const s = await state();
      if (s.capture.status === "running") waiting = Math.max(waiting, s.tail?.displayed ?? 0);
    }
    assert.ok(waiting > 0, "no newer packets listed while it watched");
    assert.equal(after - before, 0, `${after - before} slices written`);
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
      if (marked) await api("/api/select", { frame: marked });
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
    // The list shows none of the newer packets
    let view;
    for (let k = 0; k < 5 && !liveLine(view?.text ?? ""); k++) view = await tool("get_view_state");
    assert.match(liveLine(view.text), /^Live capture: \d+ newer packets \(\d+-\d+\) arrived after the last full read; the user's list shows none of them: with this display filter they wait for a full read \(the filter uses tcp\.stream\)/);
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
    // Requests for each list piled up before, each slower than the last: past a few full reads
    const readMs = (await state()).tail?.readMs ?? 0;
    assert.ok(slowest < Math.max(8000, 4 * readMs), `a page took ${slowest} ms, a full read ${readMs} ms`);
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
    const name = readdirSync(wb.captureDir).find((n) => n.startsWith(".wirebuddy-slices-"));
    sliceTag = name.split("-")[2];
    const folder = join(wb.captureDir, name);
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
      // A PDU that a packet written after the row was read completes, or a reply: Wireshark couldn't tell then either
      const info = r.c[6]
        .replace(/ \[TCP PDU reassembled in (\d+)\]$/, (all, n) => (Number(n) > knownThen ? "" : all))
        .replace(/\(reply in (\d+)\)$/, (all, n) => (Number(n) > knownThen ? "(no response found!)" : all));
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
    assert.equal(d.bytes, markedBytes);
    if (!browser) return;
    let left;
    for (const end = Date.now() + 10_000; left !== 0 && Date.now() < end; await sleep(200)) left = await browser.evaluate("document.querySelectorAll('.pl-row.prov').length + (document.querySelector('.sb-live').hidden ? 0 : 1)");
    assert.equal(left, 0, "no provisional rows or status once read in full");
  });
  browser?.close();
  browser = null;
  await wb.close();
  servers.pop();

  // A panel whose offer matches only packets that come later, and another panel, off at first
  const offersHome = join(work, "offers-home");
  const offersExt = join(offersHome, ".local/share/wirebuddy/extensions");
  const panel = (name, offer) => {
    mkdirSync(join(offersExt, name, "panel"), { recursive: true });
    writeFileSync(join(offersExt, name, "extension.json"), JSON.stringify({ label: name, version: "1", panel: offer ? { offer } : {} }));
    writeFileSync(join(offersExt, name, "panel/main.js"), "wb.ready();\n");
  };
  // 3,000 packets a second: frames 120,002-126,000 are the 2 s past 40 s, a few seconds after the burst
  panel("later", { filter: "frame.time_relative > 40 && frame.time_relative < 42", text: "Show the later packets" });
  panel("other");
  writeFileSync(join(offersHome, ".local/share/wirebuddy/extensions-state.json"), JSON.stringify({ off: { other: "" } }));
  const offers = await server("offers", {}, offersHome);
  servers.push(offers);
  await check("a panel offer that only later packets match: offered once they came, checked from slices of the newer packets, not by reading the file again, and kept as all offers are checked again", async () => {
    await offers.api("/api/capture/start", { iface: "lo", filter: "burst 100000 rate 3000", autostop: {}, ring: null });
    const started = Date.now();
    let most = 0;
    let s;
    // Past the check as the file opens, before the live tail is there
    const sample = (file) => {
      if (Date.now() - started > 10_000 && file) most = Math.max(most, sharkdsReading(offers.pid, file).length);
    };
    for (;;) {
      s = await offers.state();
      sample(s.file);
      if (s.panelOffers.some((o) => o.name === "later")) break;
      assert.ok(Date.now() - started < 120_000, `not offered after 2 min: ${JSON.stringify({ packets: s.capture.packets, offers: s.panelOffers })}`);
      await sleep(250);
    }
    assert.ok(Date.now() - started > 10_000, "offered by a later check");
    const offered = Date.now() - started;
    // Turning a panel on checks all offers again: the one shown stays
    const on = await offers.tool("extensions", { action: "enable", name: "other" });
    assert.equal(on.error, false, on.text);
    for (const end = Date.now() + 20_000; Date.now() < end; await sleep(250)) {
      const now = await offers.state();
      sample(now.file);
      assert.ok(now.panelOffers.some((o) => o.name === "later"), `the offer went as all offers were checked again, at ${now.capture.packets} packets`);
    }
    // The view's two sharkds read the file; the panels' one doesn't
    assert.ok(most > 0 && most <= 2, `${most} sharkds had the capture open`);
    const events = (await offers.api("/api/events?after=0")).events.map((e) => e.text);
    assert.deepEqual(events.filter((t) => /offers failed/.test(t)), []);
    report.push(`panel offer: offered after ${Math.round(offered / 1000)} s at ${s.capture.packets} packets, the capture open in at most ${most} sharkds`);
  });
  await offers.close();
  servers.pop();

  // The profile's own columns, and an extension whose field turns into a frame number
  const colsHome = join(work, "columns-home");
  mkdirSync(join(colsHome, ".config/wireshark"), { recursive: true });
  const columns = ["No.", "%m", "Time", "%t", "Source", "%s", "Destination", "%d", "Protocol", "%p", "Length", "%L", "Info", "%i", "ACK of", "%Cus:tcp.analysis.acks_frame:0:R", "Bytes", "%B"];
  writeFileSync(join(colsHome, ".config/wireshark/preferences"), `gui.column.format:\n${columns.map((c) => `\t"${c}"`).join(",\n")}\n`);
  const backLua = join(colsHome, ".local/share/wirebuddy/extensions/back/back.lua");
  const back = (type) => `local p = Proto("back", "Three back")\nlocal f = ProtoField.${type}("back.frame", "Three back")\np.fields = { f }\nfunction p.dissector(tvb, pinfo, tree)\n  if pinfo.number > 3 then tree:add(p, tvb(0, 0)):add(f, tvb(0, 0), pinfo.number - 3) end\nend\nregister_postdissector(p)\n`;
  mkdirSync(dirname(backLua), { recursive: true });
  writeFileSync(join(dirname(backLua), "extension.json"), JSON.stringify({ label: "back", version: "1" }));
  writeFileSync(backLua, back("uint32"));
  const cols = await server("columns", {}, colsHome);
  servers.push(cols);
  // Provisional rows kept to compare with the exact ones
  let colsSeen = null;
  await check("frame-number fields in custom columns are renumbered, typed again when an extension changes; so is the display filter's reason to wait", async () => {
    await cols.api("/api/capture/start", { iface: "lo", filter: "burst 200000 rate 3000", autostop: {}, ring: null });
    await cols.until("provisional packets", 60_000, (s) => s.tail?.frames > 2000 && s.totalFrames > 0);
    assert.equal((await cols.api("/api/columns", { columns: [{ field: "back.frame", title: "Back" }] })).ok, true);
    // The field holds frame numbers now
    writeFileSync(backLua, back("framenum"));
    await cols.api("/api/extensions/reload", {});
    assert.equal((await cols.api("/api/filter", { filter: "back.frame > 0" })).ok, true);
    assert.equal((await cols.until("the tail", 30_000, (s) => s.tail)).tail.held, "the filter uses the frame number field back.frame");
    assert.equal((await cols.api("/api/filter", { filter: "" })).ok, true);
    const { s, rows } = await cols.rows((s) => s.displayedFrames, 500);
    const at = s.columns.indexOf("Back");
    const wrong = rows.filter((r) => r.p && r.c[at] !== String(r.num - 3));
    assert.ok(rows.some((r) => r.p), "provisional rows");
    assert.deepEqual(wrong.slice(0, 3).map((r) => `${r.num}: ${r.c[at]}`), []);
    colsSeen = { columns: s.columns, rows: rows.filter((r) => r.p) };
    // Full reads without it are quicker
    await cols.api("/api/columns", { columns: [] });
    rmSync(dirname(backLua), { recursive: true });
    await cols.api("/api/extensions/reload", {});
  });

  await check("a final full read that fails: newer packets stay provisional, and the view and the agent say why and how to retry", async () => {
    const file = (await cols.state()).file;
    chmodSync(file, 0);
    try {
      // A live read failed: none under way can still cover the last packets
      let failing = false;
      for (const end = Date.now() + 180_000; !failing && Date.now() < end; await sleep(200)) {
        failing = (await cols.api("/api/events?after=0")).events.some((e) => /^Live reload: /.test(e.text));
      }
      assert.ok(failing, "a live read failed");
      await cols.api("/api/capture/stop", {});
      const failed = await cols.until("the final read to fail", 60_000, (s) => s.capture.status === "idle" && s.loadError);
      assert.match(failed.loadError, /in full failed \(.*\); its newer packets stay provisional\. View › Reload tries again$/);
      assert.equal(failed.tail.exactAfter, "reload");
      assert.equal(failed.totalFrames + failed.tail.frames, failed.capture.packets);
      assert.ok((await cols.api("/api/events?after=0")).events.some((e) => e.level === "ERROR" && /in full failed/.test(e.text)));
      const view = await cols.tool("get_view_state");
      assert.match(liveLine(view.text), /your tools see them once a full read succeeds \(View › Reload\) \(reading .* in full failed/);
      const inspect = await cols.tool("inspect_frame", { frame: failed.capture.packets });
      assert.match(inspect.text, /: it is read in full once a full read succeeds \(View › Reload\)/);
    } finally {
      chmodSync(file, 0o600);
    }
    await cols.api("/api/reload", {});
    const done = await cols.state();
    assert.deepEqual([done.tail, done.loadError, done.totalFrames], [null, null, done.capture.packets]);
  });

  await check("profile columns read as Wireshark reads them: frame-number fields renumbered, Cumulative Bytes over the whole file", async () => {
    assert.ok(colsSeen, "provisional rows to compare");
    const nums = colsSeen.rows.map((r) => r.num);
    const { s, rows } = await cols.rows(nums[0] - 1, nums.length);
    assert.equal(s.tail, null);
    const exact = new Map(rows.map((r) => [r.num, r]));
    for (const name of ["ACK of", "Bytes"]) {
      const at = colsSeen.columns.indexOf(name);
      const diff = colsSeen.rows.filter((r) => r.c[at] !== exact.get(r.num)?.c[at]);
      assert.deepEqual(diff.slice(0, 3).map((r) => `${name} of ${r.num}: ${r.c[at]}, exact ${exact.get(r.num)?.c[at]}`), []);
      if (name === "ACK of") assert.ok(colsSeen.rows.some((r) => r.c[at]), "some ACKs");
    }
  });
  await cols.close();
  servers.pop();

  // Memory too short for any second copy of the capture; an extension that a kill mustn't be blamed on
  const leanHome = join(work, "lean-home");
  const tailLua = join(leanHome, ".local/share/wirebuddy/extensions/wbtail/wbtail.lua");
  mkdirSync(dirname(tailLua), { recursive: true });
  writeFileSync(join(dirname(tailLua), "extension.json"), JSON.stringify({ label: "wbtail", version: "1" }));
  writeFileSync(tailLua, `local p = Proto("wbtail", "Live tail")\nfunction p.dissector(tvb, pinfo, tree) tree:add(p, tvb()) end\nDissectorTable.get("udp.port"):add(59999, p)\n`);
  const lean = await server("lean", { WIREBUDDY_MEM_AVAILABLE: "1" }, leanHome);
  servers.push(lean);
  await check("short of memory: full reads wait, matches a later reply changes are listed anew, View › Reload reads in place once the requests in flight are answered", async () => {
    await lean.api("/api/capture/start", { iface: "lo", filter: "burst 200000 rate 3000", autostop: {}, ring: null });
    const paused = await lean.until("full reads to wait", 60_000, (s) => s.tail?.paused);
    assert.match(paused.tail.paused, /not enough free memory/);
    assert.equal(paused.tail.exactAfter, "stop");
    await sleep(2500);
    const later = await lean.state();
    assert.equal(later.totalFrames, paused.totalFrames, "no full read while they wait");
    assert.ok(later.tail.frames > paused.tail.frames);
    // A reply that came since changes provisional matches listed before: the list's rows are read again
    assert.equal((await lean.api("/api/filter", { filter: "icmp.resp_not_found" })).ok, true);
    const listed = await lean.until("provisional matches", 20_000, (s) => s.tail?.displayed > 0);
    await lean.until("matches checked again", 30_000, (s) => s.rowsSince > listed.rowsSince && s.filter === "icmp.resp_not_found" && s.totalFrames === paused.totalFrames);
    assert.equal((await lean.api("/api/filter", { filter: "" })).ok, true);
    // View › Reload: in place of the copy there is, under an agent's slow query and pages of rows
    const slow = lean.tool("query_packets", { filter: 'frame contains "wbzz" || tcp.payload contains "zzwb"', limit: 1 });
    await sleep(150);
    let reading = true;
    const failed = [];
    const pages = async () => {
      while (reading) {
        const s = await lean.state();
        await lean.api(`/api/rows?gen=${s.generation}&start=${Math.floor(Math.random() * s.displayedFrames)}&count=200`).catch((err) => err.status !== 409 && failed.push(err.message));
      }
    };
    const loops = [pages(), pages()];
    await lean.api("/api/reload", {});
    reading = false;
    await Promise.all(loops);
    const queried = await slow;
    assert.equal(queried.error, false, queried.text);
    assert.deepEqual(failed, []);
    const reread = await lean.state();
    assert.ok(reread.totalFrames > later.totalFrames && !reread.loading && reread.tail?.paused);
    const told = (await lean.api("/api/events?after=0")).events.map((e) => e.text);
    assert.ok(told.some((t) => /reads it again in place of the one it has/.test(t)), told.join("\n"));
  });

  await check("a final read in place killed for memory: no extension is blamed, the file is listed from slices, the agent hears why", async () => {
    const before = await lean.state();
    const seen = (await lean.api("/api/events?after=0")).events.length;
    // sharkd keeps the file it read open: the one reading it in place is a new one
    const holding = sharkdsReading(lean.pid, before.file);
    await lean.api("/api/capture/stop", {});
    // The kernel's OOM killer, as it ends the sharkd reading the file
    let victim = null;
    for (const end = Date.now() + 30_000; !victim && Date.now() < end; await sleep(20)) victim = sharkdsReading(lean.pid, before.file).find((p) => !holding.includes(p));
    assert.ok(victim, "a sharkd reading the file in place");
    process.kill(victim, "SIGKILL");
    const failed = await lean.until("the final read to fail", 60_000, (s) => s.capture.status === "idle" && !s.loading && s.loadError);
    assert.match(failed.loadError, /in full failed \(sharkd exited \(SIGKILL\)\), perhaps for lack of memory; its packets are listed provisionally from slices of the file/);
    assert.equal(failed.totalFrames, 0);
    assert.equal(failed.tail.frames, failed.capture.packets);
    assert.equal(failed.tail.exactAfter, "reload");
    assert.equal(failed.extensions.revision, before.extensions.revision);
    assert.equal((await lean.api("/api/filter/check?filter=wbtail")).ok, true);
    const events = (await lean.api("/api/events?after=0")).events.slice(seen).map((e) => e.text);
    assert.deepEqual(events.filter((t) => /crashed|an extension may/.test(t)), []);
    const { rows } = await lean.rows(Infinity, 100);
    assert.ok(rows.length === 100 && rows.every((r) => r.p && r.c.length), JSON.stringify(rows[0]));
    assert.equal(rows.at(-1).num, failed.capture.packets);
    // Nothing is read in full: no "newer" packets, no frames 1-0
    const inspect = await lean.tool("inspect_frame", { frame: failed.capture.packets });
    assert.match(inspect.text, /^Error: frame \d+ is not read in full, as no packet of the live capture is: it is read in full once a full read succeeds \(View › Reload\)/);
    const view = liveLine((await lean.tool("get_view_state")).text);
    assert.match(view, /^Live capture: none of the capture's \d+ packets is read in full; the user's list shows all of them provisionally; your tools see them once a full read succeeds \(View › Reload\)/);
    assert.doesNotMatch(view, /newer/);
  });

  await check("after it, a display filter checks the whole file, also one changed while a check runs", async () => {
    try {
      assert.equal((await lean.api("/api/filter", { filter: "dns" })).ok, true);
      await lean.until("the check to run", 60_000, (s) => s.tail?.unfiltered > 0 && s.tail.unfiltered < s.tail.frames);
      assert.equal((await lean.api("/api/filter", { filter: "tcp" })).ok, true);
      const s = await lean.until("every packet checked", 180_000, (s) => s.tail?.unfiltered === 0);
      assert.ok(s.tail.displayed > 0);
    } finally {
      await lean.api("/api/filter", { filter: "" });
    }
  });

  await check("View › Reload reads it in full, and while it runs the view and the agent say so", async () => {
    const reloading = lean.api("/api/reload", {});
    let settled = false;
    reloading.finally(() => (settled = true)).catch(() => {});
    let told = null;
    while (!settled && !told) {
      if ((await lean.state()).tail?.exactAfter === "reading") told = liveLine((await lean.tool("get_view_state")).text);
      else await sleep(30);
    }
    await reloading;
    assert.ok(told !== null, "the read under way seen");
    assert.match(told, /your tools see them once the full read under way finishes$/);
    const done = await lean.state();
    assert.deepEqual([done.tail, done.loadError, done.totalFrames], [null, null, done.capture.packets]);
  });
  await lean.close();
  servers.pop();

  // A sharkd whose full reads the checks hold under way and kill, as the kernel's OOM killer would
  const holdBin = join(work, "hold-bin");
  mkdirSync(holdBin);
  writeFileSync(join(holdBin, "sharkd"), `#!/bin/sh\nexec "${process.execPath}" "${join(root, "test/holding-sharkd.mjs")}" "$@"\n`);
  chmodSync(join(holdBin, "sharkd"), 0o755);
  const realSharkd = process.env.PATH.split(":").map((d) => join(d, "sharkd")).find((p) => existsSync(p));
  const hold = { HOLD: join(work, "sharkd-hold"), HELD: join(work, "sharkd-held"), KILL: join(work, "sharkd-kill") };
  const holding = (name, env = {}) => server(name, { PATH: `${holdBin}:${bin}:${process.env.PATH}`, REAL_SHARKD: realSharkd, ...hold, ...env });
  /** Starts a capture and holds a live full read under way until the packets after the last one are listed. */
  const heldRead = async (wb) => {
    await wb.api("/api/capture/start", { iface: "lo", filter: "burst 20000 rate 1000", autostop: {}, ring: null });
    await wb.until("a full read", 30_000, (s) => s.totalFrames > 0);
    writeFileSync(hold.HOLD, "");
    return wb.until("a full read held, and the tail", 30_000, (s) => existsSync(hold.HELD) && s.tail?.frames > 0);
  };
  const stopAndKill = async (wb) => {
    await wb.api("/api/capture/stop", {});
    await wb.until("the capture to stop", 15_000, (s) => s.capture.status === "idle");
    writeFileSync(hold.KILL, "");
    return wb.until("the final read", 60_000, (s) => !existsSync(hold.KILL) && !s.tail && !s.loading && s.totalFrames === s.capture.packets);
  };

  const held = await holding("held");
  servers.push(held);
  await check("a live full read that dies after the capture stopped: the final read still makes the view exact, and nothing says it failed", async () => {
    await heldRead(held);
    const done = await stopAndKill(held);
    assert.equal(done.loadError, null);
    const events = (await held.api("/api/events?after=0")).events.map((e) => e.text);
    assert.ok(events.some((t) => /^Live reload: sharkd exited \(SIGKILL\)/.test(t)), events.join("\n"));
    assert.deepEqual(events.filter((t) => /in full failed/.test(t)), []);
  });
  await held.close();
  servers.pop();

  const heldLean = await holding("held-lean", { WIREBUDDY_MEM_AVAILABLE: "1" });
  servers.push(heldLean);
  await check("short of memory, a read in place that dies after the capture stopped: the final read is what tries again, and says so", async () => {
    await heldRead(heldLean);
    rmSync(hold.HOLD);
    await heldLean.until("full reads to wait", 30_000, (s) => !existsSync(hold.HELD) && s.tail?.paused);
    // View › Reload reads in place, held under way
    writeFileSync(hold.HOLD, "");
    const reloading = heldLean.api("/api/reload", {}).catch((err) => err);
    await heldLean.until("the read in place", 30_000, () => existsSync(hold.HELD));
    const done = await stopAndKill(heldLean);
    assert.match((await reloading).message, /sharkd exited \(SIGKILL\)/);
    assert.equal(done.loadError, null);
    const failed = (await heldLean.api("/api/events?after=0")).events.filter((e) => /in full failed/.test(e.text)).map((e) => e.text);
    assert.equal(failed.length, 1, failed.join("\n"));
    assert.match(failed[0], /, perhaps for lack of memory; its packets are listed provisionally from slices of the file\. The full read after the capture's end tries again$/);
  });
  await heldLean.close();
  servers.pop();

  await check("SIGHUP ends a server as SIGTERM does, and a server removes the slices that killed ones left behind", async () => {
    assert.ok(sliceTag, "a folder of slices seen");
    const dir = join(work, "hup");
    const stale = join(dir, `.wirebuddy-slices-${sliceTag}-99999999-stale`);
    mkdirSync(stale, { recursive: true });
    writeFileSync(join(stale, "1.pcapng"), "x");
    const hupHome = join(work, "hup-home");
    mkdirSync(hupHome);
    const proc = spawn(process.execPath, [join(root, "dist/server/main.js"), "--port", "0", "--token", "t".repeat(32), "--capture-dir", dir], {
      env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, ...homeEnv(hupHome), WIREBUDDY_EXTENSIONS: "" },
      stdio: ["ignore", "pipe", "ignore"],
    });
    let out = "";
    proc.stdout.on("data", (d) => (out += d));
    const exited = new Promise((resolve) => proc.once("exit", (code, signal) => resolve({ code, signal })));
    try {
      for (const end = Date.now() + 15_000; !out.includes("UI at") && Date.now() < end; ) await sleep(50);
      assert.match(out, /UI at/);
      assert.equal(existsSync(stale), false, "the stale folder is gone");
      const instance = join(hupHome, "run/wirebuddy", `${proc.pid}.json`);
      assert.ok(existsSync(instance));
      proc.kill("SIGHUP");
      assert.deepEqual(await exited, { code: 0, signal: null });
      assert.equal(existsSync(instance), false);
    } finally {
      if (proc.exitCode === null && proc.signalCode === null) proc.kill("SIGTERM");
    }
  });

  await check("a server signalled as soon as its URL is out ends as cleanly", async () => {
    const quickHome = join(work, "quick-home");
    mkdirSync(quickHome);
    for (let k = 0; k < 5; k++) {
      const proc = spawn(process.execPath, [join(root, "dist/server/main.js"), "--port", "0", "--token", "t".repeat(32), "--capture-dir", join(work, "quick")], {
        env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, ...homeEnv(quickHome), WIREBUDDY_EXTENSIONS: "" },
        stdio: ["ignore", "pipe", "ignore"],
      });
      let out = "";
      let sent = false;
      proc.stdout.on("data", (d) => {
        if (!sent && (out += d).includes("UI at")) sent = proc.kill("SIGHUP");
      });
      const timer = setTimeout(() => proc.kill("SIGKILL"), 15_000);
      const exited = await new Promise((resolve) => proc.once("exit", (code, signal) => resolve({ code, signal })));
      clearTimeout(timer);
      assert.deepEqual(exited, { code: 0, signal: null }, `server ${k + 1}`);
      assert.equal(existsSync(join(quickHome, "run/wirebuddy", `${proc.pid}.json`)), false);
    }
  });
} finally {
  browser?.close();
  for (const s of servers) await s.close().catch(() => {});
  rmSync(work, { recursive: true, force: true });
}
for (const line of report) console.log(`     ${line}`);
console.log(failures ? `${failures} check(s) failed` : "all checks passed");
process.exit(failures ? 1 : 0);
