// End-to-end check of the HTTP API against test/fixtures/http.pcapng.
// Usage: node test/api-smoke.mjs   (after npm run build)
import { spawn, execFileSync } from "node:child_process";
import { copyFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { gzipSync } from "node:zlib";
import { WebSocket } from "ws";
import { tmpdir } from "node:os";
import { request } from "node:http";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import assert from "node:assert/strict";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const fixture = join(root, "test/fixtures/http.pcapng");
const token = "smoke-test-token";

// A home of its own: the tester's Wireshark preferences, profiles and plugins don't apply
const home = mkdtempSync(join(tmpdir(), "wirebuddy-home-"));
const env = { ...process.env, HOME: home, XDG_CONFIG_HOME: join(home, ".config") };
const server = spawn(process.execPath, [join(root, "dist/server/main.js"), "--port", "0", "--token", token], {
  stdio: ["ignore", "pipe", "inherit"],
  env,
});

/** Live capture needs dumpcap rights (wireshark group); without them those checks are skipped. */
function canCapture() {
  try {
    execFileSync("dumpcap", ["-L", "-i", "lo"], { stdio: "ignore", timeout: 10000 });
    return true;
  } catch {
    return false;
  }
}
const capture = canCapture();
const base = await new Promise((resolve, reject) => {
  server.stdout.setEncoding("utf8");
  server.stdout.on("data", (d) => {
    const m = /UI at (http:\/\/[^/]+)\//.exec(d);
    if (m) resolve(m[1]);
  });
  server.on("exit", (code) => reject(new Error(`server exited with ${code}`)));
});

async function api(path, body) {
  const res = await fetch(base + path, {
    method: body === undefined ? "GET" : "POST",
    headers: { "X-WireBuddy-Token": token, "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const json = await res.json();
  return { status: res.status, json };
}

let failures = 0;
async function checkCapture(name, fn) {
  if (capture) await check(name, fn);
  else console.log(`skip ${name}: dumpcap may not capture on lo here`);
}

async function check(name, fn) {
  try {
    await fn();
    console.log(`ok   ${name}`);
  } catch (err) {
    failures++;
    console.log(`FAIL ${name}: ${err.message}`);
  }
}

try {
  await check("rejects requests without token", async () => {
    const res = await fetch(base + "/api/state");
    assert.equal(res.status, 401);
  });
  await check("rejects foreign Host header", async () => {
    // fetch() always sends the real host, so use a raw request
    const status = await new Promise((resolve, reject) => {
      const req = request(base + "/api/state", { headers: { "X-WireBuddy-Token": token, host: "evil.example" } }, (res) => {
        res.resume();
        resolve(res.statusCode);
      });
      req.on("error", reject);
      req.end();
    });
    assert.equal(status, 403);
  });
  await check("rejects cross-site Origin", async () => {
    const res = await fetch(base + "/api/state", { headers: { "X-WireBuddy-Token": token, origin: "https://evil.example" } });
    assert.equal(res.status, 403);
  });
  await check("serves the UI shell", async () => {
    const res = await fetch(base + "/");
    assert.equal(res.status, 200);
  });

  await check("open fixture", async () => {
    const r = await api("/api/open", { path: fixture });
    assert.equal(r.status, 200, JSON.stringify(r.json));
    const s = (await api("/api/state")).json;
    assert.equal(s.totalFrames, 29);
    assert.equal(s.displayedFrames, 29);
    assert.deepEqual(s.columns.slice(0, 2), ["No.", "Time"]);
  });

  let gen;
  await check("rows page", async () => {
    gen = (await api("/api/state")).json.generation;
    const r = await api(`/api/rows?gen=${gen}&start=10&count=5`);
    assert.equal(r.status, 200);
    assert.deepEqual(r.json.rows.map((x) => x.num), [11, 12, 13, 14, 15]);
    assert.match(r.json.rows[0].bg, /^[0-9a-f]{6}$/);
  });
  await check("stale generation gives 409", async () => {
    const r = await api(`/api/rows?gen=${gen - 1}&start=0&count=5`);
    assert.equal(r.status, 409);
  });

  await check("filter check: valid / invalid with BPF hint / warning", async () => {
    assert.equal((await api("/api/filter/check?filter=" + encodeURIComponent("tcp.port == 80"))).json.ok, true);
    const bad = (await api("/api/filter/check?filter=" + encodeURIComponent("tcp port 80"))).json;
    assert.equal(bad.ok, false);
    assert.match(bad.error, /tcp\.port == 80/);
    const warn = (await api("/api/filter/check?filter=" + encodeURIComponent("bootp"))).json;
    assert.ok(warn.ok && warn.warning, JSON.stringify(warn));
  });
  await check("complete", async () => {
    const r = (await api("/api/filter/complete?field=http.re")).json;
    assert.ok(r.fields.some((f) => f.f === "http.request"), JSON.stringify(r).slice(0, 200));
  });

  await check("apply filter http", async () => {
    const r = await api("/api/filter", { filter: "http" });
    assert.equal(r.json.ok, true);
    const s = (await api("/api/state")).json;
    assert.equal(s.displayedFrames, 4);
    const rows = (await api(`/api/rows?gen=${s.generation}&start=0&count=10`)).json.rows;
    assert.deepEqual(rows.map((x) => x.num), [4, 12, 21, 25]);
  });
  await check("invalid filter is rejected and keeps the old one", async () => {
    const r = await api("/api/filter", { filter: "http.foo ==" });
    assert.equal(r.json.ok, false);
    assert.equal((await api("/api/state")).json.filter, "http");
  });

  await check("select maps to index under the filter", async () => {
    await api("/api/select", { frame: 21 });
    const s = (await api("/api/state")).json;
    assert.equal(s.selected, 21);
    assert.equal(s.selectedIndex, 2);
    assert.equal(s.selectedBy, "user");
  });

  await check("frame detail with reassembly data source", async () => {
    const f = (await api("/api/frame?num=12")).json;
    assert.equal(f.num, 12);
    assert.equal(f.ds.length, 1);
    assert.ok(f.followers.some(([p, flt]) => p === "TCP" && flt === "tcp.stream eq 0"));
    assert.equal(f.row.num, 12);
    const http = f.tree.find((n) => n.fn === "http");
    assert.equal(http.ds, 1);
  });

  await check("marks", async () => {
    await api("/api/marks", { frames: [4, 12], note: "test" });
    assert.equal((await api("/api/state")).json.marks.length, 2);
    await api("/api/marks/clear", { frames: [4] });
    assert.deepEqual((await api("/api/state")).json.marks.map((m) => m.frame), [12]);
  });

  await check("stats", async () => {
    const phs = (await api("/api/stats/phs")).json;
    assert.equal(phs[0].proto, "frame");
    const conv = (await api("/api/stats/conv?type=tcp")).json;
    assert.equal(conv.length, 2);
    assert.ok(conv[0].filter.includes("tcp.port"));
    const endpt = (await api("/api/stats/endpt?type=tcp")).json;
    assert.ok(endpt.length >= 2, JSON.stringify(endpt).slice(0, 200));
    assert.equal((await api("/api/stats/conv?type=bogus")).status, 400);
  });

  await check("follow", async () => {
    const r = (await api("/api/follow?proto=TCP&filter=" + encodeURIComponent("tcp.stream eq 0"))).json;
    assert.equal(r.client.bytes, 86);
    assert.equal(r.server.bytes, 81243);
    assert.equal(r.payloads[0].server, false);
    const missing = await api("/api/follow?proto=TCP&filter=" + encodeURIComponent("tcp.stream eq 7"));
    assert.ok(missing.status >= 400 && missing.status < 500, `status ${missing.status}`);
    assert.match(missing.json.error, /no TCP stream matches tcp\.stream eq 7/);
  });

  await checkCapture("capture interfaces and filter check", async () => {
    const ifs = (await api("/api/capture/interfaces")).json;
    assert.ok(ifs.some((i) => i.name === "lo" && i.loopback));
    assert.equal((await api("/api/capture/check?iface=lo&filter=" + encodeURIComponent("tcp port 80"))).json.ok, true);
    const bad = (await api("/api/capture/check?iface=lo&filter=" + encodeURIComponent("tcp portt 80"))).json;
    assert.equal(bad.ok, false);
    assert.match(bad.error, /Invalid capture filter/);
  });

  await check("display filter over sharkd's 8 KiB line limit fails fast and leaves the viewer usable", async () => {
    const long = "frame.number in {" + Array.from({ length: 2000 }, (_, i) => i + 1).join(" ") + "}";
    const r = await api("/api/filter", { filter: long });
    assert.equal(r.json.ok, false);
    assert.match(r.json.error, /too long/);
    assert.equal((await api("/api/filter", { filter: "" })).json.ok, true);
  });
  await check("malformed URL gets 400 and the server keeps running", async () => {
    const status = await new Promise((resolve, reject) => {
      const req = request(base + "/%E0%A4%A", (res) => {
        res.resume();
        resolve(res.statusCode);
      });
      req.on("error", reject);
      req.end();
    });
    assert.equal(status, 400);
    assert.equal((await api("/api/state")).status, 200);
  });
  await check("a failed open leaves the current capture untouched", async () => {
    await api("/api/select", { frame: 5 });
    await api("/api/marks", { frames: [3], note: "keep" });
    const before = (await api("/api/state")).json;
    const r = await api("/api/open", { path: join(root, "package.json") });
    assert.equal(r.status, 400);
    assert.match(r.json.error, /not a capture file/);
    const after = (await api("/api/state")).json;
    assert.equal(after.file, before.file);
    assert.equal(after.generation, before.generation);
    assert.equal(after.selected, 5);
    assert.equal(after.marks.length, before.marks.length);
    assert.ok(after.loadError);
  });

  await check("custom columns", async () => {
    await api("/api/filter", { filter: "" });
    const r = await api("/api/columns", { columns: [{ field: "http.response.code", title: "" }] });
    assert.equal(r.json.ok, true, JSON.stringify(r.json));
    const s = (await api("/api/state")).json;
    assert.equal(s.columns.at(-1), "Status Code");
    assert.deepEqual(s.customColumns, [{ field: "http.response.code", title: "Status Code" }]);
    const rows = (await api(`/api/rows?gen=${s.generation}&start=11&count=1`)).json.rows;
    assert.equal(rows[0].c.at(-1), "200");
    assert.equal(rows[0].c.length, s.columns.length);
    const bad = (await api("/api/columns", { columns: [{ field: "no.such.field", title: "" }] })).json;
    assert.equal(bad.ok, false);
    assert.equal((await api("/api/columns", { columns: [] })).json.ok, true);
    assert.equal((await api("/api/state")).json.customColumns.length, 0);
  });

  await check("expert info, optionally limited to a display filter", async () => {
    const all = (await api("/api/stats/expert")).json;
    assert.equal(all.length, 12);
    assert.ok(all.every((e) => e.frame && e.severity && e.message));
    const one = (await api("/api/stats/expert?filter=" + encodeURIComponent("tcp.stream eq 1"))).json;
    assert.equal(one.length, 6);
    assert.equal((await api("/api/stats/expert?filter=" + encodeURIComponent("tcp port 80"))).status, 400);
    const phs = (await api("/api/stats/phs?filter=http")).json;
    assert.equal(phs[0].frames, 4);
  });

  await check("I/O graph and time to frame", async () => {
    const graphs = encodeURIComponent(JSON.stringify([{ metric: "packets", filter: "" }, { metric: "bytes", filter: "http" }]));
    const r = (await api(`/api/stats/iograph?interval=1&graphs=${graphs}`)).json;
    assert.equal(r.interval, 1);
    assert.equal(r.series.length, 2);
    assert.equal(r.series[0].values.reduce((a, b) => a + b, 0), 29);
    assert.equal(r.series[0].values.length, 11);
    assert.equal(r.series[1].values.reduce((a, b) => a + b, 0), 16422);
    assert.equal((await api("/api/frame-at?t=0.005")).json.frame, 18);
    assert.equal((await api("/api/frame-at?t=99")).json.frame, null);
  });

  await check("export specified packets", async () => {
    const dir = mkdtempSync(join(tmpdir(), "wirebuddy-export-test-"));
    try {
      const count = (f) => Number(/Number of packets:\s+(\d+)/.exec(execFileSync("capinfos", ["-c", f], { encoding: "utf8" }))[1]);
      const out = join(dir, "range.pcapng");
      const r = await api("/api/export", { path: out, which: "range", range: "21,23-25" });
      assert.equal(r.status, 200, JSON.stringify(r.json));
      assert.equal(r.json.frames, 4);
      assert.equal(count(out), 4);
      const again = await api("/api/export", { path: out, which: "range", range: "1-3" });
      assert.equal(again.status, 400);
      assert.match(again.json.error, /already exists/);
      assert.equal((await api("/api/export", { path: out, which: "range", range: "1-3", overwrite: true })).json.frames, 3);
      assert.equal(count(out), 3);
      await api("/api/filter", { filter: "http" });
      const shown = await api("/api/export", { path: join(dir, "shown.pcap"), which: "displayed" });
      assert.equal(shown.json.frames, 4);
      assert.equal(count(join(dir, "shown.pcap")), 4);
      await api("/api/filter", { filter: "" });
      assert.equal((await api("/api/export", { path: join(dir, "x.txt"), which: "all" })).status, 400);
      const spaced = await api("/api/export", { path: join(dir, "spaced.pcapng"), which: "range", range: "1 -3, 20- 22" });
      assert.equal(spaced.json.frames, 6, JSON.stringify(spaced.json));
      const alias = await api("/api/export", { path: join(dirname(fixture), ".", "http.pcapng"), which: "range", range: "1", overwrite: true });
      assert.equal(alias.status, 400);
      assert.match(alias.json.error, /open capture/);
      assert.equal((await api("/api/export", { path: join(dir, "bad.pcapng"), which: "range", range: "5-99" })).status, 400);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  const state = async () => (await api("/api/state")).json;

  await check("select with rows sets selectedRows and selectedCount", async () => {
    await api("/api/filter", { filter: "" });
    assert.equal((await api("/api/select", { frame: 5, rows: [[6, 8], [2, 4], [0, 0], [3, 3]] })).status, 200);
    let s = await state();
    assert.equal(s.selected, 5);
    assert.equal(s.selectedIndex, 4);
    assert.deepEqual(s.selectedRows, [[0, 0], [2, 4], [6, 8]]);
    assert.equal(s.selectedCount, 7);
    await api("/api/select", { frame: 7 });
    s = await state();
    assert.deepEqual([s.selectedRows, s.selectedCount], [[[6, 6]], 1]);
    await api("/api/select", { frame: 7, rows: [] });
    s = await state();
    assert.deepEqual([s.selected, s.selectedRows, s.selectedCount], [7, [], 0]);
    await api("/api/select", { frame: null });
    s = await state();
    assert.deepEqual([s.selected, s.selectedRows, s.selectedCount], [null, [], 0]);
  });
  await check("invalid select rows give 400 and change nothing", async () => {
    await api("/api/select", { frame: 3, rows: [[1, 2]] });
    const tooMany = Array.from({ length: 10001 }, () => [0, 0]);
    for (const rows of [[[3, 2]], [[0, 29]], [[-1, 0]], [[1.5, 2]], [[1]], [[1, 2, 3]], [["1", "2"]], "0-3", { a: 1 }, tooMany]) {
      const r = await api("/api/select", { frame: 4, rows });
      assert.equal(r.status, 400, `${JSON.stringify(rows).slice(0, 40)}: ${JSON.stringify(r.json)}`);
    }
    const s = await state();
    assert.deepEqual([s.selected, s.selectedRows], [3, [[1, 2]]]);
  });
  await check("rows from another file or filter give 409 and change nothing", async () => {
    const file = (await state()).file;
    assert.equal((await api("/api/select", { frame: 4, rows: [[2, 5]], view: { file, filter: "" } })).status, 200);
    assert.equal((await api("/api/select", { frame: 4, rows: [[0, 1]], view: { file, filter: "tcp" } })).status, 409);
    assert.equal((await api("/api/select", { frame: 4, rows: [[0, 1]], view: { file: "/elsewhere.pcapng", filter: "" } })).status, 409);
    assert.equal((await api("/api/select", { frame: 4, rows: [[0, 1]], view: "x" })).status, 400);
    assert.deepEqual((await state()).selectedRows, [[2, 5]]);
  });
  await check("rows from a list rebuilt since give 409, a plain reload keeps them valid", async () => {
    await api("/api/filter", { filter: "tcp" });
    let s = await state();
    const view = { file: s.file, filter: "tcp", generation: s.generation };
    assert.equal((await api("/api/select", { frame: 5, rows: [[1, 3]], view })).status, 200);
    await api("/api/reload", {});
    assert.equal((await api("/api/select", { frame: 5, rows: [[2, 3]], view })).status, 200);
    // Same file and filter text, but the list was rebuilt in between
    await api("/api/filter", { filter: "http" });
    await api("/api/filter", { filter: "tcp" });
    assert.equal((await api("/api/select", { frame: 5, rows: [[0, 1]], view })).status, 409);
    s = await state();
    assert.equal((await api("/api/select", { frame: 5, rows: [[0, 1]], view: { ...view, generation: s.generation } })).status, 200);
    assert.equal((await api("/api/select", { frame: 5, rows: [[0, 1]], view: { ...view, generation: 1.5 } })).status, 400);
    await api("/api/filter", { filter: "" });
  });
  await check("a display filter change resets selectedRows to the current row", async () => {
    await api("/api/select", { frame: 12, rows: [[0, 28]] });
    assert.equal((await state()).selectedCount, 29);
    await api("/api/filter", { filter: "http" });
    let s = await state();
    assert.deepEqual([s.selectedIndex, s.selectedRows, s.selectedCount], [1, [[1, 1]], 1]);
    await api("/api/select", { frame: 4, rows: [[0, 3]] });
    await api("/api/filter", { filter: "http.response" });
    s = await state();
    assert.deepEqual([s.selected, s.selectedIndex, s.selectedRows, s.selectedCount], [4, -1, [], 0]);
    await api("/api/filter", { filter: "" });
  });
  await check("opening or closing a file clears selectedRows", async () => {
    await api("/api/select", { frame: 3, rows: [[0, 5]] });
    assert.equal((await api("/api/open", { path: fixture })).status, 200);
    let s = await state();
    assert.deepEqual([s.selected, s.selectedRows, s.selectedCount], [null, [], 0]);
    await api("/api/select", { frame: 3, rows: [[0, 5]] });
    await api("/api/close", {});
    s = await state();
    assert.deepEqual([s.selected, s.selectedRows, s.selectedCount], [null, [], 0]);
    assert.equal((await api("/api/open", { path: fixture })).status, 200);
  });
  await check("a re-dissection of the same file keeps selectedRows", async () => {
    const dir = mkdtempSync(join(tmpdir(), "wirebuddy-rows-test-"));
    try {
      const keys = join(dir, "keys.log");
      writeFileSync(keys, "");
      await api("/api/filter", { filter: "http" });
      await api("/api/select", { frame: 12, rows: [[0, 1], [3, 3]] });
      const gen = (await state()).generation;
      assert.equal((await api("/api/tls", { keylog: keys })).status, 200);
      const s = await state();
      assert.ok(s.generation > gen, "the capture is re-dissected");
      assert.deepEqual([s.selected, s.selectedRows, s.selectedCount], [12, [[0, 1], [3, 3]], 3]);
    } finally {
      await api("/api/tls", { keylog: null });
      await api("/api/filter", { filter: "" });
      rmSync(dir, { recursive: true, force: true });
    }
  });

  await check("export selected rows, also under a display filter", async () => {
    const dir = mkdtempSync(join(tmpdir(), "wirebuddy-export-sel-test-"));
    try {
      const info = (f) => {
        const out = execFileSync("capinfos", ["-M", "-c", "-d", f], { encoding: "utf8" });
        return [Number(/Number of packets:\s+(\d+)/.exec(out)[1]), Number(/Data size:\s+(\d+) bytes/.exec(out)[1])];
      };
      await api("/api/select", { frame: 3, rows: [[0, 2], [10, 10]] });
      const plain = await api("/api/export", { path: join(dir, "plain.pcapng"), which: "selected" });
      assert.equal(plain.json.frames, 4, JSON.stringify(plain.json));
      // Frames 1-3 and 11
      assert.deepEqual(info(join(dir, "plain.pcapng")), [4, 74 + 74 + 66 + 66]);
      await api("/api/filter", { filter: "http" });
      await api("/api/select", { frame: 21, rows: [[0, 0], [2, 3]] });
      const filtered = await api("/api/export", { path: join(dir, "filtered.pcapng"), which: "selected" });
      assert.equal(filtered.json.frames, 3, JSON.stringify(filtered.json));
      // Frames 4, 21 and 25, not 1, 3 and 4
      assert.deepEqual(info(join(dir, "filtered.pcapng")), [3, 152 + 152 + 535]);
      await api("/api/select", { frame: 5 });
      assert.equal((await state()).selectedCount, 0);
      const hidden = await api("/api/export", { path: join(dir, "hidden.pcapng"), which: "selected" });
      assert.equal(hidden.json.frames, 1, "falls back to the selected frame");
      await api("/api/select", { frame: null });
      const none = await api("/api/export", { path: join(dir, "none.pcapng"), which: "selected" });
      assert.equal(none.status, 400);
      assert.match(none.json.error, /no packets to export/);
    } finally {
      await api("/api/filter", { filter: "" });
      rmSync(dir, { recursive: true, force: true });
    }
  });

  await check("marks/toggle flips the marks of the selected frames", async () => {
    await api("/api/marks/clear", {});
    await api("/api/marks", { frames: [3, 4], note: "x" });
    await api("/api/select", { frame: 4, rows: [[2, 5]] });
    assert.equal((await api("/api/marks/toggle", {})).status, 200);
    const marks = (await state()).marks;
    assert.deepEqual(marks, [{ frame: 5, note: "", by: "user" }, { frame: 6, note: "", by: "user" }]);
    await api("/api/marks/toggle", {});
    assert.deepEqual((await state()).marks.map((m) => m.frame), [3, 4]);
    // No selected rows: the selected frame
    await api("/api/filter", { filter: "http" });
    await api("/api/select", { frame: 5 });
    await api("/api/marks/toggle", {});
    assert.deepEqual((await state()).marks.map((m) => m.frame), [3, 4, 5]);
    await api("/api/select", { frame: null });
    await api("/api/marks/toggle", {});
    assert.deepEqual((await state()).marks.map((m) => m.frame), [3, 4, 5]);
    await api("/api/filter", { filter: "" });
  });
  await check("marks/displayed marks and unmarks the displayed frames", async () => {
    await api("/api/marks/clear", {});
    await api("/api/marks", { frames: [3, 12], note: "keep" });
    await api("/api/filter", { filter: "http" });
    assert.equal((await api("/api/marks/displayed", { on: true })).status, 200);
    const marks = (await state()).marks;
    assert.deepEqual(marks.map((m) => m.frame), [3, 4, 12, 21, 25]);
    assert.equal(marks.find((m) => m.frame === 12).note, "keep");
    assert.equal(marks.find((m) => m.frame === 21).by, "user");
    assert.equal((await api("/api/marks/displayed", { on: false })).status, 200);
    assert.deepEqual((await state()).marks.map((m) => m.frame), [3]);
    assert.equal((await api("/api/marks/displayed", {})).status, 400);
    assert.equal((await api("/api/marks/displayed", { on: "yes" })).status, 400);
    await api("/api/filter", { filter: "" });
    await api("/api/marks/displayed", { on: true });
    assert.equal((await state()).marks.length, 29);
    await api("/api/marks/clear", {});
  });

  const find = async (filter, from, dir) => api(`/api/find?filter=${encodeURIComponent(filter)}&from=${from}&dir=${dir}`);
  await check("find forward, backward, wrapping and without match", async () => {
    await api("/api/filter", { filter: "" });
    assert.deepEqual((await find("http.request", 0, 1)).json, { frame: 4, index: 3, wrapped: false });
    assert.deepEqual((await find("http.request", 4, 1)).json, { frame: 21, index: 20, wrapped: false });
    assert.deepEqual((await find("http.request", 21, 1)).json, { frame: 4, index: 3, wrapped: true });
    assert.deepEqual((await find("http.request", 21, -1)).json, { frame: 4, index: 3, wrapped: false });
    assert.deepEqual((await find("http.request", 4, -1)).json, { frame: 21, index: 20, wrapped: true });
    assert.deepEqual((await find("http.request", 0, -1)).json, { frame: 21, index: 20, wrapped: false });
    assert.deepEqual((await find("tcp.flags.syn == 1 && tcp.stream eq 1", 18, 1)).json, { frame: 19, index: 18, wrapped: false });
    assert.deepEqual((await find("dns", 5, 1)).json, { frame: null, index: -1, wrapped: false });
    assert.deepEqual((await find("dns", 5, -1)).json, { frame: null, index: -1, wrapped: false });
  });
  await check("find rejects invalid filters and parameters", async () => {
    const bad = await find("http.foo ==", 0, 1);
    assert.equal(bad.status, 400);
    assert.match(bad.json.error, /invalid display filter/);
    assert.match((await find("tcp port 80", 0, 1)).json.error, /tcp\.port == 80/);
    assert.equal((await find("", 0, 1)).status, 400);
    assert.equal((await find("http", 0, 2)).status, 400);
    assert.equal((await find("http", 1.5, 1)).status, 400);
    assert.equal((await find("http", -1, 1)).status, 400);
    assert.equal((await api("/api/find?filter=http&dir=1")).status, 400);
  });
  await check("find searches only the displayed frames", async () => {
    await api("/api/filter", { filter: "tcp.stream eq 1" });
    assert.deepEqual((await find("http", 0, 1)).json, { frame: 21, index: 3, wrapped: false });
    assert.deepEqual((await find("http", 25, 1)).json, { frame: 21, index: 3, wrapped: true });
    assert.deepEqual((await find("http.request", 30, -1)).json, { frame: 21, index: 3, wrapped: false });
    assert.deepEqual((await find("frame.number < 10", 0, 1)).json, { frame: null, index: -1, wrapped: false });
    await api("/api/filter", { filter: "http || tcp.flags.syn == 1" });
    assert.deepEqual((await find("tcp.stream eq 1", 12, 1)).json, { frame: 18, index: 4, wrapped: false });
    await api("/api/filter", { filter: "" });
  });

  await check("reload re-reads the file and keeps marks and selection", async () => {
    await api("/api/filter", { filter: "" });
    await api("/api/marks/clear", {});
    await api("/api/marks", { frames: [2, 9], note: "keep me" });
    await api("/api/select", { frame: 9, rows: [[3, 8]] });
    const before = await state();
    assert.equal((await api("/api/reload", {})).status, 200);
    const s = await state();
    assert.ok(s.generation > before.generation);
    assert.deepEqual(s.marks.map((m) => [m.frame, m.note]), [[2, "keep me"], [9, "keep me"]]);
    assert.deepEqual([s.selected, s.selectedRows], [9, [[3, 8]]]);
    await api("/api/marks/clear", {});
  });
  await check("rowsSince follows list rebuilds; a shrunk file resets the selected rows", async () => {
    const dir = mkdtempSync(join(tmpdir(), "wirebuddy-shrink-"));
    const copy = join(dir, "copy.pcapng");
    copyFileSync(fixture, copy);
    try {
      await api("/api/filter", { filter: "" });
      assert.equal((await api("/api/open", { path: copy })).status, 200);
      let s = await state();
      assert.equal(s.rowsSince, s.generation);
      await api("/api/select", { frame: 5, rows: [[2, 20]] });
      await api("/api/reload", {});
      s = await state();
      assert.ok(s.rowsSince < s.generation, "a plain re-read keeps rowsSince");
      assert.deepEqual(s.selectedRows, [[2, 20]]);
      execFileSync("editcap", ["-r", fixture, copy, "1-10"]);
      await api("/api/reload", {});
      s = await state();
      assert.equal(s.totalFrames, 10);
      assert.equal(s.rowsSince, s.generation);
      assert.deepEqual([s.selected, s.selectedRows], [5, [[4, 4]]]);
      // A frame found in another view (Find) is refused like stale rows
      assert.equal((await api("/api/select", { frame: 3, view: { file: "/elsewhere.pcapng", filter: "" } })).status, 409);
      assert.equal((await api("/api/select", { frame: 3, view: { file: s.file, filter: "" } })).status, 200);
    } finally {
      await api("/api/open", { path: fixture });
      rmSync(dir, { recursive: true, force: true });
    }
  });
  await check("events: problems and user activity for the agent, long-poll for watchers", async () => {
    const start = (await api(`/api/events?after=${Number.MAX_SAFE_INTEGER}`)).json;
    assert.equal((await state()).agent.attached, false);
    assert.equal((await api("/api/open", { path: "/nonexistent/missing.pcapng" })).status, 400);
    await api("/api/filter", { filter: "tcp.port ==== 1" });
    await api("/api/filter", { filter: "http" });
    await api("/api/filter", { filter: "" });
    assert.equal((await api("/api/events", { level: "ERROR", text: "Page error: boom", details: { at: "app.js:1:2" } })).status, 200);
    const { events, last } = (await api(`/api/events?after=${start.last}`)).json;
    const texts = events.map((e) => `${e.level} ${e.text}`);
    assert.ok(texts.some((t) => /^ERROR Opening a file failed: .*missing\.pcapng/.test(t)), texts.join("\n"));
    assert.ok(texts.some((t) => /^WARNING The user's display filter "tcp\.port ==== 1" was rejected/.test(t)), texts.join("\n"));
    assert.ok(texts.includes('INFO The user applied the display filter "http"'), texts.join("\n"));
    assert.ok(texts.includes("INFO The user cleared the display filter"), texts.join("\n"));
    assert.ok(texts.includes("ERROR Page error: boom"), texts.join("\n"));
    assert.ok((await state()).agent.pending >= 3);
    // Taking marks them seen; a watcher's long-poll wakes up for the next problem only
    const taken = (await api("/api/events/take", {})).json.events;
    assert.ok(taken.length >= 5);
    assert.equal((await state()).agent.pending, 0);
    const t0 = Date.now();
    const quiet = (await api(`/api/events?after=${last}&wait=300&problems=1`)).json;
    assert.deepEqual(quiet.events, []);
    assert.ok(Date.now() - t0 >= 250, "waited");
    const poll = api(`/api/events?after=${last}&wait=10000&problems=1`);
    await api("/api/filter", { filter: "frame" });
    await api("/api/events", { level: "WARNING", text: "Page error: second" });
    const woke = (await poll).json;
    assert.deepEqual(woke.events.map((e) => e.text), ["Page error: second"]);
    await api("/api/filter", { filter: "" });
    await api("/api/events/take", {});
  });
  await check("TLS key log setting", async () => {
    const dir = mkdtempSync(join(tmpdir(), "wirebuddy-tls-test-"));
    try {
      assert.equal((await api("/api/tls", { keylog: join(dir, "missing.log") })).status, 400);
      const keys = join(dir, "keys.log");
      writeFileSync(keys, "");
      const gen = (await api("/api/state")).json.generation;
      assert.equal((await api("/api/tls", { keylog: keys })).status, 200);
      const s = (await api("/api/state")).json;
      assert.equal(s.tlsKeylog, keys);
      assert.ok(s.generation > gen, "the capture is re-dissected");
      const listing = (await api("/api/files?kind=any&dir=" + encodeURIComponent(dir))).json;
      assert.ok(listing.entries.some((e) => e.name === "keys.log"));
      await api("/api/tls", { keylog: null });
      assert.equal((await api("/api/state")).json.tlsKeylog, null);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  await check("I/O graph over a capture spanning 100 days stays exact", async () => {
    const dir = mkdtempSync(join(tmpdir(), "wirebuddy-span-test-"));
    try {
      const shifted = join(dir, "shifted.pcapng");
      const long = join(dir, "long.pcapng");
      execFileSync("editcap", ["-t", String(100 * 86400), fixture, shifted]);
      execFileSync("mergecap", ["-w", long, fixture, shifted]);
      assert.equal((await api("/api/open", { path: long })).status, 200);
      const graphs = encodeURIComponent(JSON.stringify([{ metric: "packets", filter: "" }]));
      const r = (await api(`/api/stats/iograph?interval=1000&graphs=${graphs}`)).json;
      assert.ok(r.interval <= 2_000_000, `interval ${r.interval} overflows sharkd`);
      assert.equal(r.series[0].values.reduce((a, b) => a + b, 0), 58);
    } finally {
      await api("/api/open", { path: fixture });
      rmSync(dir, { recursive: true, force: true });
    }
  });

  await checkCapture("interface activity from dumpcap -S", async () => {
    const first = (await api("/api/capture/activity")).json;
    assert.equal(first.interval, 1);
    await new Promise((r) => setTimeout(r, 2600));
    const later = (await api("/api/capture/activity")).json;
    assert.ok(!later.error, later.error);
    assert.ok(later.ifaces.lo?.length >= 1, JSON.stringify(later).slice(0, 200));
    assert.ok(later.ifaces.lo.every((n) => Number.isInteger(n) && n >= 0));
  });

  await check("security: origin null, token in the URL, non-JSON posts, big bodies, bad WebSocket frames", async () => {
    const raw = (path, headers, body, method = "POST") =>
      new Promise((resolve, reject) => {
        const req = request(base + path, { method, headers }, (res) => {
          res.resume();
          resolve(res.statusCode);
        });
        req.on("error", reject);
        if (body) req.write(body);
        req.end();
      });
    assert.equal(await raw("/api/state", { "X-WireBuddy-Token": token, origin: "null" }, null, "GET"), 403);
    assert.equal((await fetch(`${base}/api/state?token=${token}`)).status, 401);
    assert.equal(await raw("/api/close", { "X-WireBuddy-Token": token, "content-type": "text/plain" }, "{}"), 415);
    assert.equal(await raw("/api/filter", { "X-WireBuddy-Token": token, "content-type": "application/json" }, "x".repeat(1_100_000)), 413);
    const page = await fetch(base + "/");
    assert.match(page.headers.get("content-security-policy") ?? "", /default-src 'self'/);
    assert.equal(page.headers.get("referrer-policy"), "no-referrer");
    // A frame with a reserved opcode: that client is dropped, the server keeps running
    const ws = new WebSocket(`${base.replace("http", "ws")}/ws?token=${token}`);
    await new Promise((resolve, reject) => {
      ws.once("open", resolve);
      ws.once("error", reject);
    });
    const closed = new Promise((resolve) => ws.once("close", resolve));
    ws._socket.write(Buffer.from([0x8f, 0x80, 1, 2, 3, 4]));
    await closed;
    assert.equal((await api("/api/state")).status, 200);
  });
  await check("open checks the content: renamed or compressed non-captures are refused", async () => {
    const dir = mkdtempSync(join(tmpdir(), "wirebuddy-gate-"));
    try {
      writeFileSync(join(dir, "fake.pcapng"), '{"secret": "not a capture"}');
      writeFileSync(join(dir, "key.pcap.gz"), gzipSync(Buffer.from("-----BEGIN PRIVATE KEY-----\n")));
      writeFileSync(join(dir, "zipped.pcapng.gz"), gzipSync(readFileSync(fixture)));
      for (const name of ["fake.pcapng", "key.pcap.gz"]) {
        const r = await api("/api/open", { path: join(dir, name) });
        assert.equal(r.status, 400, name);
        assert.match(r.json.error, /not a capture file/);
      }
      assert.equal((await api("/api/open", { path: join(dir, "zipped.pcapng.gz") })).status, 200);
      assert.equal((await state()).totalFrames, 29);
    } finally {
      await api("/api/open", { path: fixture });
      rmSync(dir, { recursive: true, force: true });
    }
  });
  await check("a short token is refused, an empty one replaced by a random one", async () => {
    // Async: blocking this process would let the server drop our idle keep-alive connections
    const run = (t) =>
      new Promise((resolve) => {
        const p = spawn(process.execPath, [join(root, "dist/server/main.js"), "--port", "0", "--token", t], { env: { ...env, WIREBUDDY_TOKEN: "" } });
        let text = "";
        const done = (code) => {
          clearTimeout(timer);
          p.kill();
          resolve({ code, text });
        };
        const timer = setTimeout(() => done("running"), 10000);
        p.stdout.on("data", (d) => {
          text += d;
          if (/UI at/.test(text)) done("running");
        });
        p.stderr.on("data", (d) => (text += d));
        p.on("exit", (code) => done(code));
      });
    const short = await run("short");
    assert.equal(short.code, 1, short.text);
    assert.match(short.text, /at least 16 characters/);
    const empty = await run("");
    assert.equal(empty.code, "running", empty.text);
    assert.match(empty.text, /token=[0-9a-f]{32}\b/);
  });
  await check("files and recent", async () => {
    const dir = (await api("/api/files?dir=" + encodeURIComponent(dirname(fixture)))).json;
    assert.ok(dir.entries.some((e) => e.name === "http.pcapng"));
    const recent = (await api("/api/recent")).json;
    assert.equal(recent.files[0].path, fixture);
  });
} finally {
  server.kill();
  rmSync(home, { recursive: true, force: true });
}
console.log(failures ? `${failures} check(s) failed` : "all checks passed");
process.exit(failures ? 1 : 0);
