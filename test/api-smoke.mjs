// End-to-end check of the HTTP API against test/fixtures/http.pcapng.
// Usage: node test/api-smoke.mjs   (after npm run build)
import { spawn } from "node:child_process";
import { request } from "node:http";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import assert from "node:assert/strict";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const fixture = join(root, "test/fixtures/http.pcapng");
const token = "smoke-test-token";

const server = spawn(process.execPath, [join(root, "dist/server/main.js"), "--port", "0", "--token", token], {
  stdio: ["ignore", "pipe", "inherit"],
});
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
  });

  await check("capture interfaces and filter check", async () => {
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

  await check("files and recent", async () => {
    const dir = (await api("/api/files?dir=" + encodeURIComponent(dirname(fixture)))).json;
    assert.ok(dir.entries.some((e) => e.name === "http.pcapng"));
    const recent = (await api("/api/recent")).json;
    assert.equal(recent.files[0].path, fixture);
  });
} finally {
  server.kill();
}
console.log(failures ? `${failures} check(s) failed` : "all checks passed");
process.exit(failures ? 1 : 0);
