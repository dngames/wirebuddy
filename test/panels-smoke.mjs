// Panels over HTTP: validity and trust, the panel host's routes, headers and checks, reports.
// Usage: node test/panels-smoke.mjs   (after npm run build)
import { spawn } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { request } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const token = "panels-test-token-0123";
const home = mkdtempSync(join(tmpdir(), "wirebuddy-home-"));
const env = { ...process.env, HOME: home, XDG_CONFIG_HOME: join(home, ".config"), XDG_DATA_HOME: join(home, ".local/share"), WIREBUDDY_EXTENSIONS: "" };
const extDir = join(home, ".local/share/wirebuddy/extensions");

const addPanel = (name, files, manifest = { label: name, version: "1", panel: { title: `${name} panel` } }) => {
  mkdirSync(join(extDir, name, "panel"), { recursive: true });
  writeFileSync(join(extDir, name, "extension.json"), JSON.stringify(manifest));
  for (const [rel, text] of Object.entries(files)) {
    mkdirSync(dirname(join(extDir, name, "panel", rel)), { recursive: true });
    writeFileSync(join(extDir, name, "panel", rel), text);
  }
};
mkdirSync(extDir, { recursive: true, mode: 0o700 });
addPanel("hello", { "main.js": "wb.ready();\n", "style.css": "body { color: red }\n", "img/dot.png": "png" });
addPanel("nomain", { "other.js": "1;\n" });
addPanel("badname", { "main.js": "1;\n", "-bad.js": "1;\n" });
addPanel("reserved", { "main.js": "1;\n", "_wb/x.js": "1;\n" });
addPanel("linked", { "main.js": "1;\n" });
writeFileSync(join(home, "outside.js"), "1;\n");
symlinkSync(join(home, "outside.js"), join(extDir, "linked", "panel", "lib.js"));
addPanel("badmanifest", { "main.js": "1;\n" }, { label: "x", panel: { permissions: ["everything"] } });

const server = spawn(process.execPath, [join(root, "dist/server/main.js"), "--port", "0", "--token", token], { stdio: ["ignore", "pipe", "inherit"], env });
const base = await new Promise((resolve, reject) => {
  server.stdout.setEncoding("utf8");
  server.stdout.on("data", (d) => {
    const m = /UI at (http:\/\/[^/]+)\//.exec(d);
    if (m) resolve(m[1]);
  });
  server.on("exit", (code) => reject(new Error(`server exited with ${code}`)));
});
const port = Number(new URL(base).port);

async function api(path, body) {
  const res = await fetch(base + path, {
    method: body === undefined ? "GET" : "POST",
    headers: { "X-WireBuddy-Token": token, "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: res.status, json: await res.json().catch(() => null), headers: res.headers };
}

/** A request as a browser would send it to a panel host (fetch() can't set Host). */
function panelReq(host, path, { method = "GET", headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const req = request({ host: "127.0.0.1", port, path, method, headers: { host, ...headers } }, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString("utf8") }));
    });
    req.on("error", reject);
    req.end(body);
  });
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

const frameHeaders = { "sec-fetch-site": "cross-site", "sec-fetch-dest": "iframe", "sec-fetch-mode": "navigate" };
const sub = (dest) => ({ "sec-fetch-site": "same-origin", "sec-fetch-dest": dest, "sec-fetch-mode": "no-cors" });
try {
  const ext = (list, name) => list.extensions.find((e) => e.name === name);
  await check("panels: validity and trust of panel folders", async () => {
    const list = (await api("/api/extensions")).json;
    assert.equal(ext(list, "hello").status, "loaded");
    assert.equal(ext(list, "hello").lua, false);
    assert.deepEqual(ext(list, "hello").panel, { title: "hello panel", open: false, stale: false });
    assert.match(ext(list, "nomain").error, /panel\/main\.js is missing/);
    assert.match(ext(list, "badname").error, /panel\/-bad\.js: names may only use/);
    assert.match(ext(list, "reserved").error, /panel\/_wb: names may only use/);
    assert.equal(ext(list, "linked").status, "untrusted");
    assert.match(ext(list, "linked").error, /lib\.js is a symbolic link/);
    assert.match(ext(list, "badmanifest").error, /panel: permissions may only list "control"/);
    assert.equal((await api("/api/panels/open", { name: "nomain" })).status, 400);
  });

  let host = "";
  let label = "";
  await check("panels: opening gives a one-time host; the main page may frame only panel hosts", async () => {
    assert.equal((await api("/api/panels/open", { name: "hello" })).status, 200);
    const p = (await api("/api/state")).json.panels.find((x) => x.name === "hello");
    assert.match(p.src, new RegExp(`^http://p[a-z2-7]{26}\\.localhost:${port}/$`));
    host = new URL(p.src).host;
    label = p.label;
    const page = await fetch(`${base}/`);
    assert.match(page.headers.get("content-security-policy"), new RegExp(`frame-src http://\\*\\.localhost:${port};`));
  });

  await check("panels: the page only as a frame, with WireBuddy's bridge and no token", async () => {
    assert.equal((await panelReq(host, "/")).status, 403);
    assert.equal((await panelReq(host, "/", { headers: { "sec-fetch-site": "cross-site", "sec-fetch-dest": "document" } })).status, 403);
    const doc = await panelReq(host, "/", { headers: frameHeaders });
    assert.equal(doc.status, 200);
    assert.match(doc.body, /<script src="\/_wb\/bridge\.js"><\/script><script type="module" src="\/main\.js"><\/script>/);
    assert.match(doc.body, /<link rel="stylesheet" href="\/style\.css">/);
    assert.match(doc.body, /<meta name="wb-doc" content="[a-z2-7]{24}">/);
    assert.ok(!doc.body.includes(token) && !JSON.stringify(doc.headers).includes(token));
    const csp = doc.headers["content-security-policy"];
    assert.match(csp, /^default-src 'none'; script-src 'self'; /);
    assert.match(csp, /connect-src 'self'/);
    assert.match(csp, new RegExp(`frame-ancestors http://127\\.0\\.0\\.1:${port} http://localhost:${port} http://\\[::1\\]:${port}`));
    assert.match(doc.headers["permissions-policy"], /camera=\(\).*fullscreen=\(\)/);
    assert.equal(doc.headers["x-content-type-options"], "nosniff");
    assert.equal(doc.headers["referrer-policy"], "no-referrer");
    assert.equal(doc.headers["cache-control"], "no-store");
    assert.equal(doc.headers["cross-origin-resource-policy"], "same-origin");
  });

  await check("panels: its own files only, to its own pages", async () => {
    const js = await panelReq(host, "/main.js", { headers: sub("script") });
    assert.equal(js.status, 200);
    assert.equal(js.headers["content-type"], "text/javascript");
    assert.equal((await panelReq(host, "/img/dot.png", { headers: sub("image") })).headers["content-type"], "image/png");
    assert.equal((await panelReq(host, "/_wb/bridge.js", { headers: sub("script") })).status, 200);
    assert.equal((await panelReq(host, "/main.js", { headers: { "sec-fetch-site": "cross-site", "sec-fetch-dest": "script" } })).status, 403);
    assert.equal((await panelReq(host, "/main.js", { headers: sub("document") })).status, 403);
    assert.equal((await panelReq(host, "/main.js", { headers: { ...sub("script"), "service-worker": "script" } })).status, 403);
    assert.equal((await panelReq(host, "/api/state", { headers: sub("empty") })).status, 404);
    assert.equal((await panelReq(host, "/../extension.json", { headers: sub("empty") })).status, 404);
    // Not WireBuddy's own pages, nor WireBuddy's API with its token
    const api = await panelReq(host, "/api/state", { headers: { ...sub("empty"), "x-wirebuddy-token": token } });
    assert.equal(api.status, 404);
    assert.equal((await fetch(`${base}/_wb/bridge.js`)).status, 404);
  });

  await check("panels: unknown labels, other ports and lookalike hosts are refused", async () => {
    assert.equal((await panelReq(`p${"a".repeat(26)}.localhost:${port}`, "/", { headers: frameHeaders })).status, 404);
    assert.equal((await panelReq(`p${label}.localhost:${port + 1}`, "/", { headers: frameHeaders })).status, 404);
    assert.equal((await panelReq(`p${label}.localhost.evil.example:${port}`, "/", { headers: frameHeaders })).status, 403);
    const ws = await panelReq(host, `/ws?token=${token}`, { headers: { connection: "Upgrade", upgrade: "websocket", "sec-websocket-version": "13", "sec-websocket-key": "dGhlIHNhbXBsZSBub25jZQ==" } });
    assert.equal(ws.status, 403);
  });

  await check("panels: reports only from the current page of the panel's own origin", async () => {
    const doc = await panelReq(host, "/", { headers: frameHeaders });
    const nonce = /<meta name="wb-doc" content="([a-z2-7]+)">/.exec(doc.body)[1];
    const report = (body, headers = {}) =>
      panelReq(host, "/_wb/report", { method: "POST", body: JSON.stringify(body), headers: { origin: `http://${host}`, "sec-fetch-site": "same-origin", "content-type": "application/json", "x-wb-doc": nonce, ...headers } });
    assert.equal((await report({ kind: "status", text: "x" }, { origin: base })).status, 403);
    assert.equal((await report({ kind: "status", text: "x" }, { "content-type": "text/plain" })).status, 415);
    assert.equal((await report({ kind: "status", text: "x" }, { "x-wb-doc": "old" })).status, 409);
    assert.equal((await report({ kind: "nonsense" })).status, 400);
    assert.equal((await report({ kind: "status", text: "line one\nfake line" })).status, 200);
    assert.equal((await report({ kind: "error", message: "boom", stack: `Error: boom\n    at f (http://${host}/main.js:3:9)` })).status, 200);
    assert.equal((await report({ kind: "ready", digest: "canvas 10x10" })).status, 200);
    const p = (await api("/api/state")).json.panels.find((x) => x.name === "hello");
    assert.equal(p.state, "ready");
    assert.equal(p.statusText, "line one?fake line");
    assert.equal(p.errors, 1);
    const events = (await api("/api/events/take", {})).json.events.map((e) => `${e.level} ${e.text}`).join("\n");
    assert.match(events, new RegExp(`ERROR Panel "hello" \\[panel output\\]: boom at ${extDir.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}/hello/panel/main\\.js:3:9`));
  });

  await check("panels: the watchdog's verdicts reach the agent; closing ends the host", async () => {
    assert.equal((await api("/api/panels/health", { name: "hello", label, state: "not-responding" })).status, 200);
    assert.equal((await api("/api/state")).json.panels.find((x) => x.name === "hello").state, "not-responding");
    assert.match((await api("/api/events/take", {})).json.events.map((e) => e.text).join("\n"), /Panel "hello" stopped responding/);
    assert.equal((await api("/api/panels/health", { name: "hello", label, state: "sideways" })).status, 400);
    assert.equal((await api("/api/panels/close", { name: "hello" })).status, 200);
    assert.deepEqual((await api("/api/state")).json.panels, []);
    assert.equal((await panelReq(host, "/", { headers: frameHeaders })).status, 404);
  });

  await check("panels: switching the extension off closes its panel", async () => {
    await api("/api/panels/open", { name: "hello" });
    assert.equal((await api("/api/extensions/enable", { name: "hello", on: false })).status, 200);
    assert.deepEqual((await api("/api/state")).json.panels, []);
    assert.equal((await api("/api/panels/open", { name: "hello" })).status, 400);
    await api("/api/extensions/enable", { name: "hello", on: true });
  });
} finally {
  server.kill();
  rmSync(home, { recursive: true, force: true });
}
console.log(failures ? `${failures} check(s) failed` : "all checks passed");
process.exit(failures ? 1 : 0);
