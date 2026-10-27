// Panels over HTTP: validity and trust, the panel host's routes, headers and checks, reports, the capture's data.
// Usage: node test/panels-smoke.mjs   (after npm run build)
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { appendFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { request } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";
import assert from "node:assert/strict";
import * as g from "./capgen.mjs";
import { writeAcmeCapture } from "./acme.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const fixture = join(root, "test/fixtures/http.pcapng");
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
      res.on("end", () => {
        const raw = Buffer.concat(chunks);
        resolve({ status: res.statusCode, headers: res.headers, body: raw.toString("utf8"), raw });
      });
    });
    req.on("error", reject);
    req.end(body);
  });
}

/** A WBPK page as the bridge reads it. */
function decodePage(buf) {
  assert.equal(buf.readUInt32LE(0), 0x4b504257);
  const h = buf.readUInt32LE(4);
  const head = JSON.parse(buf.subarray(8, 8 + h).toString("utf8"));
  const n = head.n;
  let at = 8 + h;
  const times = [];
  for (let i = 0; i < n; i++, at += 8) times.push(buf.readDoubleLE(at));
  const u32 = (count) => {
    const out = [];
    for (let i = 0; i < count; i++, at += 4) out.push(buf.readUInt32LE(at));
    return out;
  };
  const frames = u32(n);
  const lens = u32(n);
  const offsets = u32(n + 1);
  const dirs = head.dirs ? [...buf.subarray(at, (at += n))] : null;
  const data = buf.subarray(at, at + offsets[n]);
  return { ...head, times, frames, lens, dirs, bytes: (i) => data.subarray(offsets[i], offsets[i + 1]) };
}

/** Events of a panel page's event stream until `until` returns true for the list (or 5 s pass). */
function readEvents(host, doc, until, onOpen = () => {}) {
  return new Promise((resolve, reject) => {
    const events = [];
    const req = request({ host: "127.0.0.1", port, path: `/_wb/events?doc=${doc}`, headers: { host, "sec-fetch-site": "same-origin", "sec-fetch-dest": "empty", "sec-fetch-mode": "cors" } }, (res) => {
      if (res.statusCode !== 200) return resolve({ status: res.statusCode, events });
      let buf = "";
      const timer = setTimeout(() => (req.destroy(), resolve({ status: 200, events, timedOut: true })), 5000);
      res.setEncoding("utf8");
      res.on("data", (d) => {
        buf += d;
        for (let i = buf.indexOf("\n\n"); i >= 0; i = buf.indexOf("\n\n")) {
          const block = buf.slice(0, i);
          buf = buf.slice(i + 2);
          const event = /^event: (.+)$/m.exec(block)?.[1];
          const data = /^data: (.+)$/m.exec(block)?.[1];
          if (event) events.push({ event, data: JSON.parse(data) });
          if (events.length === 1) onOpen();
        }
        if (until(events)) {
          clearTimeout(timer);
          req.destroy();
          resolve({ status: 200, events });
        }
      });
      res.on("end", () => (clearTimeout(timer), resolve({ status: 200, events, ended: true })));
    });
    req.on("error", reject);
    req.end();
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
    assert.deepEqual(ext(list, "hello").panel, { title: "hello panel", open: false, stale: false, offer: null });
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

  // The capture's data, as the bridge asks for it
  await api("/api/panels/open", { name: "hello" });
  const panel = (await api("/api/state")).json.panels.find((x) => x.name === "hello");
  const dhost = new URL(panel.src).host;
  const page = await panelReq(dhost, "/", { headers: frameHeaders });
  const doc = /<meta name="wb-doc" content="([a-z2-7]+)">/.exec(page.body)[1];
  const call = (method, body, headers = {}) =>
    panelReq(dhost, `/_wb/api/${method}`, { method: "POST", body: JSON.stringify(body), headers: { origin: `http://${dhost}`, "sec-fetch-site": "same-origin", "content-type": "application/json", "x-wb-doc": doc, ...headers } });
  const json = (r) => JSON.parse(r.body);

  await check("panel data: only from the panel's current page; nothing without a capture", async () => {
    assert.equal((await call("packets", {}, { origin: base })).status, 403);
    assert.equal((await call("packets", {}, { "sec-fetch-site": "cross-site" })).status, 403);
    assert.equal((await call("packets", {}, { "content-type": "text/plain" })).status, 415);
    const old = await call("packets", {}, { "x-wb-doc": "old" });
    assert.equal(old.status, 409);
    assert.equal(json(old).code, "replaced");
    const none = await call("packets", {});
    assert.equal(none.status, 409);
    assert.equal(json(none).code, "no-capture");
    assert.equal((await call("capture/start", {})).status, 404);
    assert.match(page.body, /<meta name="wb-view" content="\{&#34;file&#34;:null,/);
  });

  assert.equal((await api("/api/open", { path: fixture })).status, 200);
  await check("panel data: packets with fields, cut values, paging and bytes", async () => {
    const all = decodePage((await call("packets", {})).raw);
    assert.equal(all.n, 29);
    assert.equal(all.total, 29);
    assert.equal(all.done, true);
    assert.equal(all.next, 29);
    assert.ok(all.times[0] > 1.7e9 && all.lens[0] === 74, `${all.times[0]} ${all.lens[0]}`);
    const p1 = decodePage((await call("packets", { limit: 10 })).raw);
    assert.deepEqual([p1.n, p1.next, p1.done], [10, 10, false]);
    const p3 = decodePage((await call("packets", { after: 20, limit: 10 })).raw);
    assert.deepEqual([p3.n, p3.frames[0], p3.done], [9, 21, true]);
    const f = decodePage((await call("packets", { frames: [[12, 12]], fields: ["http.file_data", "tcp.srcport"] })).raw);
    assert.equal(f.fields["http.file_data"][0].length, 2045);
    assert.deepEqual(f.clipped, [[0, "http.file_data"]]);
    assert.equal(f.fields["tcp.srcport"][0], "18080");
    const body = decodePage((await call("packets", { frames: [[12, 12]], bytes: "http.file_data" })).raw);
    assert.equal(body.bytes(0).length, 81053);
    assert.match(createHash("sha1").update(body.bytes(0)).digest("hex"), /^7bd4078f/);
    const twice = decodePage((await call("packets", { frames: [[3, 4]], fields: ["frame.number", "frame.number"] })).raw);
    assert.deepEqual(twice.fields["frame.number"], ["3", "4"]);
    // Hidden fields have no bytes in sharkd's tree: said, not left empty
    const src = decodePage((await call("packets", { frames: [[1, 2]], bytes: "ip.src" })).raw);
    assert.deepEqual([src.dropped, src.bytes(0).length], [0, 4]);
    const hidden = await call("packets", { frames: [[1, 2]], bytes: "ip.addr" });
    assert.equal(hidden.status, 400);
    assert.match(json(hidden).error, /hidden or generated field/);
    // Field text counts against maxBytes
    const text = decodePage((await call("packets", { fields: ["http.file_data"], filter: "http", maxBytes: 1000 })).raw);
    assert.ok(text.n === 1 && !text.done, `${text.n}`);
    const http = decodePage((await call("packets", { filter: "http", fields: ["frame.number"] })).raw);
    assert.deepEqual(http.frames, [4, 12, 21, 25]);
    assert.deepEqual(http.fields["frame.number"], ["4", "12", "21", "25"]);
    const sel = decodePage((await call("packets", { frames: [[1, 3], [20, 40]], filter: "tcp.srcport == 18080" })).raw);
    assert.ok(sel.frames.every((x) => (x >= 1 && x <= 3) || (x >= 20 && x <= 29)) && sel.n > 0);
  });

  await check("panel data: frame, ip and payload bytes match sharkd's", async () => {
    const frames = decodePage((await call("packets", { bytes: "frame" })).raw);
    const ip = decodePage((await call("packets", { bytes: "ip" })).raw);
    const payload = decodePage((await call("packets", { bytes: "payload" })).raw);
    const tcp = decodePage((await call("packets", { bytes: "tcp.payload" })).raw);
    for (let i = 0; i < 29; i++) {
      const detail = (await api(`/api/frame?num=${i + 1}`)).json;
      const raw = Buffer.from(detail.bytes, "base64");
      assert.ok(frames.bytes(i).equals(raw), `frame ${i + 1}`);
      // Ethernet on lo: IPv4 from byte 14
      assert.ok(ip.bytes(i).equals(raw.subarray(14, 14 + raw.readUInt16BE(16))), `ip ${i + 1}`);
      assert.ok(payload.bytes(i).equals(tcp.bytes(i)), `payload ${i + 1}`);
    }
    // A TCP packet without data has an empty payload; the field is missing there
    assert.equal(payload.dropped, 0);
    assert.equal(tcp.dropped, Array.from({ length: 29 }, (_, i) => tcp.bytes(i).length).filter((n) => n === 0).length);
    const cut = decodePage((await call("packets", { bytes: "frame", maxBytes: 1000 })).raw);
    assert.ok(cut.n > 1 && cut.n < 29 && !cut.done, `${cut.n}`);
    const one = decodePage((await call("packets", { frames: [[12, 12]], bytes: "frame", maxBytes: 10 })).raw);
    assert.equal(one.n, 1);
  });

  await check("panel data: raw matches, alone and with frames and filters, are what sharkd's filters find", async () => {
    const pkts = async (body) => {
      const r = await call("packets", body);
      assert.equal(r.status, 200, r.body);
      return decodePage(r.raw);
    };
    const byFilter = async (filter) => (await pkts({ filter })).frames;
    for (const [match, filter] of [
      [{ proto: "tcp" }, "tcp"],
      [{ proto: 6, dstport: 18080 }, "tcp.dstport == 18080"],
      [{ srcport: 18080 }, "tcp.srcport == 18080"],
      [{ port: [18080, 1] }, "tcp.port == 18080 || tcp.port == 1"],
      [{ addr: "127.0.0.0/8", ethertype: 0x0800 }, "ip.addr == 127.0.0.0/8"],
      [{ src: "127.0.0.1", dst: ["10.0.0.1", "127.0.0.1"] }, "ip.src == 127.0.0.1"],
    ]) {
      const page = await pkts({ match });
      assert.deepEqual(page.frames, await byFilter(filter), JSON.stringify(match));
      assert.equal(page.total, page.n);
    }
    for (const match of [{ proto: "udp" }, { addr: "::1" }, { vlan: 5 }, { addr: "10.0.0.0/8" }]) {
      const none = await pkts({ match });
      assert.deepEqual([none.n, none.total, none.done, none.next], [0, 0, true, null], JSON.stringify(match));
    }
    const requests = await byFilter("tcp.dstport == 18080");
    const within = await pkts({ match: { dstport: 18080 }, frames: [[1, 10]] });
    assert.deepEqual(within.frames, requests.filter((f) => f <= 10));
    const http = await pkts({ match: { dstport: 18080 }, filter: "http" });
    assert.deepEqual(http.frames, [4, 21]);
    const paged = await pkts({ match: { dstport: 18080 }, after: requests[2], limit: 3 });
    assert.deepEqual([paged.frames, paged.next, paged.total], [requests.slice(3, 6), requests[5], requests.length]);
    // Payloads of the matching packets are tcp.payload
    const payload = await pkts({ match: { srcport: 18080 }, bytes: "payload" });
    const field = await pkts({ frames: payload.frames.map((f) => [f, f]), bytes: "tcp.payload" });
    assert.deepEqual(field.frames, payload.frames);
    for (let i = 0; i < payload.n; i++) assert.ok(payload.bytes(i).equals(field.bytes(i)), `frame ${payload.frames[i]}`);
    const bad = async (match, re) => {
      const r = await call("packets", { match });
      assert.equal(r.status, 400, r.body);
      assert.equal(json(r).code, "bad-args");
      assert.match(json(r).error, re);
    };
    await bad(5, /match is an object/);
    await bad({ colour: 1 }, /no key "colour"/);
    await bad({ port: 70000 }, /match.port: 70000 is not a number from 0 to 65535/);
    await bad({ proto: "xyz" }, /or one of icmp, igmp, tcp, udp/);
    await bad({ addr: "300.1.1.1" }, /not an IPv4 or IPv6 address/);
    await bad({ addr: "10.0.0.0/33" }, /not an IPv4 or IPv6 address/);
    await bad({ port: [] }, /a value or a list/);
  });

  await check("panel data: FrameStore's times and lengths are sharkd's", async () => {
    const page = decodePage((await call("packets", { fields: ["frame.time_epoch", "frame.len", "frame.cap_len"], bytes: "frame" })).raw);
    assert.equal(page.n, 29);
    for (let i = 0; i < 29; i++) {
      assert.ok(Math.abs(page.times[i] - Number(page.fields["frame.time_epoch"][i])) < 1e-6, `time of ${i + 1}`);
      assert.equal(page.lens[i], Number(page.fields["frame.len"][i]));
      assert.equal(page.bytes(i).length, Number(page.fields["frame.cap_len"][i]));
    }
  });

  await check("panel data: bad requests are explained", async () => {
    const bad = async (body, status, code, re) => {
      const r = await call("packets", body);
      assert.equal(r.status, status, r.body);
      assert.equal(json(r).code, code);
      if (re) assert.match(json(r).error, re);
      return json(r);
    };
    await bad({ maxBytes: 17 * 1024 * 1024 }, 413, "too-large");
    await bad({ limit: 0 }, 400, "bad-args");
    await bad({ fields: Array(17).fill("ip.src") }, 400, "bad-args");
    await bad({ frames: [[0, 3]] }, 400, "bad-args");
    await bad({ filter: "http &&" }, 400, "filter", /invalid display filter "http &&": Unexpected end/);
    const unknown = await bad({ filter: "wbpc.scan == 1" }, 400, "filter", /not a valid protocol/);
    assert.match(unknown.hint, /extensions action "reload"/);
    await bad({ fields: ["nosuch.field"] }, 400, "bad-args", /unknown field "nosuch.field"/);
    await bad({ epoch: 12345 }, 409, "stale");
  });

  await check("panel data: frame, follow, objects, taps and checks", async () => {
    const fr = json(await call("frame", { frame: 12 }));
    assert.equal(Buffer.from(fr.sources[0].bytes, "base64").length, 81243);
    assert.ok(fr.tree.length && fr.followers.some(([p]) => p === "TCP"));
    assert.equal(json(await call("frame", { frame: 99 })).code, "gone");
    const fo = decodePage((await call("follow", { frame: 4 })).raw);
    assert.equal(fo.follow.protocol, "TCP");
    assert.equal(fo.follow.filter, "tcp.stream eq 0");
    assert.equal(fo.dirs.length, fo.n);
    assert.equal(fo.total, fo.follow.client.bytes + fo.follow.server.bytes);
    assert.ok(fo.dirs.includes(0) && fo.dirs.includes(1));
    const part = decodePage((await call("follow", { protocol: "TCP", stream: 0 }, {})).raw);
    assert.equal(part.total, fo.total);
    const paged = decodePage((await call("follow", { protocol: "tcp", stream: 0, offset: 100, maxBytes: 50 })).raw);
    assert.deepEqual([paged.next, paged.done], [150, false]);
    assert.equal(Buffer.concat(Array.from({ length: paged.n }, (_, i) => paged.bytes(i))).length, 50);
    const objs = json(await call("objects", { kind: "http" })).objects;
    assert.deepEqual(objs.map((o) => [o.frame, o.filename, o.size]), [[12, "big.txt", 81053], [25, "nothere", 469]]);
    const o = await call("object", { id: objs[0].id });
    assert.equal(o.status, 200);
    assert.equal(createHash("sha1").update(o.raw).digest("hex"), objs[0].sha1);
    assert.equal(decodeURIComponent(o.headers["x-wb-type"]), "text/plain");
    assert.equal(o.headers["content-disposition"], "attachment");
    assert.match(o.headers["content-security-policy"], /^sandbox/);
    assert.equal(json(await call("object", { id: "http:12:0000000000000000" })).code, "gone");
    const phs = json(await call("tap", { name: "phs" }));
    assert.ok(JSON.stringify(phs).includes('"proto":"http"'));
    assert.equal(json(await call("tap", { name: "eo:http" })).code, "bad-args");
    assert.deepEqual(json(await call("check", { filter: "http &&" })).ok, false);
    assert.deepEqual(json(await call("check", { filter: "http" })), { ok: true });
    // Object ids stay valid when the capture is read again
    await api("/api/extensions/reload", {});
    const view = (await api("/api/state")).json;
    assert.equal(json(await call("objects", { kind: "http", epoch: view.epoch - 1 })).code, "stale");
    assert.equal(json(await call("objects", { kind: "http", epoch: view.epoch })).objects[0].id, objs[0].id);
  });

  await check("panel data: events tell the page about the view, resets and the end", async () => {
    const got = await readEvents(dhost, doc, (ev) => ev.some((e) => e.event === "view" && e.data.selected === 7), () => api("/api/select", { frame: 7 }));
    assert.equal(got.events[0].event, "view");
    assert.equal(got.events[0].data.file, "http.pcapng");
    assert.equal(got.events[0].data.frames, 29);
    assert.ok(got.events.some((e) => e.event === "view" && e.data.selected === 7), JSON.stringify(got.events));
    const epoch = (await api("/api/state")).json.epoch;
    const reset = await readEvents(dhost, doc, (ev) => ev.some((e) => e.event === "reset"), () => api("/api/extensions/reload", {}));
    const r = reset.events.find((e) => e.event === "reset").data;
    assert.deepEqual([r.epoch, r.why, r.view.epoch, r.view.file], [epoch + 1, "extensions", epoch + 1, "http.pcapng"]);
    assert.equal((await readEvents(dhost, "old", () => true)).status, 409);
    const bye = await readEvents(dhost, doc, (ev) => ev.some((e) => e.event === "bye"), () => api("/api/panels/close", { name: "hello" }));
    assert.deepEqual(bye.events.find((e) => e.event === "bye").data, { why: "closed" });
    // A closed panel's page gets nothing more
    assert.equal((await call("packets", {})).status, 404);
  });

  await check("panel data: one panel can't flood WireBuddy", async () => {
    await api("/api/panels/open", { name: "hello" });
    const p = (await api("/api/state")).json.panels.find((x) => x.name === "hello");
    const h = new URL(p.src).host;
    const d = /<meta name="wb-doc" content="([a-z2-7]+)">/.exec((await panelReq(h, "/", { headers: frameHeaders })).body)[1];
    const many = await Promise.all(
      Array.from({ length: 30 }, () =>
        panelReq(h, "/_wb/api/frame", { method: "POST", body: JSON.stringify({ frame: 1 }), headers: { origin: `http://${h}`, "sec-fetch-site": "same-origin", "content-type": "application/json", "x-wb-doc": d } }),
      ),
    );
    const busy = many.filter((r) => r.status === 429);
    assert.ok(busy.length >= 10, `${busy.length} refused`);
    assert.equal(JSON.parse(busy[0].body).code, "busy");
    assert.ok(JSON.parse(busy[0].body).retryMs > 0);
  });

  // Files of our own: one that grows, and ones FrameStore can't read
  await api("/api/panels/open", { name: "hello" });
  const own = new URL((await api("/api/state")).json.panels.find((x) => x.name === "hello").src).host;
  const ownDoc = /<meta name="wb-doc" content="([a-z2-7]+)">/.exec((await panelReq(own, "/", { headers: frameHeaders })).body)[1];
  const ownCall = (method, body) =>
    panelReq(own, `/_wb/api/${method}`, { method: "POST", body: JSON.stringify(body), headers: { origin: `http://${own}`, "sec-fetch-site": "same-origin", "content-type": "application/json", "x-wb-doc": ownDoc } });
  const pkts = async (body) => {
    const r = await ownCall("packets", body);
    assert.equal(r.status, 200, r.body);
    return decodePage(r.raw);
  };
  const packetsEvent = (frames) => (ev) => ev.some((e) => e.event === "packets" && e.data.frames === frames);

  await check("panel data: a growing file sends packets events, and raw pages run ahead of the view", async () => {
    const file = join(home, "grow.pcap");
    const rec = (i) => g.pcapRecord(1700000000 + Math.floor(i / 1000), (i % 1000) * 1000, g.udpFrame(i, { dport: i % 2 ? 9999 : 7502 }));
    writeFileSync(file, Buffer.concat([g.pcapHeader(), ...Array.from({ length: 3000 }, (_, i) => rec(i + 1))]));
    assert.equal((await api("/api/open", { path: file })).status, 200);
    // More than sharkd's 2000 a page: these bytes come from the file
    const all = await pkts({ bytes: "frame", limit: 3000 });
    assert.deepEqual([all.n, all.done], [3000, true]);
    const even = await pkts({ match: { dstport: 7502 }, bytes: "payload", limit: 50000 });
    assert.equal(even.n, 1500);
    assert.ok(even.frames.every((f, i) => f === 2 * (i + 1) && even.bytes(i).readUInt32BE(0) === f));
    // The panel engine reads the file as it is now
    assert.equal((await pkts({ filter: "udp", limit: 1 })).total, 3000);
    // Appended while the page listens: the event comes without the view reading the file again
    const grown = await readEvents(own, ownDoc, packetsEvent(3010), () => appendFileSync(file, Buffer.concat(Array.from({ length: 10 }, (_, i) => rec(3001 + i)))));
    assert.ok(packetsEvent(3010)(grown.events), JSON.stringify(grown.events));
    assert.equal((await api("/api/state")).json.totalFrames, 3000);
    const ahead = await pkts({ match: { dstport: 7502 }, after: 3000 });
    assert.deepEqual(ahead.frames, [3002, 3004, 3006, 3008, 3010]);
    assert.deepEqual([ahead.total, ahead.pending, ahead.live, ahead.done], [1505, false, false, true]);
    // A half-written record waits for its end
    const half = rec(3011);
    appendFileSync(file, half.subarray(0, 30));
    assert.deepEqual((await pkts({ after: 3009 })).frames, [3010]);
    const rest = await readEvents(own, ownDoc, packetsEvent(3011), () => appendFileSync(file, half.subarray(30)));
    assert.ok(packetsEvent(3011)(rest.events), JSON.stringify(rest.events));
    assert.deepEqual((await pkts({ match: { dstport: 9999 }, after: 3008 })).frames, [3009, 3011]);
    // The engine is behind until the view reads the file again
    const behind = await pkts({ match: { dstport: 9999 }, filter: "udp", after: 2990 });
    assert.deepEqual([behind.frames, behind.pending], [[2991, 2993, 2995, 2997, 2999], true]);
    await api("/api/reload", {});
    assert.equal((await api("/api/state")).json.totalFrames, 3011);
    // It reads a grown file again at most once a second
    let caught = behind;
    for (let tries = 0; caught.pending && tries < 20; tries++) {
      await new Promise((done) => setTimeout(done, 200));
      caught = await pkts({ match: { dstport: 9999 }, filter: "udp", after: 2990 });
    }
    assert.deepEqual([caught.frames.length, caught.pending], [11, false]);
  });

  await check("panel data: compressed files, and counts unlike Wireshark's, leave raw packets to sharkd", async () => {
    const gz = join(home, "http.pcapng.gz");
    writeFileSync(gz, gzipSync(readFileSync(fixture)));
    assert.equal((await api("/api/open", { path: gz })).status, 200);
    const m = await ownCall("packets", { match: { proto: "tcp" } });
    assert.equal(m.status, 400);
    assert.match(json(m).error, /can't read http\.pcapng\.gz: it is compressed\. Use a display filter instead/);
    const frames = await pkts({ bytes: "frame", frames: [[10, 12]] });
    for (let i = 0; i < 3; i++) assert.ok(frames.bytes(i).equals(Buffer.from((await api(`/api/frame?num=${10 + i}`)).json.bytes, "base64")));
    // Wireshark numbers a systemd journal entry as a frame; FrameStore doesn't: off for that file
    const journal = join(home, "journal.pcapng");
    writeFileSync(journal, Buffer.concat([g.shb(), g.idb(1), g.epb(0, 1n, g.udpFrame(1)), g.block(9, Buffer.from("__REALTIME_TIMESTAMP=1700000000000000\nMESSAGE=hi\n")), g.epb(0, 2n, g.udpFrame(2))]));
    await api("/api/events/take", {});
    assert.equal((await api("/api/open", { path: journal })).status, 200);
    const j = await ownCall("packets", { match: { proto: "udp" } });
    assert.equal(j.status, 400);
    assert.match(json(j).error, /found 2 packets, Wireshark 3/);
    assert.equal((await ownCall("packets", { match: { proto: "udp" } })).status, 400);
    const warnings = (await api("/api/events/take", {})).json.events.filter((e) => /through sharkd only/.test(e.text));
    assert.equal(warnings.length, 1);
    assert.match(warnings[0].text, /Panels read journal\.pcapng through sharkd only/);
    assert.equal((await pkts({ bytes: "frame" })).n, 3);
  });

  // Control: what a panel may change in the user's view (relayed by the page after a click), what it keeps, offers
  await api("/api/open", { path: fixture });
  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  const events = async () => (await api("/api/events/take", {})).json.events.map((e) => `${e.level} ${e.text}`).join("\n");
  const until = async (what, fn) => {
    for (let i = 0; i < 100; i++, await sleep(100)) if (await fn()) return;
    throw new Error(`timed out waiting for ${what}`);
  };
  const docOf = async (h) => /<meta name="wb-doc" content="([a-z2-7]+)">/.exec((await panelReq(h, "/", { headers: frameHeaders })).body)[1];
  addPanel("ctl", { "main.js": "wb.ready();\n" }, { label: "Ctl", version: "1", panel: { title: "Ctl" } });
  addPanel("ctlfilter", { "main.js": "wb.ready();\n" }, { label: "Ctl filter", version: "1", panel: { title: "Filter", permissions: ["control"] } });
  await api("/api/panels/open", { name: "ctl" });
  await api("/api/panels/open", { name: "ctlfilter" });
  const opened = (await api("/api/state")).json.panels;
  const ctl = opened.find((x) => x.name === "ctl");
  const ctlf = opened.find((x) => x.name === "ctlfilter");
  const act = (p, m, a, clicked = true) => api("/api/panels/act", { name: p.name, label: p.label, m, a, clicked });

  await check("control: a panel's select needs the token and a click in it", async () => {
    assert.deepEqual([ctl.control, ctlf.control], [false, true]);
    const body = JSON.stringify({ name: "ctl", label: ctl.label, m: "select", a: 3, clicked: true });
    assert.equal((await fetch(`${base}/api/panels/act`, { method: "POST", headers: { "content-type": "application/json" }, body })).status, 401);
    const h = new URL(ctl.src).host;
    const fromPanel = await panelReq(h, "/api/panels/act", { method: "POST", body, headers: { ...sub("empty"), origin: `http://${h}`, "content-type": "application/json", "x-wirebuddy-token": token } });
    assert.equal(fromPanel.status, 403);
    await events();
    const unclicked = await act(ctl, "select", 3, false);
    assert.deepEqual([unclicked.status, unclicked.json.code], [403, "denied"]);
    assert.notEqual((await api("/api/state")).json.selected, 3);
    assert.equal((await act(ctl, "select", 3)).status, 200);
    const s = (await api("/api/state")).json;
    assert.deepEqual([s.selected, s.selectedBy], [3, "user"]);
    assert.match(s.agentNotice.text, /^Panel "Ctl" selected frame 3$/);
    const ev = await events();
    assert.match(ev, /WARNING Panel "ctl" called wb\.select, which was refused: the user hadn't just clicked or typed in the panel/);
    assert.match(ev, /INFO Panel "ctl" selected frame 3 \(the user clicked in it\)/);
    assert.deepEqual([(await act(ctl, "select", 99)).status, (await act(ctl, "select", 99)).json.code], [400, "bad-args"]);
    assert.equal((await act(ctl, "mark", 3)).status, 400);
    assert.equal((await act({ ...ctl, label: "a".repeat(26) }, "select", 4)).json.code, "gone");
    await sleep(1000);
    const burst = await Promise.all(Array.from({ length: 8 }, () => act(ctl, "select", 5)));
    assert.ok(burst.some((r) => r.status === 429 && r.json.code === "busy"), burst.map((r) => r.status).join());
  });

  await check("control: setFilter only with the control permission", async () => {
    await events();
    const refused = await act(ctl, "setFilter", "http");
    assert.deepEqual([refused.status, refused.json.code], [403, "denied"]);
    assert.match(refused.json.error, /"permissions": \["control"\]/);
    assert.equal((await api("/api/state")).json.filter, "");
    const bad = await act(ctlf, "setFilter", "http &&");
    assert.deepEqual([bad.status, bad.json.code], [400, "filter"]);
    await sleep(1000);
    assert.equal((await act(ctlf, "setFilter", "http")).status, 200);
    const s = (await api("/api/state")).json;
    assert.deepEqual([s.filter, s.displayedFrames], ["http", 4]);
    assert.match(s.agentNotice.text, /^Panel "Filter" applied the display filter "http"$/);
    assert.equal((await act(ctlf, "setFilter", "tcp")).json.code, "busy");
    await sleep(1000);
    assert.equal((await act(ctlf, "setFilter", "")).status, 200);
    assert.equal((await api("/api/state")).json.filter, "");
    const ev = await events();
    assert.match(ev, /WARNING Panel "ctl" called wb\.setFilter, which was refused: it needs "permissions": \["control"\]/);
    assert.match(ev, /INFO Panel "ctlfilter" applied the display filter "http" \(the user clicked in it\)/);
  });

  await check("control: wb.storage keeps JSON per extension, at most 256 KiB, across panel reloads", async () => {
    let h = new URL(ctl.src).host;
    let d = await docOf(h);
    const store = (body, headers = {}) =>
      panelReq(h, "/_wb/api/storage", { method: "POST", body: JSON.stringify(body), headers: { origin: `http://${h}`, "sec-fetch-site": "same-origin", "content-type": "application/json", "x-wb-doc": d, ...headers } });
    assert.deepEqual(JSON.parse((await store({ op: "get" })).body), { value: null });
    const kept = { zoom: 2, seen: [1, 2], note: "ü" };
    assert.equal((await store({ op: "set", value: kept, epoch: 1 })).status, 200);
    assert.deepEqual(JSON.parse((await store({ op: "get" })).body), { value: kept });
    assert.equal(statSync(join(home, ".local/share/wirebuddy/panel-storage/ctl.json")).mode & 0o777, 0o600);
    // Too large, from another origin, or an old page
    const big = await store({ op: "set", value: "x".repeat(256 * 1024) });
    assert.deepEqual([big.status, JSON.parse(big.body).code], [413, "too-large"]);
    assert.equal((await store({ op: "get" }, { origin: base })).status, 403);
    assert.equal((await store({ op: "get" }, { "x-wb-doc": "old" })).status, 409);
    assert.equal(JSON.parse((await store({ op: "drop" })).body).code, "bad-args");
    // A reloaded panel (a new origin) finds it; another extension has its own
    await api("/api/panels/reload", { name: "ctl" });
    h = new URL((await api("/api/state")).json.panels.find((x) => x.name === "ctl").src).host;
    d = await docOf(h);
    assert.deepEqual(JSON.parse((await store({ op: "get" })).body), { value: kept });
    const fh = new URL(ctlf.src).host;
    const other = await panelReq(fh, "/_wb/api/storage", { method: "POST", body: '{"op":"get"}', headers: { origin: `http://${fh}`, "sec-fetch-site": "same-origin", "content-type": "application/json", "x-wb-doc": await docOf(fh) } });
    assert.deepEqual(JSON.parse(other.body), { value: null });
    assert.equal((await store({ op: "set", value: null })).status, 200);
    assert.deepEqual(JSON.parse((await store({ op: "get" })).body), { value: null });
  });

  await check("control: offers appear for a matching capture; an invalid offer filter is reported, the others still count", async () => {
    await api("/api/panels/close", { name: "ctl" });
    await api("/api/panels/close", { name: "ctlfilter" });
    const offer = (name, filter, text) => addPanel(name, { "main.js": "wb.ready();\n" }, { label: `Offer ${name}`, version: "1", panel: { offer: { filter, text } } });
    offer("offerhttp", "http", "Show HTTP");
    offer("offerdns", "dns", "Show DNS");
    offer("offerudp", "udp", "Show UDP");
    offer("offerbad", "nosuchproto.field == 1", "Never");
    // More than one iograph pass: ten offers per pass
    for (let i = 0; i < 11; i++) offer(`offerframe${String(i).padStart(2, "0")}`, `frame.number == ${i + 1}`, `Frame ${i + 1}`);
    await events();
    await api("/api/extensions/reload", {});
    const offered = async () => (await api("/api/state")).json.panelOffers.map((o) => o.name);
    await until("the offers", async () => (await offered()).includes("offerhttp"));
    const names = await offered();
    assert.deepEqual(names, ["offerframe00", "offerframe01", "offerframe02", "offerframe03", "offerframe04", "offerframe05", "offerframe06", "offerframe07", "offerframe08", "offerframe09", "offerframe10", "offerhttp"]);
    assert.deepEqual((await api("/api/state")).json.panelOffers.find((o) => o.name === "offerhttp"), { name: "offerhttp", label: "Offer offerhttp", text: "Show HTTP" });
    const list = (await api("/api/extensions")).json;
    assert.match(ext(list, "offerbad").panel.offerError, /^invalid offer filter "nosuchproto\.field == 1": /);
    assert.equal(ext(list, "offerhttp").panel.offer, "Show HTTP");
    assert.equal(ext(list, "offerdns").panel.offerError, undefined);
    assert.match(await events(), /WARNING The offer filter "nosuchproto\.field == 1" of the panel "offerbad" is invalid/);
    // Not while it is open; a dismissed one stays away for this file only
    await api("/api/panels/open", { name: "offerhttp" });
    assert.ok(!(await offered()).includes("offerhttp"));
    await api("/api/panels/close", { name: "offerhttp" });
    assert.ok((await offered()).includes("offerhttp"));
    assert.equal((await api("/api/panels/offers/dismiss", { name: "offerhttp" })).status, 200);
    assert.ok(!(await offered()).includes("offerhttp"));
    assert.match(await events(), /INFO The user dismissed the offer of the panel "offerhttp" for this capture/);
    const acme = join(home, "acme.pcap");
    writeAcmeCapture(acme);
    await api("/api/open", { path: acme });
    await until("the offers of another capture", async () => (await offered()).includes("offerudp"));
    assert.ok(!(await offered()).includes("offerhttp"));
    await api("/api/open", { path: fixture });
    await until("the offer to come back", async () => (await offered()).includes("offerhttp"));
    assert.ok(!(await offered()).includes("offerudp"));
  });
} finally {
  server.kill();
  rmSync(home, { recursive: true, force: true });
}
console.log(failures ? `${failures} check(s) failed` : "all checks passed");
process.exit(failures ? 1 : 0);
