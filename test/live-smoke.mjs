// Live capture on the loopback interface: live reload, autostop, ring buffer, stop.
// Generates its own ICMP traffic with ping, and TCP with the robot-arm and ct-archive examples.
// test/live-tail.mjs covers captures big enough for provisional packets.
// Usage: node test/live-smoke.mjs   (after npm run build)
import { spawn, execFileSync } from "node:child_process";
import { createSocket } from "node:dgram";
import { copyFileSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { request } from "node:http";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import assert from "node:assert/strict";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const token = "live-smoke-test-token";
const captureDir = mkdtempSync(join(tmpdir(), "wirebuddy-live-"));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// A home of its own: the tester's Wireshark preferences, profiles and plugins don't apply
const home = mkdtempSync(join(tmpdir(), "wirebuddy-home-"));
// A panel, to read the live capture as panels do
const panelDir = join(home, ".local/share/wirebuddy/extensions/live/panel");
mkdirSync(panelDir, { recursive: true, mode: 0o700 });
writeFileSync(join(panelDir, "main.js"), "wb.ready();\n");
writeFileSync(join(panelDir, "../extension.json"), JSON.stringify({ label: "live", version: "1", panel: true }));
const server = spawn(process.execPath, [join(root, "dist/server/main.js"), "--port", "0", "--token", token, "--capture-dir", captureDir], {
  stdio: ["ignore", "pipe", "inherit"],
  env: { ...process.env, HOME: home, XDG_CONFIG_HOME: join(home, ".config"), XDG_DATA_HOME: join(home, ".local/share"), WIREBUDDY_EXTENSIONS: "" },
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
  if (!res.ok) throw new Error(`${path}: ${res.status} ${JSON.stringify(json)}`);
  return json;
}
const state = () => api("/api/state");
// Only echo request/reply: other loopback ICMP (e.g. port unreachable) may be around
const ECHO = "icmp[icmptype] == icmp-echo or icmp[icmptype] == icmp-echoreply";
const ping = (seconds) => spawn("ping", ["-i", "0.2", "-c", String(seconds * 5), "127.0.0.1"], { stdio: "ignore" });

async function waitIdle(timeoutMs) {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) {
    const s = await state();
    if (s.capture.status === "idle" || s.capture.status === "error") return s;
    await sleep(250);
  }
  throw new Error("capture did not stop");
}

/** An MCP client of a WireBuddy of its own that captures into `dir`, and its tools: text, or they throw. */
async function agent(dir) {
  const client = new Client({ name: "live-smoke", version: "0" });
  await client.connect(
    new StdioClientTransport({
      command: process.execPath,
      args: [join(root, "dist/server/main.js"), "--mcp", "--port", "0", "--capture-dir", dir],
      env: { ...process.env, HOME: home, XDG_CONFIG_HOME: join(home, ".config"), XDG_DATA_HOME: join(home, ".local/share"), WIREBUDDY_EXTENSIONS: "" },
      stderr: "ignore",
    }),
  );
  const tool = async (name, args) => {
    const r = await client.callTool({ name, arguments: args });
    const text = r.content.map((c) => c.text).join("\n");
    if (r.isError) throw new Error(`${name}: ${text}`);
    return text;
  };
  return { client, tool };
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
  await check("invalid capture filter is refused", async () => {
    await assert.rejects(api("/api/capture/start", { iface: "lo", filter: "icmpp", autostop: {}, ring: null }), /capture filter/);
  });
  await check("unknown interface is refused", async () => {
    await assert.rejects(api("/api/capture/start", { iface: "-w/etc/passwd", filter: "", autostop: {}, ring: null }), /unknown interface/);
  });

  await check("live view grows, filter survives reloads, autostop", async () => {
    const pinger = ping(6);
    await api("/api/capture/start", { iface: "lo", filter: ECHO, autostop: { durationSec: 4 }, ring: null });
    const seen = new Set();
    const gens = new Set();
    let filtered = false;
    for (let i = 0; i < 14; i++) {
      await sleep(300);
      const s = await state();
      if (s.file) {
        seen.add(s.totalFrames);
        gens.add(s.generation);
      }
      // Full reads of a small capture are quick: nothing is provisional
      assert.equal(s.tail, null);
      if (!filtered && s.totalFrames > 4) {
        const r = await api("/api/filter", { filter: "icmp.type == 8" });
        assert.equal(r.ok, true);
        filtered = true;
      }
    }
    const s = await waitIdle(6000);
    pinger.kill();
    assert.equal(s.capture.status, "idle", s.capture.error ?? "");
    assert.ok(seen.size >= 3, `frame count should grow during capture, saw ${[...seen]}`);
    assert.ok(gens.size >= 3, "generation should bump on each live reload");
    await sleep(1200); // final reload after stop
    const end = await state();
    assert.equal(end.filter, "icmp.type == 8");
    assert.equal(end.tail, null);
    assert.ok(end.totalFrames >= 30, `expected ~40 frames, got ${end.totalFrames}`);
    assert.ok(Math.abs(end.displayedFrames * 2 - end.totalFrames) <= 2, `requests should be half: ${end.displayedFrames}/${end.totalFrames}`);
    assert.ok(Math.abs(end.capture.packets - end.totalFrames) <= 2, `dumpcap count ${end.capture.packets} vs frames ${end.totalFrames}`);
    const rows = await api(`/api/rows?gen=${end.generation}&start=0&count=3`);
    const info = end.columns.indexOf("Info");
    assert.ok(rows.rows.every((r) => /Echo \(ping\) request/.test(r.c[info])), JSON.stringify(rows.rows[0]));
    await api("/api/filter", { filter: "" });
  });

  await check("ring buffer rotates files and keeps only N", async () => {
    const pinger = ping(8);
    await api("/api/capture/start", { iface: "lo", filter: ECHO, autostop: { durationSec: 7 }, ring: { files: 2, durationSec: 2 } });
    let files = new Set();
    for (let i = 0; i < 30; i++) {
      await sleep(300);
      const s = await state();
      if (s.file) files.add(s.file);
      if (s.capture.status === "idle") break;
    }
    const s = await waitIdle(5000);
    pinger.kill();
    assert.ok(s.capture.files.length >= 3, `expected >= 3 ring files, got ${s.capture.files.length}`);
    assert.ok(files.size >= 2, "the viewer should follow the current ring file");
    const onDisk = readdirSync(captureDir).filter((f) => f.includes("_0000"));
    assert.equal(onDisk.length, 2, `ring keeps 2 files on disk: ${onDisk}`);
    assert.equal(s.file, s.capture.currentFile);
  });

  await check("two simultaneous starts run only one dumpcap", async () => {
    const req = { iface: "lo", filter: ECHO, autostop: { durationSec: 3 }, ring: null };
    const results = await Promise.allSettled([api("/api/capture/start", req), api("/api/capture/start", req)]);
    assert.equal(results.filter((r) => r.status === "fulfilled").length, 1, JSON.stringify(results.map((r) => r.status)));
    await api("/api/capture/stop", {});
    await waitIdle(6000);
    const pids = await new Promise((resolve) => {
      const ps = spawn("pgrep", ["-P", String(server.pid), "dumpcap"]);
      let out = "";
      ps.stdout.on("data", (d) => (out += d));
      ps.on("exit", () => resolve(out.trim()));
    });
    assert.equal(pids, "", "no dumpcap may survive stop");
  });
  await check("ring buffer with auto-stop by size is refused", async () => {
    await assert.rejects(
      api("/api/capture/start", { iface: "lo", filter: "", autostop: { filesizeKB: 100 }, ring: { files: 2, durationSec: 2 } }),
      /cannot be combined/,
    );
  });
  await check("new files without a ring keep every file, stop after N files", async () => {
    const before = new Set(readdirSync(captureDir));
    const pinger = ping(8);
    await api("/api/capture/start", { iface: "lo", filter: ECHO, autostop: { files: 3, durationSec: 20 }, ring: { durationSec: 1 } });
    const s = await waitIdle(15000);
    pinger.kill();
    assert.equal(s.capture.files.length, 3, JSON.stringify(s.capture.files));
    const written = readdirSync(captureDir).filter((f) => !before.has(f));
    assert.equal(written.length, 3, `all 3 files stay on disk: ${written}`);
  });
  await check("promiscuous mode off passes -p to dumpcap", async () => {
    await api("/api/capture/start", { iface: "lo", filter: ECHO, promiscuous: false, autostop: { durationSec: 3 }, ring: null });
    try {
      const s = await state();
      assert.equal(s.capture.promiscuous, false);
      const pid = await new Promise((resolve) => {
        const ps = spawn("pgrep", ["-P", String(server.pid), "dumpcap"]);
        let out = "";
        ps.stdout.on("data", (d) => (out += d));
        ps.on("exit", () => resolve(out.trim().split("\n")[0]));
      });
      assert.ok(pid, "dumpcap runs");
      assert.ok(readFileSync(`/proc/${pid}/cmdline`, "utf8").split("\0").includes("-p"));
    } finally {
      await api("/api/capture/stop", {});
      await waitIdle(6000);
    }
  });
  await check("capture options that don't fit together are refused", async () => {
    await assert.rejects(api("/api/capture/start", { iface: "lo", filter: "", autostop: { files: 2 }, ring: null }), /needs new files/);
    await assert.rejects(api("/api/capture/start", { iface: "lo", filter: "", autostop: {}, ring: { files: 1, durationSec: 2 } }), /at least 2 files/);
    await assert.rejects(api("/api/capture/start", { iface: "lo", filter: "", autostop: {}, ring: { files: 2 } }), /a new file needs/);
  });

  await check("export with more selections than one editcap run allows", async () => {
    const pinger = spawn("ping", ["-i", "0.005", "-c", "700", "127.0.0.1"], { stdio: "ignore" });
    await api("/api/capture/start", { iface: "lo", filter: ECHO, autostop: { durationSec: 5 }, ring: null });
    const s = await waitIdle(10000);
    pinger.kill();
    await sleep(1200);
    const total = (await state()).totalFrames;
    assert.ok(total >= 1100, `need >1000 frames, got ${total}`);
    // every other frame: about 550 single-frame selections
    const odd = Array.from({ length: Math.floor(total / 2) }, (_, i) => 2 * i + 1);
    const out = join(captureDir, "odd.pcapng");
    const r = await api("/api/export", { path: out, which: "range", range: odd.join(",") });
    assert.equal(r.frames, odd.length);
    const n = Number(/Number of packets:\s+(\d+)/.exec(execFileSync("capinfos", ["-c", out], { encoding: "utf8" }))[1]);
    assert.equal(n, odd.length);
    assert.equal(s.capture.error, null);
  });

  await check("TLS decryption with a key log file", async () => {
    // Local HTTPS server with a throwaway certificate; curl writes its session keys
    const dir = join(captureDir, "tls");
    mkdirSync(dir);
    execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost", "-days", "1",
      "-keyout", join(dir, "key.pem"), "-out", join(dir, "cert.pem")], { stdio: "ignore" });
    const serverPy = [
      "import http.server, ssl, sys",
      "s = http.server.HTTPServer(('127.0.0.1', 18443), http.server.SimpleHTTPRequestHandler)",
      "c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); c.load_cert_chain(sys.argv[1], sys.argv[2])",
      "s.socket = c.wrap_socket(s.socket, server_side=True); s.serve_forever()",
    ].join("\n");
    const https = spawn("python3", ["-c", serverPy, join(dir, "cert.pem"), join(dir, "key.pem")], { cwd: dir, stdio: "ignore" });
    try {
      await sleep(700);
      await api("/api/capture/start", { iface: "lo", filter: "tcp port 18443", autostop: { durationSec: 3 }, ring: null });
      await sleep(800);
      const keylog = join(dir, "keys.log");
      execFileSync("curl", ["-sk", "--http1.1", "-o", "/dev/null", "https://127.0.0.1:18443/cert.pem"], { env: { ...process.env, SSLKEYLOGFILE: keylog } });
      await waitIdle(8000);
      await sleep(1200);
      const http = () => api("/api/filter", { filter: "http" }).then(() => state()).then((s) => s.displayedFrames);
      assert.equal(await http(), 0, "without keys the HTTP inside TLS stays hidden");
      await api("/api/tls", { keylog });
      assert.ok((await http()) >= 2, "with the key log the request and response are decrypted");
      await api("/api/tls", { keylog: null });
      await api("/api/filter", { filter: "" });
    } finally {
      https.kill();
    }
  });

  await check("stop", async () => {
    const pinger = ping(5);
    await api("/api/capture/start", { iface: "lo", filter: "", autostop: {}, ring: null });
    await sleep(1500);
    assert.equal((await state()).capture.status, "running");
    await assert.rejects(api("/api/capture/start", { iface: "lo", filter: "", autostop: {}, ring: null }), /already running/);
    await api("/api/capture/stop", {});
    const s = await waitIdle(5000);
    pinger.kill();
    assert.equal(s.capture.status, "idle");
    assert.equal(s.capture.error, null);
    assert.ok(s.totalFrames > 0);
  });

  await check("a panel reads the live capture as it grows", async () => {
    await api("/api/panels/open", { name: "live" });
    const host = new URL((await state()).panels[0].src).host;
    const port = Number(new URL(base).port);
    const panelReq = (path, { method = "GET", headers = {}, body } = {}, onData) =>
      new Promise((resolve, reject) => {
        const req = request({ host: "127.0.0.1", port, path, method, headers: { host, "sec-fetch-site": "same-origin", ...headers } }, (res) => {
          const chunks = [];
          res.on("data", (c) => (chunks.push(c), onData?.(Buffer.concat(chunks).toString("utf8"), req)));
          res.on("end", () => resolve({ status: res.statusCode, raw: Buffer.concat(chunks) }));
          res.on("close", () => resolve({ status: res.statusCode, raw: Buffer.concat(chunks) }));
        });
        req.on("error", (e) => (e.code === "ECONNRESET" ? resolve({}) : reject(e)));
        req.end(body);
      });
    const doc = /<meta name="wb-doc" content="([a-z2-7]+)">/.exec((await panelReq("/", { headers: { "sec-fetch-site": "cross-site", "sec-fetch-dest": "iframe" } })).raw.toString())[1];
    const packets = async (q) => {
      const r = await panelReq("/_wb/api/packets", { method: "POST", body: JSON.stringify(q), headers: { origin: `http://${host}`, "content-type": "application/json", "x-wb-doc": doc } });
      assert.equal(r.status, 200, r.raw.toString());
      const h = r.raw.readUInt32LE(4);
      return JSON.parse(r.raw.subarray(8, 8 + h).toString());
    };
    const pinger = ping(5);
    try {
      await api("/api/capture/start", { iface: "lo", filter: ECHO, autostop: { durationSec: 5 }, ring: null });
      // The event stream tells the panel when packets come
      let seen = "";
      await panelReq(`/_wb/events?doc=${doc}`, { headers: { "sec-fetch-dest": "empty" } }, (text, req) => {
        seen = text;
        if ((text.match(/event: packets\ndata: \{"frames":\d+,"live":true\}/g) ?? []).length >= 2) req.destroy();
      });
      assert.match(seen, /event: packets/);
      // A capture that grows is the same capture: no reset once it is open
      assert.doesNotMatch(seen.slice(seen.indexOf("event: packets")), /event: reset/);
      const early = await packets({ filter: "icmp" });
      assert.ok(early.n > 0 && early.live, JSON.stringify(early));
      await sleep(2000);
      const later = await packets({ filter: "icmp" });
      assert.ok(later.n > early.n, `${early.n} then ${later.n}`);
      const s = await waitIdle(10000);
      const end = await packets({});
      assert.equal(end.live, false);
      assert.equal(end.total, s.totalFrames);
    } finally {
      pinger.kill();
      await api("/api/panels/close", { name: "live" });
    }
  });

  await check("robot-arm example: a MOVE's payload waits for the ACK of its header, not after the fix", async () => {
    const example = join(root, "examples/investigations/robot-arm");
    const probe = createServer();
    await new Promise((r) => probe.listen(0, "127.0.0.1", r));
    const port = probe.address().port;
    await new Promise((r) => probe.close(r));
    const udp = createSocket("udp4");
    await new Promise((r) => udp.bind(0, "127.0.0.1", r));
    const telemetry = udp.address().port;
    await new Promise((r) => udp.close(r));
    const work = mkdtempSync(join(tmpdir(), "wirebuddy-arm-"));
    let device;
    try {
      // The fixed app: solution/fix.diff applied to a copy, as from the repository root
      const fixedDir = join(work, "examples/investigations/robot-arm");
      mkdirSync(fixedDir, { recursive: true });
      copyFileSync(join(example, "app.mjs"), join(fixedDir, "app.mjs"));
      execFileSync("git", ["apply", join(example, "solution/fix.diff")], { cwd: work, env: { ...process.env, GIT_CEILING_DIRECTORIES: dirname(work) }, stdio: "pipe" });

      device = spawn(process.execPath, [join(example, "device.mjs"), "--port", String(port), "--telemetry", String(telemetry)], { stdio: ["ignore", "pipe", "ignore"] });
      await new Promise((resolve, reject) => {
        device.stdout.setEncoding("utf8").on("data", (d) => /listening on/.test(d) && resolve());
        device.on("exit", (code) => reject(new Error(`device exited with ${code}`)));
      });
      const runApp = (app) =>
        new Promise((resolve, reject) => {
          const p = spawn(process.execPath, [app, "--port", String(port), "--telemetry", String(telemetry), "--seconds", "2"], { stdio: "ignore" });
          p.on("exit", (code) => (code === 0 ? resolve() : reject(new Error(`${app} exited with ${code}`))));
        });
      /** Segments with data toward the controller while `app` runs, in capture order. */
      const toDevice = async (app) => {
        await api("/api/capture/start", { iface: "lo", filter: `tcp port ${port}`, autostop: { durationSec: 20 }, ring: null });
        await sleep(800);
        await runApp(app);
        await sleep(300);
        await api("/api/capture/stop", {});
        const s = await waitIdle(6000);
        assert.equal(s.capture.error, null);
        await sleep(1200); // final reload after stop
        const cols = await api("/api/columns", { columns: ["tcp.stream", "tcp.len", "frame.time_relative"].map((field) => ({ field, title: "" })) });
        assert.equal(cols.ok, true, JSON.stringify(cols));
        assert.equal((await api("/api/filter", { filter: `tcp.dstport == ${port} && tcp.len > 0` })).ok, true);
        const { generation, displayedFrames } = await state();
        const segments = [];
        for (let start = 0; start < displayedFrames; start += 500) {
          for (const row of (await api(`/api/rows?gen=${generation}&start=${start}&count=500`)).rows) {
            const [stream, len, t] = row.c.slice(-3);
            segments.push({ stream, len: Number(len), t: Number(t) });
          }
        }
        return segments;
      };

      // Header alone (8 bytes), then the MOVE payload (14 bytes) of the same connection
      const buggy = await toDevice(join(example, "app.mjs"));
      const gaps = [];
      buggy.forEach((seg, i) => {
        if (seg.len !== 8) return;
        const next = buggy.slice(i + 1).find((n) => n.stream === seg.stream);
        if (next?.len === 14) gaps.push(next.t - seg.t);
      });
      assert.ok(gaps.length >= 20, `MOVE headers sent on their own: ${gaps.length} in ${buggy.length} segments`);
      const late = gaps.filter((g) => g >= 0.03).length;
      assert.ok(late >= 0.8 * gaps.length, `payload 30 ms or more after its header in only ${late} of ${gaps.length}`);

      const fixed = await toDevice(join(fixedDir, "app.mjs"));
      assert.equal(fixed.filter((seg) => seg.len === 14).length, 0, "no MOVE payload in a segment of its own");
      const whole = fixed.filter((seg) => seg.len === 22).length;
      assert.ok(whole >= 60, `MOVEs with header and payload in one segment: ${whole}`);
    } finally {
      device?.kill();
      await api("/api/capture/stop", {}).catch(() => {});
      await waitIdle(6000).catch(() => {});
      await api("/api/filter", { filter: "" }).catch(() => {});
      await api("/api/columns", { columns: [] }).catch(() => {});
      rmSync(work, { recursive: true, force: true });
    }
  });

  await check("ct-archive example: Wireshark exports an image per C-STORE of the exporter, 184 with 124 UIDs", async () => {
    const example = join(root, "examples/investigations/ct-archive");
    const probe = createServer();
    await new Promise((r) => probe.listen(0, "127.0.0.1", r));
    const port = probe.address().port;
    await new Promise((r) => probe.close(r));
    const dir = mkdtempSync(join(tmpdir(), "wirebuddy-live-ct-"));
    const { client, tool } = await agent(dir);
    let archive;
    try {
      archive = spawn(process.execPath, [join(example, "device.mjs"), "--port", String(port)], { stdio: ["ignore", "pipe", "ignore"] });
      await new Promise((resolve, reject) => {
        archive.stdout.setEncoding("utf8").on("data", (d) => /listening on/.test(d) && resolve());
        archive.on("exit", (code) => reject(new Error(`archive exited with ${code}`)));
      });
      await tool("start_capture", { interface: "lo", filter: `tcp port ${port}`, stop_after_seconds: 30 });
      await sleep(800);
      await new Promise((resolve, reject) => {
        const p = spawn(process.execPath, [join(example, "app.mjs"), "--port", String(port)], { stdio: "ignore" });
        p.on("exit", (code) => (code === 0 ? resolve() : reject(new Error(`app.mjs exited with ${code}`))));
      });
      await sleep(300);
      await tool("stop_capture", {});
      // The objects of the whole file, once the view has read it after the stop
      let listing = "";
      for (let i = 0; i < 40 && !/^184 DICOM objects:/.test(listing); i++) {
        await sleep(250);
        if (/Capture \(started by agent\): idle/.test(await tool("get_view_state", {}))) listing = await tool("export_objects", { kind: "dicom" });
      }
      const uids = [...listing.matchAll(/^frame \d+: \d+-\d+-([\d.]+)\.dcm — /gm)].map((m) => m[1]);
      assert.equal(uids.length, 184, listing.slice(0, 300));
      assert.equal(new Set(uids).size, 124);
    } finally {
      archive?.kill();
      await tool("stop_capture", {}).catch(() => {});
      await client.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  await check("the agent starts a capture over MCP", async () => {
    const dir = mkdtempSync(join(tmpdir(), "wirebuddy-live-mcp-"));
    const { client, tool } = await agent(dir);
    const pinger = ping(4);
    try {
      const started = await tool("start_capture", { interface: "lo", filter: ECHO, stop_after_seconds: 3 });
      assert.match(started, /^Capturing on lo with the capture filter .* into .*\.pcapng\. The view follows it live/);
      assert.match(await tool("get_view_state", {}), /Capture \(started by agent\): running/);
      await assert.rejects(tool("start_capture", { interface: "lo" }), /already running/);
      let view = "";
      for (let i = 0; i < 40 && !/Capture \(started by agent\): idle/.test(view); i++) {
        await sleep(250);
        view = await tool("get_view_state", {});
      }
      assert.match(view, /Capture \(started by agent\): idle/);
      const frames = Number(/Frames: (\d+)/.exec(view)?.[1]);
      assert.ok(frames > 0, view);
      assert.ok(readdirSync(dir).some((f) => f.endsWith(".pcapng")), "written into the capture folder");
    } finally {
      pinger.kill();
      await client.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });
} finally {
  server.kill();
  rmSync(captureDir, { recursive: true, force: true });
}
console.log(failures ? `${failures} check(s) failed` : "all checks passed");
process.exit(failures ? 1 : 0);
