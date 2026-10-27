// Live capture on the loopback interface: live reload, autostop, ring buffer, stop.
// Generates its own ICMP traffic with ping. Usage: node test/live-smoke.mjs   (after npm run build)
import { spawn, execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import assert from "node:assert/strict";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const token = "live-smoke-test-token";
const captureDir = mkdtempSync(join(tmpdir(), "wirebuddy-live-"));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// A home of its own: the tester's Wireshark preferences, profiles and plugins don't apply
const home = mkdtempSync(join(tmpdir(), "wirebuddy-home-"));
const server = spawn(process.execPath, [join(root, "dist/server/main.js"), "--port", "0", "--token", token, "--capture-dir", captureDir], {
  stdio: ["ignore", "pipe", "inherit"],
  env: { ...process.env, HOME: home, XDG_CONFIG_HOME: join(home, ".config") },
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
} finally {
  server.kill();
  rmSync(captureDir, { recursive: true, force: true });
}
console.log(failures ? `${failures} check(s) failed` : "all checks passed");
process.exit(failures ? 1 : 0);
