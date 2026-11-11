// The sharkd client: how long sharkd may take for a request, and what callers hear when it dies
// or answers something unreadable, against a stand-in sharkd.
// Usage: node test/sharkd.mjs   (bundles the sources itself; needs no sharkd)
import { build } from "esbuild";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const out = mkdtempSync(join(tmpdir(), "wirebuddy-sharkd-"));
await build({ entryPoints: [join(root, "src/server/sharkd.ts")], outfile: join(out, "sharkd.mjs"), bundle: true, platform: "node", format: "esm", packages: "external", logLevel: "silent" });
const { Sharkd, SharkdError, SharkdExit } = await import(join(out, "sharkd.mjs"));

// A stand-in sharkd: works on one request at a time, in order, for params.ms each. "hang" is
// never answered and "skip" neither, but the requests after it are; "garbled" gets half an
// answer, after "die" it exits and after "killed" a signal ends it.
const fake = join(out, "fake-sharkd");
writeFileSync(
  fake,
  `#!${process.execPath}
let buf = "";
let turn = Promise.resolve();
const work = (req) => new Promise((done) => {
  if (req.method === "hang") return;
  if (req.method === "skip") return done();
  setTimeout(() => {
    const answer = { jsonrpc: "2.0", id: req.id, result: { did: req.method, pid: process.pid } };
    process.stdout.write((req.method === "garbled" ? JSON.stringify(answer).slice(0, -6) : JSON.stringify(answer)) + "\\n");
    if (req.method === "die") process.exit(3);
    if (req.method === "killed") process.kill(process.pid, "SIGKILL");
    done();
  }, req.params?.ms ?? 0);
});
process.stdin.on("data", (d) => {
  buf += d;
  for (let nl; (nl = buf.indexOf("\\n")) >= 0; ) {
    const req = JSON.parse(buf.slice(0, nl));
    buf = buf.slice(nl + 1);
    turn = turn.then(() => work(req));
  }
});
`,
);
chmodSync(fake, 0o755);

const engines = [];
/** A client of the stand-in, with what it reported as failures. */
const client = (callTimeout) => {
  const s = new Sharkd(fake);
  if (callTimeout) s.callTimeout = callTimeout;
  const failures = [];
  s.onFailure = (message) => failures.push(message);
  engines.push(s);
  return { s, failures };
};
/** How a call ended: its result, or its error. */
const ended = (call) => call.then((result) => ({ result }), (error) => ({ error }));
/** Keeps the event loop from noticing anything for `ms`. */
const busy = (ms) => {
  for (const until = Date.now() + ms; Date.now() < until; );
};

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
  await check("a request's time starts when its turn comes: ones waiting behind slow ones are answered", async () => {
    const { s, failures } = client(1000);
    // Four requests of 400 ms each, sent at once: the last one is answered 1.6 s after it was sent
    const all = await Promise.all(["tap", "frames", "frames", "frame"].map((method) => ended(s.call(method, { ms: 400 }))));
    assert.deepEqual(all.map((r) => r.result?.did ?? r.error.message), ["tap", "frames", "frames", "frame"]);
    assert.equal(new Set(all.map((r) => r.result.pid)).size, 1);
    assert.deepEqual(failures, []);
  });

  await check("a request sharkd doesn't answer in time fails, with those behind it, and sharkd starts again", async () => {
    const { s, failures } = client(300);
    const started = Date.now();
    const [first, hung, behind] = await Promise.all([s.call("status", { ms: 200 }), ended(s.call("hang")), ended(s.call("status"))]);
    // From its turn on, not from when it was sent
    assert.ok(Date.now() - started >= 480, `after ${Date.now() - started} ms`);
    assert.ok(hung.error instanceof SharkdExit && hung.error.message === 'sharkd did not answer "hang" within 0.3 s', hung.error?.message);
    assert.ok(!(behind.error instanceof SharkdExit) && behind.error?.message === "sharkd restarted after a timeout", behind.error?.message);
    assert.deepEqual(failures, ['sharkd did not answer "hang" within 0.3 s and was restarted']);
    const again = await s.call("status");
    assert.ok(again.did === "status" && again.pid !== first.pid);
  });

  await check("a request sharkd passes over fails in time, however many later ones it answers meanwhile", async () => {
    const { s, failures } = client(400);
    const started = Date.now();
    const skipped = ended(s.call("skip"));
    let answered = 0;
    const later = setInterval(() => s.call("status").then(() => answered++, () => {}), 50);
    try {
      const { error } = await skipped;
      assert.ok(error instanceof SharkdExit && error.message === 'sharkd did not answer "skip" within 0.4 s', error?.message);
      assert.ok(Date.now() - started < 2000 && answered >= 3, `after ${Date.now() - started} ms, ${answered} answered`);
      assert.deepEqual(failures, ['sharkd did not answer "skip" within 0.4 s and was restarted']);
    } finally {
      clearInterval(later);
    }
  });

  await check("a sharkd that died is found out when the next request is written: callers hear how it died", async () => {
    for (const [method, message, signal] of [["die", "sharkd exited (3)", null], ["killed", "sharkd exited (SIGKILL)", "SIGKILL"]]) {
      const { s, failures } = client();
      const { pid } = await s.call(method);
      // It is gone, but its exit hasn't been noticed yet: the write fails first
      busy(300);
      const [next, behind] = await Promise.all([ended(s.call("status")), ended(s.call("status"))]);
      for (const r of [next, behind]) assert.ok(r.error instanceof SharkdExit && r.error.message === message && r.error.signal === signal, `${method}: ${r.error?.message ?? JSON.stringify(r.result)}`);
      assert.deepEqual(failures, [message]);
      const again = await s.call("status");
      assert.ok(again.did === "status" && again.pid !== pid);
    }
  });

  await check("an answer that can't be read fails its request at once, and sharkd goes on answering", async () => {
    const { s, failures } = client(5000);
    const started = Date.now();
    const [garbled, next] = await Promise.all([ended(s.call("garbled")), ended(s.call("status"))]);
    assert.ok(garbled.error && !(garbled.error instanceof SharkdExit) && !(garbled.error instanceof SharkdError), JSON.stringify(garbled.result));
    assert.equal(garbled.error.message, `sharkd's answer to "garbled" could not be read`);
    assert.ok(Date.now() - started < 3000, `after ${Date.now() - started} ms`);
    assert.equal(next.result?.did, "status");
    assert.equal((await s.call("status")).pid, next.result.pid);
    assert.deepEqual(failures, []);
  });
} finally {
  for (const s of engines) s.close();
  rmSync(out, { recursive: true, force: true });
}
console.log(failures ? `${failures} check(s) failed` : "all checks passed");
process.exit(failures ? 1 : 0);
