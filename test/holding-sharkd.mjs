// A stand-in for sharkd that runs the real one (REAL_SHARKD) and can hold a full read: while the
// file HOLD exists, loading a capture outside a folder of slices waits, with the file HELD there,
// until HOLD goes (the load goes on) or KILL appears (KILL and HOLD go, and sharkd is SIGKILLed,
// as by the kernel's OOM killer).
// Usage: put an executable named sharkd first on PATH that runs node test/holding-sharkd.mjs "$@".
import { spawn } from "node:child_process";
import { existsSync, rmSync, writeFileSync } from "node:fs";

const { REAL_SHARKD, HOLD, HELD, KILL } = process.env;
const sharkd = spawn(REAL_SHARKD, process.argv.slice(2), { stdio: ["pipe", "inherit", "inherit"] });
sharkd.on("exit", (code, signal) => (signal ? process.kill(process.pid, signal) : process.exit(code ?? 0)));
sharkd.stdin.on("error", () => {});
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Passes a request on, a held load once it may go on. */
async function pass(line) {
  let file = "";
  try {
    const m = JSON.parse(line);
    if (m.method === "load") file = String(m.params?.file ?? "");
  } catch {
    // not a request
  }
  if (file && !file.includes(".wirebuddy-slices-") && existsSync(HOLD)) {
    writeFileSync(HELD, String(process.pid));
    while (existsSync(HOLD)) {
      if (existsSync(KILL)) {
        for (const f of [KILL, HOLD, HELD]) rmSync(f, { force: true });
        sharkd.kill("SIGKILL");
        process.kill(process.pid, "SIGKILL");
      }
      await sleep(10);
    }
    rmSync(HELD, { force: true });
  }
  sharkd.stdin.write(line);
}

let queue = Promise.resolve();
let buf = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (d) => {
  buf += d;
  for (let nl; (nl = buf.indexOf("\n")) >= 0; ) {
    const line = buf.slice(0, nl + 1);
    buf = buf.slice(nl + 1);
    queue = queue.then(() => pass(line));
  }
});
process.stdin.on("end", () => queue.then(() => sharkd.stdin.end()));
