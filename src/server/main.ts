import { randomBytes } from "node:crypto";
import { accessSync, constants } from "node:fs";
import { homedir } from "node:os";
import { delimiter, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { Viewer } from "./viewer.ts";
import { startHttp } from "./http.ts";
import { startMcp } from "./mcp.ts";

const USAGE = `Usage: wirebuddy [options] [capture-file]

  --mcp               also serve MCP over stdio (for Claude Code); logs go to stderr
  --port <n>          HTTP port on 127.0.0.1 (default 8765, falls back to a free one)
  --token <t>         session token for the UI/API (default: random; env WIREBUDDY_TOKEN)
  --capture-dir <d>   where live captures are written (default ~/.local/share/wirebuddy/captures)
  --profile <name>    Wireshark configuration profile for dissection (also used by Open in Wireshark)
  --tls-keylog <file> decrypt TLS with this key log file (SSLKEYLOGFILE format)
  -h, --help          show this help`;

function which(name: string): string | null {
  for (const dir of (process.env.PATH ?? "").split(delimiter)) {
    if (!dir) continue;
    const candidate = join(dir, name);
    try {
      accessSync(candidate, constants.X_OK);
      return candidate;
    } catch {
      // not here
    }
  }
  return null;
}

const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    mcp: { type: "boolean", default: false },
    port: { type: "string", default: process.env.WIREBUDDY_PORT ?? "8765" },
    token: { type: "string", default: process.env.WIREBUDDY_TOKEN },
    "capture-dir": { type: "string", default: process.env.WIREBUDDY_CAPTURE_DIR },
    profile: { type: "string", default: process.env.WIREBUDDY_PROFILE },
    "tls-keylog": { type: "string" },
    help: { type: "boolean", short: "h", default: false },
  },
});

if (values.help) {
  console.log(USAGE);
  process.exit(0);
}

// In MCP mode stdout carries the protocol, so everything human goes to stderr
const log = (msg: string) => (values.mcp ? process.stderr : process.stdout).write(`wirebuddy: ${msg}\n`);

const sharkd = which("sharkd");
if (!sharkd) {
  process.stderr.write("wirebuddy: sharkd not found on PATH (it ships with Wireshark; on Debian/Ubuntu: wireshark-common)\n");
  process.exit(1);
}
const dumpcap = which("dumpcap");
if (!dumpcap) log("dumpcap not found on PATH; live capture is unavailable");

const viewer = new Viewer({
  captureDir: resolve(values["capture-dir"] ?? join(homedir(), ".local/share/wirebuddy/captures")),
  sharkd,
  dumpcap: dumpcap ?? "dumpcap",
  wireshark: which("wireshark"),
  profile: values.profile,
  editcap: which("editcap") ?? "editcap",
  mergecap: which("mergecap") ?? "mergecap",
});
const tlsKeylog = values["tls-keylog"];
if (tlsKeylog) await viewer.setTlsKeylog(resolve(tlsKeylog)).catch((err) => log(`TLS key log: ${(err as Error).message}`));
else void viewer.loadTlsPreference();

const webRoot = join(dirname(fileURLToPath(import.meta.url)), "../web");
const http = await startHttp(viewer, {
  port: Number(values.port),
  token: values.token ?? randomBytes(16).toString("hex"),
  webRoot,
});
log(`UI at ${http.url}`);

if (positionals[0]) {
  viewer.open(resolve(positionals[0])).catch((err) => log(`could not open ${positionals[0]}: ${(err as Error).message}`));
}

const shutdown = () => {
  viewer.shutdown();
  http.close();
  process.exit(0);
};
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

if (values.mcp) {
  await startMcp(viewer, () => http.url);
  // The MCP client closing stdin ends the session
  process.stdin.on("close", shutdown);
}
