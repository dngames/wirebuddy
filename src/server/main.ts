import { randomBytes } from "node:crypto";
import { accessSync, constants } from "node:fs";
import { homedir } from "node:os";
import { delimiter, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { Extensions } from "./extensions.ts";
import { Viewer } from "./viewer.ts";
import { startHttp } from "./http.ts";
import { startMcp } from "./mcp.ts";
import { VERSION } from "../shared/version.ts";
import { instanceFile, removeInstance, watch, writeInstance } from "./watch.ts";

const USAGE = `Usage: wirebuddy [options] [capture-file]

  --mcp               also serve MCP over stdio (for Claude Code); logs go to stderr
  --port <n>          HTTP port on 127.0.0.1 (default 8765, falls back to a free one)
  --token <t>         session token for the UI/API, at least 16 characters (default: random;
                      env WIREBUDDY_TOKEN, which unlike --token other local users can't see in ps)
  --capture-dir <d>   where live captures are written (default ~/.local/share/wirebuddy/captures)
  --profile <name>    Wireshark configuration profile for dissection (also used by Open in Wireshark)
  --tls-keylog <file> decrypt TLS with this key log file (SSLKEYLOGFILE format)
  --watch <file>      wait for the next problem in the viewer that wrote this instance file, print it, exit
  --version           print the version
  -h, --help          show this help

Environment: WIREBUDDY_PORT, WIREBUDDY_TOKEN, WIREBUDDY_CAPTURE_DIR, WIREBUDDY_PROFILE
set the defaults of the options of the same name. WIREBUDDY_EXTENSIONS lists more folders
of Lua extensions (separated by ":"), after ~/.local/share/wirebuddy/extensions.`;

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
    watch: { type: "string" },
    help: { type: "boolean", short: "h", default: false },
    version: { type: "boolean", default: false },
  },
});

if (values.help) {
  console.log(USAGE);
  process.exit(0);
}
if (values.version) {
  console.log(`wirebuddy ${VERSION}`);
  process.exit(0);
}

if (values.watch) process.exit(await watch(values.watch));

// In MCP mode stdout carries the protocol, so everything human goes to stderr
const log = (msg: string) => (values.mcp ? process.stderr : process.stdout).write(`wirebuddy: ${msg}\n`);

const sharkd = which("sharkd");
if (!sharkd) {
  process.stderr.write("wirebuddy: sharkd not found on PATH (it ships with Wireshark; on Debian/Ubuntu: wireshark-common)\n");
  process.exit(1);
}
const dumpcap = which("dumpcap");
if (!dumpcap) log("dumpcap not found on PATH; live capture is unavailable");

const extensions = new Extensions();
await extensions.init(sharkd);
if (extensions.unavailable) log(`extensions are unavailable: ${extensions.unavailable}`);

const viewer = new Viewer({
  captureDir: resolve(values["capture-dir"] ?? join(homedir(), ".local/share/wirebuddy/captures")),
  sharkd,
  dumpcap: dumpcap ?? "dumpcap",
  wireshark: which("wireshark"),
  profile: values.profile,
  editcap: which("editcap") ?? "editcap",
  mergecap: which("mergecap") ?? "mergecap",
  extensions,
});
// The status bar's count only: never a reason not to start
try {
  viewer.refreshExtensions();
} catch (err) {
  log(`extensions: ${(err as Error).message}`);
}
const tlsKeylog = values["tls-keylog"];
if (tlsKeylog) await viewer.setTlsKeylog(resolve(tlsKeylog)).catch((err) => log(`TLS key log: ${(err as Error).message}`));
else void viewer.loadTlsPreference();

// An empty token would let anyone on this machine in
const token = values.token || randomBytes(16).toString("hex");
if (token.length < 16) {
  process.stderr.write("wirebuddy: the token must be at least 16 characters\n");
  process.exit(1);
}

const webRoot = join(dirname(fileURLToPath(import.meta.url)), "../web");
const http = await startHttp(viewer, {
  port: Number(values.port),
  token,
  webRoot,
});
log(`UI at ${http.url}`);
const instance = instanceFile();
writeInstance(instance, http.url);

if (positionals[0]) {
  viewer.open(resolve(positionals[0])).catch((err) => log(`could not open ${positionals[0]}: ${(err as Error).message}`));
}

const shutdown = () => {
  viewer.shutdown();
  http.close();
  removeInstance(instance);
  process.exit(0);
};
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

if (values.mcp) {
  viewer.attachAgent();
  await startMcp(viewer, http, `"${process.execPath}" "${fileURLToPath(import.meta.url)}" --watch "${instance}"`);
  // The MCP client closing stdin ends the session
  process.stdin.on("close", shutdown);
}
