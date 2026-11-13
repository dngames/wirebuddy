import { accessSync, constants } from "node:fs";
import { homedir } from "node:os";
import { delimiter, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { Extensions } from "./extensions.ts";
import { investigationDir } from "./investigation.ts";
import { removeStaleSlices } from "./livetail.ts";
import { keptToken, settingsDir } from "./settings.ts";
import { Viewer } from "./viewer.ts";
import { startHttp } from "./http.ts";
import { startMcp } from "./mcp.ts";
import { VERSION } from "../shared/version.ts";
import { instanceFile, removeInstance, watch, writeInstance } from "./watch.ts";

const USAGE = `Usage: wirebuddy [options] [capture-file]

  --mcp               also serve MCP over stdio (for Claude Code); logs go to stderr
  --port <n>          HTTP port on 127.0.0.1 (default 8765, falls back to a free one)
  --token <t>         session token for the UI/API, at least 16 characters (default: the random one
                      kept from the last start, see below; env WIREBUDDY_TOKEN, which unlike --token
                      other local users can't see in ps)
  --capture-dir <d>   where live captures are written (default ~/.local/share/wirebuddy/captures)
  --profile <name>    Wireshark configuration profile for dissection (also used by Open in Wireshark)
  --tls-keylog <file> decrypt TLS with this key log file (SSLKEYLOGFILE format)
  --watch <file>      wait for the next problem or question in the viewer that wrote this instance file, print it, exit
  --version           print the version
  -h, --help          show this help

Environment: WIREBUDDY_PORT, WIREBUDDY_TOKEN, WIREBUDDY_CAPTURE_DIR, WIREBUDDY_PROFILE
set the defaults of the options of the same name. WIREBUDDY_EXTENSIONS lists more folders
of Lua extensions (separated by ":"), after ~/.local/share/wirebuddy/extensions.

Without --token WireBuddy reuses the token of its last start, kept for you alone in
~/.local/share/wirebuddy/state/token, so that an open page survives a restart. Delete that file
for a new one at the next start.`;

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

/** An option the command line got wrong: said in a line, not as a stack trace. */
function usageError(message: string): never {
  process.stderr.write(`wirebuddy: ${message}\n(wirebuddy --help lists the options)\n`);
  process.exit(2);
}

function parse() {
  try {
    return parseArgs({
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
  } catch (err) {
    usageError((err as Error).message);
  }
}
const { values, positionals } = parse();

if (values.help) {
  console.log(USAGE);
  process.exit(0);
}
if (values.version) {
  console.log(`wirebuddy ${VERSION}`);
  process.exit(0);
}

if (values.watch) process.exit(await watch(values.watch));

const port = Number(values.port);
if (!/^\d+$/.test(values.port) || port > 65535) usageError(`the port must be a number from 0 to 65535, not "${values.port}"`);

// In MCP mode stdout carries the protocol, so everything human goes to stderr
const log = (msg: string) => (values.mcp ? process.stderr : process.stdout).write(`wirebuddy: ${msg}\n`);

const sharkd = which("sharkd");
if (!sharkd) {
  process.stderr.write("wirebuddy: sharkd not found on PATH (it ships with Wireshark; on Debian/Ubuntu: wireshark-common)\n");
  process.exit(1);
}
const dumpcap = which("dumpcap");
if (!dumpcap) log("dumpcap not found on PATH; live capture is unavailable");

const extensions = new Extensions(join(dirname(fileURLToPath(import.meta.url)), "../../examples/extensions"), join(dirname(fileURLToPath(import.meta.url)), ".."));
await extensions.init(sharkd);
if (extensions.unavailable) log(`extensions are unavailable: ${extensions.unavailable}`);

const captureDir = resolve(values["capture-dir"] ?? join(homedir(), ".local/share/wirebuddy/captures"));
// Slices of big live captures that servers killed before left there
removeStaleSlices(captureDir);
const viewer = new Viewer({
  captureDir,
  sharkd,
  dumpcap: dumpcap ?? "dumpcap",
  wireshark: which("wireshark"),
  profile: values.profile,
  editcap: which("editcap") ?? "editcap",
  mergecap: which("mergecap") ?? "mergecap",
  extensions,
  panelRuntime: join(dirname(fileURLToPath(import.meta.url)), "../panel"),
  investigations: investigationDir(),
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
let token = values.token;
if (token && token.length < 16) {
  process.stderr.write("wirebuddy: the token must be at least 16 characters\n");
  process.exit(1);
}

const webRoot = join(dirname(fileURLToPath(import.meta.url)), "../web");
if (!token) {
  // The one used last, so that a page open across a restart (an agent's client restarting its MCP server) reconnects with it
  const kept = keptToken(settingsDir());
  token = kept.token;
  if (kept.problem) log(`the session token is not kept for the next start: ${kept.problem}`);
}
const http = await startHttp(viewer, {
  port,
  token,
  webRoot,
});
const instance = instanceFile();
const shutdown = () => {
  viewer.shutdown();
  http.close();
  removeInstance(instance);
  process.exit(0);
};
// Set before the URL is out: a caller may signal as soon as it sees it
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
// The terminal closed
process.on("SIGHUP", shutdown);
// The watcher's way in, there before the URL is out; without it the server runs all the same
try {
  writeInstance(instance, http.url);
} catch (err) {
  log(`--watch is unavailable: ${(err as Error).message}`);
}
log(`UI at ${http.url}`);

if (positionals[0]) {
  viewer.open(resolve(positionals[0])).catch((err) => log(`could not open ${positionals[0]}: ${(err as Error).message}`));
}

if (values.mcp) {
  viewer.attachAgent();
  await startMcp(viewer, http, `"${process.execPath}" "${fileURLToPath(import.meta.url)}" --watch "${instance}"`);
  // The MCP client closing stdin ends the session
  process.stdin.on("close", shutdown);
}
