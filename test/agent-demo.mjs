// Plays a short scripted "agent" session over MCP so you can watch the UI react.
// Usage: node test/agent-demo.mjs [capture] [--port 8766]   then open the printed URL
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";
import { parseArgs } from "node:util";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const { values, positionals } = parseArgs({ allowPositionals: true, options: { port: { type: "string", default: "8766" } } });
const capture = resolve(positionals[0] ?? join(root, "test/fixtures/http.pcapng"));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const client = new Client({ name: "agent-demo", version: "0" });
await client.connect(
  new StdioClientTransport({
    command: process.execPath,
    args: [join(root, "dist/server/main.js"), "--mcp", "--port", values.port, "--token", "demo-token"],
    stderr: "ignore",
  }),
);
const call = async (name, args = {}) => {
  const r = await client.callTool({ name, arguments: args });
  const text = r.content.map((c) => c.text).join("\n");
  console.log(`> ${name} ${JSON.stringify(args)}\n${text.split("\n").slice(0, 6).join("\n")}\n`);
  return text;
};

console.log(`Open ${await call("viewer_url")} now; the demo starts in 8 s.\n`);
await sleep(8000);
await call("open_capture", { path: capture });
await sleep(3000);
await call("set_display_filter", { filter: "http" });
await sleep(3000);
await call("mark_frames", { frames: [21, 25], note: "request for a missing file and its 404" });
await sleep(3000);
await call("goto_frame", { frame: 25 });
await sleep(3000);
await call("inspect_frame", { protocols: ["http"], max_lines: 12 });
console.log("Demo done; the server stays up for 60 s.");
await sleep(60000);
await client.close();
