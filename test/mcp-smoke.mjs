// Drives the MCP tools over stdio the way Claude Code would, against test/fixtures/http.pcapng.
// Usage: node test/mcp-smoke.mjs [--verbose]   (after npm run build)
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import assert from "node:assert/strict";
import { rmSync } from "node:fs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const fixture = join(root, "test/fixtures/http.pcapng");
const verbose = process.argv.includes("--verbose");

const transport = new StdioClientTransport({
  command: process.execPath,
  args: [join(root, "dist/server/main.js"), "--mcp", "--port", "0"],
  stderr: "ignore",
});
const client = new Client({ name: "mcp-smoke", version: "0" });
await client.connect(transport);

let failures = 0;
async function call(name, args, expect) {
  try {
    const r = await client.callTool({ name, arguments: args ?? {} });
    const text = r.content.map((c) => c.text).join("\n");
    if (verbose) console.log(`--- ${name} ${JSON.stringify(args ?? {})}\n${text}\n`);
    if (expect) expect(text, r);
    console.log(`ok   ${name}`);
    return text;
  } catch (err) {
    failures++;
    console.log(`FAIL ${name}: ${err.message}`);
  }
}

try {
  const { tools } = await client.listTools();
  const names = tools.map((t) => t.name);
  assert.ok(!names.some((n) => /start_capture/.test(n)), "the agent must not be able to start a capture");
  console.log(`tools: ${names.join(", ")}`);

  await call("viewer_url", {}, (t) => assert.match(t, /^http:\/\/127\.0\.0\.1:\d+\/\?token=[0-9a-f]{32}$/));
  await call("get_view_state", {}, (t) => assert.match(t, /No capture is open/));
  await call("open_capture", { path: fixture }, (t) => assert.match(t, /29 frames/));
  await call("capture_summary", {}, (t) => {
    assert.match(t, /Protocol hierarchy/);
    assert.match(t, /http: 4 frames/);
    assert.match(t, /Expert info/);
  });
  await call("query_packets", { filter: "http", limit: 2 }, (t) => {
    assert.match(t, /^4 frames match "http"; showing 1-2/);
    assert.match(t, /more: offset=2/);
  });
  await call("check_display_filter", { filter: "tcp port 18080" }, (t) => assert.match(t, /Invalid.*tcp\.port == 18080/));
  await call("set_display_filter", { filter: "tcp port 18080" }, (t, r) => assert.ok(r.isError && /tcp\.port == 18080/.test(t)));
  await call("set_display_filter", { filter: "http.response" }, (t) => assert.match(t, /2 of 29 frames/));
  await call("goto_frame", { frame: 25 }, (t) => assert.match(t, /row 2 of 2/));
  await call("get_view_state", {}, (t) => {
    assert.match(t, /Selected frame \(by agent\): 25/);
    assert.match(t, /404 File not found/);
  });
  await call("inspect_frame", { protocols: ["http"] }, (t) => {
    assert.match(t, /Status Code: 404\s+\{http\.response\.code\}/);
    assert.match(t, /Frame 25: Packet.*\(collapsed\)/);
  });
  await call("inspect_frame", { frame: 12, max_lines: 15, hex: true }, (t) => {
    assert.match(t, /cut at 15 lines/);
    assert.match(t, /^0000  00 00 00/m);
  });
  await call("follow_stream", { frame: 4, max_bytes: 300 }, (t) => {
    assert.match(t, /client -> server/);
    assert.match(t, /GET \/big\.txt HTTP\/1\.1/);
    assert.match(t, /--- frames 6-\d+ server -> client ---/);
    assert.match(t, /cut at about 300 characters; 81329 payload bytes/);
  });
  await call("mark_frames", { frames: [21, 25], note: "404 request/response" }, (t) => assert.match(t, /2 marked in total/));
  await call("query_packets", { filter: "http", fields: ["http.request.uri", "http.response.code"] }, (t) => {
    assert.match(t, /^No\. \| http\.request\.uri \| http\.response\.code$/m);
    assert.match(t, /^25 \| \/nothere \| 404$/m);
  });
  await call("set_columns", { columns: [{ field: "http.response.code" }] }, (t) => assert.match(t, /\| Status Code$/));
  await call("get_view_state", {}, (t) => {
    assert.match(t, /Custom columns: Status Code \(http\.response\.code\)/);
    assert.match(t, /TLS decryption: off/);
  });
  await call("set_columns", { columns: [] }, (t) => assert.match(t, /Removed/));
  await call("expert_info", { min_severity: "Note" }, (t) => {
    assert.match(t, /^4 expert items in 2 groups/);
    assert.match(t, /Note \/ Sequence \/ TCP \/ This frame initiates the connection closing: 2/);
  });
  await call("expert_info", { min_severity: "Error" }, (t) => assert.match(t, /No expert items/));
  await call("io_graph", { filters: ["", "http"], interval_ms: 1 }, (t) => {
    assert.match(t, /packets per 1 ms/);
    assert.match(t, /"all packets": total 29/);
    assert.match(t, /"http": total 4/);
  });
  const exportPath = join(dirname(fixture), `.mcp-export-${process.pid}.pcapng`);
  await call("export_packets", { path: exportPath, filter: "tcp.stream eq 1" }, (t) => assert.match(t, /Wrote 12 packets/));
  await call("export_packets", { path: exportPath, filter: "http" }, (t, r) => assert.ok(r.isError && /already exists/.test(t)));
  rmSync(exportPath, { force: true });
  await call("clear_marks", {}, (t) => assert.match(t, /0 marks left/));
  await call("list_interfaces", {}, (t) => assert.match(t, /^lo \(Loopback\) \[loopback\]: 127\.0\.0\.1, ::1 — \d+ pkt\/s now/m));
  await call("stop_capture", {}, (t) => assert.match(t, /No capture is running/));
} finally {
  await client.close();
}
console.log(failures ? `${failures} check(s) failed` : "all checks passed");
process.exit(failures ? 1 : 0);
