// Drives the MCP tools over stdio the way Claude Code would, against test/fixtures/http.pcapng.
// Usage: node test/mcp-smoke.mjs [--verbose]   (after npm run build)
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmodSync, copyFileSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { WebSocket } from "ws";
import { execFileSync, spawn } from "node:child_process";
import { writeAcmeCapture } from "./acme.mjs";
import * as g from "./capgen.mjs";
import { writeOddPortsCapture } from "./oddports.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const fixture = join(root, "test/fixtures/http.pcapng");
const verbose = process.argv.includes("--verbose");

// A home of its own: the tester's Wireshark preferences, profiles and plugins don't apply
const home = mkdtempSync(join(tmpdir(), "wirebuddy-home-"));
// In /tmp itself, whatever TMPDIR says: where objects may be saved depends on the folders above
const out = mkdtempSync("/tmp/wirebuddy-mcp-");
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [join(root, "dist/server/main.js"), "--mcp", "--port", "0"],
  env: { ...process.env, HOME: home, XDG_CONFIG_HOME: join(home, ".config"), XDG_DATA_HOME: join(home, ".local/share"), WIREBUDDY_EXTENSIONS: "" },
  stderr: "ignore",
});
let capture = true;
try {
  execFileSync("dumpcap", ["-L", "-i", "lo"], { stdio: "ignore", timeout: 10000 });
} catch {
  capture = false;
}
const client = new Client({ name: "mcp-smoke", version: "0" });
await client.connect(transport);

/** Packet comments of a capture, frame by frame, as sharkd reads them. */
function packetComments(file) {
  const input = [
    { id: 1, method: "load", params: { file } },
    { id: 2, method: "frames", params: { column0: "frame.number:0" } },
  ].map((m) => JSON.stringify({ jsonrpc: "2.0", ...m }) + "\n").join("");
  const env = { ...process.env, HOME: home, XDG_CONFIG_HOME: join(home, ".config"), XDG_DATA_HOME: join(home, ".local/share") };
  const lines = execFileSync("sharkd", ["-"], { input, env, stdio: ["pipe", "pipe", "ignore"], timeout: 20000 }).toString().trim().split("\n");
  return JSON.parse(lines[lines.length - 1]).result.map((r) => r.comments ?? []);
}

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
  assert.ok(names.includes("start_capture") && names.includes("stop_capture"), "the agent starts and stops captures");
  assert.ok(names.includes("decode_as"), "the agent decodes ports as protocols Wireshark knows");
  assert.ok(tools.find((t) => t.name === "panel").inputSchema.properties.action.enum.includes("snapshot"), "panel action snapshot");
  console.log(`tools: ${names.join(", ")}`);

  const ui = new URL(await call("viewer_url", {}, (t) => assert.match(t, /^http:\/\/127\.0\.0\.1:\d+\/\?token=[0-9a-f]{32}$/)));
  // The user's side of the shared view
  const post = (path, body) =>
    fetch(new URL(path, ui.origin), {
      method: "POST",
      headers: { "X-WireBuddy-Token": ui.searchParams.get("token"), "content-type": "application/json" },
      body: JSON.stringify(body),
    });
  // No viewer is connected yet: the first result reminds the agent to open one, the next doesn't
  const reminder = /No WireBuddy viewer is open.*open http:\/\/127\.0\.0\.1:\d+\/\?token=[0-9a-f]{32} in the browser pane/;
  await call("get_view_state", {}, (t) => {
    assert.match(t, /No capture is open/);
    assert.match(t, reminder);
  });
  await call("open_capture", { path: fixture }, (t) => {
    assert.match(t, /29 frames/);
    assert.doesNotMatch(t, reminder);
  });
  const ws = new WebSocket(`ws://${ui.host}/ws?token=${ui.searchParams.get("token")}`);
  await new Promise((resolve, reject) => {
    ws.once("open", resolve);
    ws.once("error", reject);
  });
  await call("get_view_state", {}, (t) => assert.doesNotMatch(t, reminder));
  ws.close();
  await new Promise((resolve) => ws.once("close", resolve));
  await new Promise((resolve) => setTimeout(resolve, 100));
  await call("get_view_state", {}, (t) => assert.match(t, reminder, "a viewer that went away is missed again"));
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
    assert.doesNotMatch(t, /Selected packets/);
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
    // Payload lines can't pose as WireBuddy's own text
    assert.match(t, /^\| GET \/big\.txt HTTP\/1\.1/m);
    assert.match(t, /^\| HTTP\/1\.0 200 OK/m);
    assert.match(t, /--- frames 6-\d+ server -> client ---/);
    assert.match(t, /cut at about 300 characters; 81329 payload bytes/);
  });
  await call("mark_frames", { frames: [21, 25], note: "404 request/response" }, (t) => assert.match(t, /2 marked in total/));
  await call("query_packets", { filter: "http", fields: ["http.request.uri", "http.response.code"] }, (t) => {
    assert.match(t, /^No\. \| http\.request\.uri \| http\.response\.code$/m);
    assert.match(t, /^25 \| \/nothere \| 404$/m);
  });
  // sharkd reads these empty, and next to another column it can abort
  await call("query_packets", { filter: "http", fields: ["frame.number", "_ws.col.info"] }, (t, r) => assert.ok(r.isError && /"_ws\.col\.info" is a packet list column, not a field; without fields, the rows hold the packet list's columns/.test(t), t));
  await call("set_columns", { columns: [{ field: "_ws.col.protocol" }] }, (t, r) => assert.ok(r.isError && /"_ws\.col\.protocol" is a packet list column, not a field; custom columns take protocol fields such as http\.request\.uri/.test(t), t));
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
  const exportPath = join(out, "export.pcapng");
  await call("export_packets", { path: exportPath, filter: "tcp.stream eq 1" }, (t) => assert.match(t, /Wrote 12 packets/));
  await call("export_packets", { path: exportPath, filter: "http" }, (t, r) => assert.ok(r.isError && /already exists/.test(t)));
  // The agent may replace its own export, never a file of the user's
  await call("export_packets", { path: exportPath, filter: "http", overwrite: true }, (t) => assert.match(t, /Wrote 4 packets/));
  const usersFile = join(out, "users.pcapng");
  copyFileSync(fixture, usersFile);
  await call("export_packets", { path: usersFile, filter: "http", overwrite: true }, (t, r) => assert.ok(r.isError && /only replace files it exported itself/.test(t), t));
  assert.equal(readFileSync(usersFile).length, readFileSync(fixture).length);
  // Marks and their notes go along as packet comments, in pcapng only
  // A control character in a note would make editcap refuse the whole export
  assert.equal((await post("/api/marks", { frames: [12], note: "a\u0000b" })).status, 200);
  const markedPath = join(out, "marked.pcapng");
  await call("export_packets", { path: markedPath, which: "marked" }, (t) => assert.match(t, /^Wrote 3 packets \(\d+ bytes, 3 marks as packet comments\)/));
  const agentMark = "WireBuddy mark (Agent): 404 request/response";
  assert.deepEqual(packetComments(markedPath), [["WireBuddy mark (user): a?b"], [agentMark], [agentMark]]);
  await call("export_packets", { path: markedPath, which: "marked", overwrite: true, mark_comments: false }, (t) => assert.match(t, /^Wrote 3 packets \(\d+ bytes\) to/));
  assert.deepEqual(packetComments(markedPath), [[], [], []]);
  await call("export_packets", { path: join(out, "marked.pcap"), which: "marked" }, (t) => assert.match(t, /^Wrote 3 packets \(\d+ bytes\) to/));
  const userExport = await post("/api/export", { path: join(out, "users-marked.pcapng"), which: "range", range: "20-25", markComments: true });
  assert.equal((await userExport.json()).comments, 2);
  assert.deepEqual(packetComments(join(out, "users-marked.pcapng")).map((c) => c.length), [0, 1, 0, 0, 0, 1]);
  assert.equal((await post("/api/marks/clear", { frames: [12] })).status, 200);
  // Packet comments: the agent's and the user's, shown to both, written by exports
  const viewState = async () => (await fetch(new URL("/api/state", ui.origin), { headers: { "X-WireBuddy-Token": ui.searchParams.get("token") } })).json();
  await call("packet_comments", { action: "add", frames: [3, 4, 99], comment: "agent note\nsecond line" }, (t) => {
    assert.match(t, /^Added the comment to 2 frame\(s\); ignored 1 frame\(s\) beyond the 29 in the capture: 99; the comments of 2 packet\(s\) are edited and not exported yet/);
  });
  assert.equal((await viewState()).agentNotice.text, "Added a packet comment to 2 frames: agent note second line");
  await call("packet_comments", { action: "add", frames: [3] }, (t, r) => assert.ok(r.isError && /needs a comment/.test(t), t));
  assert.equal((await post("/api/comments", { frames: [4], comment: "the user's" })).status, 200);
  await call("packet_comments", { action: "replace", frames: [5], comment: "replaced" }, (t) => {
    assert.match(t, /^Set the comment of 1 frame\(s\)/);
    assert.match(t, /INFO The user added the packet comment "the user's" to frame 4/);
  });
  await call("get_view_state", {}, (t) => {
    assert.match(t, /^Packet comments edited in the viewer \(3 packets, 3 not exported yet; only export_packets to pcapng keeps them/m);
    assert.match(t, /^ {2}3: "agent note second line"$/m);
    assert.match(t, /^ {2}4: "agent note second line" \| "the user's"$/m);
  });
  await call("inspect_frame", { frame: 4 }, (t) => {
    assert.match(t, /^Packet comments {2}<Comment>\n {2}agent note \[\.\.\.\] {2}\{frame\.comment\} {2}<Comment>\n {4}agent note {2}\{frame\.comment\}\n {4}second line {2}\{frame\.comment\}\n {2}the user's {2}\{frame\.comment\} {2}<Comment>$/m);
  });
  const commentsPath = join(out, "comments.pcapng");
  await call("export_packets", { path: commentsPath, which: "range", range: "3-5" }, (t) => assert.match(t, /\(\d+ bytes, the edited comments of 3 packets\)/));
  assert.deepEqual(packetComments(commentsPath), [["agent note\nsecond line"], ["agent note\nsecond line", "the user's"], ["replaced"]]);
  await call("packet_comments", { action: "delete", frames: [3, 4, 5] }, (t) => assert.match(t, /^Deleted the comments of 3 frame\(s\)/));
  await call("get_view_state", {}, (t) => assert.match(t, /^ {2}5: \(comments deleted\)$/m));
  // Many long comments on a packet: the first in a short line, and how many more
  for (let i = 0; i < 30; i++) await client.callTool({ name: "packet_comments", arguments: { action: "add", frames: [7], comment: `${i} ${"z".repeat(300)}` } });
  await call("get_view_state", {}, (t) => assert.match(t, /^ {2}7: "0 z{197}…" \.\.\. and 29 more$/m));
  // Files carried in the traffic: listed, then saved into new private folders
  await call("export_objects", {}, (t) => {
    assert.match(t, /^2 HTTP objects:/);
    assert.match(t, /^frame 12: big\.txt — 81053 bytes, text\/plain, from 127\.0\.0\.1:18080, sha1 7bd4078f0ca5a0db563ee91eb5443480c455e5c8$/m);
    assert.match(t, /^frame 25: nothere — 469 bytes, text\/html/m);
  });
  await call("export_objects", { kind: "imf" }, (t) => assert.equal(t.split("\n")[0], "No IMF objects in the capture"));
  await call("export_objects", { action: "save" }, (t, r) => assert.ok(r.isError && /needs dir/.test(t), t));
  await call("export_objects", { action: "save", dir: "objects" }, (t, r) => assert.ok(r.isError && /absolute/.test(t), t));
  mkdirSync(join(out, ".hidden"));
  await call("export_objects", { action: "save", dir: join(out, ".hidden") }, (t, r) => assert.ok(r.isError && /hidden/.test(t), t));
  await call("export_objects", { action: "save", dir: out, frames: [3] }, (t, r) => assert.ok(r.isError && /none of the http objects/.test(t), t));
  // A folder others can write: they could swap the new folder for a link
  const open = mkdtempSync("/tmp/wirebuddy-open-");
  try {
    chmodSync(open, 0o777);
    await call("export_objects", { action: "save", dir: open }, (t, r) => {
      assert.ok(r.isError && /others can write/.test(t), t);
      assert.deepEqual(readdirSync(open), []);
    });
  } finally {
    rmSync(open, { recursive: true, force: true });
  }
  const saved = join(realpathSync(out), "http-objects");
  await call("export_objects", { action: "save", dir: out }, (t) => {
    assert.ok(t.startsWith(`Saved 2 HTTP objects to ${saved} (files from the traffic`), t);
    assert.match(t, /^f12-big\.txt — 81053 bytes, frame 12, text\/plain$/m);
  });
  assert.deepEqual(readdirSync(saved).sort(), ["f12-big.txt", "f25-nothere"]);
  assert.equal(createHash("sha1").update(readFileSync(join(saved, "f12-big.txt"))).digest("hex"), "7bd4078f0ca5a0db563ee91eb5443480c455e5c8");
  assert.equal(statSync(join(saved, "f12-big.txt")).mode & 0o777, 0o600);
  await call("export_objects", { action: "save", dir: out, frames: [25] }, (t) => assert.match(t, /^Saved 1 HTTP object to .*http-objects-2 /));
  assert.deepEqual(readdirSync(join(out, "http-objects-2")), ["f25-nothere"]);
  assert.match((await viewState()).agentNotice.text, /^Saved 1 HTTP object to .*http-objects-2$/);
  await call("set_display_filter", { filter: "" }, (t) => assert.match(t, /29 of 29 frames/));
  assert.equal((await post("/api/select", { frame: 5, rows: [[2, 4], [6, 8], [10, 10]] })).status, 200);
  let selection;
  await call("get_view_state", {}, (t) => {
    assert.match(t, /Selected frame \(by user\): 5/);
    selection = /^Selected packets \(7\): (frame\.number in \{3\.\.5, 7\.\.9, 11\})$/m.exec(t)?.[1];
    assert.ok(selection, t);
  });
  await call("check_display_filter", { filter: selection }, (t) => assert.equal(t, "Valid"));
  await call("query_packets", { filter: selection, fields: ["frame.number"] }, (t) => {
    assert.match(t, /^7 frames match/);
    assert.deepEqual(t.split("\n").slice(2).map((l) => Number(l.split(" | ")[0])), [3, 4, 5, 7, 8, 9, 11]);
  });
  await call("set_display_filter", { filter: "http" }, (t) => assert.match(t, /4 of 29 frames/));
  assert.equal((await post("/api/select", { frame: 12, rows: [[1, 3]] })).status, 200);
  await call("get_view_state", {}, (t) => assert.match(t, /^Selected packets \(3\): frame\.number in \{12, 21, 25\}$/m));
  const selectedPath = join(out, "selected.pcapng");
  await call("export_packets", { path: selectedPath, which: "selected" }, (t) => assert.match(t, /Wrote 3 packets/));
  rmSync(selectedPath, { force: true });
  // One selected row that is not the current packet is still news to the agent
  assert.equal((await post("/api/select", { frame: 4, rows: [[2, 2]] })).status, 200);
  await call("get_view_state", {}, (t) => assert.match(t, /^Selected packets \(1\): frame\.number in \{21\}$/m));
  await call("goto_frame", { frame: 4 }, (t) => assert.match(t, /row 1 of 4/));
  await call("get_view_state", {}, (t) => assert.doesNotMatch(t, /Selected packets/));
  await call("clear_marks", {}, (t) => assert.match(t, /0 marks left/));
  // Time references: the user sees them with a notice; the agent's rows, fields and details count from them
  const notice = async () => (await (await fetch(new URL("/api/state", ui.origin), { headers: { "X-WireBuddy-Token": ui.searchParams.get("token") } })).json()).agentNotice?.text;
  assert.ok(names.includes("time_references"));
  assert.match(client.getInstructions() ?? "", /mark_frames, time_references, packet_comments, set_columns and decode_as change what the user sees/);
  await call("set_display_filter", { filter: "" });
  await call("time_references", { action: "set" }, (t, r) => assert.ok(r.isError && /give the frames to set/.test(t), t));
  await call("time_references", { action: "set", frames: [8, 4, 500] }, (t) => assert.match(t, /^Set time references on 2 frames; ignored 1 frame\(s\) beyond the 29 in the capture: 500; 2 time reference\(s\): 4, 8/));
  assert.equal(await notice(), "Set time references on 2 frames");
  await call("get_view_state", {}, (t) => {
    assert.match(t, /^Time references \(2\): 4, 8$/m);
    assert.match(t, /Time columns show \*REF\* on them and count each later packet from the nearest one before it/);
    assert.match(t, /display filters on frame\.time_relative still count from the first packet; the filter frame\.ref_time matches them$/m);
  });
  await call("query_packets", { filter: "frame.number >= 7 && frame.number <= 9" }, (t) => {
    assert.match(t, /^3 frames match/);
    assert.match(t, /^8 \| \*REF\* \|/m);
    assert.match(t, /^9 \| 0\.000005433 \|/m);
  });
  await call("query_packets", { filter: "frame.ref_time", fields: ["frame.time_relative", "frame.ref_time"] }, (t) => {
    assert.match(t, /^2 frames match "frame\.ref_time"/);
    assert.match(t, /^8 \| 0\.000000000 \| ✓$/m);
  });
  await call("inspect_frame", { frame: 9, protocols: ["frame"] }, (t) => assert.match(t, /Time since reference or first frame: 5\.433 microseconds/));
  await call("time_references", { action: "unset", frames: [4] }, (t) => assert.match(t, /^Unset the time reference on frame 4; 1 time reference\(s\): 8/));
  await call("time_references", { action: "clear" }, (t) => assert.match(t, /^Unset the time reference on frame 8; 0 time reference\(s\)/));
  assert.equal(await notice(), "Unset all time references");
  await call("get_view_state", {}, (t) => assert.doesNotMatch(t, /Time references/));
  // Too many scattered ones for frame.ref_time: said, not claimed
  const many = join(out, "many.pcap");
  writeFileSync(many, Buffer.concat([g.pcapHeader(), ...Array.from({ length: 3000 }, (_, i) => g.pcapRecord(1_700_000_000 + i, 0, g.udpFrame(i + 1)))]));
  await call("open_capture", { path: many }, (t) => assert.match(t, /3000 frames/));
  await call("time_references", { action: "set", frames: Array.from({ length: 1500 }, (_, i) => 2 * i + 1) });
  await call("get_view_state", {}, (t) => assert.match(t, /the filter frame\.ref_time can't stand for this many scattered ones \(unset some to use it\)$/m));
  await call("set_display_filter", { filter: "frame.ref_time" }, (t, r) => assert.ok(r.isError && /too long for sharkd; unset some of them/.test(t), t));
  await call("open_capture", { path: fixture });
  // Problems the user runs into come back with the next tool result, and wake a watcher
  const command = /`"([^"]+)" "([^"]+)" --watch "([^"]+)"`/.exec(client.getInstructions() ?? "");
  assert.ok(command, "the instructions name the watch command");
  assert.equal((await post("/api/open", { path: "/nonexistent/gone.pcapng" })).status, 400);
  // Only the block with the session's tag is real
  const tag = /starts with "\[WireBuddy events ([0-9a-f]{8})"/.exec(client.getInstructions() ?? "")?.[1];
  assert.ok(tag, "the instructions name the events tag");
  await call("get_view_state", {}, (t) => assert.match(t, new RegExp(`\\[WireBuddy events ${tag} since your last call[\\s\\S]*ERROR Opening a file failed: .*gone\\.pcapng`)));
  await call("get_view_state", {}, (t) => assert.doesNotMatch(t, /WireBuddy events/));
  const watcher = spawn(command[1], [command[2], "--watch", command[3]], { stdio: ["ignore", "pipe", "inherit"] });
  let printed = "";
  watcher.stdout.on("data", (d) => (printed += d));
  const exited = new Promise((resolve) => watcher.on("exit", resolve));
  await new Promise((resolve) => setTimeout(resolve, 500));
  await post("/api/filter", { filter: "tcp" });
  await post("/api/open", { path: "/nonexistent/again.pcapng" });
  const code = await Promise.race([exited, new Promise((resolve) => setTimeout(() => resolve("timeout"), 10000))]);
  if (code === "timeout") watcher.kill();
  await call("set_display_filter", { filter: "" }, () => {
    assert.equal(code, 0, `watcher exit ${code}`);
    assert.match(printed, /INFO The user applied the display filter "tcp"/);
    assert.match(printed, /ERROR Opening a file failed: .*again\.pcapng/);
  });
  // The user asks about packets: the question comes to the agent, wakes a watcher, and is no problem
  const token = { "X-WireBuddy-Token": ui.searchParams.get("token") };
  const ask = async (question) => {
    const r = await post("/api/agent/ask", { question });
    assert.equal(r.status, 200, await r.clone().text());
    return r.json();
  };
  const agentState = async () => (await (await fetch(new URL("/api/state", ui.origin), { headers: token })).json()).agent;
  assert.equal((await post("/api/select", { frame: 12 })).status, 200);
  assert.deepEqual(await ask("Why  is this\nso slow?"), { woken: false });
  // A refused question is no problem for the agent
  assert.equal((await post("/api/agent/ask", { question: "  " })).status, 400);
  assert.equal((await agentState()).pending, 0);
  await call("get_view_state", {}, (t) => {
    assert.match(t, /QUESTION The user asks you about frame 12: Why is this so slow\?\]?$/m);
    assert.doesNotMatch(t, /Asking the agent failed/);
  });
  // The packets the dialog showed, not what is selected when it is sent; refused once that view is gone
  const { generation } = await (await fetch(new URL("/api/state", ui.origin), { headers: token })).json();
  const shown = { file: fixture, filter: "", generation };
  assert.deepEqual(await (await post("/api/agent/ask", { question: "and these?", frame: 3, rows: [[1, 2]], view: shown })).json(), { woken: false });
  await call("get_view_state", {}, (t) => assert.match(t, /QUESTION The user asks you about 2 packets: and these\? \{"frames":"frame\.number in \{2\.\.3\}"\}\]?$/m));
  assert.equal((await post("/api/agent/ask", { question: "stale?", frame: 3, view: { ...shown, filter: "tcp" } })).status, 409);
  const asked = spawn(command[1], [command[2], "--watch", command[3]], { stdio: ["ignore", "pipe", "inherit"] });
  let heard = "";
  asked.stdout.on("data", (d) => (heard += d));
  const askedExit = new Promise((resolve) => asked.on("exit", resolve));
  for (const end = Date.now() + 10_000; !(await agentState()).watching && Date.now() < end; ) await new Promise((resolve) => setTimeout(resolve, 50));
  assert.equal((await post("/api/select", { frame: 12, rows: [[11, 13]] })).status, 200);
  assert.deepEqual(await ask("What are these?"), { woken: true });
  const askedCode = await Promise.race([askedExit, new Promise((resolve) => setTimeout(() => resolve("timeout"), 10000))]);
  if (askedCode === "timeout") asked.kill();
  await call("get_view_state", {}, () => {
    assert.equal(askedCode, 0, `watcher exit ${askedCode}`);
    assert.match(heard, /QUESTION The user asks you about 3 packets: What are these\? \{"frames":"frame\.number in \{12\.\.14\}"\}/);
  });
  assert.equal((await agentState()).watching, false);
  if (capture) await call("list_interfaces", {}, (t) => assert.match(t, /^lo\b.*\[loopback\]/m));
  else console.log("skip list_interfaces: dumpcap may not capture on lo here");
  await call("stop_capture", {}, (t) => assert.match(t, /No capture is running/));
  await call("start_capture", { interface: "-w/etc/passwd" }, (t, r) => {
    assert.ok(r.isError);
    assert.match(t, /unknown interface/);
  });
  await call("start_capture", { interface: "lo", ring_files: 3 }, (t, r) => {
    assert.ok(r.isError);
    assert.match(t, /new file needs/);
  });

  // A protocol Wireshark knows on a port it doesn't expect: one decode_as call
  const oddPorts = join(out, "odd-ports.pcap");
  writeOddPortsCapture(oddPorts);
  await call("open_capture", { path: oddPorts }, (t) => assert.match(t, /11 frames/));
  await call("decode_as", { action: "set", table: "udp.port", value: 50000, protocol: "rtp" }, (t) => {
    assert.match(t, /^udp\.port 50000 now decodes as RTP \(before: no dissector, so heuristics or Data\)\. 5 frames match "rtp && udp\.port == 50000"\.$/m);
    assert.match(t, /^Decode As entries \(1, until WireBuddy exits\): udp\.port 50000 → rtp \(agent\)$/m);
  });
  assert.equal((await viewState()).agentNotice.text, "Decode As: udp.port 50000 as RTP");
  await call("query_packets", { filter: "rtp" }, (t) => assert.match(t, /^5 frames match "rtp"; showing 1-5/));
  await call("decode_as", { action: "set", table: "tcp.port", value: 18830, protocol: "mtqq" }, (t, r) => assert.ok(r.isError && /close matches: mqtt \(MQ Telemetry Transport Protocol\)/.test(t), t));
  await call("decode_as", { action: "clear", table: "udp.port" }, (t, r) => assert.ok(r.isError && /give both table and value/.test(t), t));
  await call("get_view_state", {}, (t) => assert.match(t, /^Decode As \(until WireBuddy exits, every capture; the user's Wireshark profile is unchanged\): udp\.port 50000 → rtp \(agent\)$/m));
  await call("capture_summary", {}, (t) => assert.match(t, /^Decode As entries in effect: udp\.port 50000 → rtp \(agent\)$/m));
  assert.equal((await post("/api/decode-as", { action: "set", table: "udp.port", value: 123, protocol: "dns" })).status, 200);
  await call("decode_as", { action: "set", table: "udp.port", value: 123, protocol: "DNS" }, (t) => {
    assert.match(t, /^udp\.port 123 already decodes as dns; nothing changed\.$/m);
    assert.match(t, /INFO The user set Decode As udp\.port 123 → dns \(4 frames match\)/);
  });
  await call("decode_as", { action: "clear", table: "udp.port", value: 123 }, (t) => assert.match(t, /^Removed udp\.port 123 → dns; Wireshark decides how that port decodes again\.\n/));
  await call("decode_as", { action: "clear" }, (t) => assert.match(t, /^Removed all Decode As entries\.\nNo Decode As entries\.$/m));
  await call("get_view_state", {}, (t) => assert.match(t, /^Decode As: none$/m));

  // Teaching the viewer a protocol, the way the guide tells the agent to
  const acmeFile = join(out, "acme.pcap");
  writeAcmeCapture(acmeFile);
  const extDir = join(home, ".local/share/wirebuddy/extensions");
  // Comments edited and not exported: the agent hears they are gone
  await call("packet_comments", { action: "add", frames: [3, 4, 5, 7], comment: "left behind" });
  await call("open_capture", { path: acmeFile }, (t) => assert.match(t, /20 frames.*; the comments edited in 4 packets and not exported were discarded$/m));
  await call("capture_summary", {}, (t) => {
    assert.match(t, /Undecoded payload \("data"\): 20 frames\. A protocol Wireshark knows on an unexpected port: decode_as decodes it in one call/);
    assert.match(t, /UDP 10\.0\.0\.1:40000 <-> 10\.0\.0\.2:50000: 20 frames/);
  });
  const guide = await call("extensions", { action: "guide" }, (t) => {
    assert.ok(t.includes(`Folder: ${extDir}/<name>/`), "the guide names the folder");
    assert.match(t, /Template, protocol on a fixed port:/);
    // One Wireshark knows needs no template
    assert.doesNotMatch(t, /Template, a known protocol on another port/);
    assert.match(t, /needs no extension: the decode_as tool/);
  });
  const template = (title) => new RegExp(`Template, ${title}:\\n([\\s\\S]*?)\\n(?:Template,|Panels \\(|$)`).exec(guide ?? "")?.[1] ?? "";
  const addExtension = (name, lua) => {
    mkdirSync(join(extDir, name), { recursive: true });
    writeFileSync(join(extDir, name, "extension.json"), JSON.stringify({ label: name, version: "1", description: "test" }));
    writeFileSync(join(extDir, name, `${name}.lua`), lua);
  };
  addExtension("acme", template("protocol on a fixed port"));
  addExtension("acme_heur", template("heuristic \\(recognized by content\\)"));
  addExtension("acme_gap", template("post-dissector \\(computed field on packets decoded by others\\)"));
  // Each template on its own: the port and heuristic ones both register "acme"
  await call("extensions", { action: "test", name: "acme" }, (t) => {
    assert.match(t, /Extension "acme": loaded/);
    assert.match(t, /^  acme: 20 packets, first 1$/m);
    assert.match(t, /Sequence: 0/);
    assert.match(t, /No Lua errors/);
  });
  await call("extensions", { action: "test", name: "acme_heur" }, (t) => {
    assert.match(t, /^  acme: 19 packets, first 1$/m);
    assert.match(t, /No Lua errors/);
  });
  await call("extensions", { action: "test", name: "acme_gap" }, (t) => {
    assert.match(t, /^  acme_gap: 19 packets, first 2$/m);
    assert.match(t, /Since previous ACME packet \(ms\): 99\.9/);
  });
  addExtension("acme_rtp", 'DissectorTable.get("udp.port"):add(50000, Dissector.get("rtp"))\n');
  await call("extensions", { action: "test", name: "acme_rtp" }, (t) => {
    // ACME bytes aren't RTP: the hierarchy shows what the extension made of them
    assert.match(t, /no protocol of its own \(like Decode As\); with it the capture decodes as:\n\s+frame > eth > ip > udp > \S+: 20 frames/);
    assert.match(t, /^ {2}A protocol Wireshark knows on another port needs no extension: decode_as\.$/m);
  });
  // The view's Decode As applies in the test too: it takes the extension's port over
  await call("decode_as", { action: "set", table: "udp.port", value: 50000, protocol: "rtp" });
  await call("extensions", { action: "test", name: "acme" }, (t) => {
    assert.match(t, /^ {2}acme: 0 packets$/m);
    assert.match(t, /WireBuddy's Decode As entries apply here too \(udp\.port 50000 → rtp\): one on this extension's port takes it over; decode_as action "clear" removes it\./);
  });
  await call("decode_as", { action: "clear" });
  rmSync(join(extDir, "acme_rtp"), { recursive: true });
  addExtension("acme_syntax", "local x = \n");
  await call("extensions", { action: "test", name: "acme_syntax" }, (t) => {
    assert.match(t, /Extension "acme_syntax": error: acme_syntax\/acme_syntax\.lua:2: unexpected symbol/);
    assert.match(t, /Fix it and test again/);
    assert.doesNotMatch(t, /No Lua errors|applies it there/);
  });
  rmSync(join(extDir, "acme_syntax"), { recursive: true });
  await call("extensions", { action: "test", name: "nonexistent" }, (t, r) => {
    assert.ok(r.isError);
    assert.match(t, /no extension "nonexistent"/);
  });
  // The view still shows Data: testing never changes it
  await call("query_packets", { filter: "acme", limit: 1 }, (t, r) => assert.ok(r.isError || /0 of|no packets|0 rows/i.test(t), t));
  rmSync(join(extDir, "acme_heur"), { recursive: true });
  await call("extensions", { action: "reload" }, (t) => {
    assert.match(t, /^acme \[loaded\] \[lua\] acme v1 — test; protocols: acme$/m);
    assert.match(t, /^acme_gap \[loaded\]/m);
    assert.match(t, /Extension "acme" loaded \(protocols: acme\)/);
  });
  await call("query_packets", { filter: "acme.kind == 2", fields: ["acme.seq"] }, (t) => assert.match(t, /\b18\b/));
  await call("extensions", { action: "disable", name: "acme_gap" }, (t) => assert.match(t, /^acme_gap \[off\]/m));
  await call("extensions", { action: "test", name: "acme_gap" }, (t) => assert.match(t, /extensions action "enable" applies it/));
  await call("extensions", { action: "list" }, (t) => assert.match(t, /^acme \[loaded\] \[lua\]/m));

  // Panels: written by the agent, checked before they run
  await call("extensions", { action: "guide", topic: "panel" }, (t) => assert.match(t, /wb\.ready\(\)[\s\S]*wb\.subscribe\(q/));
  mkdirSync(join(extDir, "viewpanel", "panel"), { recursive: true });
  writeFileSync(join(extDir, "viewpanel", "extension.json"), JSON.stringify({ label: "View", version: "1", panel: { offer: { filter: "udp", text: "Show the view" } } }));
  writeFileSync(join(extDir, "viewpanel", "panel", "main.js"), "const x = 1;\nconst y = ;\n");
  await call("extensions", { action: "test", name: "viewpanel" }, (t) => assert.match(t, /viewpanel\/panel\/main\.js:2: SyntaxError/));
  await call("panel", { action: "open", name: "viewpanel" }, (t, r) => {
    assert.ok(r.isError);
    assert.match(t, /not opened/);
  });
  writeFileSync(join(extDir, "viewpanel", "panel", "main.js"), "wb.ready();\n");
  await call("panel", { action: "open", name: "viewpanel", wait_ms: 200 }, (t) => assert.match(t, /The panel starts once the viewer is open: open http/));
  await call("panel", { action: "status" }, (t) => assert.match(t, /^viewpanel: starting/m));
  await call("get_view_state", {}, (t) => {
    assert.match(t, /^Panels open: viewpanel \(starting, opened by agent\)$/m);
    assert.doesNotMatch(t, /Panels offered/);
  });
  await call("panel", { action: "snapshot", name: "viewpanel" }, (t, r) => {
    assert.ok(r.isError);
    assert.match(t, /only runs while the viewer is open: open http/);
  });
  await call("panel", { action: "close", name: "viewpanel" }, (t) => assert.match(t, /Closed the panel "viewpanel"/));
  await call("panel", { action: "snapshot", name: "viewpanel" }, (t, r) => assert.ok(r.isError && /is not open/.test(t)));
  // Its offer matches the open ACME capture
  await call("extensions", { action: "reload" }, (t) => assert.match(t, /^viewpanel \[loaded\] \[panel\] View v1; offers "Show the view"$/m));
  await call("capture_summary", {}, (t) => assert.match(t, /^Panel available: viewpanel \("Show the view"\): panel action "open"/m));
  await call("get_view_state", {}, (t) => assert.match(t, /^Panels offered to the user in the status bar: viewpanel \("Show the view"\)$/m));
} finally {
  await client.close();
  rmSync(out, { recursive: true, force: true });
  rmSync(home, { recursive: true, force: true });
}
console.log(failures ? `${failures} check(s) failed` : "all checks passed");
process.exit(failures ? 1 : 0);
