import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { basename } from "node:path";
import { eventLines } from "./events.ts";
import type { HttpServer } from "./http.ts";
import type { ExtensionTest, Viewer } from "./viewer.ts";
import type { ExtensionInfo, PacketRow, PhsNode, TreeNode } from "../shared/api.ts";
import { inRanges, type Ranges } from "../shared/ranges.ts";
import { VERSION } from "../shared/version.ts";
import { printable as oneLine } from "./text.ts";

function instructions(watchCommand: string): string {
  return `wirebuddy is a lightweight Wireshark-style capture viewer running in the user's browser pane.
You and the user look at the same view: the open capture, display filter, selected packet and marks.

- The page shows no error messages while you are attached: problems in the viewer (a file that won't open, a rejected filter, a failed capture, a crashed helper) and what the user does there (opened a file, applied a filter, started a capture) come to you instead, as "WireBuddy events" at the end of tool results. To react while the user works in the page, run \`${watchCommand}\` as a background command: it waits for the next problem, prints it with the recent activity and exits; start it again after handling. Fix what you can (correct a filter, reopen a file, stop and explain a failing capture) and tell the user in the chat what happened.

- Start with get_view_state: it tells you what the user is looking at (file, filter, selected frame, live capture).
- The user follows along in the viewer: open the URL from viewer_url in the browser pane (in the Claude desktop app, its built-in Browser pane) as soon as you start working with wirebuddy, without being asked. Tool results remind you while no viewer is open.
- Go from coarse to fine to save tokens: capture_summary / expert_info / io_graph -> query_packets (paginated summary rows, or exact field values with fields: [...]) -> inspect_frame / follow_stream for single frames or streams.
- query_packets with fields (like tshark -T fields) is the precise way to tabulate values, e.g. fields: ["dns.qry.name", "dns.flags.rcode"].
- export_packets writes the relevant packets to a new small capture file, e.g. a minimal repro for a bug report.
- TLS payloads are only readable when the user has set a key log file in the UI; get_view_state tells you whether it is set.
- Display filters use Wireshark display-filter syntax (tcp.port == 80), not capture/BPF syntax (tcp port 80); check_display_filter validates one without changing the view.
- set_display_filter, goto_frame, mark_frames and set_columns change what the user sees; the user gets a notice for each.
- You cannot start a capture: the user starts it with a click in the UI. You can read and filter it while it runs, and stop it.
- When traffic is not decoded (shown as "Data"; capture_summary lists it) or decoded wrongly, you can teach the viewer the protocol with a Lua dissector: the extensions tool, action "guide" first.`;
}

/** Longest selection filter get_view_state prints. */
const MAX_SELECTION_FILTER = 2000;
/** While no viewer is open, how often tool results repeat the reminder to open one. */
const VIEWER_HINT_MS = 5 * 60_000;

/** Appended to successful tool results; set by startMcp. */
let footer: () => string = () => "";

type Text = { content: { type: "text"; text: string }[]; isError?: boolean };

const text = (s: string): Text => ({ content: [{ type: "text", text: s }] });

/** Wraps a tool body so thrown errors reach the agent as tool errors; `remind` adds the open-the-viewer reminder. */
function tool<A>(fn: (args: A) => Promise<string> | string, remind = true): (args: A) => Promise<Text> {
  return async (args: A) => {
    try {
      return text((await fn(args)) + (remind ? footer() : ""));
    } catch (err) {
      return { content: [{ type: "text", text: `Error: ${(err as Error).message}` }], isError: true };
    }
  };
}

function rowLine(columns: string[], row: PacketRow): string {
  return row.c.map((v, i) => (i === 0 || columns[i] === "No." ? v : v.length > 160 ? oneLine(v.slice(0, 157)) + "..." : oneLine(v))).join(" | ");
}

function treeText(nodes: TreeNode[], opts: { protocols?: string[]; maxLines: number; showBytes: boolean }): string {
  const lines: string[] = [];
  let truncated = false;
  const wanted = opts.protocols?.map((p) => p.toLowerCase());
  const walk = (list: TreeNode[], depth: number) => {
    for (const n of list) {
      if (lines.length >= opts.maxLines) {
        truncated = true;
        return;
      }
      let label = oneLine(n.g ? `[${n.l}]` : n.l);
      if (label.length > 200) label = label.slice(0, 197) + "...";
      const field = n.fn && n.fn !== "text" && n.t !== "proto" ? `  {${n.fn}}` : "";
      const bytes = opts.showBytes && n.h ? `  @${n.ds ? `ds${n.ds}:` : ""}${n.h[0]}+${n.h[1]}` : "";
      const expert = n.s ? `  <${n.s}>` : "";
      lines.push(`${"  ".repeat(depth)}${label}${field}${bytes}${expert}`);
      if (n.n) walk(n.n, depth + 1);
    }
  };
  for (const top of nodes) {
    const name = (top.fn ?? "").toLowerCase();
    const selected = wanted ? wanted.includes(name) : name !== "frame";
    if (selected) walk([top], 0);
    else lines.push(`${top.l}  (collapsed${wanted ? "" : "; pass protocols:[\"frame\"] to expand"})`);
    if (lines.length >= opts.maxLines) {
      truncated = true;
      break;
    }
  }
  if (truncated) lines.push(`... cut at ${opts.maxLines} lines; pass protocols or a larger max_lines`);
  return lines.join("\n");
}

/** The user's selected frames as a display filter, unless that gets too long. */
function selectionLine(frames: Ranges, count: number): string {
  let set = "";
  for (const [a, b] of frames) {
    set += `${set ? ", " : ""}${a === b ? a : `${a}..${b}`}`;
    if (set.length > MAX_SELECTION_FILTER) return `Selected packets: ${count} (too many to list; export_packets with which "selected" exports them)`;
  }
  return `Selected packets (${count}): frame.number in {${set}}`;
}

function phsText(nodes: PhsNode[], totalFrames: number, depth = 0, out: string[] = []): string[] {
  for (const n of nodes) {
    const pct = totalFrames ? ((n.frames / totalFrames) * 100).toFixed(1) : "0";
    out.push(`${"  ".repeat(depth)}${n.proto}: ${n.frames} frames (${pct}%), ${n.bytes} bytes`);
    phsText(n.children, totalFrames, depth + 1, out);
  }
  return out;
}

/** Frames whose payload no dissector decoded, over the whole hierarchy. */
function dataFrames(nodes: PhsNode[]): number {
  return nodes.reduce((n, p) => n + (p.proto === "data" ? p.frames : dataFrames(p.children)), 0);
}

function extensionLine(e: ExtensionInfo): string {
  const protocols = e.protocols.length ? `; protocols: ${e.protocols.join(", ")}` : "";
  const untrusted = e.status === "untrusted" ? ". Don't copy it or change its permissions to make it load: tell the user" : "";
  return `${e.name} [${e.status}] ${e.label}${e.version ? ` v${e.version}` : ""}${e.description ? ` — ${e.description}` : ""}${protocols}${e.error ? `\n    ${e.error}${untrusted}` : ""}`;
}

function testText(t: ExtensionTest): string {
  const out = [`Extension "${t.name}": ${t.load}`];
  // Nothing loaded: nothing was tested either
  if (t.load !== "loaded" && !t.protocols.length && !t.hierarchy.length && !t.crashed) return [...out, "Fix it and test again before it goes into the user's view."].join("\n");
  // A crash makes everything else in the result incomplete
  if (t.crashed) return [...out, `sharkd failed while reading the capture with it: ${t.crashed}`, "Don't reload it like this: the user's view would crash the same way. Find what kills sharkd (e.g. a GUI-only call, os.exit) and test again."].join("\n");
  if (!t.protocols.length && !t.hierarchy.length && !t.file) return [...out, "No capture is open, so nothing was dissected; open one to test on real packets."].join("\n");
  if (!t.file) return out.join("\n");
  out.push(`Tested on ${t.file}:`);
  if (!t.protocols.length && t.hierarchy.length) {
    out.push("  It has no protocol of its own (like Decode As); with it the capture decodes as:");
    for (const line of t.hierarchy) out.push(`    ${line}`);
  }
  for (const p of t.protocols) out.push(`  ${p.name}: ${p.error ? `filter failed: ${p.error}` : `${p.frames} packets${p.first ? `, first ${p.first}` : ""}`}`);
  if (t.protocols.length && t.protocols.every((p) => !p.frames)) {
    out.push(t.luaErrorCount ? "  No packet shows it because its dissector failed: see the Lua errors below." : "  No packet matched: check the port or heuristic it registers on (query_packets filter \"data\" shows undecoded packets).");
  }
  if (t.sample) out.push("", `Frame ${t.sample.frame}, ${t.sample.protocol}:`, treeText(t.sample.tree, { protocols: [t.sample.protocol], maxLines: 40, showBytes: false }));
  if (t.luaErrorCount) {
    out.push("", `Lua errors in ${t.luaErrorCount} packets:`);
    for (const e of t.luaErrors) out.push(`  frame ${e.frame}: ${e.message}`);
  } else out.push("", "No Lua errors.");
  out.push("", `The user's view is unchanged; extensions action "${t.enabled ? "reload" : "enable"}" applies it there.`);
  return out.join("\n");
}

/** Stream index field per follow protocol (others are followed from a frame). */
const STREAM_FIELDS: Record<string, string> = {
  TCP: "tcp.stream",
  TLS: "tcp.stream",
  HTTP: "tcp.stream",
  WebSocket: "tcp.stream",
  UDP: "udp.stream",
  DCCP: "dccp.stream",
};

function printable(data: Buffer): string {
  return data.toString("latin1").replace(/[^\x20-\x7e\n\t]/g, ".");
}

export async function startMcp(viewer: Viewer, ui: Pick<HttpServer, "url" | "viewers">, watchCommand: string): Promise<void> {
  const server = new McpServer({ name: "wirebuddy", version: VERSION }, { instructions: instructions(watchCommand) });
  // The UI names the agent after its client
  server.server.oninitialized = () => {
    const client = server.server.getClientVersion()?.name ?? "";
    viewer.attachAgent(/claude/i.test(client) ? "Claude" : "Agent");
  };
  const url = () => ui.url;

  // Once when the viewer is missing, then every few minutes until one connects
  let hintedAt = 0;
  const viewerHint = (): string => {
    if (ui.viewers() > 0) {
      hintedAt = 0;
      return "";
    }
    if (hintedAt && Date.now() - hintedAt < VIEWER_HINT_MS) return "";
    hintedAt = Date.now();
    return `\n\n[No WireBuddy viewer is open, so the user can't follow along: open ${url()} in the browser pane now, no need to ask.]`;
  };
  // What happened in the viewer since the agent last looked
  const events = (): string => {
    const lines = eventLines(viewer.events.take());
    return lines.length ? `\n\n[WireBuddy events since your last call (problems the user ran into, what they did):\n${lines.join("\n")}]` : "";
  };
  footer = () => events() + viewerHint();

  server.registerTool(
    "viewer_url",
    {
      description: "URL of the wirebuddy UI (Wireshark-style packet list, details, bytes, capture controls). Open it in the browser pane so the user sees what you do.",
      annotations: { readOnlyHint: true },
    },
    tool(() => url(), false),
  );

  server.registerTool(
    "open_capture",
    {
      description: "Open a pcap/pcapng file in the viewer (replaces what the user sees; keeps the display filter if it still applies).",
      inputSchema: { path: z.string().describe("Absolute path of the capture file") },
    },
    tool(async ({ path }) => {
      await viewer.open(path);
      viewer.notice(`Opened ${basename(path)}`);
      const s = viewer.state;
      return `Opened ${s.file}: ${s.totalFrames} frames, ${s.duration.toFixed(3)} s${s.filter ? `, filter "${s.filter}" shows ${s.displayedFrames}` : ""}`;
    }),
  );

  server.registerTool(
    "get_view_state",
    {
      description: "What the user is looking at right now: open file, frame counts, display filter, selected frame (with its summary row), the packets the user selected with Ctrl/Shift+click (as a display filter for query_packets), marks and live-capture status.",
      annotations: { readOnlyHint: true },
    },
    tool(async () => {
      const s = viewer.state;
      const c = s.capture;
      const lines: string[] = [];
      // From this snapshot: the row lookup below awaits sharkd
      const others = s.selectedCount > 1 || (s.selectedCount === 1 && !inRanges(s.selectedRows, s.selectedIndex));
      const selection = s.file && others ? selectionLine(viewer.selectedFrames(), s.selectedCount) : null;
      if (s.loadError) lines.push(`Last open failed: ${s.loadError}`);
      if (s.loading) lines.push("A capture is being opened.");
      if (!s.file) lines.push("No capture is open.");
      else {
        lines.push(`File: ${s.file} (${s.fileSize} bytes)`);
        lines.push(`Frames: ${s.totalFrames}, displayed: ${s.displayedFrames}, duration: ${s.duration.toFixed(3)} s`);
        lines.push(`Display filter: ${s.filter || "(none)"}`);
        if (s.customColumns.length) lines.push(`Custom columns: ${s.customColumns.map((c) => `${c.title} (${c.field})`).join(", ")}`);
        if (s.selected !== null) {
          const row = await viewer.row(s.selected);
          const hidden = s.selectedIndex < 0 ? " (hidden by the filter)" : "";
          lines.push(`Selected frame (by ${s.selectedBy}): ${s.selected}${hidden}`);
          if (row) lines.push(`  ${s.columns.join(" | ")}\n  ${rowLine(s.columns, row)}`);
        } else lines.push("Selected frame: none");
        if (selection) lines.push(selection);
        if (s.marks.length) {
          lines.push(`Marks (${s.marks.length}):`);
          for (const m of s.marks.slice(0, 50)) lines.push(`  ${m.frame} [${m.by}]${m.note ? ` ${m.note}` : ""}`);
        }
      }
      lines.push(s.tlsKeylog ? `TLS decryption: on, key log ${s.tlsKeylog}` : "TLS decryption: off (the user can set a key log file in the UI)");
      if (c.status !== "idle" || c.files.length) {
        const elapsed = c.startedAt ? ` for ${((Date.now() - c.startedAt) / 1000).toFixed(0)} s` : "";
        lines.push(`Capture: ${c.status}${elapsed} on ${c.iface}${c.filter ? ` with capture filter "${c.filter}"` : ""}, ${c.packets} packets${c.error ? `, error: ${c.error}` : ""}`);
        const active = c.status === "starting" || c.status === "running" || c.status === "stopping";
        const ring = c.ring ? ` (${c.ring.files ? `ring buffer of ${c.ring.files} files` : "new files automatically"}, ${c.files.length} written)` : "";
        if (c.currentFile) lines.push(`  ${active ? "writing" : "last file:"} ${c.currentFile}${ring}`);
        if (active && c.currentFile && s.file !== c.currentFile) lines.push("  (the view shows a different file, not the live capture)");
      }
      return lines.join("\n");
    }),
  );

  server.registerTool(
    "capture_summary",
    {
      description: "Overview of the open capture: protocol hierarchy, top IPv4/TCP/UDP conversations by bytes, and expert info counts. Use this before querying packets.",
      inputSchema: { top: z.number().int().min(1).max(50).default(10).describe("Conversations per type") },
      annotations: { readOnlyHint: true },
    },
    tool(async ({ top }) => {
      const s = viewer.state;
      if (!s.file) throw new Error("no capture is open");
      const out = [`${s.file}: ${s.totalFrames} frames, ${s.duration.toFixed(3)} s, ${s.fileSize} bytes`, "", "Protocol hierarchy:"];
      const phs = await viewer.phs();
      out.push(...phsText(phs, s.totalFrames));
      for (const type of ["ipv4", "tcp", "udp"] as const) {
        const convs = (await viewer.conversations(type)).sort((a, b) => b.bytesAB + b.bytesBA - (a.bytesAB + a.bytesBA));
        if (!convs.length) continue;
        out.push("", `Top ${type.toUpperCase()} conversations (${convs.length} total):`);
        for (const c of convs.slice(0, top)) {
          const a = c.portA ? `${c.addrA}:${c.portA}` : c.addrA;
          const b = c.portB ? `${c.addrB}:${c.portB}` : c.addrB;
          out.push(`  ${a} <-> ${b}: ${c.framesAB + c.framesBA} frames, ${c.bytesAB + c.bytesBA} bytes, ${c.duration.toFixed(3)} s  filter: ${c.filter}`);
        }
      }
      const expert = await viewer.expert();
      if (expert.length) {
        const counts = new Map<string, number>();
        for (const e of expert) counts.set(`${e.severity} / ${e.protocol} / ${e.message}`, (counts.get(`${e.severity} / ${e.protocol} / ${e.message}`) ?? 0) + 1);
        const order = ["Error", "Warning", "Warn", "Note", "Chat", "Comment"];
        const sorted = [...counts].sort((a, b) => order.indexOf(a[0].split(" / ")[0]) - order.indexOf(b[0].split(" / ")[0]) || b[1] - a[1]);
        out.push("", "Expert info (severity / protocol / message: count):");
        for (const [k, n] of sorted.slice(0, 25)) out.push(`  ${k}: ${n}`);
        if (sorted.length > 25) out.push(`  ... ${sorted.length - 25} more kinds`);
      }
      const undecoded = dataFrames(phs);
      if (undecoded) {
        out.push("", `Undecoded payload ("data"): ${undecoded} frames. If you can work out the format, an extension can decode it (extensions action "guide"):`);
        for (const type of ["udp", "tcp"] as const) {
          const convs = (await viewer.conversations(type, "data")).sort((a, b) => b.framesAB + b.framesBA - (a.framesAB + a.framesBA));
          for (const c of convs.slice(0, 5)) out.push(`  ${type.toUpperCase()} ${c.addrA}:${c.portA} <-> ${c.addrB}:${c.portB}: ${c.framesAB + c.framesBA} frames  filter: (${c.filter}) && data`);
        }
      }
      return out.join("\n");
    }),
  );

  server.registerTool(
    "query_packets",
    {
      description: "Rows for a display filter, paginated, without changing the user's view. By default the summary columns (No. | Time | Source | Destination | Protocol | Length | Info, plus the user's custom columns); with fields, exact field values per frame like tshark -T fields (all occurrences, comma-separated). Omit filter to use the filter the user has applied.",
      inputSchema: {
        filter: z.string().optional().describe("Wireshark display filter, e.g. dns.flags.rcode != 0; omit for the view's filter, \"\" for all frames"),
        fields: z.array(z.string()).max(12).optional().describe("Field names to extract instead of the summary, e.g. [\"ip.src\", \"tcp.analysis.ack_rtt\"]"),
        offset: z.number().int().min(0).default(0),
        limit: z.number().int().min(1).max(200).default(25),
      },
      annotations: { readOnlyHint: true },
    },
    tool(async ({ filter, fields, offset, limit }) => {
      const f = filter ?? viewer.state.filter;
      if (fields?.length) {
        const { total, rows } = await viewer.extract(f, fields, offset, limit);
        const head = `${total} frames match ${f ? `"${f}"` : "(no filter)"}; showing ${rows.length ? `${offset + 1}-${offset + rows.length}` : "none"}`;
        const more = offset + rows.length < total ? `\n(more: offset=${offset + rows.length})` : "";
        return [head, ["No.", ...fields].join(" | "), ...rows.map((r) => [r.num, ...r.values.map(oneLine)].join(" | "))].join("\n") + more;
      }
      const { total, rows } = await viewer.query(f, offset, limit);
      const cols = viewer.state.columns;
      const head = `${total} frames match ${f ? `"${f}"` : "(no filter)"}; showing ${rows.length ? `${offset + 1}-${offset + rows.length}` : "none"}`;
      const more = offset + rows.length < total ? `\n(more: offset=${offset + rows.length})` : "";
      return [head, cols.join(" | "), ...rows.map((r) => rowLine(cols, r))].join("\n") + more;
    }),
  );

  server.registerTool(
    "inspect_frame",
    {
      description: "Decoded protocol tree of one frame as indented text ({field.name} after each field). The 'frame' metadata node is collapsed unless requested.",
      inputSchema: {
        frame: z.number().int().min(1).optional().describe("Frame number; omit for the user's selected frame"),
        protocols: z.array(z.string()).optional().describe("Only expand these top-level protocols, e.g. [\"ip\",\"dns\"]"),
        max_lines: z.number().int().min(10).max(2000).default(250),
        show_bytes: z.boolean().default(false).describe("Append @offset+length to each item"),
        hex: z.boolean().default(false).describe("Also return a hex dump of the frame (first 512 bytes)"),
      },
      annotations: { readOnlyHint: true },
    },
    tool(async ({ frame, protocols, max_lines, show_bytes, hex }) => {
      const num = frame ?? viewer.state.selected;
      if (!num) throw new Error("no frame given and nothing is selected");
      const d = await viewer.frame(num);
      const out = [`Frame ${num}${d.row ? `: ${rowLine(viewer.state.columns, d.row)}` : ""}`];
      out.push(treeText(d.tree, { protocols, maxLines: max_lines, showBytes: show_bytes }));
      if (d.followers.length) out.push(`Streams: ${d.followers.map(([p, f]) => `${oneLine(p)} (${oneLine(f ?? "")})`).join(", ")}`);
      // Extensions can name data sources after packet content
      if (d.ds.length) out.push(`Extra data sources: ${d.ds.map((x, i) => `ds${i + 1}=${oneLine(x.name)}`).join(", ")}`);
      if (hex) {
        const bytes = Buffer.from(d.bytes, "base64").subarray(0, 512);
        const lines: string[] = [];
        for (let i = 0; i < bytes.length; i += 16) {
          const chunk = bytes.subarray(i, i + 16);
          lines.push(`${i.toString(16).padStart(4, "0")}  ${[...chunk].map((b) => b.toString(16).padStart(2, "0")).join(" ").padEnd(47)}  ${printable(chunk).replace(/\n|\t/g, ".")}`);
        }
        out.push("Hex:", ...lines);
      }
      return out.join("\n");
    }),
  );

  server.registerTool(
    "follow_stream",
    {
      description: "Reassembled payload of a TCP/UDP/... stream as text (non-printable bytes shown as '.'), with direction markers. Give a frame to follow its stream, or protocol + stream index.",
      inputSchema: {
        frame: z.number().int().min(1).optional().describe("Any frame of the stream"),
        protocol: z.enum(["TCP", "UDP", "TLS", "HTTP", "HTTP2", "QUIC", "SIP", "DCCP", "WebSocket"]).optional(),
        stream: z.number().int().min(0).optional().describe("Stream index: tcp.stream for TCP/TLS/HTTP/WebSocket, udp.stream for UDP, dccp.stream for DCCP"),
        max_bytes: z.number().int().min(100).max(200000).default(8000),
      },
      annotations: { readOnlyHint: true },
    },
    tool(async ({ frame, protocol, stream, max_bytes }) => {
      let proto: string | undefined = protocol;
      let filter: string;
      if (frame) {
        const d = await viewer.frame(frame);
        const pick = (proto ? d.followers.find(([p]) => p === proto) : null) ?? d.followers.find(([p]) => p === "TCP" || p === "UDP") ?? d.followers[0];
        if (!pick) throw new Error(`frame ${frame} is not part of a followable stream`);
        [proto, filter] = pick;
      } else if (proto && stream !== undefined) {
        const field = STREAM_FIELDS[proto];
        if (!field) throw new Error(`give a frame to follow ${proto}; it has no simple stream index`);
        filter = `${field} eq ${stream}`;
      } else throw new Error("give a frame, or protocol and stream");
      const r = await viewer.follow(proto!, filter, max_bytes);
      if (!r.payloads.length && !r.client.bytes && !r.server.bytes) throw new Error(`no ${proto} stream matches ${filter}`);
      const out = [
        `${proto} stream (${filter}): client ${r.client.host}:${r.client.port} sent ${r.client.bytes} bytes, server ${r.server.host}:${r.server.port} sent ${r.server.bytes} bytes`,
      ];
      // Consecutive payloads in one direction share a header, keeping small-packet streams compact
      let size = out[0].length;
      let i = 0;
      while (i < r.payloads.length && size < max_bytes) {
        const server = r.payloads[i].server;
        const first = r.payloads[i].frame;
        let last = first;
        const parts: Buffer[] = [];
        for (; i < r.payloads.length && r.payloads[i].server === server; i++) {
          parts.push(Buffer.from(r.payloads[i].data, "base64"));
          last = r.payloads[i].frame;
        }
        const header = `--- ${first === last ? `frame ${first}` : `frames ${first}-${last}`} ${server ? "server -> client" : "client -> server"} ---`;
        let body = printable(Buffer.concat(parts));
        if (size + header.length + body.length > max_bytes) body = body.slice(0, Math.max(0, max_bytes - size - header.length));
        out.push(header, body);
        size += header.length + body.length + 2;
      }
      const shown = out.slice(1).join("\n").length;
      const total = r.client.bytes + r.server.bytes;
      if (shown < total || r.truncated) out.push(`... cut at about ${max_bytes} characters; ${total} payload bytes in the stream`);
      return out.join("\n");
    }),
  );

  server.registerTool(
    "check_display_filter",
    {
      description: "Validate a Wireshark display filter without applying it. Returns OK, a warning, or the syntax error (with a hint when capture-filter syntax was used).",
      inputSchema: { filter: z.string() },
      annotations: { readOnlyHint: true },
    },
    tool(async ({ filter }) => {
      const r = await viewer.checkFilter(filter);
      return r.ok ? (r.warning ? `Valid, with warning: ${r.warning}` : "Valid") : `Invalid: ${r.error}`;
    }),
  );

  server.registerTool(
    "set_display_filter",
    {
      description: "Apply a display filter in the user's view (\"\" clears it). Invalid filters are rejected with the error so you can correct them.",
      inputSchema: { filter: z.string() },
    },
    tool(async ({ filter }) => {
      const r = await viewer.setFilter(filter, "agent");
      if (!r.ok) throw new Error(`invalid display filter: ${r.error}`);
      const s = viewer.state;
      return `Applied ${s.filter ? `"${s.filter}"` : "no filter"}: ${s.displayedFrames} of ${s.totalFrames} frames shown${r.warning ? ` (warning: ${r.warning})` : ""}`;
    }),
  );

  server.registerTool(
    "goto_frame",
    {
      description: "Select a frame in the user's view and scroll to it.",
      inputSchema: { frame: z.number().int().min(1) },
    },
    tool(({ frame }) => {
      viewer.select(frame, "agent");
      return viewer.state.selectedIndex < 0
        ? `Selected frame ${frame}, but the current display filter hides it`
        : `Selected frame ${frame} (row ${viewer.state.selectedIndex + 1} of ${viewer.state.displayedFrames})`;
    }),
  );

  server.registerTool(
    "mark_frames",
    {
      description: "Highlight frames in the user's packet list with a short note (shown as a tooltip and under Go → Marked Packets).",
      inputSchema: {
        frames: z.array(z.number().int().min(1)).min(1).max(5000),
        note: z.string().max(200).describe("Why these frames matter, e.g. \"DNS NXDOMAIN\""),
      },
    },
    tool(({ frames, note }) => {
      const marked = viewer.mark(frames, note, "agent");
      const valid = new Set(marked);
      const ignored = [...new Set(frames)].filter((f) => !valid.has(f));
      const skipped = ignored.length ? `; ignored ${ignored.length} frame(s) beyond the ${viewer.state.totalFrames} in the capture: ${ignored.slice(0, 20).join(", ")}${ignored.length > 20 ? ", ..." : ""}` : "";
      return `Marked ${marked.length} frame(s)${skipped}; ${viewer.state.marks.length} marked in total`;
    }),
  );

  server.registerTool(
    "clear_marks",
    {
      description: "Remove marks from the given frames, or all marks when frames is omitted.",
      inputSchema: { frames: z.array(z.number().int().min(1)).optional() },
    },
    tool(({ frames }) => {
      const before = viewer.state.marks.length;
      viewer.clearMarks(frames);
      const removed = before - viewer.state.marks.length;
      if (removed) viewer.notice(frames ? `Unmarked ${removed} frame${removed === 1 ? "" : "s"}` : "Cleared all marks");
      return `${viewer.state.marks.length} marks left`;
    }),
  );

  server.registerTool(
    "set_columns",
    {
      description: "Show fields as extra columns in the user's packet list, like Wireshark's Apply as Column (replaces earlier custom columns; [] removes them).",
      inputSchema: {
        columns: z.array(z.object({ field: z.string(), title: z.string().optional() })).max(10).describe("e.g. [{\"field\": \"http.response.code\"}]; the title defaults to the field's name"),
      },
    },
    tool(async ({ columns }) => {
      const r = await viewer.setColumns(columns.map((c) => ({ field: c.field, title: c.title ?? "" })), "agent");
      if (!r.ok) throw new Error(r.error);
      const s = viewer.state;
      return s.customColumns.length ? `Columns now: ${s.columns.join(" | ")}` : "Removed the custom columns";
    }),
  );

  server.registerTool(
    "expert_info",
    {
      description: "Wireshark's Expert Information: dissector warnings and errors (retransmissions, malformed packets, resets, ...) grouped by severity and message, with example frames. The quickest way to find what's wrong.",
      inputSchema: {
        min_severity: z.enum(["Comment", "Chat", "Note", "Warning", "Error"]).default("Note"),
        filter: z.string().optional().describe("Only packets matching this display filter"),
        frames_per_item: z.number().int().min(1).max(50).default(8),
      },
      annotations: { readOnlyHint: true },
    },
    tool(async ({ min_severity, filter, frames_per_item }) => {
      const order = ["Comment", "Chat", "Note", "Warning", "Error"];
      const rank = (sev: string) => order.indexOf(sev === "Warn" ? "Warning" : sev);
      const items = (await viewer.expert(filter)).filter((e) => rank(e.severity) >= rank(min_severity));
      if (!items.length) return `No expert items at ${min_severity} or above${filter ? ` for "${filter}"` : ""}`;
      const groups = new Map<string, { severity: string; group: string; protocol: string; message: string; frames: number[] }>();
      for (const e of items) {
        const key = `${e.severity}|${e.group}|${e.protocol}|${e.message}`;
        const g = groups.get(key) ?? { severity: e.severity, group: e.group, protocol: e.protocol, message: e.message, frames: [] };
        g.frames.push(e.frame);
        groups.set(key, g);
      }
      const sorted = [...groups.values()].sort((a, b) => rank(b.severity) - rank(a.severity) || b.frames.length - a.frames.length);
      const out = [`${items.length} expert items in ${sorted.length} groups${filter ? ` for "${filter}"` : ""} (severity / group / protocol / message: count, frames)`];
      for (const g of sorted.slice(0, 60)) {
        const frames = g.frames.slice(0, frames_per_item).join(", ") + (g.frames.length > frames_per_item ? ", ..." : "");
        out.push(`${g.severity} / ${g.group} / ${g.protocol} / ${g.message}: ${g.frames.length}  [${frames}]`);
      }
      if (sorted.length > 60) out.push(`... ${sorted.length - 60} more groups; raise min_severity or add a filter`);
      return out.join("\n");
    }),
  );

  server.registerTool(
    "io_graph",
    {
      description: "Wireshark's I/O Graph as numbers: packets, bytes or bits per time interval for up to 4 display filters. Finds spikes, gaps and stalls; returns peaks, empty stretches and a downsampled series.",
      inputSchema: {
        filters: z.array(z.string()).min(1).max(4).default([""]).describe("One display filter per series; \"\" for all packets"),
        metric: z.enum(["packets", "bytes", "bits"]).default("packets"),
        interval_ms: z.number().int().min(1).optional().describe("Bucket width; default fits about 100 buckets to the capture"),
        points: z.number().int().min(10).max(400).default(60).describe("Values to return per series (buckets are summed down to this)"),
      },
      annotations: { readOnlyHint: true },
    },
    tool(async ({ filters, metric, interval_ms, points }) => {
      const s = viewer.state;
      if (!s.file) throw new Error("no capture is open");
      const auto = Math.max(1, Math.ceil((s.duration * 1000) / 100));
      const r = await viewer.ioGraph(filters.map((filter) => ({ metric, filter })), interval_ms ?? auto);
      const out = [`${metric} per ${r.interval} ms over ${s.duration.toFixed(3)} s (${r.series[0]?.values.length ?? 0} buckets)`];
      for (const series of r.series) {
        const v = series.values;
        const total = v.reduce((a, b) => a + b, 0);
        let peak = 0;
        for (let i = 1; i < v.length; i++) if (v[i] > v[peak]) peak = i;
        const gaps: string[] = [];
        for (let i = 0; i < v.length; ) {
          if (v[i] !== 0) {
            i++;
            continue;
          }
          let j = i;
          while (j < v.length && v[j] === 0) j++;
          if (j - i >= 3) gaps.push(`${((i * r.interval) / 1000).toFixed(3)}-${((j * r.interval) / 1000).toFixed(3)} s`);
          i = j;
        }
        const step = Math.max(1, Math.ceil(v.length / points));
        const down: number[] = [];
        for (let i = 0; i < v.length; i += step) down.push(v.slice(i, i + step).reduce((a, b) => a + b, 0));
        out.push(
          "",
          `"${series.filter || "all packets"}": total ${total}, peak ${v[peak] ?? 0} at ${((peak * r.interval) / 1000).toFixed(3)} s` +
            (gaps.length ? `, empty: ${gaps.slice(0, 10).join(", ")}${gaps.length > 10 ? ", ..." : ""}` : ""),
          `per ${step * r.interval} ms: ${down.join(" ")}`,
        );
      }
      return out.join("\n");
    }),
  );

  server.registerTool(
    "export_packets",
    {
      description: "Write packets of the open capture to a new pcapng/pcap file (Wireshark's Export Specified Packets), e.g. a minimal capture with just the relevant packets. Choose by display filter, the user's view, marks, the user's selection or a frame range.",
      inputSchema: {
        path: z.string().describe("Absolute path ending in .pcapng or .pcap; its directory must exist"),
        filter: z.string().optional().describe("Export the frames matching this display filter"),
        which: z.enum(["displayed", "marked", "selected", "range", "all"]).default("displayed").describe("Used when no filter is given; \"selected\" is the packets the user selected (Ctrl/Shift+click), else the selected one"),
        range: z.string().optional().describe("For which=range, e.g. \"1-10,25\""),
        overwrite: z.boolean().default(false).describe("Replace a file this session exported before; other existing files are never replaced"),
      },
    },
    tool(async ({ path, filter, which, range, overwrite }) => {
      const r = await viewer.exportPackets({ path, which, range, overwrite, ...(filter !== undefined ? { filter } : {}) }, "agent");
      return `Wrote ${r.frames} packet${r.frames === 1 ? "" : "s"} (${r.size} bytes) to ${r.path}`;
    }),
  );

  server.registerTool(
    "list_interfaces",
    {
      description: "Capture interfaces available to dumpcap with their current traffic (packets/s), to advise the user which one to capture on. Only the user can start a capture, in the UI.",
      annotations: { readOnlyHint: true },
    },
    tool(async () => {
      const list = await viewer.capture.interfaces();
      let activity = viewer.capture.activity();
      // Freshly started statistics need two samples for a rate
      if (!Object.keys(activity.ifaces).length && !activity.error) {
        await new Promise((r) => setTimeout(r, 2300));
        activity = viewer.capture.activity();
      }
      const rate = (name: string) => {
        const h = activity.ifaces[name];
        if (!h?.length) return Object.keys(activity.ifaces).length ? " — no traffic statistics (dumpcap can't open it)" : "";
        const avg = h.reduce((a, b) => a + b, 0) / h.length;
        return ` — ${h[h.length - 1]} pkt/s now, ${avg < 10 ? avg.toFixed(1) : Math.round(avg)} pkt/s avg over ${h.length} s`;
      };
      const lines = list.map((i) => `${i.name}${i.description ? ` (${i.description})` : ""}${i.loopback ? " [loopback]" : ""}${i.addresses.length ? `: ${i.addresses.join(", ")}` : ""}${rate(i.name)}`);
      if (activity.error) lines.push(`(traffic statistics unavailable: ${activity.error})`);
      return lines.join("\n");
    }),
  );

  server.registerTool(
    "stop_capture",
    {
      description: "Stop the running live capture (the file stays open in the viewer).",
    },
    tool(() => {
      if (!viewer.capture.running) return "No capture is running";
      viewer.capture.stop();
      viewer.notice("Stopped the capture");
      return "Stopping the capture";
    }),
  );

  server.registerTool(
    "open_in_wireshark",
    {
      description: "Open the current capture in the real Wireshark GUI with the same display filter, jumping to a frame (default: the selected one).",
      inputSchema: { frame: z.number().int().min(1).optional() },
    },
    tool(async ({ frame }) => {
      await viewer.openInWireshark(frame ?? null);
      return "Wireshark is starting";
    }),
  );

  server.registerTool(
    "extensions",
    {
      description:
        "Teach the viewer protocols Wireshark doesn't decode, with Lua dissectors you write into WireBuddy's extension folder. guide: how, with templates (read it first); list: extensions and their status; test: load one into a separate sharkd with the open capture and report what it decodes, without changing the user's view; reload: the user's view decodes with the extensions as they are on disk; enable / disable: switch one on or off.",
      inputSchema: {
        action: z.enum(["guide", "list", "test", "reload", "enable", "disable"]),
        name: z.string().optional().describe("Extension folder name, for test, enable and disable"),
      },
    },
    tool(async ({ action, name }) => {
      const named = (): string => {
        if (!name) throw new Error(`action "${action}" needs the extension's name`);
        return name;
      };
      const listing = (): string => {
        const l = viewer.extensionList();
        const lines = [`Folder: ${l.dir}`];
        if (l.unavailable) lines.push(`Extensions are unavailable: ${l.unavailable}`);
        lines.push(...(l.extensions.length ? l.extensions.map(extensionLine) : ["No extensions yet."]));
        for (const why of l.ignored) lines.push(`Not loaded, others could change it: ${why}`);
        return lines.join("\n");
      };
      switch (action) {
        case "guide":
          return viewer.extensions.guide();
        case "list":
          return listing();
        case "test":
          return testText(await viewer.testExtension(named()));
        case "reload":
          await viewer.reloadExtensions();
          viewer.notice("Reloaded the extensions");
          return `Reloaded.\n${listing()}`;
        case "enable":
        case "disable": {
          const on = action === "enable";
          await viewer.setExtensionEnabled(named(), on);
          // One that crashes sharkd while loading is switched off again
          const off = on && !viewer.extensionList().extensions.find((e) => e.name === name)?.enabled;
          viewer.notice(off ? `Could not enable the extension "${name}": it crashed sharkd and stays off` : `${on ? "Enabled" : "Disabled"} the extension "${name}"`);
          return listing();
        }
      }
    }),
  );

  await server.connect(new StdioServerTransport());
}
