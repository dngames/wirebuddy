# WireBuddy

[![CI](https://github.com/dngames/wirebuddy/actions/workflows/ci.yml/badge.svg)](https://github.com/dngames/wirebuddy/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

<p align="center">
  <a href="docs/demo.mp4"><img src="docs/demo.gif" alt="WireBuddy demo: an AI agent opens a capture, filters and marks packets, then a live capture is analysed together" width="900"></a>
  <br><sub>45-second demo · <a href="docs/demo.mp4">MP4 version</a></sub>
</p>

A lightweight, Wireshark-style packet viewer that runs in a browser tab — built to sit next to
an AI chat (e.g. the Claude Code desktop app's browser pane) so you and the agent look at the
same capture, filter, selected packet and marks.

- **Packet list / details / bytes** like Wireshark: coloring rules, display filter bar with live
  validation and field autocompletion, linked tree ↔ hex highlighting, follow stream,
  protocol hierarchy, conversations, endpoints.
- **Live capture** with `dumpcap`: interface picker, capture-filter check, auto-stop
  (duration / size / packets), ring buffer. The view updates about once a second.
- **Open in Wireshark** jumps to the real GUI with the same file, filter and packet.
- **MCP server** so an agent can read the capture, apply filters, select and mark packets, and
  follow streams. The agent **cannot start a capture** — only you can, with a click in the UI.

All protocol decoding is done by Wireshark's own engine (`sharkd`), so dissection is identical
to Wireshark.

![WireBuddy screenshot: a reassembled HTTP response, with frames marked by the agent](docs/screenshot.png)

## Requirements

- Wireshark 4.x with `sharkd` (Debian/Ubuntu: `wireshark-common`) — tested with 4.6.6
- `dumpcap` with capture permission for your user (member of the `wireshark` group) for live capture
- Node.js ≥ 20

Developed on Ubuntu 22.04 with Wireshark 4.6.6; CI runs on Ubuntu 24.04 with the current stable
Wireshark. Other Linux distributions should work; macOS and Windows are untested.

## Build and run

```bash
npm install
npm run build
npm start                      # prints the UI URL, e.g. http://127.0.0.1:8765/?token=…
node dist/server/main.js path/to/capture.pcapng   # open a file right away
```

Options: `--port <n>` (default 8765, falls back to a free port), `--token <t>`,
`--capture-dir <dir>` (default `~/.local/share/wirebuddy/captures`), `--profile <name>`, `--mcp`.

## Dissector plugins and profiles

WireBuddy decodes with `sharkd`, which loads the same plugins and settings as Wireshark:

- **C plugins** from the global folder (e.g. `/usr/lib/x86_64-linux-gnu/wireshark/plugins/4.6/epan`)
  and the personal one (`~/.local/lib/wireshark/plugins/4.6/epan`).
- **Lua plugins** from `~/.config/wireshark/plugins` (and the global Lua plugin folder).
- **Preferences, Decode As, enabled/disabled protocols, coloring rules** from `~/.config/wireshark`.
- **Profiles**: `--profile <name>` starts `sharkd` (and "Open in Wireshark") with that
  configuration profile.

A plugin's fields show up in the details tree, can be filtered on, appear in filter
autocompletion, and are visible to the agent through `inspect_frame`. Restart WireBuddy after
adding or changing a plugin.

## Use with Claude Code

Register the MCP server (it also starts the web UI):

```bash
claude mcp add wirebuddy -- node /path/to/wirebuddy/dist/server/main.js --mcp
```

(If `node` is not on your `PATH`, give its full path, e.g. `~/.local/opt/node-v24.22.1-linux-x64/bin/node`.)

To see what the agent side looks like without Claude, `node test/agent-demo.mjs` plays a short
scripted session (filter, mark, select) against the fixture; open the URL it prints.

Then ask Claude to open the viewer: the `viewer_url` tool returns the URL, which Claude opens in
the browser pane next to the chat. Example prompts:

- "Open ~/captures/slow-login.pcapng and tell me why the login is slow."
- "Explain the packet I have selected."
- "Mark all DNS failures and filter to them."
- (after you start a live capture) "Watch the capture and tell me when you see TCP retransmissions."

### MCP tools

| Tool | What it does |
|---|---|
| `viewer_url` | URL of the UI to show in the browser pane |
| `get_view_state` | What the user sees: file, counts, filter, selected frame, marks, capture status |
| `open_capture` | Open a capture file in the viewer |
| `capture_summary` | Protocol hierarchy, top conversations, expert info counts |
| `query_packets` | Paginated summary rows for any display filter (doesn't change the view) |
| `inspect_frame` | Protocol tree of one frame as compact text, optionally limited to protocols, with hex |
| `follow_stream` | Reassembled stream payload as text |
| `check_display_filter` | Validate a filter; hints when capture-filter (BPF) syntax was used |
| `set_display_filter` | Apply a filter in the user's view |
| `goto_frame` | Select and scroll to a frame |
| `mark_frames` / `clear_marks` | Highlight frames with a note |
| `list_interfaces` | Capture interfaces (read-only) |
| `stop_capture` | Stop the running capture |
| `open_in_wireshark` | Open the capture in the real Wireshark at the selected frame |

Every agent action that changes the view shows a notice in the UI.

## How it works

```
 browser (src/web)  ──HTTP/WebSocket──▶  Node server (src/server)  ──stdio JSON-RPC──▶  sharkd ×2
                                              │                                         (alternate during
 Claude (MCP over stdio) ────────────────────▶│                                          live reloads)
                                              └──▶ dumpcap (live capture → .pcapng)
                                              └──▶ wireshark -r … -Y … -g …
```

- One server process holds the view state; the UI and the MCP tools share it.
- During a live capture, one `sharkd` answers requests while the other re-reads the growing
  file; then they swap, so the UI never waits for a reload.
- The packet list is virtualized and pages rows from `sharkd`, so large captures stay smooth.

## Security

- Binds to `127.0.0.1` only; every API/WebSocket call needs the per-session token from the URL.
- Requests with a foreign `Host` (DNS rebinding) or a cross-site `Origin` are rejected.
- Capture starts only through the UI's Start button; there is no MCP tool for it.
- `open_capture` / Open only accept capture files (by extension or pcap/pcapng/compressed magic
  bytes), so they can't be used to read arbitrary files.
- Anyone who has the URL with its token can read captures and start captures as you — don't
  share it.

## Tests

```bash
npm run build
node test/api-smoke.mjs     # HTTP API against test/fixtures/http.pcapng
node test/mcp-smoke.mjs     # MCP tools over stdio
node test/live-smoke.mjs    # live capture on loopback (needs dumpcap permissions; pings 127.0.0.1)
```

## Limitations

- A live capture re-reads the whole current file on every update, so very long or busy captures
  get slower to refresh; use a ring buffer or a capture filter for those.
- Statistics cover the whole capture, not just the displayed packets.
- No packet comments, time references, IO graph or export yet.

## Contributing

Issues and pull requests are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). Please report
security problems privately as described in [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) © 2026 Michael Haar

Wireshark is a registered trademark of the Wireshark Foundation. WireBuddy is an independent
project and is not affiliated with or endorsed by the Wireshark Foundation.
