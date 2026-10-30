# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

- Releases are published to npm from GitHub Actions, with provenance

## [0.14.0] - 2026-10-30

- Decode As: decode a port as a protocol Wireshark knows, from a packet's context menu or the agent's `decode_as` tool
- TLS keys set while a big live capture's newest packets load now decrypt those packets too
- An open Expert Information dialog refreshes when extensions are reloaded

## [0.13.0] - 2026-10-29

- File › Export Objects: list the files carried in the traffic and save them to a new folder
- `export_objects` refuses WireBuddy's own `dist` folder
- Chrome's ResizeObserver note no longer reaches the agent as a page error

## [0.12.0] - 2026-10-29

- Time references, as in Wireshark's Edit menu, and the agent's `time_references` tool
- Packet comments: add, edit and delete them as in Wireshark's Edit › Packet Comments, for the agent too; pcapng exports keep them

## [0.11.0] - 2026-10-28

- Install from npm: `npm install -g wirebuddy`, or `claude mcp add wirebuddy -- npx -y wirebuddy --mcp`

## [0.10.1] - 2026-10-28

- The agent learns whether a panel it opens runs in a process of its own also when the panel is ready at once

## [0.10.0] - 2026-10-28

- Big live captures list new packets within about a second, provisionally until the next full read
- Example investigation of a CT archive that loses thin slices, `examples/investigations/ct-archive`
- Panels reopen at the size they had when closed, not at the smallest size
- WireBuddy shuts down cleanly when its terminal closes, as on Ctrl+C
- Cumulative Bytes columns count from the first packet also when a capture is read again
- Scrolling up with the mouse wheel in a live capture of over 400,000 packets turns auto-scroll off
- Checking which panels to offer no longer reads a live capture again every 30 seconds

## [0.9.0] - 2026-10-27

First public version.

- Wireshark-style packet list, details tree and bytes view, decoded by `sharkd`
- Wireshark's menu bar, main toolbar and keyboard shortcuts
- Select several packets with Ctrl+click and Shift+click, to mark, copy or export them
- Find Packet by display filter, string or hex value; packet history; zoom
- Follow Stream window like Wireshark's: stream stepping, C Arrays, UTF-8 and Raw views, find, filter out, save
- Display filter bar with validation, field autocompletion and capture-filter hints
- Protocol hierarchy, conversations and endpoints
- Custom columns ("Apply as Column"), Expert Information and I/O Graph
- TLS decryption with a key log file
- Export Specified Packets to pcapng or pcap
- Live capture with `dumpcap` and Wireshark's Capture Options dialog: interfaces with traffic,
  promiscuous mode, capture-filter check, new files automatically, ring buffer, stop conditions
- Traffic sparklines for capture interfaces on the start page and in the Capture Options dialog
- "Open in Wireshark" at the same file, filter and packet
- MCP server with tools to start and stop captures, read, filter, select and mark packets and
  follow streams; it reminds the agent to open the viewer in the browser pane
- Problems in the viewer go to the agent instead of the screen; `--watch` wakes it when one happens
- Ask the agent about packets from the packet list's context menu; the question wakes `--watch`
- Marks and their notes are written as packet comments when exporting to pcapng
- `export_objects` MCP tool: list and save the files carried in the traffic
- Wireshark dissector plugins, preferences and `--profile` support
- Extensions: the agent teaches the viewer protocols Wireshark doesn't decode with Lua
  dissectors, tests them on the open capture and reloads; Analyze › Extensions and
  Reload Lua Plugins
- Panels: agent-written views of the capture in a sandboxed window (View › Panels), offered in the
  status bar when a capture fits
- An example investigation to try with the agent: a robot arm that stutters
  (`examples/investigations/robot-arm`), also the demo video's story

[Unreleased]: https://github.com/dngames/wirebuddy/compare/v0.14.0...HEAD
[0.14.0]: https://github.com/dngames/wirebuddy/compare/v0.13.0...v0.14.0
[0.13.0]: https://github.com/dngames/wirebuddy/compare/v0.12.0...v0.13.0
[0.12.0]: https://github.com/dngames/wirebuddy/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/dngames/wirebuddy/compare/v0.10.1...v0.11.0
[0.10.1]: https://github.com/dngames/wirebuddy/compare/v0.10.0...v0.10.1
[0.10.0]: https://github.com/dngames/wirebuddy/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/dngames/wirebuddy/releases/tag/v0.9.0
