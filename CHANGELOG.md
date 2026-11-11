# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

- The check that a panel runs in a process of its own no longer reads a busy page or a slow-starting panel as "not isolated": one page task inside the panel's busy window proves it, and only three empty rounds, spaced out, say no
- Extensions, panels and Decode As on macOS, where the same checks are made (verified in CI on a hosted runner, not by hand): group-writable entries count as others', every folder's and file's ACL is read with `/bin/ls -led`, and only local APFS or HFS+ volumes that keep ownership are looked into; Export Objects checks folders the same way there and compares code folders ignoring case
- Security: the server also takes its port on `::1`, so no other program on the machine can answer for the panels' `localhost` hosts there
- Security: the instance file `--watch` reads (URL and token) is never written through a link or into another user's folder
- Security: packet exports are written in a private folder next to the target; nothing of them is readable by others or under a guessable name meanwhile
- Security: an ACL that can't be read counts as letting others write an extension; without `getfacl`, an entry with any ACL isn't loaded
- A URL in the packet details opens on a double-click, not on a click
- A click in the I/O graph finds its packet also when time references are set
- Modal dialogs keep the keyboard focus; text typed into the filter bar while a filter applies keeps its own validation
- Export Specified Packets exports the selection the dialog named, and asks before replacing only a file that is there
- A Follow Stream window acts on nothing once its capture is closed
- A capture that goes on in new files lists its newest 100 files and counts the rest
- The file dialog lists only the formats WireBuddy opens
- `extensions` action "test" also checks the panel of an extension that is switched off
- Panels: `eval`, `new Function` and network imports found in a panel's text are warnings, only code that doesn't parse keeps it from opening; `wb.subscribe` asks again after a passing failure and the agent hears when one ends; an unsupported `match` rejects with `e.unsupported === "match"`
- Panels: at most 100 reports a second, `wb.storage` counts against the four requests at a time, and a panel's malformed requests no longer show up as viewer errors for the agent
- Switching a panel-only extension off no longer reads the capture again
- A slow request no longer makes the ones queued behind it time out: sharkd gets its 5 minutes per request from the moment it starts on it
- A sharkd crash noticed while writing to it is reported like any other crash (exit code or signal, extension rollback) instead of "write EPIPE"
- Live capture: provisional rows read while the columns, TLS keys or Decode As changed are no longer shown under the new view, and they are read again when their slice brings along other packets
- Provisional packets, panel raw matches and the `ip`/`payload` layers see IP behind PPPoE sessions and MPLS labels; later IPv6 fragments of packets with extension headers are recognized as IPv6
- A wrong command-line option or port is said in one line

## [0.15.0] - 2026-11-03

- Now: in a live capture, tap the flag (or N) to have the agent look at what just happened, or hold it to flag a span, marked with packet comments
- A packet the agent shows during a live capture stays in view: auto-scroll pauses until the next capture

## [0.14.1] - 2026-10-30

- A release workflow publishes to npm from GitHub Actions, with provenance, from the next release on
- Decode As suggests close matches for a protocol name misspelt in its first letter too
- A packet list column given as a field (`_ws.col.info`) is refused instead of coming back empty or crashing sharkd
- Dialogs move back into view when the window gets smaller

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

[Unreleased]: https://github.com/dngames/wirebuddy/compare/v0.15.0...HEAD
[0.15.0]: https://github.com/dngames/wirebuddy/compare/v0.14.1...v0.15.0
[0.14.1]: https://github.com/dngames/wirebuddy/compare/v0.14.0...v0.14.1
[0.14.0]: https://github.com/dngames/wirebuddy/compare/v0.13.0...v0.14.0
[0.13.0]: https://github.com/dngames/wirebuddy/compare/v0.12.0...v0.13.0
[0.12.0]: https://github.com/dngames/wirebuddy/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/dngames/wirebuddy/compare/v0.10.1...v0.11.0
[0.10.1]: https://github.com/dngames/wirebuddy/compare/v0.10.0...v0.10.1
[0.10.0]: https://github.com/dngames/wirebuddy/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/dngames/wirebuddy/releases/tag/v0.9.0
