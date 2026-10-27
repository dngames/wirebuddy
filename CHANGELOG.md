# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

First version.

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
- Traffic sparklines for capture interfaces on the start page and in the capture bar
- "Open in Wireshark" at the same file, filter and packet
- MCP server with tools to read, filter, select and mark packets and follow streams; it reminds
  the agent to open the viewer in the browser pane
- Problems in the viewer go to the agent instead of the screen; `--watch` wakes it when one happens
- Wireshark dissector plugins, preferences and `--profile` support
- Extensions: the agent teaches the viewer protocols Wireshark doesn't decode with Lua
  dissectors, tests them on the open capture and reloads; Analyze › Extensions and
  Reload Lua Plugins
