# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

- A page that is open when WireBuddy restarts reconnects by itself: without `--token` the session token is the one the last start made, kept for the user alone in `~/.local/share/wirebuddy/state/token` (delete it for a new one; SECURITY.md says what that changes)
- A page whose token the server refuses (another token, a session that ended) says so in a notice over the page, with where the current address comes from, and keeps trying; a page that lost its server dims what it shows after a few seconds
- A restart keeps the custom columns and the recent files list (the display filter and the questions are not kept, which the README now says)
- A question about packets of a capture that is not open any more names that capture in the page, in `get_view_state` and in the result of `answer_question`, which refuses a `frame` with it
- The agent's `follow_stream` of a TLS stream names the client and the server the right way round (the page's Follow dialog too), and a TCP follow of a stream that carries TLS, with a key log set, says that the decrypted stream comes with protocol TLS or HTTP
- Add Comment, Mark Packet with Note and Ask Agent for one packet go by its frame number: a display filter set while the dialog is open no longer loses the text, and when the capture changed the dialog stays open with the text and says why
- The background watcher prints the activity before the problem or question too, as the server instructions say
- Provisional rows of a big live capture carry a "≈" before the packet number and a stronger dashed edge in both themes; the status bar's text is short enough not to be cut (the rest is in its tooltip) and counts the seconds to the exact rows down with the full read under way instead of staying as it was

## [0.17.0] - 2026-11-13

- A folder for live captures that can't be created (`--capture-dir`) says which user WireBuddy runs as and that this user can't create it, not a bare `EACCES`
- Applying a display filter with no capture running shows the selected packet if the list still has it, else the top of the list, not its last row; Auto Scroll in Live Capture matters only while a capture runs
- The agent's `extensions` test says how many packets of the capture still show as undecoded payload and, for an extension over TCP, how many are segments of a message reassembled in a later packet, so those are not read as a hole
- A panel whose capture is closed (or changed) while it reads no longer counts as a problem sent to the agent: a read with no capture open or a stale one rejects with `no-capture` or `stale`, which is not reported, and the panel guide says what a panel sees then
- The agent's panel guide says how a panel follows a live capture (`wb.subscribe`, or reading again on the `packets` event) and not to pick packets by a client's ephemeral TCP port
- The agent's extension guide has a template for a length-prefixed protocol over TCP (several messages in a segment, a message split over segments, every message in the Info column) and says what several messages in one packet mean for display filters and columns
- A question to the agent (Ask Agent, Now) shows in the page: a quiet line says it is waiting, and the answer the agent gives with the new `answer_question` tool takes its place in the banner until you dismiss it; Tools › Questions to Claude… lists the session's last 20 questions with their answers, and a click selects the packet a question was about
- Mark Packet with Note… (the packet list's menu and Edit) gives a mark a note of your own, Edit Mark's Note… changes it, and the agent hears which packets got which note; Mark Packet stays the quick toggle
- The agent's mark on a packet the user marked still replaces it, but `mark_frames` now names those frames and the notice the user gets says so
- A packet's mark shows as the first line of its details ("Marked by Claude: note", "Marked: note"), and Go › Marked Packets shows a note in full, wrapped, not cut off
- Opening another capture clears a display filter on `frame.number` (it named the other capture's packets) and says so; the notice of restored marks says how many the display filter hides, so they no longer read as lost
- The agent's `expert_info` counts every expert item in its header as the Expert Information dialog does (Chat and Comment too), with the count per severity, and says how many of them it lists
- A write refused for lack of permission (export, findings report, saved objects) says which user WireBuddy runs as and that this user can't write to the folder (or can't reach it), not only `EACCES: permission denied`
- A display filter with a set whose members are separated by spaces (`frame.number in {430 432}`) gets a hint to separate them with commas, not only Wireshark's `"432" was unexpected in this context`
- A live capture on `lo`, `lo0` or `any` leaves out WireBuddy's own traffic (TCP on its port on the loopback addresses), which the page's fetches made with every new packet and which filled the capture, the I/O graph and Find String; your capture filter stays as typed and is combined with that, and the capture's state, the status bar and `start_capture` say it
- Run as root, extensions and Decode As say that sharkd loads no Lua plugins for root (Wireshark's rule) and to run WireBuddy as an ordinary user, instead of "this sharkd has no Lua support"
- The page gets only what changed of the view's state after the first, so many marks or a long selection no longer slow a live capture's updates
- Marks, time references and packet comments edited in the viewer are kept with their capture and come back when it (or a copy of it) is opened again, also after another capture or a restart; a notice says what came back
- Security: what is kept for each capture is written to `~/.local/share/wirebuddy/investigations` (folder `0700`, files `0600`), never next to the capture, and a file there that doesn't check out is ignored whole and set aside, not overwritten
- File › Forget Kept Marks and Comments… drops the marks, time references and comment edits of the open capture, so its packets read as the capture file has them again
- File › Write Findings Report… and the agent's `write_findings` write the summary, the marked packets with their notes, the packet comments and the capture's facts as one Markdown file, under the rules of exports; text from the capture is escaped so it can't render as a link, image, HTML or heading
- Open, Close and Start Capture ask before discarding edited packet comments only when they can't be kept with the capture

## [0.16.0] - 2026-11-12

- Errors you run into in the viewer show there also while an agent is attached; the agent hears of them too
- In a container with a memory limit, full reads of a live capture wait for the container's free memory, not the host's
- The check that a panel runs in a process of its own no longer reads a busy page or a slow-starting panel as "not isolated": one page task inside the panel's busy window proves it, and only three empty rounds, spaced out, say no
- A menu that opens where a notification shows is no longer covered by it: its items take the click
- The packet list no longer jumps back to where it was when it is scrolled just as the view updates, as it does several times a second in a live capture
- Live capture where there is no `/sys` or `/proc` (macOS): new or removed interfaces are noticed by name for the activity sampler, a sharkd's size comes from `ps`, and the folders of slices that killed servers left behind are found by the boot session, not the host name, which changes with the network there
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

[Unreleased]: https://github.com/dngames/wirebuddy/compare/v0.17.0...HEAD
[0.17.0]: https://github.com/dngames/wirebuddy/compare/v0.16.0...v0.17.0
[0.16.0]: https://github.com/dngames/wirebuddy/compare/v0.15.0...v0.16.0
[0.15.0]: https://github.com/dngames/wirebuddy/compare/v0.14.1...v0.15.0
[0.14.1]: https://github.com/dngames/wirebuddy/compare/v0.14.0...v0.14.1
[0.14.0]: https://github.com/dngames/wirebuddy/compare/v0.13.0...v0.14.0
[0.13.0]: https://github.com/dngames/wirebuddy/compare/v0.12.0...v0.13.0
[0.12.0]: https://github.com/dngames/wirebuddy/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/dngames/wirebuddy/compare/v0.10.1...v0.11.0
[0.10.1]: https://github.com/dngames/wirebuddy/compare/v0.10.0...v0.10.1
[0.10.0]: https://github.com/dngames/wirebuddy/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/dngames/wirebuddy/releases/tag/v0.9.0
