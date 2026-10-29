# WireBuddy

[![CI](https://github.com/dngames/wirebuddy/actions/workflows/ci.yml/badge.svg)](https://github.com/dngames/wirebuddy/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/wirebuddy)](https://www.npmjs.com/package/wirebuddy)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

<p align="center">
  <a href="docs/demo.mp4"><img src="docs/demo.gif" alt="WireBuddy demo: an AI agent investigates a stuttering robot arm. It captures the traffic, writes a dissector for the arm's protocol, finds where each command loses 40 ms, plots the arm's moves in a panel and confirms the fix with a second capture" width="900"></a>
  <br><sub>50-second demo · <a href="docs/demo.mp4">MP4 version</a></sub>
</p>

**You and your AI agent, looking at the same packets.**

WireBuddy is a Wireshark-style packet viewer in a browser tab, built to sit next to an AI chat
(for example in the Claude Code desktop app's browser pane). The agent works the viewer over MCP
while you watch and click in the same view, and when a capture holds something Wireshark can't
decode or a packet list can't show, the agent extends the viewer itself.

- **One view for both of you.** The agent's filters, selected packet, marks, comments and columns
  show up in your view as it works, each with a notice; what you do there (open a file, apply a
  filter, start a capture) reaches the agent with its next call, and it sees which packets you
  selected.
  Right-click packets to ask the agent about them without leaving the view. You check its
  findings in the packets instead of taking a summary on trust.
- **The agent extends the viewer.** Traffic Wireshark doesn't know, such as a company's sensor
  stream or a game's protocol, shows up as "Data". The agent writes a Lua dissector for it from
  the bytes or a spec, tests it against the open capture and reloads the view, which then
  decodes the new protocol, with fields you can filter on and show as columns. When rows aren't
  enough, it writes a **panel**: a sandboxed page next to the packets that plots, plays or draws
  what's in the capture (images, video, point clouds, a field over time).
- **Wireshark's own decoding.** Everything is dissected by Wireshark's engine (`sharkd`), with
  your plugins and preferences (and a profile you choose), so results match Wireshark; **Open in
  Wireshark** jumps to the real GUI at the same file, filter and packet.
- **Live captures the agent can run.** The agent starts and stops captures with `dumpcap` and
  reads them as they grow; so can you, with a Capture Options dialog like Wireshark's.

The viewer itself works like Wireshark:

- **Packet list, details and bytes** with Wireshark's menu bar, toolbar and keyboard shortcuts:
  coloring rules, a display filter bar with live validation and field autocompletion, linked tree
  and hex highlighting, custom columns ("Apply as Column"), time references the Time column counts
  from, Find Packet, packet history, zoom.
- **Follow Stream** like Wireshark's window (TCP, UDP, TLS, HTTP and more), and **several
  packets selected** with Ctrl+click and Shift+click to mark, copy or export them; the agent sees
  the selection too, so you can ask "what's wrong with these packets?".
- **Statistics:** Expert Information, I/O Graph, protocol hierarchy, conversations and
  endpoints, optionally limited to the display filter.
- **TLS decryption** with a key log file (`SSLKEYLOGFILE`), and **Export Specified Packets**
  (displayed, marked, selected or a range) to a new pcapng/pcap; in pcapng the marks and their
  notes go along as packet comments, which Wireshark shows.
- **Export Objects** as in Wireshark's File menu: list the files carried in HTTP, email (IMF),
  SMB, TFTP, DICOM and FTP traffic, go to their packets, and save them, each save into a new
  folder; the agent hears where, so you can ask it about them.
- **Packet comments** as in Wireshark's Edit › Packet Comments: add, edit and delete them, for
  you and the agent alike; the packet list marks commented packets, and pcapng exports (Save As)
  write the comments as edited.
- **Live capture** with traffic sparklines per interface, promiscuous mode, a capture filter
  checked as you type, new files automatically, a ring buffer and stop conditions; the view
  updates about once a second.

![WireBuddy screenshot: a reassembled HTTP response, with frames marked by the agent](docs/screenshot.png)

## How it compares

Several MCP servers give an agent packet data through Wireshark's command-line tools, for example
[Wireshark MCP](https://github.com/bx33661/Wireshark-MCP) and
[WireMCP](https://github.com/0xKoda/WireMCP). They are the better fit when the agent works on its
own: they run wherever `tshark` runs (macOS, Windows and Linux, also headless on a server),
Wireshark MCP installs and registers itself with one pip command, they capture live traffic too,
and they bring ready-made analyses WireBuddy doesn't have, such as security and anomaly checks,
threat-intelligence lookups, credential extraction and capture indexes.

WireBuddy is for working on a capture together with the agent:

| | tshark-based MCP servers | WireBuddy |
|---|---|---|
| What you see | the agent's answer, in Wireshark MCP with frame references and `tshark` commands to re-check it | the packets, with the agent's filters, marks and selected packet in your view |
| Protocols Wireshark doesn't decode | stay "Data" unless you install a dissector yourself (Wireshark MCP offers Decode As for protocols Wireshark has) | Lua dissectors the agent writes, tests and loads into the view |
| Beyond packet rows | text and JSON for the agent | panels the agent writes: plots, images, video, point clouds |
| Ready-made analyses | many, from statistics to threat intelligence | Wireshark's statistics and expert info |
| Where it runs | anywhere `tshark` runs, headless too | Linux with a browser, Wireshark 4.6 and Node.js 22 (macOS and Windows untested; extensions and panels need Linux) |

(Compared with what those projects describe in their READMEs, October 2026.)

## Requirements

- **Wireshark 4.6** with `sharkd`, `editcap` and `mergecap` (Debian/Ubuntu package
  `wireshark-common`); the `wireshark` package too for "Open in Wireshark". Older versions are
  untested, and Ubuntu 22.04 and 24.04 ship 3.6 and 4.2, so take the Wireshark PPA there:

  ```bash
  sudo add-apt-repository ppa:wireshark-dev/stable
  sudo apt install wireshark-common wireshark
  ```

- **For live capture**, `dumpcap` must be allowed to capture as your user:

  ```bash
  sudo dpkg-reconfigure wireshark-common   # answer "Yes"
  sudo usermod -aG wireshark $USER         # then log out and in again
  ```

- **Node.js ≥ 22**

Developed on Ubuntu 22.04 with Wireshark 4.6.6; CI runs on Ubuntu 24.04 with the current stable
Wireshark from the PPA. Other Linux distributions should work; macOS and Windows are untested.

## Install and run

```bash
npm install -g wirebuddy
wirebuddy                      # prints the UI URL, e.g. http://127.0.0.1:8765/?token=…
wirebuddy path/to/capture.pcapng   # open a file right away
```

`npx wirebuddy` runs it without installing. From a clone of the repository:

```bash
npm install && npm run build
npm start
```

Options (`--help` shows the same):

| Option | Environment | |
|---|---|---|
| `--port <n>` | `WIREBUDDY_PORT` | HTTP port on 127.0.0.1; default 8765, falls back to a free one |
| `--token <t>` | `WIREBUDDY_TOKEN` | session token, at least 16 characters; default random. Prefer the variable: other local users can see command lines in `ps` |
| `--capture-dir <dir>` | `WIREBUDDY_CAPTURE_DIR` | where live captures go; default `~/.local/share/wirebuddy/captures` |
| `--profile <name>` | `WIREBUDDY_PROFILE` | Wireshark configuration profile for dissection and Open in Wireshark |
| `--tls-keylog <file>` | | decrypt TLS with this key log file |
| | `WIREBUDDY_EXTENSIONS` | more folders of extensions, separated by `:` |
| `--mcp` | | also serve MCP over stdio; logs go to stderr |
| `--watch <file>` | | wait for the next problem or question in a running viewer, print it, exit (see below) |
| `--version` | | print the version |

## TLS decryption

Start the program whose traffic you want to read with `SSLKEYLOGFILE` set, e.g.

```bash
SSLKEYLOGFILE=~/tls-keys.log firefox
```

then choose that file under **Tools → TLS Keys…** in WireBuddy (or start WireBuddy with
`--tls-keylog ~/tls-keys.log`). The capture is re-dissected, HTTP/2, HTTP and other protocols
inside TLS become visible, and "Open in Wireshark" passes the key log on. A key log file set in
Wireshark's own preferences is picked up automatically. The agent can see whether decryption is
on, but only you choose the file. Treat the key log like a password.

## Extensions

Wireshark decodes thousands of protocols, but not your company's sensor stream or a game's
network protocol: those show up as "Data". Ask the agent to decode them. It finds the undecoded
traffic (`capture_summary` lists it), works out the format from the bytes or from a spec you give
it, and writes a Lua dissector into WireBuddy's extension folder:

```
~/.local/share/wirebuddy/extensions/<name>/
  extension.json    {"label": "ACME telemetry", "version": "1", "description": "…"}
  acme.lua          a Wireshark Lua dissector
```

It tests the extension against the open capture in a separate `sharkd` first, then reloads the
view, which decodes the new protocol: its fields appear in the details tree, in filters and
autocompletion, as columns and in "Open in Wireshark". Problems come back to the agent: Lua that
doesn't load, dissectors failing on some packets (with the frame and line), endless loops (stopped
after a second), an extension that crashes `sharkd` (switched off when it crashes while loading;
the view keeps its previous extensions when one crashes while reading the capture).

**Analyze › Extensions…** lists the extensions with their status and switches them on and off;
**Analyze › Reload Lua Plugins** (Ctrl+Shift+L) loads them again after you edited one. You can
write extensions yourself the same way, or share a folder of them with `WIREBUDDY_EXTENSIONS`.

Extensions are Lua code that runs as you, with access to your files. WireBuddy only loads
extensions no other user could have changed (see [SECURITY.md](SECURITY.md)): a shared team
folder that colleagues can write is ignored, and so is a folder on a network or FUSE filesystem,
where that can't be checked. Only let an agent write extensions if you would let it run commands,
and look at what it wrote. Extensions need Linux.

### Panels

An extension can also bring a **panel**: a small web page of its own (`panel/main.js`, plus
optional HTML, CSS and further modules) that WireBuddy shows in a window next to the packets and
feeds with the open capture, also during a live capture: images or files in the traffic, video,
point clouds, a field over time. The agent writes one when a picture says more than packet rows,
checks it (`extensions action "test"` finds syntax errors with file and line), opens it with the
`panel` tool and gets told whether it started, what it shows and every error it throws;
`panel action "snapshot"` gives it an image of the panel.

You open panels under **View › Panels** or in Analyze › Extensions. An extension can offer its
panel for captures it fits (`"offer": {"filter": "rtp", "text": "Play the video"}`): the offer
shows as a chip in the status bar that opens the panel, or with × goes away for that capture. A
panel can select a packet in your view, and with the `"control"` permission apply a display
filter, but only right after you clicked or typed in it. It can keep up to 256 KiB of JSON
(`wb.storage`) across restarts. Examples to copy from are in
[examples/extensions](examples/extensions).

Each panel runs sandboxed on a one-time origin of its own (`p<random>.localhost`), in its own
browser process, and gets only its own files and the capture, never WireBuddy's API, its token or
(WebRTC aside) the network. A panel that stops responding is stopped after 20 seconds without
slowing WireBuddy down, and one that tries to navigate is closed; [SECURITY.md](SECURITY.md) has
the details.

## Dissector plugins and profiles

WireBuddy decodes with `sharkd`, which loads the same plugins and settings as Wireshark:

- **C plugins** from the global folder (e.g. `/usr/lib/x86_64-linux-gnu/wireshark/plugins/4.6/epan`)
  and the personal one (`~/.local/lib/wireshark/plugins/4.6/epan`).
- **Lua plugins** from the global folder, `~/.local/lib/wireshark/plugins` and
  `~/.config/wireshark/plugins`.
- **Preferences, Decode As, enabled/disabled protocols, coloring rules** from `~/.config/wireshark`.
- **Profiles**: `--profile <name>` starts `sharkd` (and "Open in Wireshark") with that
  configuration profile.

A plugin's fields show up in the details tree, can be filtered on, appear in filter
autocompletion, and are visible to the agent through `inspect_frame`. After changing a Lua
plugin, use Analyze › Reload Lua Plugins; restart WireBuddy after adding a C plugin.

## Use with Claude Code

Register the MCP server (it also starts the web UI):

```bash
claude mcp add wirebuddy -- npx -y wirebuddy --mcp
```

That needs `node` on the `PATH` Claude Code starts MCP servers with. Where it isn't (Node from
nvm or a folder of your own, Claude Code started from the desktop), install WireBuddy and register
it with full paths:

```bash
npm install -g wirebuddy
claude mcp add wirebuddy -- "$(command -v node)" "$(npm root -g)/wirebuddy/dist/server/main.js" --mcp
```

From a clone of the repository, use its `dist/server/main.js` the same way. There,
`node test/agent-demo.mjs` shows what the agent side looks like without Claude: it plays a short
scripted session (filter, mark, select) against the fixture; open the URL it prints.

Claude opens the viewer in the browser pane next to the chat by itself as soon as it starts
working with WireBuddy: while no viewer is connected, the tool results remind it, with the URL.

While Claude is attached, the viewer shows you no error messages. Problems (a file that won't
open, a rejected filter, a failed capture, a crashed `sharkd`) and what you do in the viewer go
to Claude instead, with its next WireBuddy tool call; the status bar only counts the problems
waiting for it. To react while you work, Claude runs `wirebuddy --watch <instance-file>` as a
background command: it waits for the next problem or question, prints it and exits, which wakes
Claude.

To ask about packets without switching to the chat, right-click them in the packet list and
choose **Ask Claude about This Packet…** (or **Ask Claude about These N Packets…**). The question
goes to Claude with the packet numbers and wakes it if its watch is running (the dialog says
whether it is); otherwise it comes with Claude's next step. Claude answers in the chat.

Example prompts:

- "Open ~/captures/slow-login.pcapng and tell me why the login is slow."
- "Explain the packet I have selected."
- "Mark all DNS failures and filter to them."
- "Capture on eth0 for a minute and tell me when you see TCP retransmissions."
- "Save the files that were downloaded over HTTP and check them against these hashes."

### Example: a robot arm that stutters

[`examples/investigations/robot-arm`](examples/investigations/robot-arm) is an investigation to
try, all on your machine over loopback: an emulated arm controller and the control app that drives
it. The app should send the controller 50 commands a second but gets about 22 through, and the
arm moves in jerks, while the controller's vendor says it answers in under a millisecond.

> The robot arm stutters. Our control app, examples/investigations/robot-arm/app.mjs, should send
> the arm controller 50 MOVE commands a second, but gets about 22 through and the arm moves in
> jerks. The vendor says the controller answers every command in under a millisecond; their
> protocol document is examples/investigations/robot-arm/PROTOCOL.md. The controller is running
> on port 7700. Capture the traffic while the app runs and find out why.

As in the demo above, the agent:

1. starts a capture on `lo` with `start_capture`, runs the app and stops the capture;
2. finds the controller's protocol undecoded, writes a Lua dissector from the vendor's document,
   tests it on the capture and reloads the view;
3. adds a time-delta column, finds where every command loses its time and marks an example;
4. writes a panel that plots the arm's joints and each command's latency;
5. names the cause, fixes the app and captures again to show the fix.

The example's [README](examples/investigations/robot-arm/README.md) has the setup and, at its
end, the solution; `solution/armc` is a dissector and a panel as the agent might write them. The
commands there assume a clone of the repository; the npm package has the examples too, in
`$(npm root -g)/wirebuddy/examples` after a global install.

### Example: a CT archive that loses slices

[`examples/investigations/ct-archive`](examples/investigations/ct-archive) is a second one, from
radiology: an emulated image archive and the reconstruction server's exporter that sends it the CT
images of a head phantom over DICOM. The exporter gets Success for all 184 images, yet the archive
holds only 100 of the 160 images of the thin-slice series, and the archive team says it keeps what
it receives.

> Radiologists say our new 0.625 mm thin-slice head series show up in the archive with only about
> 100 of 160 images, and the reformats have steps; the 5 mm series from the same scan are complete.
> Our reconstruction server's exporter, examples/investigations/ct-archive/app.mjs, logs every image
> as stored with status Success. The archive vendor's conformance statement is
> examples/investigations/ct-archive/CONFORMANCE.md. The archive is running on port 11112. Capture
> an export and find out where the slices go.

The agent:

1. captures on `lo` while the exporter runs;
2. finds the DICOM decoded by Wireshark itself: 184 C-STOREs, each answered with Success;
3. lists the images with `export_objects` and finds 184 of them with only 124 SOP Instance UIDs;
4. marks the pairs of slices that share a UID and may write a panel that shows the series as sent
   and as the archive keeps it;
5. names the cause, fixes the exporter and, with the archive restarted, captures again: 184 UIDs,
   and the archive keeps all 160.

The example's [README](examples/investigations/ct-archive/README.md) has the setup and the
solution; `solution/ctseries` is the panel.

### MCP tools

| Tool | What it does |
|---|---|
| `viewer_url` | URL of the UI to show in the browser pane |
| `get_view_state` | What the user sees: file, counts, filter, selected frame and selected packets, marks, time references, edited packet comments, capture status, open and offered panels |
| `open_capture` | Open a capture file in the viewer |
| `capture_summary` | Protocol hierarchy, top conversations, expert info counts |
| `query_packets` | Paginated rows for any display filter, or exact field values per packet with `fields` (like `tshark -T fields`) |
| `inspect_frame` | Protocol tree of one frame as compact text, optionally limited to protocols, with hex |
| `follow_stream` | Reassembled stream payload as text |
| `expert_info` | Expert Information grouped by severity and message, with example frames |
| `io_graph` | Packets/bytes/bits over time for up to 4 filters: peaks, empty stretches, a downsampled series |
| `export_packets` | Write matching, displayed, marked, selected or ranged packets to a new capture file, with their packet comments as edited and marks as comments (pcapng) |
| `export_objects` | List the files carried in the traffic (HTTP, email, SMB, TFTP, DICOM, FTP), or save them to a new folder |
| `check_display_filter` | Validate a filter; hints when capture-filter (BPF) syntax was used |
| `set_display_filter` | Apply a filter in the user's view |
| `goto_frame` | Select and scroll to a frame |
| `mark_frames` / `clear_marks` | Highlight frames with a note (listed under Go → Marked Packets) |
| `time_references` | Set or unset time references (`*REF*`), which the Time column counts from, or clear them |
| `packet_comments` | Add, replace or delete packet comments in the user's view (kept by exports to pcapng) |
| `set_columns` | Show fields as extra columns in the user's packet list |
| `list_interfaces` | Capture interfaces with their current traffic (read-only) |
| `start_capture` | Start a live capture with the Capture Options settings; the view follows it |
| `stop_capture` | Stop the running capture |
| `open_in_wireshark` | Open the capture in the real Wireshark at the selected frame |
| `extensions` | Lua dissector extensions and panels: a guide with templates, list, test one on the open capture, reload, enable, disable |
| `panel` | Open, reload, check on, snapshot or close an extension's panel in the user's view |

Every agent action that changes the view shows a notice in the UI. Every tool result also
carries what happened in the viewer since the agent's last call: problems, what you did and
the questions you asked it.

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
- Once such a re-read takes a second or more, the packets that arrived since are listed within
  about a second anyway, in italics, until the next re-read replaces them: two more `sharkd` read
  them from slices of the file (about 64 MiB at most) that also hold the packets before them, the
  start of their connections, the messages under way and the answers still owed, so they nearly
  always read as the full read will. Display filters on stream indices, TCP conversation
  completeness or frame numbers, statistics, Follow Stream, Find and the agent's queries wait for
  the full read. When another full read would need more memory than is free, full reads wait
  until the capture stops, and a reload reads the file in place of the copy there is.
- The packet list is virtualized and pages rows from `sharkd`, so large captures stay smooth.

## Security

- **The session token is the only boundary.** Anyone or anything holding the viewer URL with its
  token can do everything you can in the UI, starting a capture included. That covers an AI agent
  that also has a shell or controls the browser pane: give WireBuddy only to agents you trust,
  and don't share the URL.
- The server listens on `127.0.0.1` only. API calls need the random per-session token in an
  `X-WireBuddy-Token` header (the WebSocket takes it in its URL); it is compared in constant time.
- Requests with a foreign `Host` (DNS rebinding), any `Origin` but the server's own (`null`
  included) or a body that isn't JSON are refused. The page has a Content Security Policy.
- The MCP tools can start and stop captures on the interfaces `dumpcap` may capture on, always
  into WireBuddy's capture folder. They can open any capture file you can read, read packets,
  change the filter, marks, time references, packet comments, selection and columns, open Wireshark, and write new
  `.pcap`/`.pcapng` exports where you can write; an existing file is never replaced unless the
  agent exported it itself in the same session.
- File › Export Objects and `export_objects` save files from the traffic, whose names and
  contents a sender chose, only into a new folder they create (`http-objects`, `http-objects-2`,
  …) in a directory you or the agent name, under names of their own (`f12-report.pdf`). No other
  user may be able to change that folder or any folder above it: `/tmp` works, and so do your
  own folders unless one of them is writable by others; network and FUSE filesystems are
  refused. It is never a hidden folder such as `~/.config`, nor one Wireshark or WireBuddy loads
  code or configuration from. It never replaces or follows an existing file. The dialog shows
  names, hosts and types from the capture as plain text, and the agent hears only the folder a
  save went to.
- Text from a capture can't pose as WireBuddy's own messages to the agent: every event is one
  line, the real events block carries a random tag the agent learns at startup, and followed
  stream payload lines start with `| `.
- Open only accepts files whose content is a capture (pcap, pcapng, snoop, Network Monitor; also
  gzip- or zstd-compressed), whatever their name, so it can't be used to read other files.
- Live captures, exports and saved objects are readable only by you (files `0600`, folders
  `0700`), and so are the slices of big live captures, written to a hidden folder next to the
  capture and removed once it is read in full.
- Extensions are Lua code that runs as you inside `sharkd` and the Wireshark WireBuddy opens. The
  MCP tools can test, reload and switch extensions, not write them: an agent writes them with its
  own file tools, so it needs file access anyway. Extensions another user could have changed are
  not loaded.
- The traffic sparklines and `list_interfaces` only read per-interface packet counters
  (`dumpcap -S`), never packet contents; that sampler runs only while something shows it.

## Tests

```bash
npm run build
npm test               # unit checks, the capture file reader, live slices against full reads, the HTTP API, MCP tools and panels
npm run test:browser   # panels and the examples in headless Chrome (skipped without Chrome)
npm run test:examples  # the investigations' bugs and their fixes, over loopback without a capture
npm run test:package   # the npm package installed as users get it, run over MCP
npm run test:live      # live captures on loopback: pings, a local HTTPS server, the investigations; then big generated ones, followed in headless Chrome
```

The tests run their servers with an empty home folder, so your own Wireshark preferences and
plugins don't change the results. The capture checks in `npm test` need `dumpcap` permissions
(see Requirements) and are skipped without them; `npm run test:live` needs them.

## Limitations

- In a big live capture the newest packets stay provisional until the next full read of the file,
  which takes longer the bigger the file gets (about 10 s at a million packets, more with a
  display filter). A ring buffer or a capture filter keeps files small. Provisional packets of a
  TLS connection that carried more than a few requests before (HTTP/2, keep-alive) can't be
  decrypted. Ones of a message that began more than about 16 MiB before them, or that more than
  three requests were pipelined into, read as plain TCP segments, and ones of a message that ends
  more than about 8 MiB after them don't say where it is reassembled (less when many connections
  are busy at once).
- A time reference the display filter hides stays hidden, while Wireshark lists time references
  whatever the filter; the packets after it count from it all the same, and Next/Previous Time
  Reference go to it. "Open in Wireshark" doesn't take the time references along.
- Display filters on `frame.time_relative` (also Apply as Filter on "Time since reference") count
  from the first packet, not from the time references. In a filter, `frame.ref_time` stands for
  the references' frame numbers: it works only as a test of its own, not inside a function or
  with `#` or `@`, and for a few hundred scattered references at most (about 4 KB of numbers).
- Packet comments added, edited or deleted in the viewer stay there until the capture is closed
  or another one opened, also when a live capture goes on in a new file (ring buffer, new file
  after …; WireBuddy says when that discards edits); only an export to pcapng (File › Save As)
  keeps them, and "Open in Wireshark" opens the file without them. Display filters on
  `frame.comment`, Expert Information and the agent's `query_packets` fields read the comments in
  the file: edits reach them once exported and that file opened.
- In the Wireshark window that "Open in Wireshark" starts, the interface list stays empty until
  Capture → Refresh Interfaces (F5): Wireshark skips the scan when it starts with a file.

## Contributing

Issues and pull requests are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). Please report
security problems privately as described in [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) © 2026 Michael Haar

Wireshark and the "fin" logo are registered trademarks of the Wireshark Foundation. WireBuddy is
an independent project and is not affiliated with or endorsed by the Wireshark Foundation.
