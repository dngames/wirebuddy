# Open items

What is known to be wrong, missing or untested in WireBuddy, kept current as items are fixed or found.
Most of it comes from two investigations played through the tool in November 2026 by an agent on the MCP
tools and a human in the page, neither knowing the cause: a shop kiosk with two faults in traffic Wireshark
decodes ("case 1"), and a brewery's tank controller that speaks a protocol Wireshark does not decode
("case 2"). "Replay" is the re-check of case 1's fixes in the page.

What the two cases showed about WireBuddy's use: an agent working alone finds the cause just as well with
`sharkd`, and faster; the difference is the human, who with `sharkd` alone has nothing to look at, and with
WireBuddy reads the decoded packets, follows the agent's marks and filters live, and gets an answer in the page.

Legend: **fix** wrong or misleading today · **gap** missing · **polish** small. Numbers stay with their
items, so a gap in the numbering is an item that is done (section E).

## A. To fix or build, from real use

| # | Kind | Item | Where it came from |
|---|---|---|---|
| A1 | gap | No time display format (seconds since previous packet and the like); the human had to know the field and Apply as Column | case 1 |
| A2 | gap | Decode As takes free text only: no list of protocols to pick from | case 1 |
| A3 | gap | The exported capture renumbers packets, so a report's packet numbers don't match it; the original number is not carried along | case 1 |
| A4 | fix | The agent's `set_columns` replaces the human's own columns | case 1 |
| A5 | polish | The agent's notice "the user changed the custom columns" doesn't say to what; Follow, Find, I/O graph and a cancelled Decode As are not reported to the agent at all | case 1 |
| A6 | fix | The details pane says "[Frame is marked: False]" for a packet the viewer shows as marked (Wireshark's own field; the new "Marked…" first line sits right above it) | case 1 |
| A7 | polish | Time values cut with "…" in the default column width once a time reference exists | case 1 |
| A8 | polish | `get_view_state` repeats a long paragraph on time references in every call, and shows the last capture's line ("Capture … last file") as if it described the open file | case 1 |
| A9 | fix | The agent's banner stays up long after the event ("Started a capture on lo…" still there 41 s later, mid-capture) | replay |
| A10 | gap | Follow Stream shows no timestamps, so a 5 s wait inside a conversation is invisible there | case 1 |
| A11 | polish | Findings report: lists the current display filter as a fact of the capture; a time reference appears only as a packet number; covers only the open capture | case 1 |
| A12 | polish | Analyze › Apply as Column is greyed out until a field is selected, with no hint why | case 1 |
| A14 | gap | An open question stays "waiting" for good when the agent detaches; a question's packet can't be selected from the list once another capture is open | mark notes / answers |
| A15 | gap | "Mark Packet with Note…" has no keyboard shortcut (the Ctrl+M family is taken) | mark notes / answers |
| A16 | fix | A menu title clicked within 300 ms of its menu closing is swallowed | mark notes / answers (seen while testing) |
| A17 | polish | `frame.comment` finds nothing for comments edited in the viewer (the Now comments too) until export; `get_view_state` says why, the page does not | replay |
| A18 | polish | A user capture filter with `vlan` shifts the offsets of what follows it, the own-traffic exclusion included (irrelevant on `lo` and `any`, noted for completeness) | fixes for case 1 |
| A19 | fix | A crash report from the active engine while the standby loads makes that load retry once more than needed | engine session work |

| A24 | gap | A panel floats over the packet list and hides the columns the filter was set up to show; it can be maximized or closed, not docked | case 2 |
| A28 | gap | The findings report leaves out the questions and answers of the session (and still covers only the open capture, see A11) | case 2 |
| A29 | gap | Nothing in the page tells the human that the agent has seen a question or is working on it; the agent hears a question only with its next tool call unless it runs the background watcher | case 2 |
| A30 | polish | The details pane is cramped while the answer banner is open, though the bytes pane below has room to spare (dragging the splitter was not tried) | case 2 |
| A31 | polish | A reopened capture's panel briefly showed "0 samples" (a race on reset; not looked into) | case 2 |
| A32 | polish | In a browser that can't isolate a panel, the warning about it is counted as "1 problem sent to Agent" in the status bar | case 2 |

## B. Not exercised yet (what the tests did not do)

| # | What | Status |
|---|---|---|
| B1 | A protocol Wireshark does not decode: the agent writing a dissector (extensions), a panel | **done in case 2** |
| B2 | Decode As on traffic that really needs it (case 1's odd ports were decoded by Wireshark's heuristics; it was only tried on plain-text metrics; case 2 did not need it) | open |
| B3 | Now button: hold to flag a span (only the tap was tried) | open |
| B4 | The background watcher (`--watch`), so the agent reacts while the human works | open |
| B5 | TLS decryption with a key log file | open |
| B6 | A live capture too big to re-read every second (the provisional newest rows) | open |
| B7 | Export Objects, ring-buffer captures, a capture on `any` with another host's traffic on WireBuddy's port | open |
| B8 | A baseline agent with `tshark` (the realistic rival; not installed here, the comparison used `sharkd`) | open |
| B9 | macOS by hand (only CI on a hosted runner), Windows at all | open |
| B10 | The mark notes and the answers in the page in a real investigation (built after case 1) | **done in case 2** |
| B11 | Marks, comments, questions and the extension after a restart of WireBuddy itself (both cases only closed and reopened the capture) | open |
| B12 | Open in Wireshark, and the page's own Expert Information and I/O Graphs with a custom protocol | open |
| B13 | An agent that does not know Wireshark's Lua API writing the dissector from the guide alone (case 2's agent knew it); the guide has a TCP template now, unproven in real use | open |

## C. Our own checks

| # | Item |
|---|---|
| C1 | `api-smoke` "export objects: listed without tokens…" fails when the repository is not writable by the user running the tests |
| C2 | `browser-control`: three Set/Unset Time Reference checks fail locally as an ordinary user (they pass in CI); cause not looked into |
| C3 | `browser-control`: Write Findings Report, two Export Objects checks and "Now in a live capture" fail now and then under load |
| C4 | Two macOS browser checks time out now and then (from before) |
| C5 | Run as root, the suites lose Lua (Wireshark loads no Lua plugins for root) and fail in every check that needs an extension or Decode As: run them as an ordinary user |

## D. Waiting on a decision

| # | Item | Recommendation |
|---|---|---|
| D1 | The live tail's future (fifth piece of the `viewer.ts` work depends on it) | keep it frozen, ask Wireshark upstream |
| D3 | Dependabot pull requests 8 and 9 (9 needs a fresh CI run) | — |
| D4 | Required reviewers on the `npm` environment, as a gate before publishing | — |

## E. Done from real use (for reference)

Own traffic left out of loopback captures · the root/Lua message · the agent's mark names the user mark it
replaced · a mark is the first line of the details, notes in full in Go › Marked Packets · a `frame.number`
filter cleared when another capture opens, restored marks hidden by the filter are counted · `expert_info`
counts as the dialog does · refused writes name the user · hint for a set without commas (all PR 21, on main).
A note on the human's own mark · questions and answers in the page (`answer_question`) (PR 22, on main).
From case 2: a template for a protocol over TCP in the extension guide, proven on batched and split messages
(A20) · the guide on fields with several values in a packet (A21) · a panel's read after its capture closed
is no longer a problem reported to the agent, and the guide says what a panel sees then (A22) · the panel
guide on following a live capture (A23) · a new display filter shows the selected packet or the top, not the
end (A25) · the extension test says what stayed undecoded (A26) · the README's name for the questions dialog
(A27) · the capture folder's refused creation names the user (A13).
Released as 0.17.0 (tag `v0.17.0`), with everything above.
