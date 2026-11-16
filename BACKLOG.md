# Backlog

The one list of open work. Not in this file means not open. One block per item: a `### ` title line, then
`key: value` lines.

First sweep, 2026-11-15, from docs/open-items.md (sections A to D), the owner's points of that day, the
code notes and the branches. Old ids of open-items.md (A7, B2, ...) are kept in the text for tracing.

### Decode As takes free text only, no list of protocols to pick from
id: B-001
area: page/dialogs
kind: wish
state: not-started
when: 2026-11-13, 2026-11-15
what: [open-items A2] Decode As takes free text only: no list of protocols to pick from. Next step: decide the shape of the picker.
evidence: docs/open-items.md section A, A2; came from: case 1

### Exported capture renumbers packets; report numbers do not match it
id: B-002
area: export
kind: wish
state: not-started
when: 2026-11-13, 2026-11-15
what: [open-items A3] The exported capture renumbers packets, so a report's packet numbers do not match it; the original number is not carried along.
evidence: docs/open-items.md section A, A3; came from: case 1

### The agent's set_columns replaces the human's own columns
id: B-003
area: agent/tools
kind: bug
state: not-started
when: 2026-11-13, 2026-11-15
what: [open-items A4] The agent's set_columns replaces the human's own columns.
evidence: docs/open-items.md section A, A4; came from: case 1

### Agent notice on changed columns says nothing of what; Follow, Find, I/O graph not reported
id: B-004
area: agent/tools
kind: wish
state: not-started
when: 2026-11-13, 2026-11-15
what: [open-items A5] The agent's notice 'the user changed the custom columns' does not say to what; Follow, Find, I/O graph and a cancelled Decode As are not reported to the agent at all.
evidence: docs/open-items.md section A, A5; came from: case 1

### Details pane says '[Frame is marked: False]' for a packet the viewer shows as marked
id: B-005
area: page/list
kind: bug
state: not-started
when: 2026-11-13, 2026-11-15
what: [open-items A6] The details pane says '[Frame is marked: False]' for a packet the viewer shows as marked (Wireshark's own field; the new 'Marked...' first line sits right above it).
evidence: docs/open-items.md section A, A6; came from: case 1

### Time values cut with an ellipsis in the default column width once a time reference exists
id: B-006
area: page/list
kind: wish
state: not-started
when: 2026-11-13, 2026-11-15
what: [open-items A7] Time values are cut with '...' in the default column width once a time reference exists.
evidence: docs/open-items.md section A, A7; came from: case 1

### get_view_state repeats a long time-reference paragraph and shows the last capture's line as current
id: B-007
area: agent/tools
kind: wish
state: not-started
when: 2026-11-13, 2026-11-15
what: [open-items A8] get_view_state repeats a long paragraph on time references in every call, and shows the last capture's line ('Capture ... last file') as if it described the open file.
evidence: docs/open-items.md section A, A8; came from: case 1

### The agent's banner stays up long after the event
id: B-008
area: page/questions
kind: bug
state: not-started
when: 2026-11-13, 2026-11-15
what: [open-items A9] The agent's banner stays up long after the event ('Started a capture on lo...' still there 41 s later, mid-capture).
evidence: docs/open-items.md section A, A9; came from: replay

### Follow Stream shows no timestamps
id: B-009
area: page/dialogs
kind: wish
state: not-started
when: 2026-11-13, 2026-11-15
what: [open-items A10] Follow Stream shows no timestamps, so a 5 s wait inside a conversation is invisible there.
evidence: docs/open-items.md section A, A10; came from: case 1

### Findings report: shows the display filter as a capture fact, time reference as a number only
id: B-010
area: findings
kind: wish
state: not-started
when: 2026-11-13, 2026-11-15
what: [open-items A11] Findings report: lists the current display filter as a fact of the capture; a time reference appears only as a packet number; covers only the open capture.
evidence: docs/open-items.md section A, A11; came from: case 1

### Analyze > Apply as Column is greyed out until a field is selected, with no hint why
id: B-011
area: page/list
kind: wish
state: not-started
when: 2026-11-13, 2026-11-15
what: [open-items A12] Analyze > Apply as Column is greyed out until a field is selected, with no hint why.
evidence: docs/open-items.md section A, A12; came from: case 1

### An open question stays waiting when the agent detaches; its packet cannot be selected later
id: B-012
area: page/questions
kind: wish
state: not-started
when: 2026-11-13, 2026-11-15
what: [open-items A14] An open question stays 'waiting' for good when the agent detaches; a question's packet cannot be selected from the list once another capture is open.
evidence: docs/open-items.md section A, A14; came from: mark notes / answers work

### Mark Packet with Note... has no keyboard shortcut
id: B-013
area: page/list
kind: wish
state: not-started
when: 2026-11-13, 2026-11-15
what: [open-items A15] 'Mark Packet with Note...' has no keyboard shortcut (the Ctrl+M family is taken).
evidence: docs/open-items.md section A, A15; came from: mark notes / answers work

### A menu title clicked within 300 ms of its menu closing is swallowed
id: B-014
area: page/list
kind: bug
state: not-started
when: 2026-11-13, 2026-11-15
what: [open-items A16] A menu title clicked within 300 ms of its menu closing is swallowed.
evidence: docs/open-items.md section A, A16; came from: mark notes / answers work (seen while testing)

### frame.comment finds nothing for comments edited in the viewer until export
id: B-015
area: page/list
kind: wish
state: not-started
when: 2026-11-13, 2026-11-15
what: [open-items A17] `frame.comment` finds nothing for comments edited in the viewer (the Now comments too) until export; get_view_state says why, the page does not.
evidence: docs/open-items.md section A, A17; came from: replay

### A user capture filter with vlan shifts the offsets of what follows it
id: B-016
area: capture/live
kind: idea-later
state: not-started
when: 2026-11-13, 2026-11-15
what: [open-items A18] A user capture filter with `vlan` shifts the offsets of what follows it, the own-traffic exclusion included (irrelevant on lo and any, noted for completeness).
evidence: docs/open-items.md section A, A18; came from: fixes for case 1

### A crash report from the active engine while the standby loads causes one retry too many
id: B-017
area: capture/live
kind: bug
state: not-started
when: 2026-11-13, 2026-11-15
what: [open-items A19] A crash report from the active engine while the standby loads makes that load retry once more than needed.
evidence: docs/open-items.md section A, A19; came from: engine session work

### Details pane is cramped while the answer banner is open
id: B-018
area: page/questions
kind: wish
state: not-started
when: 2026-11-13, 2026-11-15
what: [open-items A30] The details pane is cramped while the answer banner is open, though the bytes pane below has room to spare (dragging the splitter was not tried).
evidence: docs/open-items.md section A, A30; came from: case 2

### A reopened capture's panel briefly showed '0 samples'
id: B-019
area: page/panels
kind: bug
state: not-started
when: 2026-11-13, 2026-11-15
what: [open-items A31] A reopened capture's panel briefly showed '0 samples' (a race on reset; not looked into).
evidence: docs/open-items.md section A, A31; came from: case 2

### Panel isolation warning is counted as '1 problem sent to Agent' in the status bar
id: B-020
area: page/panels
kind: wish
state: not-started
when: 2026-11-13, 2026-11-15
what: [open-items A32] In a browser that cannot isolate a panel, the warning about it is counted as '1 problem sent to Agent' in the status bar.
evidence: docs/open-items.md section A, A32; came from: case 2

### Server instructions' watcher command names a state file from before the restart (unconfirmed)
id: B-021
area: agent/tools
kind: bug
state: unsure
when: 2026-11-13, 2026-11-15
what: [open-items A35] Checked in the round 3 fixes: WireBuddy writes the live process's file into the instructions of each start, so a client that initializes again after a restart gets the right path; the tester's bridge kept the first initialize result. Not changed. Whether anything is left to fix is not settled.
evidence: docs/open-items.md section A, A35; came from: round 3

### Now: little feedback when held, stale banner, counter mismatch in a flood, 409s in the console
id: B-022
area: capture/live
kind: wish
state: not-started
when: 2026-11-13, 2026-11-15
what: [open-items A41] Holding Now gives no feedback but a red outline; the old 'answered' banner sits under a new waiting line; the capture's packet counter and the list's count disagree during a flood; 409s in the browser console at a filter change and at stop (no visible effect). Four small faults in one item.
evidence: docs/open-items.md section A, A41; came from: round 3

### Extension guide lacks the Lua version, checksums and the buffer methods
id: B-023
area: extensions
kind: wish
state: not-started
when: 2026-11-13, 2026-11-15
what: [open-items A43] The extension guide does not say which Lua version runs, has no word on checksums (a CRC-16 in pure Lua), and does not list the buffer methods.
evidence: docs/open-items.md section A, A43; came from: guide-only run

### With several packets selected, dialogs are refused when the list changes under them
id: B-024
area: page/dialogs
kind: wish
state: not-started
when: 2026-11-13, 2026-11-15
what: [open-items A45] With several packets selected, Add Comment, Mark with Note and Ask Agent are still refused when the list changes under the dialog (the text stays, with the reason).
evidence: docs/open-items.md section A, A45; came from: round 3 fixes

### Not exercised: Export Objects, ring-buffer captures, capture on any with foreign traffic
id: B-025
area: capture/live
kind: task
state: not-started
when: 2026-11-13, 2026-11-15
what: [open-items B7] Export Objects, ring-buffer captures and a capture on `any` with another host's traffic on WireBuddy's port were not exercised in the case work. Next step: a run that does them (some are covered by the live suites; which is not checked here).
evidence: docs/open-items.md section B, B7; not exercised yet

### Not exercised: a baseline agent with tshark as the realistic rival
id: B-026
area: docs
kind: task
state: not-started
when: 2026-11-13, 2026-11-15
what: [open-items B8] The comparison used sharkd; tshark was not installed on the machine. Next step: install tshark and repeat the comparison, or drop the claim.
evidence: docs/open-items.md section B, B8; not exercised yet

### Not exercised: macOS by hand (CI only)
id: B-027
area: platform/macos
kind: task
state: not-started
when: 2026-11-13, 2026-11-15
what: [open-items B9] macOS is verified only in CI on a hosted runner, never by hand. Windows is the point of a separate item (see the Windows items).
evidence: docs/open-items.md section B, B9; not exercised yet

### Not exercised: Open in Wireshark, and Expert Information and I/O Graphs with a custom protocol
id: B-028
area: extensions
kind: task
state: not-started
when: 2026-11-13, 2026-11-15
what: [open-items B12] Open in Wireshark, and the page's own Expert Information and I/O Graphs with a custom protocol, were not played.
evidence: docs/open-items.md section B, B12; not exercised yet

### api-smoke 'export objects: listed without tokens' fails in a folder the user cannot write
id: B-029
area: tests/local
kind: bug
state: not-started
when: 2026-11-13, 2026-11-15
what: [open-items C1] test/api-smoke.mjs 'export objects: listed without tokens...' fails when the repository is not writable by the user running the tests.
evidence: docs/open-items.md section C, C1

### Three browser-control Set/Unset Time Reference checks fail on a short local window
id: B-030
area: tests/browser
kind: bug
state: not-started
when: 2026-11-13, 2026-11-15
what: [open-items C2] Three Set/Unset Time Reference checks of test/browser-control.mjs fail locally as an ordinary user and pass in CI. Known on 2026-11-15: they fail on a short local window (innerHeight 677), where the details row they click is not drawn. Not fixed: next step is to make the checks scroll the row into view or size the window, without loosening what they assert.
evidence: docs/open-items.md section C, C2; owner's point (d) of 2026-11-15; test/browser-control.mjs line 637 and following

### Two macOS browser checks time out now and then
id: B-031
area: tests/browser
kind: bug
state: unsure
when: 2026-11-13, 2026-11-15
what: [open-items C4] Two macOS browser checks time out now and then (from before); which two is not recorded. Seen on the CI macOS runner; the macOS workflow is a probe, not a gate.
evidence: docs/open-items.md section C, C4

### Suites run as root lose Lua and fail every check that needs an extension or Decode As
id: B-032
area: tests/local
kind: idea-later
state: held
when: 2026-11-13, 2026-11-15
what: [open-items C5] Run as root, the suites lose Lua (Wireshark loads no Lua plugins for root) and fail in every check that needs an extension or Decode As. Known and documented: run them as an ordinary user (AGENTS.md says so). Possible next step, not decided: a suite could stop early with a plain message when it runs as root.
evidence: docs/open-items.md section C, C5

### The live tail's future: freeze it or build its control (fifth piece of the viewer.ts split)
id: B-033
area: capture/tail
kind: question-for-owner
state: waiting-owner
when: 2026-11-13, 2026-11-15
what: [open-items D1] The fifth piece of the viewer.ts split (live tail control) depends on what happens to the live tail. Waiting for the owner's decision.
evidence: docs/open-items.md section D, D1; owner's point (i) of 2026-11-15
options: keep it frozen, ask Wireshark upstream | build live tail control as the fifth piece of the viewer.ts split
recommend: keep it frozen, ask Wireshark upstream

### Dependabot pull requests 8 and 9 are open and not looked at
id: B-034
area: ci
kind: question-for-owner
state: unsure
when: 2026-11-13, 2026-11-15
what: [open-items D3] Pull requests 8 and 9 are open; 9 needs a fresh CI run. Not looked at, and not visible from the working environment, so what they change and whether they pass is unknown. Four dependabot branches exist on origin (hono 4.13.18, hono/node-server 2.1.8, types/node 26.6.6, ws 8.22.1); which two are 8 and 9 was not checked.
evidence: docs/open-items.md section D, D3; owner's point (f) of 2026-11-15; origin/dependabot/npm_and_yarn/* branches
options: merge after a green CI run | close | leave open for now

### Required reviewers on the npm environment as a gate before publishing
id: B-035
area: release
kind: question-for-owner
state: waiting-owner
when: 2026-11-13, 2026-11-15
what: [open-items D4] release.yml's publish job runs in the environment npm; the owner can require an approval there (Settings > Environments > npm > required reviewers); npm's trusted-publisher entry must name the same environment, if it names one. Waiting for the owner's choice.
evidence: docs/open-items.md section D, D4; owner's point (j) of 2026-11-15; .github/workflows/release.yml (comment above the publish job)
options: require reviewers on the npm environment | publish without a reviewer gate

### Five dialogs show request errors in the dialog body, not the footer line
id: B-036
area: page/dialogs
kind: bug
state: not-started
when: 2026-11-15, 2026-11-15
what: Objects, Capture Options, Go to, Extensions and Open File still show an error a request brings back in the dialog body; the other seven dialogs show it in the footer's free left side (two lines at most, whole text in the tooltip) since 0.19.0. Make the five do the same.
evidence: src/web/dialogs/objects.ts, capopts.ts, goto.ts, extensions.ts, openfile.ts; CHANGELOG 0.19.0; test/browser-control.mjs 'an error a request brings back sits in the footer's free side' (covers the seven)

### Time references ignored and no *REF* in the Time column's non-default formats, unlike Wireshark
id: B-037
area: page/list
kind: wish
state: not-started
when: 2026-11-15, 2026-11-15
what: Time references count only for the default Time display format; in the other formats they are ignored and no *REF* shows, where Wireshark shows it. README Limitations says so. Next step: decide with the owner whether to match Wireshark, then change the formats.
evidence: README.md Limitations (The Time column's other display formats); CHANGELOG 0.19.0 (Time Display Format)

### browser-control: 'Decode As ... the status bar lists the entries' failed once in five CI-size runs
id: B-038
area: tests/browser
kind: bug
state: not-started
when: 2026-11-15, 2026-11-15
what: The check 'browser: Decode As in a packet's menu decodes its port; the status bar lists the entries and removes them' failed once in five runs at CI window size: the status bar segment was empty when read. Cause not looked into (test timing or a page race are both open).
evidence: test/browser-control.mjs line 1145; one failure in five runs, no report id

### macOS probe workflow not run for the changes of 0.19.0
id: B-039
area: platform/macos
kind: task
state: not-started
when: 2026-11-15, 2026-11-15
what: macos.yml (workflow_dispatch only) was not run for 0.19.0. macOS stays verified in CI only; one probe per change, by hand-start, on the owner's word or the orchestrator's plan.
evidence: .github/workflows/macos.yml; decision 5 of 2026-11-15 (one macOS probe per change)

### Cloud environment's saved setup script never proven on a fresh container
id: B-040
area: process
kind: task
state: not-started
when: 2026-11-15, 2026-11-15
what: The saved setup script of the cloud environment (installs Wireshark 4.6 from the PPA, makes the user wb) was never run on a fresh container. Next step: start a fresh container and check Wireshark 4.6, the user wb and one smoke suite as wb.
evidence: the cloud environment's setup script (not in the repository)

### Windows becomes a target and has never been run
id: B-041
area: platform/windows
kind: task
state: not-started
when: 2026-11-15, 2026-11-15
owner-words: "Linux, Wireshark 4.6 + new: Windows (I can set up a local session  a windows machine!)"
what: Windows has never been run. README says it is untested and that no extension folder is looked into there, so no extensions, panels or Decode As. Next steps: bring it up through a session on the owner's Windows machine (task queue item), find what starts and what does not, then write down what Windows is to support.
evidence: README.md Requirements and SECURITY.md (Windows: no extension folder is looked into); decision 1 of 2026-11-15

### Task queue for the owner's Windows machine (tasks/windows.md)
id: B-042
area: platform/windows
kind: task
state: not-started
when: 2026-11-15, 2026-11-15
what: Write tasks/windows.md on the status branch: numbered tasks with commit, exact commands, expected duration and what to return (install Node 22 and Wireshark 4.6, npm ci, build, typecheck, npm test, what starts). Results come back on evidence/windows/<task>/ with a REPORT.md. The owner sets up the polling session. Waiting for the owner's session before anything can run.
evidence: decision 1 of 2026-11-15

### GitHub release pages are not created by the release workflow
id: B-043
area: release
kind: wish
state: not-started
when: 2026-11-15, 2026-11-15
what: release.yml publishes to npm only; no GitHub release page is made for a tag. Decide whether it should (needs contents: write for that step) or whether the owner writes the page by hand.
evidence: .github/workflows/release.yml (jobs check-tag, test, publish)

### Three old local branches (macos-live-capture, macos-trust-checks, panel-isolation) not checked
id: B-044
area: process
kind: task
state: unsure
when: 2026-11-15, 2026-11-15
what: Local branches claude/macos-live-capture, claude/macos-trust-checks and claude/panel-isolation (last commits 2026-11-11) differ from origin/main by about 10,000 lines each, as branches from before later squash merges do. Probably merged already; not checked. Next step: confirm each by its changes in main, then delete or keep.
evidence: git branch -a; git diff --stat origin/main <branch>

### live-tail: two short-of-memory checks failed under heavy machine load, not checked on main
id: B-046
area: tests/live
kind: question
state: not-started
when: 2026-11-16, 2026-11-16
what: During the three loaded runs for B-045 (6 busy loops on 4 cores, load about 12), the checks 'short of memory: full reads wait...' and 'a final read in place killed for memory...' failed in two of three runs. They pass unloaded and in CI. Unknown whether main behaves the same under that load. Next step: run the suite on main under the same load, three times.
evidence: implementer report of 2026-11-16 on branch fix/live-tail-time-format-check; CI run https://github.com/dngames/wirebuddy/actions/runs/43784916052 green
