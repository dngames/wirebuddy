# Requirements

**DRAFT, 2026-11-15.** First draft of the standing rules, made from the README, SECURITY.md, CONTRIBUTING.md,
the pull request template and the owner's decisions. Nothing here has been confirmed by the owner. A rule is
`holds` only where a named check proves it today; everything else is `unverified`.

The standing rules the product must satisfy. One rule per block: a `### ` title line, then `key: value` lines.

### The server listens on the loopback addresses only (127.0.0.1, and ::1 where there is one)
id: R-SEC-01
area: security
tags: security,network
applies-to: server
source: README Security; SECURITY.md Security model
why: So no other machine and no other program can answer for the page.
checked-by: test test/units.mjs (check "loopback: one port on every address")
status: holds

### An API request without the session token is rejected
id: R-SEC-02
area: security
tags: security
applies-to: server HTTP API
source: README Security; SECURITY.md Security model
why: The token is the only boundary.
checked-by: test test/api-smoke.mjs (check "rejects requests without token")
status: holds

### A request with a foreign Host header is rejected
id: R-SEC-03
area: security
tags: security
applies-to: server HTTP API
source: README Security; SECURITY.md
why: Stops DNS rebinding.
checked-by: test test/api-smoke.mjs (check "rejects foreign Host header")
status: holds

### A request with any Origin but the server's own (null included) or a non-JSON body is rejected
id: R-SEC-04
area: security
tags: security
applies-to: server HTTP API and WebSocket
source: README Security; SECURITY.md
why: Stops other pages from driving the API.
checked-by: test test/api-smoke.mjs (check "security: origin null, token in the URL, non-JSON posts, big bodies, bad WebSocket frames")
status: holds

### The kept session token is readable by its user alone and a token given on the command line is never kept
id: R-SEC-06
area: security
tags: security
applies-to: server start, state/token file
source: SECURITY.md (The token is kept between starts)
why: A kept token is a secret at rest.
checked-by: test test/units.mjs (check "session token: the one used last is kept for the user alone and reused")
status: holds

### The UI is served with a Content Security Policy, nosniff and Referrer-Policy: no-referrer
id: R-SEC-07
area: security
tags: security
applies-to: server HTTP
source: SECURITY.md Security model
why: Browser-side defence in depth.
vague: test/panels-smoke.mjs asserts x-content-type-options only for panel documents; nothing asserts the main page's CSP or Referrer-Policy headers
checked-by: none
status: unverified

### Packet contents are always rendered as text, never as HTML
id: R-SEC-08
area: security
tags: security,ui
applies-to: web UI
source: README Contributing guidelines; SECURITY.md
why: A crafted capture must not run script in the UI.
vague: no check feeds hostile packet text to the page and looks at the DOM
checked-by: none
status: unverified

### Open accepts only files whose content is a capture, whatever the name
id: R-SEC-09
area: security
tags: security
applies-to: open file
source: README Security; SECURITY.md
why: So Open cannot be used to read other files.
checked-by: test test/api-smoke.mjs (check "open checks the content: renamed or compressed non-captures are refused")
status: holds

### Findings reports and exported captures are created readable by their user only, written whole under a temporary name
id: R-SEC-10
area: security
tags: security,files
applies-to: findings report, export packets
source: SECURITY.md Security model
why: Captured data may be private.
checked-by: test test/units.mjs (checks "findings report: a new file is written 0600 and whole" and "export: written in a folder only the user can open next to the target")
status: holds

### Export Objects saves only into a new private folder, with names reduced to safe characters, never over or through a file
id: R-SEC-11
area: security
tags: security,files
applies-to: export objects
source: README Security; SECURITY.md
why: Names and contents come from a sender.
checked-by: test test/units.mjs (check "saved objects: safe names, a new private folder, never over a file")
status: holds

### Live captures and the slice folders of big live captures are readable by their user only (files 0600, folders 0700)
id: R-SEC-12
area: security
tags: security,files
applies-to: live capture, slices
source: README Security; SECURITY.md
why: Live data is private.
vague: slices.mjs asserts 0700/0600 for the slice folder; no check found for the live capture file itself
checked-by: test test/slices.mjs (the slice folder's modes)
status: unverified

### An MCP write never replaces an existing file, except one the agent wrote itself in the same session
id: R-SEC-13
area: security
tags: security,mcp,files
applies-to: agent tools: export, findings report
source: README Security; SECURITY.md
why: An agent must not overwrite the user's files.
vague: the findings report is covered; no check found for packet exports over a file the agent did not write
checked-by: test test/units.mjs (findings report: ... one that exists only with overwrite)
status: unverified

### A findings report writes text from captures, notes and comments escaped, so none can become a link, image, HTML, heading, table break or code fence
id: R-SEC-14
area: findings
tags: security,findings
applies-to: findings report
source: SECURITY.md Security model
why: Capture text is hostile.
checked-by: test test/units.mjs (check "findings text: code spans, table cells and quotes of hostile text read exactly as given")
status: holds

### An extension is read and loaded only when no other user could have changed it
id: R-SEC-15
area: extensions
tags: security,extensions
applies-to: extension folders (Linux; macOS in CI)
source: README Extensions; SECURITY.md
why: Extensions are Lua that runs as the user.
checked-by: test test/api-smoke.mjs (check "extensions: files others could change are untrusted and stay unread")
status: holds

### A panel runs sandboxed on a one-time origin of its own and the main page frames only panel hosts
id: R-SEC-16
area: extensions
tags: security,panels
applies-to: panels
source: README Panels; SECURITY.md
why: A panel must not reach the token or the API.
checked-by: test test/panels-smoke.mjs (check "panels: opening gives a one-time host; the main page may frame only panel hosts")
status: holds

### A panel changes the display filter only with the control permission
id: R-SEC-17
area: extensions
tags: security,panels
applies-to: panels
source: README Panels; SECURITY.md
why: Least privilege for panels.
checked-by: test test/panels-smoke.mjs (check "control: setFilter only with the control permission")
status: holds

### The events block in tool results carries a random tag named in the server instructions and appears once
id: R-SEC-19
area: agent/tools
tags: security,mcp
applies-to: MCP tool results
source: README Security; SECURITY.md
why: Capture text must not pose as WireBuddy's events.
vague: mcp-smoke.mjs checks the tag and that the block is not repeated; no check feeds hostile capture text to see it cannot pose as an event
checked-by: test test/mcp-smoke.mjs (check "WireBuddy events")
status: holds

### WireBuddy runs on Linux with Wireshark 4.6 and Node 22 or later; CI runs Node 22 and 24
id: R-TGT-01
area: platform
tags: target,ci
applies-to: product, CI
source: decision 1 of 2026-11-15; README Requirements; ci.yml matrix
why: This is the target the budgets and checks are set for.
vague: ci.yml installs the current stable Wireshark from the PPA, not a pinned 4.6; no check asserts the sharkd version is 4.6
checked-by: review orchestrator (ci.yml)
status: unverified

### Windows is brought up through a session on the owner's Windows machine, with tasks from a queue file
id: R-TGT-03
area: platform/windows
tags: target
applies-to: Windows
source: decision 1 of 2026-11-15
why: Windows has never been run.
vague: no statement yet of what Windows must support; README says untested and no extensions, panels or Decode As there
checked-by: none
status: unverified

### As root, WireBuddy says why extensions and Decode As are unavailable
id: R-TGT-04
area: extensions
tags: target,tests
applies-to: server as root
source: README Requirements; CONTRIBUTING.md
why: Wireshark loads no Lua plugins for root.
checked-by: test test/units.mjs (check "the reason a sharkd shows no Lua: root loads none")
status: holds

### An error a request brings back shows in the dialog's footer line, two lines at most, so Cancel and OK stay put
id: R-UI-01
area: page/dialogs
tags: ui
applies-to: all dialogs
source: CHANGELOG 0.19.0; open-items A46
why: Buttons that move under a click are missed.
vague: the check covers seven dialogs; Objects, Capture Options, Go to, Extensions and Open File are not covered and do not hold it
checked-by: test test/browser-control.mjs (check "browser: an error a request brings back sits in the footer")
status: broken (B-036)

### View > Time Display Format offers seconds since the beginning, since the previous displayed or captured packet, time of day, date and time, local and UTC, and keeps the choice across a restart
id: R-UI-02
area: page/list
tags: ui,time
applies-to: Time column
source: README; CHANGELOG 0.19.0
why: The formats of Wireshark's Time column.
checked-by: test test/api-smoke.mjs (check "time display format: each format")
status: holds

### In the default time format rows show *REF* and count from the nearest time reference
id: R-UI-03
area: page/list
tags: ui,time
applies-to: Time column
source: README
why: Matches Wireshark's time references.
checked-by: test test/api-smoke.mjs (check "time references: rows show *REF* and count from the nearest one")
status: holds

### A question to the agent shows as 'not seen by the agent yet' until its event was handed over, then as seen
id: R-UI-05
area: page/questions
tags: ui,agent
applies-to: waiting line, Questions dialog
source: CHANGELOG 0.19.0; README
why: The user must know whether the agent has the question.
checked-by: test test/units.mjs (check "a question is seen once the agent takes its event")
status: holds

### Every agent action that changes the view shows a notice in the UI
id: R-UI-06
area: page/questions
tags: ui,agent
applies-to: web UI
source: README (MCP tools)
why: The user sees what the agent did.
vague: browser checks see notices for single actions; no check goes through every tool that changes the view
checked-by: none
status: unverified

### Every tool result carries what happened in the viewer since the agent's last call
id: R-UI-07
area: agent/tools
tags: agent,mcp
applies-to: MCP tool results
source: README (MCP tools)
why: The agent works from the same state as the user.
vague: checked for problems and user activity in one flow; not for every tool
checked-by: test test/mcp-smoke.mjs (events block after a problem)
status: unverified

### Marks, time references and comments edited in the viewer come back when the capture is opened again, also after a restart
id: R-KEPT-01
area: investigation
tags: persistence
applies-to: kept investigation
source: README; SECURITY.md
why: The investigation stays with the capture.
checked-by: test test/api-smoke.mjs (check "investigation: marks, time references and comments come back when the capture opens again")
status: holds

### A kept file that does not check out is refused whole, left alone and reported to the agent
id: R-KEPT-02
area: investigation
tags: persistence,security
applies-to: kept investigation
source: README Security; SECURITY.md
why: A forged or damaged file must not change the view.
checked-by: test test/units.mjs (check "investigation: a file with anything wrong is refused whole and left alone")
status: holds

### A capture on loopback or any leaves WireBuddy's own traffic out and says so when it starts
id: R-LIVE-01
area: capture/live
tags: capture
applies-to: live capture
source: README Live capture
why: Otherwise the capture records itself.
checked-by: test test/live-smoke.mjs (check "a capture on loopback records no packet of WireBuddy")
status: holds

### In a big live capture, provisional rows carry a mark before the packet number and the status bar counts them
id: R-LIVE-02
area: capture/tail
tags: capture,ui
applies-to: live capture view
source: README How it works; CHANGELOG
why: The user must see which rows are not yet exact.
checked-by: test test/live-tail.mjs (check "the packet list marks provisional rows, the status bar counts them (headless Chrome)")
status: holds

### The live view lists new packets within about a second and a big capture's newest packets within about 2 s
id: R-LIVE-03
area: capture/live
tags: capture,performance
applies-to: live capture view
source: README Live capture and How it works
why: The page must follow the traffic.
vague: 'about once a second' has no stated tolerance; the 2 s check is on a generated capture, on one machine
checked-by: test test/live-tail.mjs (check "a big capture: newer packets show within about 2 s")
status: unverified

### The page stays responsive while a flooded live capture runs
id: R-LIVE-04
area: capture/live
tags: capture,performance
applies-to: page, live capture
source: open-items B6 (round 3)
why: One measured run only: 442,129 packets, about 5,200 a second, a click 0.12 s, a filter change 2.1 s.
vague: no budget is stated and the measurement is a single run on one machine; no check keeps it
checked-by: none
status: unverified

### A Decode As entry wins over the user's profile for the same port
id: R-DEC-01
area: extensions
tags: decode-as
applies-to: Decode As
source: README Decode As
why: Documented behaviour.
checked-by: test test/api-smoke.mjs (check "decode as: an entry wins over the profile")
status: holds

### WireBuddy never writes the user's Wireshark profile
id: R-DEC-02
area: extensions
tags: decode-as,security
applies-to: Decode As, profile
source: README Decode As
why: The user's configuration is theirs.
checked-by: none
status: unverified

### Before a pull request: typecheck, build and npm test pass; test:browser when src/web, src/panel or examples changed; test:live when capture code changed
id: R-PROC-01
area: process
tags: process,ci
applies-to: pull requests
source: pull request template; CONTRIBUTING.md
why: The change must not break the suites.
checked-by: review orchestrator (ci.yml runs them on every pull request)
status: unverified

### CHANGELOG.md is updated for user-visible changes
id: R-PROC-02
area: process
tags: process,docs
applies-to: pull requests
source: pull request template
why: The changelog is the release's source.
checked-by: review orchestrator
status: unverified

### The UI has no runtime dependencies and the server's dependencies stay minimal
id: R-PROC-04
area: process
tags: process
applies-to: src/web, package.json
source: CONTRIBUTING.md Guidelines
why: Small attack and maintenance surface.
checked-by: none
status: unverified

### The orchestrator opens the pull request and merges to main only on the owner's word; the owner tags and releases
id: R-PROC-06
area: process
tags: process,release
applies-to: main branch, tags
source: decision 2 of 2026-11-15
owner-words: "Keep: my word each time"
why: The owner decides what ships.
checked-by: review orchestrator
status: unverified

### Process documents and their tools stay out of the public repository; the status files are public as plain text
id: R-PROC-07
area: process
tags: process
applies-to: public repository
source: decision 3 of 2026-11-15
why: The project is open source; how the team works is kept private for now.
checked-by: none
status: unverified

### Commit and pull request texts carry no trailers and no tool footers
id: R-PROC-08
area: process
tags: process
applies-to: commits, pull requests
source: decision 4 of 2026-11-15
why: The owner's decision; existing history stays.
vague: no hook or check looks at message trailers
checked-by: none
status: unverified

### No CI run while another runs on the same branch, no speculative runs, one macOS probe per change
id: R-PROC-09
area: process
tags: process,ci
applies-to: CI
source: decision 5 of 2026-11-15
owner-words: "I get ci fail emails all the time - why?"
why: The owner gets CI failure emails all the time.
vague: ci.yml cancels a superseded run of the same ref; nothing stops speculative or repeated runs
checked-by: none
status: unverified

### Open work is kept as a file (the backlog), not as GitHub issues
id: R-PROC-10
area: process
tags: process
applies-to: backlog
source: decision 5 of 2026-11-15
owner-words: "but better put them on a pushed list"
why: Found bugs go on a pushed list.
checked-by: none
status: unverified

### A release tag names package.json's version and is on main
id: R-PROC-11
area: process
tags: process,release
applies-to: release.yml
source: release workflow, job check-tag
why: A tag from a branch must not publish.
checked-by: review orchestrator (release.yml check-tag)
status: unverified
