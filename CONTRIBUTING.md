# Contributing to WireBuddy

Thanks for your interest! Bug reports, ideas and pull requests are welcome.

## Development setup

You need Node.js ≥ 22 and Wireshark 4.6 (`sharkd`, `dumpcap`, `editcap`, `mergecap`; on
Debian/Ubuntu they come with `wireshark-common`, see the README for the PPA). For the capture
tests your user must be allowed to run `dumpcap` (member of the `wireshark` group). The live
test also uses `openssl`. On macOS, `dumpcap` needs read access to `/dev/bpf*`
(Wireshark's ChmodBPF sets it up), and the robot-arm checks are skipped: they need Linux's
delayed ACK on the loopback.

```bash
npm install
npm run build        # bundles src/server → dist/server, src/web → dist/web and src/panel → dist/panel
npm start            # prints the UI URL
```

There is no watch mode yet: rerun `npm run build` and restart the server after a change.

## Project layout

| Path | What lives there |
|---|---|
| `src/shared/api.ts` | The HTTP/WebSocket contract between server and UI — start here |
| `src/server/` | Node server: `sharkd` client, `dumpcap` capture control, view state, HTTP/WS, MCP tools, the event log for the agent and `--watch` |
| `src/web/` | The browser UI: vanilla TypeScript and DOM, no framework, no runtime dependencies; `commands.ts` holds the menu bar, toolbar and shortcut commands |
| `src/panel/` | The bridge script and base style every extension panel loads (`wb`), built to `dist/panel` |
| `examples/` | Example extensions with panels, and the investigations the README walks through |
| `test/` | Smoke tests that drive the real server, plus the fixture capture |
| `scripts/media/` | Records the README demo and screenshot |
| `.github/` | CI workflow, issue and pull request templates |

## Before you open a pull request

```bash
npm run typecheck
npm run build
npm test             # unit checks, then the HTTP API, MCP tools and panels against test/fixtures/http.pcapng
npm run test:browser # the page, panels and the examples in headless Chrome (if anything in src/web, src/panel or examples changed)
npm run test:live    # live capture on the loopback interface (needs dumpcap permission)
```

The tests run their servers with an empty home folder, so your Wireshark settings don't change
the results. Without `dumpcap` permission `npm test` skips its capture checks, and without
Chrome or Chromium (`CHROME=<path>` names one) the browser checks are skipped. CI runs these
steps with both, and `npm run test:examples` and `npm run test:package` too; there a missing
Chrome fails.

The suites are plain Node scripts; `test/harness.mjs` holds what they share: `check` and the closing summary, `sleep`, starting the server, and headless Chrome.

## Guidelines

- Keep the UI dependency-free and the server's dependencies minimal.
- Change `src/shared/api.ts` first when the server/UI contract changes, and keep both sides in sync.
- Treat everything inside a capture as untrusted input: never render packet data as HTML.
- Keep comments short and about what the code does now.
- Only contribute code you wrote or that is under a license compatible with MIT. Don't copy code
  from Wireshark or other GPL-licensed projects.

By contributing you agree that your contribution is licensed under the MIT License.
