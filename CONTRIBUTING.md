# Contributing to WireBuddy

Thanks for your interest! Bug reports, ideas and pull requests are welcome.

## Development setup

You need Node.js ≥ 20 and Wireshark 4.x (`sharkd` and `dumpcap`; on Debian/Ubuntu both come
with `wireshark-common`). For live capture your user must be allowed to run `dumpcap`
(e.g. member of the `wireshark` group).

```bash
npm install
npm run build        # bundles src/server → dist/server and src/web → dist/web
npm start            # prints the UI URL
```

There is no watch mode yet: rerun `npm run build` and restart the server after a change.

## Project layout

| Path | What lives there |
|---|---|
| `src/shared/api.ts` | The HTTP/WebSocket contract between server and UI — start here |
| `src/server/` | Node server: `sharkd` client, `dumpcap` capture control, view state, HTTP/WS, MCP tools |
| `src/web/` | The browser UI: vanilla TypeScript and DOM, no framework, no runtime dependencies |
| `test/` | Smoke tests that drive the real server, plus the fixture capture |

## Before you open a pull request

```bash
npm run typecheck
npm run build
npm test             # HTTP API and MCP tools against test/fixtures/http.pcapng
npm run test:live    # live capture on the loopback interface (needs dumpcap permission)
```

CI runs the same steps.

## Guidelines

- Keep the UI dependency-free and the server's dependencies minimal.
- Change `src/shared/api.ts` first when the server/UI contract changes, and keep both sides in sync.
- Treat everything inside a capture as untrusted input: never render packet data as HTML.
- Only the user may start a capture. Don't add MCP tools or code paths that let an agent start one.
- Keep comments short and about what the code does now.
- Only contribute code you wrote or that is under a license compatible with MIT. Don't copy code
  from Wireshark or other GPL-licensed projects.

By contributing you agree that your contribution is licensed under the MIT License.
