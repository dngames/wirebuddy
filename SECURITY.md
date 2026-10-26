# Security policy

WireBuddy runs a local web server that can read capture files and start live captures, so
security reports are taken seriously.

## Reporting a vulnerability

Please **do not open a public issue**. Report it privately through GitHub:
**Security → Report a vulnerability** on https://github.com/dngames/wirebuddy.

Include what you found, how to reproduce it, and the impact you expect. You'll get an answer
as soon as possible; please give us a reasonable time to fix it before disclosing.

## Security model

- The server binds to `127.0.0.1` only and requires a random per-session token (in the UI URL)
  on every API and WebSocket request.
- Requests with a foreign `Host` header (DNS rebinding) or a cross-site `Origin` are rejected.
- Captures are started only by the user clicking Start in the UI; the MCP tools cannot start one.
- Only capture files can be opened (checked by extension or pcap/pcapng/compression magic bytes).
- Packet contents are untrusted and are always rendered as text, never as HTML.

In scope: anything that lets a web page, another local user, a crafted capture file, or a
prompt-injected AI agent bypass these rules (for example start a capture, read arbitrary files,
or run script in the UI).

Out of scope: someone who already has the session URL with its token — treat it like a password.
