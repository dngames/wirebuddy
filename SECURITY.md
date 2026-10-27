# Security policy

WireBuddy runs a local web server that reads capture files and can start live captures, so
security reports are taken seriously.

## Reporting a vulnerability

Please **do not open a public issue**. Report it privately through GitHub:
**Security → Report a vulnerability** on https://github.com/dngames/wirebuddy. If that is not
available, contact the maintainer through the address on their GitHub profile.

Include what you found, how to reproduce it, and the impact you expect. You'll get an answer
as soon as possible; please give us a reasonable time to fix it before disclosing.

Supported versions: the latest `main` and the latest release.

## Security model

- **The session token is the only boundary.** It is random by default (at least 16 characters
  when you set one). Anyone or anything holding the viewer URL with its token can do everything
  the UI can, starting a capture included. That covers an AI agent that also has a shell or
  controls the browser pane: give WireBuddy only to agents you trust.
- The server binds to `127.0.0.1` only. API requests need the token in an `X-WireBuddy-Token`
  header, compared in constant time; the WebSocket takes it in its URL.
- Requests with a foreign `Host` header (DNS rebinding), any `Origin` but the server's own
  (`null` included) or a non-JSON body are rejected. The UI is served with a Content Security
  Policy, `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer`.
- The MCP tools cannot start a capture. They can open any capture file the user can read, read
  packets, change the filter, selection, marks and columns, stop a capture, open Wireshark, and
  write new `.pcap`/`.pcapng` exports wherever the user can write. They never replace an existing
  file, except one the agent exported itself in the same session.
- Open accepts only files whose content is a capture (pcap, pcapng, snoop, Network Monitor;
  also gzip- or zstd-compressed), whatever the name.
- Live captures and exports are created readable only by the user.
- Packet contents are untrusted and are always rendered as text, never as HTML.
- Problems in the viewer and what the user does there are reported to the attached agent
  (`--watch` reads them through an instance file only the user can read).

In scope: anything that lets a web page, another local user, a crafted capture file, or an MCP
client limited to WireBuddy's tools break these rules (for example start a capture, read
arbitrary files, replace the user's files, or run script in the UI).

Out of scope: anyone who already has the session URL with its token, including an agent given
a shell or the browser pane — treat the token like a password.
