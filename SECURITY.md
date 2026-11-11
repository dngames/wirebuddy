# Security policy

WireBuddy runs a local web server that reads capture files and can start live captures, so
security reports are taken seriously.

## Reporting a vulnerability

Please **do not open a public issue**. Report it privately through GitHub:
**Security → Report a vulnerability** on https://github.com/dngames/wirebuddy. If that is not
available, contact the maintainer through the website linked from their GitHub profile.

Include what you found, how to reproduce it, and the impact you expect. You'll get an answer
as soon as possible; please give us a reasonable time to fix it before disclosing.

Supported versions: the latest `main` and the latest release.

Releases from 0.15.0 on are published to npm by this repository's [release workflow](.github/workflows/release.yml)
with provenance: each version's npm page links to the commit and the workflow run it was built from.

## Security model

- **The session token is the only boundary.** It is random by default (at least 16 characters
  when you set one). Anyone or anything holding the viewer URL with its token can do everything
  the UI can, starting a capture included. That covers an AI agent that also has a shell or
  controls the browser pane: give WireBuddy only to agents you trust.
- The server binds to the loopback addresses only: `127.0.0.1`, and the same port on `::1` where
  the machine has it, so that no other program can answer there for the `localhost` names
  browsers also resolve to it (the panels' hosts among them). API requests need the token in an
  `X-WireBuddy-Token` header, compared in constant time; the WebSocket takes it in its URL.
- Requests with a foreign `Host` header (DNS rebinding), any `Origin` but the server's own
  (`null` included) or a non-JSON body are rejected. The UI is served with a Content Security
  Policy, `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer`.
- The MCP tools can start and stop captures on the interfaces `dumpcap` may capture on, always
  into WireBuddy's capture folder. They can open any capture file the user can read, read
  packets, change the filter, selection, marks, time references, packet comments, columns and
  Decode As entries, open, reload and close panels, open Wireshark, and write new
  `.pcap`/`.pcapng` exports wherever the user can write. They never replace an existing
  file, except one the agent exported itself in the same session and WireBuddy's own record of
  switched-off extensions.
- File › Export Objects and `export_objects` save files carried in the traffic only into a new
  folder they create in a directory the user or the agent names, under names made of the frame
  number and the object's name reduced to letters, digits, `.`, `_` and `-`. The new folder must
  not be in or below a hidden folder or a folder Wireshark or WireBuddy loads code or
  configuration from (WireBuddy's own `dist`, whose pages it serves, the extension folders,
  every WireBuddy's plugin folders, Wireshark's global plugin folder, its personal
  configuration and plugin folders, `WIRESHARK_PLUGIN_DIR` and `WIRESHARK_CONFIG_DIR`; on macOS
  compared ignoring case and Unicode normalization, as its volumes usually do). Every
  folder from `/` down to it must belong to root or the user and be closed to other writers (on
  each platform as for extensions, below), except sticky ones like `/tmp`, below which only the
  user's own entries count; unlike for
  extensions, a private folder doesn't vouch for the ones below it, since one of them may be a
  bind mount. The folder is checked as made, so one swapped for a link is refused and its
  target left alone. Each file is created exclusively, so it never replaces an existing file
  or follows a link in its own name.
- Open accepts only files whose content is a capture (pcap, pcapng, snoop, Network Monitor;
  also gzip- or zstd-compressed), whatever the name.
- Live captures, exports and saved objects are created readable only by the user. While a big
  live capture is read provisionally, slices of its newest packets are written next to it, into
  a folder `.wirebuddy-slices-<machine>-<pid>-<random>` only the user can open (`0700`, files
  `0600`, created exclusively); the folder is removed once the capture is read in full, the view
  moves on or WireBuddy exits (also when its terminal closes). One left behind by a server that
  was killed is removed by a later WireBuddy when it starts, starts a capture or writes slices
  there, but only a folder of the user's own (not a link) of a server on the same machine (host,
  boot and pid namespace) that is gone.
- Extensions are Lua code that runs as the user inside `sharkd` and the Wireshark WireBuddy
  opens. The MCP tools and the UI can test, reload and switch them on and off, not write them;
  switching one off doesn't stop the agent from testing it or switching it on again.
- An extension is only read and loaded when no other user could have changed it: every folder
  from `/` down belongs to root or the user and only they can write it (sticky folders like `/tmp`
  protect only the user's entries), or a folder of the user's on the way is closed to others and
  the extension is on the same filesystem. The extension folders and files themselves must belong
  to the user (or root), be writable only by them, and be on the same filesystem; files must be
  regular files with a single hard link, not symbolic links, and are checked again as they are
  read. Folders that fail these checks are not looked into. Who "only they" are depends on the
  platform:
  - On Linux a group counts only when it is the user's own private group and no ACL lets others
    in: read with `getfacl`, and where that isn't installed an entry with any ACL at all, or whose
    ACL can't be read, counts as writable by others. Folders on network or FUSE filesystems (by
    their `statfs` type), whose owners and modes don't say who can write, are not looked into.
  - On macOS, where the same checks are made (verified in CI on a hosted runner, not by hand), a
    group never counts: users share `staff`. ACLs there don't depend on the mode, so the ACL of
    every folder and file the checks rely on is read with `/bin/ls -led` (by its absolute path, so
    no other `ls` on `PATH` answers). An `allow` entry, inherited or not, for anyone but the user
    and root that grants more than reading (anything but `read`, `list`, `search`, `execute`,
    `readattr`, `readextattr`, `readsecurity`, `synchronize` and the inheritance flags) counts as
    others being able to write; `deny` entries never do, so home folders' `group:everyone deny
    delete` is fine. An `ls` that fails, complains or prints anything it wouldn't, a gap in its
    numbered entries among it, counts as others being able to write. A folder closed by its mode
    vouches for those below it only when its ACL allows others nothing, and a sticky folder
    protects the user's entries only while its ACL lets others change nothing. The volume, found
    by its device in `/sbin/mount`'s table (not by path, since `/Users` leads from `/` to the data
    volume), is judged from every `local` mount of the table (network and other mounts are never
    looked at, as they may not answer). At least one local mount must have that device, and every
    local mount that has it (two can report the same number) must be an APFS or HFS+ volume that
    keeps ownership (not `noowners`, which external disks default to and where every file shows as
    the viewer's), not a union mount, not mounted by another user, and listed once, not covered by
    another mount; otherwise, and when the table doesn't read, it is refused. Not checked on
    macOS: ACL entries `ls` skips at the end
    of the list without a trace, file flags, sandbox and privacy (TCC) rules, which only take
    rights away, and Time Machine's folder hard links on HFS+ volumes.
  - Elsewhere (Windows) no extension folder is looked into, so there are no extensions, panels or
    Decode As.
- On every reload WireBuddy copies the extensions into its own plugin folder, created fresh with a
  random name in a folder only the user can write; `sharkd` and Wireshark load those copies.
- An extension's panel (its own web page) runs in a sandboxed frame on a one-time origin of its
  own, `p<130 random bits>.localhost:<port>`, never with the token. Its responses carry a Content
  Security Policy that allows only its own files and requests to its own origin, and the panel
  host serves nothing but the files read (and checked like Lua) when the panel opened, and only to
  that page. The main page frames only panel hosts, so a panel can't navigate elsewhere either;
  one that tries is closed, and one that stops responding is stopped.
- A panel reads the open capture only through a data API on its own origin (`/_wb/api/…`):
  packets, bytes, fields, streams, exported objects, taps and filter checks of the capture the
  user's view shows, from a `sharkd` of its own, within per-panel quotas. It can't name another
  file, and there is no route to start a capture.
- A panel changes the user's view only through the page that shows it: `wb.select` and, with the
  `"control"` permission in its `extension.json`, `wb.setFilter`. The page passes either on only
  right after the user clicked or typed in that panel (its frame has focus and the page holds the
  user activation the browser passes up from it); the server checks the permission again, limits
  how often, shows a notice and reports every change and refusal to the agent. Panels can't mark
  packets, change columns or start captures.
- `wb.storage` keeps at most 256 KiB of JSON per extension in WireBuddy's data folder
  (`~/.local/share/wirebuddy/panel-storage`, files readable only by the user); a panel reads and
  writes only its own extension's.
- Residual risks of panels: code in a panel can still reach the network through WebRTC, which no
  Content Security Policy blocks, so a panel has the same trust as the Lua the agent writes; a
  panel reads everything in the open capture, TLS-decrypted data included; and the isolation needs
  a browser that puts each `*.localhost` site into a process of its own (the page checks this and
  reports a panel that isn't).
- Packet contents are untrusted and are always rendered as text, never as HTML.
- Problems in the viewer, what the user does there and the questions the user asks the agent
  are reported to the attached agent (`--watch` reads them through an instance file only the
  user can read). Every event is one line; the block of events in tool results carries a random
  tag named in the server's instructions, and followed stream payload lines start with `| `, so
  text from a capture can't pose as an event or a question from the user.

In scope: anything that lets a web page, another local user, a crafted capture file, or an MCP
client limited to WireBuddy's tools break these rules (for example capture outside WireBuddy's
capture folder, read arbitrary files, replace the user's files, run script in the UI, or get Lua
loaded that the user didn't put in an extension folder).

Out of scope: anyone who already has the session URL with its token, including an agent given
a shell or the browser pane — treat the token like a password.
