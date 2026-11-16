# Status

**2026-11-16, 06:35 UTC:** main = `b205f2a` (release 0.19.1, pushed by the owner's local session; before it `eca0e9e`, PR 32). Tag `v0.19.1` is on it and its release run is under way.
Tag `v0.19.0` (on `e1037f4`, 2026-11-15) failed its release run and never reached npm: 0.19.1 is the first published 0.19. The release runs the checks of the
tagged commit. No batch branch in assembly.

Working branch `claude/beautiful-noether-f96fnh`: a merge of main after the squash of PR 31; its tree is
identical to main's. The branch is not ahead of main in content.

## In flight
| Topic | Session | Branch | State |
|---|---|---|---|

## Who owns which paths
One orchestrator session owns the status files and every merge. Implementers get one topic each, on their own
branch, and touch only the paths of their topic.

| Path | Owner |
|---|---|
| everything (src/server, src/web, src/panel, src/shared, test, examples, docs, .github) | the orchestrator; an implementer per topic while the topic is in flight |
| status files (STATUS.md, BACKLOG.md, REQUIREMENTS.md, decisions/) | the orchestrator |
| release: version, tag, npm publish | the owner |

## Release flow
- `ci.yml`: on pull requests and on pushes to main (also by hand, on a schedule on Mondays, and called by the
  release). Node 22 and 24 on Ubuntu 24.04 with Wireshark from the PPA: typecheck, build, `npm test`,
  `test:examples`, `test:package`, `test:browser`, `test:live`. A newer run of the same ref cancels the older.
- `release.yml`: on a tag `v*`. `check-tag` (the tag equals package.json's version and is on main), `test` (ci.yml
  again), then `publish` to npm with provenance, in the environment `npm` (reviewers not required yet, see the
  backlog). No GitHub release page is made.
- `macos.yml`: by hand only, a probe, not a gate. One run per change.
- Merging: pull requests are squash-merged into main, only on the owner's word. The owner tags and releases.

## Standing notes
- Suites run as an ordinary user, never root: Wireshark loads no Lua plugins for root.
- These status files are public as plain text on this branch; process documents and their tools stay out of the
  public repository (decision 3, 2026-11-15).
- Open work is the backlog file, not GitHub issues. 45 items; items B-030 to B-044 are the
  owner's points of 2026-11-15 and the branch check.
- Dependabot pull requests 8 and 9 are open and have not been looked at (B-034).
