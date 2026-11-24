# ADR-0067: native local credential input hardening and milestone batching

**Status:** pending exact-head native CI.

## Context and decision

The v1 invitation import and independent CA selection previously checked path metadata before a separate ordinary open. A final link could be substituted between these calls, and a Windows UNC path is absolute even though the intended contract is local input. Share the bounded reader and enforce an explicit absolute path without parent traversal. Reject Windows UNC, device and alternate-stream syntax before opening. Use Linux no-follow/nonblocking and Windows open-reparse-point flags; require regular-file metadata on the actual opened handle and reject reparse attributes. Read at most limit+1 bytes and reject overflow. Use zeroizing buffers for both input types.

## Acceptance

- Valid local v1 URI/file and independent valid CA succeed; malformed, oversized, missing, directory, URL, relative and parent-traversal inputs reject. Exact bounded read succeeds; one byte over rejects.
- Linux final symlinks reject for both types. Windows lexical tests reject UNC, device, alternate streams and drive-relative forms without accessing them.
- Existing secure credential storage, grants, strict TLS and F-14 cross-host tests remain required.
- Group this production correction, M3.5a9–a10 regressions, documentation and the known formatter fix in one head update. AGENTS.md clarifies milestone-level batching; no extra CI runs for preparatory slices.

## Limits

No race-free parent traversal, physical-local-volume verification, Windows reparse race simulation, filesystem ACL verification of selected source files, or binding CA preview bytes to later runtime. The final-handle checks narrow the previous gap; they do not establish that any arbitrary path is safe. No new invitation schema, trust protocol, remote scanning, or F-18 production feature. No local test run is evidence of CI acceptance.
