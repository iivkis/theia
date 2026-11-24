# ADR-0070: shared bounded configuration and credential input lifecycle

**Status:** accepted in PR #108, exact-head run 45395505034 (13/13).

## Decision

Use one bounded reader for local invitation and CA import, typed configuration, editor reads, client CA/bearer, server PEM and bound reload/restart reads. Separate native absolute file references from explicitly supplied CLI configuration paths. Check regular type, size and Unix private mode (where required) before and after opening. Linux uses O_NOFOLLOW/O_NONBLOCK; Windows opens the final reparse point itself and rejects reparse attributes. Read at most limit+1 bytes. No raw path or contents in errors. Native file references reject Windows UNC/device/alternate streams. Portable structural validation stays non-I/O.

Keep raw runtime PEM/token buffers in Zeroizing owners, including preflight PEM. The v1 codec zeroizes owned wire token and intermediate encoded/decoded data where possible. Return values remain caller-owned and confidential. This is not a proof of complete erasure.

Make direct screen reveal use the same exact saved-byte check as protected file export. A stale or unreadable saved document consumes and refuses the offer. No automatic rotation or Apply.

## Acceptance

- Given regular input at its limit, read succeeds; oversized, missing, directory, final symlink and disallowed reference forms refuse. Unix private mode rejects group/other access. Direct config, client runtime and server PEM reader regressions verify that the shared contract is actually wired into callers.
- Given valid file-backed bearer and CA, native client E2E and server TLS/restart/preflight remain functional. Existing wrong CA, wrong token and identity drift tests still reject.
- Given changed saved issuance, direct reveal and file export refuse without recovering the old token.
- Existing v1 roundtrip and invalid encoding tests remain unchanged; no new fields, TLS profiles, grants or protocol.

## Limits

No hostile-parent-path protection, physical-local-volume proof, Windows arbitrary input ACL verification, secure erase guarantee or power-loss guarantee. Relative config CLI paths remain supported, but final symlinked config is now refused (use the actual file path). No new F-18 runtime capability or independent review claim. Full exact-head CI remains required.
