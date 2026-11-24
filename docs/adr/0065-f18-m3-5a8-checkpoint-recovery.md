# ADR-0065: F-18 M3.5a8 — bounded trust checkpoint recovery model

**Status:** test-only, pending native CI and independent review.

## Context

ADR-0063 models authorized in-memory key policy replacement. Restart loses the retired history unless explicitly restored. A checksum stored beside the same file is not an anti-rollback mechanism.

## Decision

The lab serializes public policy data only: format version, scope, generation, active pins and intervals, retired history and last observed time. Decode requires an independently supplied expected digest and exact generation, a 16 KiB input bound, strict unknown-field rejection, scope equality, nondecreasing time, valid active pins and unique nonzero disjoint retired keys within capacity. The test harness supplies the expected anchor from an already authorized snapshot, never from the bytes under test. SHA-256 here binds the exact bytes to trusted metadata; it is not a signature or trust establishment.

The isolated filesystem fixture uses a unique temporary directory, create_new/write/sync and a same-directory rename into a previously absent path. Recovery reads only the explicitly selected regular file, with a bounded read and strict UTF-8 parsing; it never scans for an alternative snapshot. The independently supplied anchor is not written alongside the file.

## Given / When / Then

- Given an authorized newer checkpoint and independent anchor, when reconstructing trust, then retired keys remain rejected and the valid new pin can verify a fresh proof on both branches.
- Given old, truncated, modified or oversized bytes, wrong scope/time/generation or unknown fields, then restore rejects rather than falling back to default.
- Given authorized malformed retired history (overlap, duplicate, capacity overflow), then restore rejects even though the bytes match the fixture anchor.
- Given an explicit deny-all checkpoint, then recovery retains the empty active set and cannot reintroduce retired keys.
- Given missing, stale, incomplete or damaged selected files, then recovery refuses without falling back to an older complete checkpoint. A correctly published file can be reopened and restores revocation.
- Given independently anchored invalid versions, zero generation, duplicate/zero/oversized pins, reversed validity intervals or zero retired keys, then validation still fails.

## Limits and release hold

The anchor is simulated, not provisioned or persisted. An attacker who can roll back both checkpoint and trusted anchor defeats this model. The filesystem fixture does not establish race-free path resolution, atomic replacement of an existing file, directory fsync, owner ACL, power-loss recovery, authenticated policy distribution, multi-process locking or a durable generation source. This checkpoint does not persist replay state or TLS sessions. Reconstructing the model is not an actual process restart, and safe runtime recovery needs independent evidence of fresh verified TLS channels and any required durable replay policy. No secrets or tokens in the checkpoint; no production protocol, config migration or new mode. Full exact-head native Linux/Windows CI and ci-gate are required. F-18 remains P0 blocked.
