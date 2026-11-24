# ADR-0066: F-18 M3.5a9 — native storage and process-exit regression evidence

**Status:** test-only acceptance extension, pending full native CI.

## Context and decision

ADR-0065 proved bounded checkpoint parsing and controlled file recovery, not a shipping identity store. Reuse evidence from the existing F-14 private bearer primitives instead of introducing another production credential API. The tests exercise the actual existing storage code without changing it.

## Given / When / Then

- Given a new native private directory or credential file, when a second create-new targets the same name, then it fails without changing data or widening permissions.
- Given two concurrent create-new operations, when both target the same path, then exactly one succeeds and its bytes remain.
- Given two independent PrivateBearer guards, when one commits and the other is dropped, then only the latter's owned files are removed. Assert Linux modes 0700/0600 and exact Windows current-user and LocalSystem DACL using existing platform test helpers.
- Given a child process that creates a private bearer then exits before commit without unwinding, when the parent inspects files, then original TOML is unchanged and the orphan remains private and unreferenced. A separate creation does not adopt or overwrite it.
- Given separately anchored new public policy bytes, when a child exits after partial write, complete staging or publication into an absent destination, then only the published exact committed path restores. An older complete snapshot never passes the newer anchor. The exit code proves the child test actually ran.

## Additional a10 acceptance in the same CI block

- Two concurrently submitted next-generation policies are serialized by a test-local Mutex. Exactly one succeeds, the other rejects stale generation, and the retired pin cannot verify.
- Two identical concurrent proof verifications on each branch admit exactly one. The remaining seven replay slots are usable; an eighth distinct proof then fails at capacity.
- Separate local inbound identities at an identical host and port, with distinct pins and independently authorized anchors, reject checkpoint/pin substitution. Replay state and deny-all remain local to the selected policy.
- No interprocess CAS, hostile concurrency or isolation if the same key is reused across inbounds is claimed.

## Limits

No production change. The tests use controlled temporary directories, synthetic keys and trusted fixture anchors. Process exit bypasses destructors but does not simulate operating-system crash or power loss. No proof of directory durability, atomic replacement of an existing destination, race-free hostile path handling, secure orphan cleanup, persistent anchor, or protected F-18 private-key store. F-14 ACL evidence concerns the existing bearer store only. The F-18 checkpoint is public metadata; never store private keys or bearer tokens in it. No changes to trust negotiation, wire format, config, routing, or CI workflows. Independent review and full exact-head native CI remain mandatory.
