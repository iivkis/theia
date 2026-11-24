# F-14 acceptance matrix: invitation and credential lifecycle

Scope: existing versioned v1 connection data, local server/client editors, and authorization transactions. This is not a release declaration. F-18/F-19 and other independent P0 gates are outside this matrix.

| Requirement | Evidence | State |
|---|---|---|
| Canonical v1 codec, no unknown fields/implicit TLS downgrade | invite unit tests, ADR-0064 | Previously accepted |
| Explicit selected-inbound grant, CSPRNG issuance, digest-only persisted | editor and invitation regressions, ADR-0055 | Previously accepted |
| One-time confirmed confidential reveal or protected file export | native TUI, editor, Linux mode/Windows DACL tests; PR #107 run 45392909341 | Accepted |
| Masked import preview, independent CA, explicit env for public invitations | native editor/TUI and client tests | Previously accepted |
| Normal duplicate import refuses; active profile and OS proxy unchanged | native TUI/editor, cross-host harness | Previously accepted |
| Protected bearer creation, collisions, guarded save, uncertainty and process-exit handling | PR #106 run 45391036352; ADR-0066/0068 | Accepted within controlled fixtures |
| Bounded runtime/import inputs and stale issuance refusal | ADR-0070, PR #108 | Accepted: PR #108 run 45395505034, 13/13 |
| Explicit matching-profile credential-only replacement | ADR-0071, PR #108 | Accepted: PR #108 run 45395505034, 13/13 |
| Disabled-user recovery with fresh digest, retained grants | ADR-0072, PR #108 | Accepted: PR #108 run 45395505034, 13/13 |
| Linux binary IPC recovery through import/refresh and CAS Apply; old tokens rejected | reload_apply_runtime.rs, PR #108 | Accepted: PR #108 run 45395505034, 13/13 |
| Public saved-record tokenless share; no mutation or secret read | editor and TUI tests, ADR-0073 | Accepted: PR #109 run 45397074048, 13/13 |
| Native Windows binary Named Pipe recovery through import/refresh and CAS Apply | reload_apply_windows.rs, ADR-0073 | Accepted: PR #109 run 45397074048, 13/13 |
| Actual Linux WSL2 → Windows host H2/H3 CONNECT/SOCKS5, wrong CA/token denial | f14_cross_host.rs, PR #107 run 45392909341 | Accepted for VM topology; rerun passed in PR #109 |
| Public profile with wrong explicit env credential rejected, then guarded replacement succeeds on real cross-host H2/H3 | f14_cross_host.rs, ADR-0073 | Accepted: PR #109 run 45397074048, 13/13 |

## Remaining boundaries

- Public links do not convey authorization or trusted CA. Confidential transfer is operator-managed; clipboard/QR not implemented.
- Local native recovery E2E does not prove a complete SSH-driven issuance/recovery operation across distinct physical hosts.
- A saved change does not change live authorization before separately confirmed Apply. Existing authenticated tunnels retain their documented behavior. No hard revocation.
- Retained private credentials and crash orphans are not automatically removed; no power-loss guarantee or proof of secure erasure. Trusted parent directories required.
- Release readiness requires all P0 gates and independent security review; do not convert pending entries to accepted until the exact-head mandatory CI succeeds.

Evidence links: [PR #106](https://github.com/iivkis/theia/pull/106), [PR #107](https://github.com/iivkis/theia/pull/107), [PR #108](https://github.com/iivkis/theia/pull/108), [PR #109](https://github.com/iivkis/theia/pull/109), [ADR-0073](adr/0073-f14-public-share-and-native-parity.md).
