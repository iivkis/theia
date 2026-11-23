# ADR-0054: M4.4b2b1 explicit existing-user bearer rotation (server TUI)

**Status:** proposed implementation; requires exact-head mandatory Linux/Windows 14/14 CI. **Date:** 2026-11-24.

## Context and decision

F-14 mandates explicit token rotation, not reconstruction from a SHA-256 digest. M4.4b1 already issues a new account and a one-time `theia://v1` secret after durable TOML save; M4.4b2a explicitly disables an existing account without hard-revoking open sessions.

The next bounded slice is **rotation for an existing, enabled user only**, performed from `theia tui --role server --config FILE` on a **selected inbound that already grants that exact user ID**. Typing `t` opens ID input, Enter reviews consequences, and a separate `y` generates a new 32-byte CSPRNG bearer and changes **only** `server.users[].token_sha256` for that user (globally across all inbound). The ID, `disabled=false`, inbound grants, TLS/listener config, peers, policy and quotas do not change. Unknown, disabled, ungranted, dirty/editor-active or client-role use fails closed.

A strict `Invitation::public_from_server` preflight rejects incompatible auto-profile H2/H3 ports before generation. The checked `Invitation::issued_from_server` ties the freshly generated 32 bytes to the newly validated digest, user ID and selected inbound. The existing editor's guarded atomic TOML commit rejects an external-file conflict and never triggers a live Apply. Only after successful commit may the UI separately offer `y` to reveal the full secret URI *once*; `n/Esc` destroys the pending secret, and Esc closes the revealed link. A save error allows `r` retry or `d` discard with no secret exposure.

## Safety and exact semantics

- **Save is not Apply.** Running H2/H3 admission still recognizes its old token until a separate, explicitly confirmed revisioned **auth-only CAS Apply** using saved TOML. After Apply, new sessions need the rotated bearer; already authenticated tunnels remain alive. No session-kill or automatic reconnect.
- **Rotation is global**, despite choosing an inbound to authorize action and derive the invitation endpoint. Other inbound grants remain exactly the same, but the previous token will stop authenticating to *all* of them after Apply.
- No silent re-enable of `disabled=true`, no implicit token recovery, no auto export to file/clipboard, no secret in TOML/logs/errors/normal TUI, no Windows proxy changes.
- Best-effort zeroization is confined to existing protected token/URI buffers. A copied URI and terminal/SSH scrollback remain operator-controlled secrets.
- The interactive modal and background guarded writer reuse M4.4b1; no new stateful network API, dependencies, invite wire field or TOML schema.

## Given / When / Then and CI acceptance

1. Given two inbounds with the same active granted user, when `t → user-id → Enter → y` saves, then **only one** SHA-256 digest changes to fresh random material; both inbound grant lists and the enabled state remain byte-equivalent, and no token appears before successful save.
2. Given the committed rotation, when the operator separately presses `y`, then a canonical `theia://v1` containing the matching fresh 32-byte bearer is displayed once. Esc erases the in-memory display; no repeat/reconstruction from digest is possible.
3. Given disabled, unknown, ungranted or client-role user, dirty field, pending issuance, incompatible ports or changed-on-disk TOML, then **no successful rotation/save, no secret exposure and no Apply**. On external-file conflict, retry/discard stays explicit.
4. Confirm and cancellation keyboard flows, generated token uniqueness and native Linux/Windows Rust/fmt/Clippy + full `ci-gate` must succeed automatically on the exact PR head SHA.

## Not included

Re-enabling disabled users, secure file/clipboard/QR export, client import/persistence, revocation of existing connections, automatic auth Apply and Linux-server → Windows-client E2E remain open F-14 milestones. See [INVITATIONS](../INVITATIONS.md), [TUI_UX](../TUI_UX.md), [IMPLEMENTATION_PLAN](../IMPLEMENTATION_PLAN.md) and [STATUS](../STATUS.md).
