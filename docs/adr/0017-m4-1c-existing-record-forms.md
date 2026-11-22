# ADR-0017: M4.1c existing record and whitelisted field focus

**Date:** 2026-11-22
**Status:** Proposed in PR #41; gated by exact-head CI.

## Context

M4.1b could edit only the first server inbound's DNS name or the active client's endpoint. The TUI spec requires keyboard-first lists and multi-field forms. Combining this with inbound/user creation, secret lifecycle or management IPC would be a high-risk, untestable slice.

## Decision

With an explicitly supplied, valid, typed `--role` and `--config FILE`, the editor maintains an in-memory **selected record index** and **selected field index**, distinct from configuration content. Server starts at first inbound; client starts on the existing active profile. On the focused server/client panel, ↑/↓ or j/k wraps over existing records, Tab/Shift+Tab wraps over exactly three non-secret fields, Enter/e enters input, Enter validates the full typed document. No record can be created, deleted, or disabled in this phase.

Server fields: `server_name`, `h2_listen`, `quic_listen`. Client fields: `server`, `server_name`, `transport` (strict auto/h2/h3). All fields are backed by Rust's typed `Config`, not regex-rewritten TOML. Selected record ID and whether a client profile is actually active are visible as text. **Selecting a profile to edit never changes the active profile or starts network activity.**

## Safety

- One selected field edit is accepted only after **full v1 validation**, so duplicate or overlapping wildcard H2 TCP/H3 UDP listeners, invalid DNS/endpoint and unsupported transport fail closed; no partial draft commit.
- Only the allowlisted fields are rendered; no authentication token references, hashes, TLS private key references, grants or TLS trust overrides.
- During input, j/k, q and digits are ordinary text; while a dirty draft is not being edited, changing record/field focus does not discard draft changes. Leaving the editor/role still triggers existing Save/Discard/Stay guard.
- Save still uses the M4.1b single worker thread, exact-byte best-effort external change protection, typed validation and atomic file replacement, **never live reload**, OS settings modification or RPC.
- Document schema and wire protocol are unchanged. Existing save may discard comments; source file parent directory must be trusted to avoid TOCTOU attacks, and full runtime/secret verification remains separate.

## Tests and acceptance

- Given two server inbounds, edit all three fields of the second inbound and retain the first inbound's contents and user grants. Given an overlapping TCP bind, reject it before touching disk or draft state.
- Given two client profiles, select a nonactive profile and edit endpoint, TLS SNI and strict transport; retain active-profile reference and authentication token refs. Unsupported transport must reject.
- Given keyboard navigation, input mode isolates hotkeys; terminal renders a selected non-secret form at 60x18, 80x24 and 120x40 without panic, leakage or made-up status.
- Mandatory Linux/Windows tests, rustfmt, all-features clippy, feature matrix, Chromium browser E2E and exact-head `ci-gate` must all succeed before merge.

## Explicit remaining work

Adding/removing or enabling/disabling inbounds/users/profiles, editing users and ACL grants, secret generation/rotation, active-profile switching, multi-page settings forms, IPC/reload, Windows proxy and F-13/F-11/M5 release blockers are **not delivered** by M4.1c. They remain future milestones.

## Rollback

Remove selection index and field-focus additions, returning to the prior one-field editor without migrations.
