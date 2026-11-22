# ADR-0031: M4.5c, offline candidate groups and manually scoped IPv4 CIDR

**Date:** 2026-11-23. **Status:** narrowly scoped server TUI implementation; exact-head native CI required.

## Context

M4.5a,b introduce a passive interface/egress preview and a separately consented, exactly pinned TLS/H2 probe for one **locally assigned** public IP. The F-18 UX specification also expects grouped candidates from the server subnet, a fixed popular HTTPS seed catalogue and manually entered operator ranges. Critically, an assigned mask, IP echo, provider prefix or BGP data **does not prove CIDR ownership**. Accepting these as scan permission would silently enable traffic to unowned neighbor hosts. The last implemented step still does not render the individual candidate groups or offer a reviewed manual CIDR.

## Decision and user journey

- In the server `p` network preview, press **`r`** for **pure, offline** candidate review. Initial groups: **Подсеть сервера** (actual assigned public IPs), **Популярные домены** (14 static **unverified** seed names, never DNS-resolved), **Добавленные вручную** (none by default). Show bounded sample IPs, actual counts, and a global zero-evidence TLS/H2 score of **0/100**, confidence **0%**, eligibility **NO**, emphatically **not bypass probability**. Grouping is based on existing `CandidateSource`; no fake fingerprints.
- Key **`a`** starts a maximum-64-byte ASCII-only CIDR input. Enter *reviews* the input; it does not accept it. A range must be a valid **IPv4 /24..=/32** and pass the existing `build_preview(OperatorApprovedCidrs)` guards: contain a locally assigned public IP, fit **within** that interface's observed mask, avoid broad ranges, refused IPv6 enumeration and any truncated candidate set. Invalid input leaves the user in edit state with an explanation, no network.
- The reviewed CIDR is **canonicalized**, e.g. `93.184.216.10/29` becomes `93.184.216.8/29`, and the exact range and number of *additional* neighbor IP candidates are displayed. Users are warned that any declared access rights are **self-attested** and must be independently substantiated. Only a **separate `y`** makes the CIDR visible in the in-memory offline plan. **`n`** or Esc discards the unconfirmed claim. A /32 can be accepted as a single own-address planning scope with *zero* extra neighbors.
- Even after confirmation, this is **not** `ProbeApproval`, not persisted in TOML, not a scanner grant, and not supplied to `ProbePanel` or `camouflage_batch`. Re-opening resets it. No DNS, TLS, ping, connection, provider lookup, remote API, OS proxy action, config write, IPC reload, encryption-profile application, or actual active scan occurs during this UI flow. The existing exact-IP `p→t→Enter→y` flow remains a **separate** independent consent boundary.
- Esc in an edit/confirmation state first cancels the pending input and stays in the review; Esc on overview/accepted view exits to passive discovery, erasing transient scope. Reject keys from client, home, help, active ipify consent or running requests. No event-loop blocking.
- `NetworkPrefix` now has canonical `Display` without changing parsing semantics, to prevent showing an input host-bit CIDR as though it were its actual effective network.

## Given / When / Then

1. Given one public UP assigned `93.184.216.10/29` and private `10.0.0.3/24`, initial review shows **one** server IP and all 14 unverified seed names, no manually authorized neighbors; 0/100 and 0% are explicitly *unknown* and not a chance of bypass.
2. Given `93.184.216.10/29`, Enter shows canonical `93.184.216.8/29`, five additional usable neighbors and a distinct warning; no scope before y. Only y adds these to an **offline** view; cancelling input/confirmation drops it.
3. Given /24 with assigned /29, a /23, unassigned network, private-only range, malformed /0 or /33, IPv6 or no public local addresses, deny. Never manufacture ownership by matching an IP or from ipify/BGP. /32 permits zero additional neighbors.
4. Given 256-character input, truncate at 64 ASCII printable characters and never execute it as a command, DNS name or network target.
5. Given Home/Client/Help or active ipify consent, r does not open review. Esc unwinds nested edit, review and discovery without changing editor, secrets, state, system proxy or runtime.

## Not implemented or authorized

Still open: **proof** of delegated CIDR ownership/consent with audit, manual third-party hostname probes, passive DNS/CT enrichment, sustained rate budgets, active multi-IP scanner, score from real measured fingerprint/H3/QUIC evidence, final selection → transactionally validated Apply + IPC rollback, Windows native interface collection, REALITY-like auth mode, TLS-in-TLS mitigation. The user-entered CIDR is an offline view only; no release-readiness or F-18/F-19 completion claim.

All required locked Rust tests, rustfmt, Clippy -D warnings, Windows/Linux native smoke, BBR, BoringSSL, browser E2E and exact-head `ci-gate` must succeed. No public network probing is used in CI.
