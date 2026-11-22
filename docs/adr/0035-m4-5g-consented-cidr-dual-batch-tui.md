# ADR-0035: M4.5g, individually selected CIDR candidates in a consented dual H2+H3 server TUI batch

**Date:** 2026-11-23. **Status:** narrow production feature in PR, exact-head Linux/Windows CI required.

## Problem and security boundary

F-18 requires a usable server-side candidate selection workflow, rather than only an API for batch checks. M4.5c already has a passive view of local public IPs, 14 popular DNS seeds and separately reviewed, operator-declared /24..=/32 CIDRs. M4.5f already provides strict source-aware **two-transport** batch probing but no user entry point. An assigned subnet mask is **not** proof of ownership: merely accepting an offline CIDR must never automatically scan its neighbor IPs. IPs named by DNS/BGP/ipify or catalogued domains do not imply scanning authority.

## User-visible flow

Server `theia tui --role server --config server.toml`:

1. **`p → r`** opens offline source groups. Optional **`a → IPv4 CIDR → Enter → y`** reviews a range that includes a real UP assigned public IP and lies within its actual mask; this is **only** transient offline planning.
2. **`b`** opens an IP picker from the current offline plan. Without a reviewed CIDR it lists **only own assigned public IPs**. With one approved offline CIDR, neighbors appear as `Подсеть: заявлен оператором`, distinctly from `назначен серверу`. There is never automatic selection. **j/k** navigates the bounded view of candidates; **Space** checks/unchecks each exact IP, up to **8**. Private, loopback, unrelated provider CIDR, seed domains and NAT/ipify-only egress never become selected active targets.
3. **Enter** displays a second, separate, **exact** confirmation listing **every** selected IP:443, the current selected inbound `server_name` TLS SNI/SAN, TCP/h2 + UDP/h3 disclosure, 2 concurrent candidates, 5s/target, 20s/batch, and a warning that the operator must independently possess active-checking permission for **each** exact IP. `n` declines; Esc cancels the confirmation without network. Only **`y`** can launch a worker, one batch, once.
4. Worker uses loaded native CA roots (no insecure verifier), pinned exact `ProbeApproval::public_https_ip` for each individually checked IP and `CandidateConsent::PlannedIp`, existing `probe_dual_batch` **all-target preflight** before first TCP/UDP socket. Bounded Tokio worker is outside 50ms UI loop; Esc sends cancellation signal and drops all temporary selection/consent. No auto DNS, retry, fallback, connection to unselected IP, HTTP request, TOML write, runtime reload or system proxy effect.
5. Render true stable per-IP H2 and H3 evidence score/confidence, or **Unknown** for each individual failure, plus `dual_verified_count()/N`, observation age and an explicit statement **REALITY not ready** even when both TLS handshakes pass. Ordinary TLS/QUIC + ALPN is *not* proof of HTTP/3 semantics, browser fingerprint, cryptographic REALITY server identity, TLS-in-TLS resistance or DPI bypass. Scores are not bypass probabilities.
6. Missing config/SNI, no selected IPs, no public local IP, invalid scope, missing native roots, duplicate target or worker/timeouts all fail closed. The picker never surfaces secret refs and doesn't store authorization or results. No UI action short of `y` opens TCP or UDP.

## Given / When / Then

- Given a real UP local public `93.184.216.10/29` and private `127.0.0.1`, initial review lists only own public IP; zero selected. Enter/y do nothing without Space.
- Given the *separately reviewed* offline `93.184.216.10/29`, show own .10 plus five extra usable IPs. Cursor/Space selecting exactly .10 and .9 produces an Enter confirmation listing **both exact targets** and SNI; `n/Esc` cancels without sockets, a second y consent is mandatory.
- Given /24 with many candidate neighbors, the UI cannot select a ninth IP, even after repeated navigation; order remains operator selected and no hidden automatic range scan.
- Given no loaded valid server TOML, zero public addresses, an unapproved CIDR, or missing CA, no active network I/O. Client/Home/ipify pending/editing/confirming CIDR are blocked from opening this modal.
- Given worker failure, wrong CA, H2-only or H3-only, display per-protocol failure as Unknown, not dual compatible; full REALITY remains prohibited.
- Existing production loopback batch tests and native Linux/Windows CI validate exact-IP approvals, quotas, both PKI/h2 and QUIC/h3 positive and negative conditions. Unit UI/state tests never send real traffic.

## Not implemented

This step only makes **manually selected IP** batches actionable. The fourteen public seed domains are still passive; their DNS A/AAAA resolution and exact pinned-IP domain opt-in, proof of delegated provider CIDR ownership, automatically authorized search, HTTP/3 SETTINGS/browser fingerprint, REALITY server key auth and anti-replay, candidate ranking/final Apply with IPC rollback, F-19 flow-shaping remain P0 blockers. Windows native interface collector is still absent. No new crates or changes to TOML/wire/invite.

## Quality gate

Mandatory exact HEAD `cargo test --workspace --all-targets --locked`, rustfmt, Clippy -D warnings, native Linux and Windows BoringSSL, BBR, Windows smoke, Chromium E2E, and final `ci-gate`. No manual-only tests or Internet scanning during CI.
