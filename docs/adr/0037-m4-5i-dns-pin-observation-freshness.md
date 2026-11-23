# ADR-0037: M4.5i, preserve DNS pin observation age across asynchronous TUI delivery

**Date:** 2026-11-23. **Status:** proposed; exact-head native Linux/Windows CI is required.

## Context / threat model

M4.5h allows a separately authorized, bounded catalogue DNS A/AAAA lookup followed by independently consented exact-IP TCP/H2 and UDP/QUIC/H3 checks. The IPs are supposed to expire after 60 seconds. Previously the worker sent only the address vector and `DomainPanel::poll()` recorded `Instant::now()`, thereby restarting the TTL whenever the TUI finally consumed the channel. If a terminal event loop was stalled or the DNS worker response had been buffered, an already stale observation could be presented and used for a new active scan. Also, `Instant::elapsed()` saturates for future timestamps. The active-probe worker can be queued or delayed by native CA loading after UI approval.

A DNS result is neither proof of ownership nor permission to send probes. The active batch must remain limited to operator-selected, explicitly approved exact `IP:443/SNI` pairs.

## Decision

1. The bounded DNS resolver worker stamps **successful lookup completion** with monotonic `Instant` and sends one `DnsObservation { addresses, completed_at }` over the local channel. No wall-clock timestamps or persistence are introduced.
2. The TUI never renews a pin's age when polling. It accepts an address list only if nonempty and `0 <= now - completed_at <= 60s` using `checked_duration_since`. Delayed or future-dated observations fail closed with a fixed safe message and clear all pins/selection. A new DNS approval is required.
3. `fresh()`, the Space picker and the second confirmation all share the same timestamp policy. The separately approved probe worker checks the original resolver timestamp **again immediately before invoking the active batch**, after local trust-store and runtime setup. A delay across the TTL boundary must not turn an old IP into a new authorized connection.
4. Keep DNS resolution limited to one expressly approved catalogue name, `<=64` vetted records, `<=8` public pinned IPs, one 5s lookup; keep each subsequent TCP and UDP target separately approved and pinned. No DNS re-resolution, automatic batch, CIDR sweep, HTTP request, REALITY activation, TOML/invite/wire change, remote lookup in CI, or system proxy change.

## Given / When / Then and CI

- **Given** a successful DNS reply completed 61 seconds before the TUI receives it, **when** `poll()` processes the buffered response, **then** the UI shows a stale-observation failure, retains no pins and cannot enter active-probe confirmation.
- **Given** an observation completed 2 seconds earlier, **when** the TUI polls, **then** it retains the worker's *original* timestamp, not the time of delivery, and no IP is pre-selected.
- **Given** a future monotonic timestamp or TTL+epsilon age, **when** the operator attempts to select and approve it, **then** the action fails with no worker/socket. Exactly 60s is the defined inclusive freshness boundary.
- **Given** a valid approval at the TUI, **when** the background worker is delayed until the DNS snapshot expires before network start, **then** it returns `StaleDnsPin` and does not call `probe_dual_batch`.
- Tests use injected in-process channels and fixed `Instant` arithmetic; no real public DNS or third-party network traffic. Run all Linux/Windows locked tests, format/Clippy and exact-head `ci-gate` through GitHub Actions. The test-only commit intentionally precedes implementation.

## Remaining limitations

This is only freshness hardening. It does not establish active-scan authorization by itself or solve delayed OS resolver cache provenance, domain ownership, HTTP/3 request semantics, browser-like fingerprint, REALITY authentication, F-19 TLS-in-TLS camouflage, Windows proxy restore, or release benchmarking. No new user-visible Apply action or success claim.
