# ADR-0027: M3.5b2b3, exact-consent bounded TLS/H2 batch observations

**Дата:** 2026-11-23. **Статус:** PR implementation, final exact-head CI gate mandatory; no user-facing scanner.

## Goal and threat model

M3.5b2a has a strict TLS1.3/h2 probe for one explicitly pinned socket. M3.5b2b2 adds a passive preview of local interfaces, optional external egress observation and 14 *unverified* seed domains. Connecting these without additional admission controls could accidentally mass-probe a provider's IP range, access unowned hosts, resolve/scan popular seed domains, or silently turn one TLS failure into an eligible fingerprint result. Any batch API must reject insufficient consent, unplanned public addresses, duplicates and unreasonable work **before any network call**.

This is not full CIDR ownership validation: a caller constructing `OperatorApprovedCidrs` and `PublicHttpsIp` is responsible for separately proving authorization. The module itself cannot attest legal scope or operator identity. No TUI/CLI exposes it yet.

## Decision

- `camouflage_batch::probe_explicit_batch(preview, targets)` accepts exactly the list supplied by the caller. It does **not** enumerate `preview.plan.candidates`, resolve domains, or create requests from seed domains/IP prefixes.
- At most **8 targets** per call, and no zero-sized batch. Reject duplicate `SocketAddr` even with different SNI names so a caller cannot repeatedly test the same IP with many names.
- Every public target must satisfy both (a) presence as an IP in the existing offline plan (ServerAddress or AuthorizedSubnet), and (b) an independent exact `ProbeApproval::PublicHttpsIp(ip)` for **that** public TCP/443 target. `Denied`, mismatched address/port, a private host, or a public IP missing from the plan fails the *whole batch* before network. This is defense in depth, **not** proof of ownership.
- `ProbeApproval::IsolatedLoopbackFixture(socket)` is accepted only for that exact loopback socket to permit deterministic Linux/Windows PKI tests without internet calls. No other private-IP fixtures, DNS rebinding, HTTP redirects or public target scan in CI.
- Reuse existing `probe_tls_h2` without changing PKI/ALPN rules: TLS1.3, standard CA/SNI/SAN/expiry, ALPN `h2`, global semaphore **4**, end-to-end **5s** per target, no HTTP application request. Overall batch cancellation deadline **20s**. `JoinSet` aborts unfinished tasks when the future/owner is dropped; no unattended background operations.
- Preserve original input ordering in `BatchResult.results`; each entry is an explicit `Result<ProbeReport, ProbeError>`. `all_handshakes_verified` is true **only** if every individual TLS/H2 probe succeeded, **not** that browser fingerprints, REALITY or TLS-in-TLS were proven. Errors never silently fallback. Debug formatting of target/result/redacted target data must not disclose IP/SNI.
- No additional Cargo dependencies, runtime/TOML/invite/protocol changes or automatic system-proxy effects.

## Given/When/Then test gates

- Given two approved exact loopback TLS1.3/h2 fixtures, when the batch runs, then return two successful bounded reports in submitted order, with fingerprint `Unknown`.
- Given one valid H2 and one h3-only/invalid fixture, then preserve one success and one TLS error; `all_handshakes_verified=false`, no fallback.
- Given `Denied`, a missing public IP in preview, a duplicate socket, empty list or nine targets, then fail before opening sockets or scanning any range.
- Given one stalled TLS fixture with a small per-target deadline, then return `TimedOut` as its result and never emit positive evidence.

All native Linux/Windows GitHub Actions jobs, `cargo test --workspace --all-targets --locked`, `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, browser E2E and exact-head `ci-gate` must pass. Cancelled/skipped mandatory jobs are not success.

## Open constraints / alternatives rejected

Reject automatic CIDR sweeps, inherited approval from egress IP-echo, DNS resolution from the 14 popular domain seeds, arbitrary ports, retries across ALPN/PKI failures, fake pass metrics, and browser-fingerprint claims. Missing production capabilities: consent persistence and revocation in server TUI, verified delegated CIDR provenance, globally metered per-target/period rate budgets and audit, approved DNS pinning/CT evidence, QUIC/H3 probes, actual REALITY security mode and measured TLS-in-TLS shaping/classifier regressions. M4.5 two-action server UI and F-18/F-19 remain open.
