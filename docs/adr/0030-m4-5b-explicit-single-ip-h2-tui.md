# ADR-0030: M4.5b, exact assigned-IP TLS/H2 review in server TUI

**Дата:** 2026-11-23. **Статус:** implementable narrow native Linux/Windows CI slice, not completion of F-18/F-19.

## Why this slice

M4.5a added passive local-interface/offline seed preview and explicit consented external ipify egress observation. M3.5b2b3 already includes bounded, exact-IP `probe_explicit_batch` with strict TLS1.3/h2 and negative PKI checks, but no operator UI. Unconditionally scanning the 14 seed domains, all addresses in a detected CIDR, or the IP reported by ipify would be an inappropriate third-party probe and would violate explicit authorization. The next step must offer a bounded **single exact IP** with an independent operator confirmation, a known TLS name and no hidden network effects.

## Security decision

1. In the server `p` network preview, key **t** opens an *explicit TLS/H2 review pane*; it does not start a probe. It uses **only true, UP, plausible-public IPv4/IPv6 interface addresses**, with valid assigned prefix lengths, and intersects them with offline `CandidateSource::ServerAddress`. No address is selected from the ipify witness, private LAN, provider CIDR, authorized neighbor expansion, seed domains, unassigned local route, or manual guess. Deduplicate and truncate to eight choices maximum. No target ⇒ show a clear refusal without any socket.
2. A validated selected server inbound is required. Its SNI name (`server_name`) is used for TLS hostname and SAN verification, **not** DNS resolution; `theia tui` without server configuration can view the review pane but cannot start a probe. The operator selects exactly one assigned public IP with j/k. The port is fixed **TCP/443**. Different configured inbound port is not silently tried. This is not proof of ownership or entitlement, and the consent text explicitly asks the operator to confirm authority to contact that specific address.
3. Enter/t displays a distinct **СОГЛАСИЕ НА АКТИВНУЮ TLS/H2 ПРОВЕРКУ** with the exact IP:443 and SNI; only a subsequent **y** triggers network I/O. n declines, Esc cancels and returns to passive discovery; no direct jump from ipify confirmation to probing, and no automatic network on initial page load. A standalone `y` without the confirmation state is inert.
4. Background worker, independent Tokio runtime and native system CA roots (`rustls-native-certs=0.8.5`, already required by M4.5a) call the existing `probe_explicit_batch` with a **single exact** `BatchTarget`: `ProbeApproval::public_https_ip(ip)`, strict TLS1.3 SNI/SAN/certificate/expiry and ALPN h2, original global 4-handshake semaphore, 5s per-target deadline. No HTTP application request or DNS query is sent by the active probe. Tokio oneshot + select! cancellation on Esc prevents a detached long-running task; results/errors polled by UI without blocking 50ms event loop.
5. On successful TLS and h2, display **only** verified TLS/CA/SNI/ALPN and handshake timing. Browser-like first flight, QUIC/h3, REALITY-like identity, TLS-in-TLS mitigation and bypass-probability are **Unknown**, never automatically inferred. A rejected certificate, wrong ALPN, timeout, empty system trust or any batch preflight failure produces a sanitized code and zero positive results, without retries or fallback.

## Given / When / Then tests

- Given no server TOML, p → t opens a no-SNI review; y must do nothing and Esc must return to passive discovery. Client, Home, Help screens are still excluded.
- Given a native fixture with one RFC1918 IP, two real-looking assigned public IPs and one invalid prefix, the chooser contains only the two valid publics in stable order; j/k chooses one, t/Enter **only opens confirmation** and n declines. Address and SNI must be visible before y. No external calls from tests.
- Given no selected public assigned address, disabled/down or invalid-prefix interfaces, then no selection and no outgoing TCP. Egress IP from a remote witness does not qualify.
- Given 30 public assigned addresses, limit chooser to eight; user cannot trigger CIDR or port sweep.
- Given synthetic timeout/error delivered to the UI channel, result must be failure and never say verified; given Esc or dropping the modal, the oneshot cancellation must signal the worker. Loopback strict TLS/H2 actual handshakes, PKI and ALPN remain independently covered by `crates/theia/tests/camouflage_batch.rs` on native Linux and Windows.

## Explicit non-goals

No automatic probing, no scan of BGP/RDAP routes, provider subnet, or popular domains, no manual arbitrary IP input, no Windows native OS interface collector, no persistent authority/consent, no per-period rate budget/audit, no H3/QUIC, no score/selection/Apply, no IPC reload, no change to TOML/invite/wire/system proxy. This does **not** complete two-step F-18 picker or F-19 defense. It is a deliberately conservative, functional TLS witness stage.

Required gate: exact final SHA GitHub Actions native Linux/Windows locked cargo tests, rustfmt, Clippy -D warnings, all PKI/BoringSSL/BBR checks, Chromium E2E and ci-gate. No CI calls to the public internet through this new probe; network tests for TLS are isolated loopback fixtures.
