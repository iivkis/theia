# ADR-0009: M3.4e production H2Client with an isolated experimental BoringSSL TLS backend

**Дата:** 2026-11-22  
**Статус:** implementation in PR, awaiting exact-SHA Linux/Windows CI acceptance. **F-13 P0 and M5 remain BLOCKED.**  
**Связано:** ADR-0005, ADR-0006, ADR-0007, ADR-0008.

## Context

Existing production `H2Client` uses strict `rustls` TLS1.3 + H2 and a SmartTheia HELLO/OPEN_TCP/OPEN_OK-gated full-duplex relay. M3.4a showed that real default rustls H2 ClientHello does not have GREASE or ALPS. M3.4b/c demonstrated on Linux/Windows that `btls 0.5.6` + `tokio-btls 0.5.6` emit GREASE and ALPS 17613, verify CA/SAN, enforce ALPN h2 and drive standard H2 full duplex. ADR-0008 updated production Tokio to 1.52.1 with native regressions before the backend boundary changes.

The next P0 risk is integration with the **real shipping SmartTheia state machine**, not another synthetic H2 stream or fake HTTP header. However a raw backend prototype is not ready to advertise as Chrome-like or switch on by default. BoringSSL introduces native dependency/supply-chain and audit risks, a separate PEM trust format and H3 incompatibility.

## Decision

Add an **explicitly feature-gated, non-default** Cargo capability named `experimental-btls-h2`. The source is linked into the `theia` library when that feature is requested, but neither the normal CLI nor TOML can select it. Add a test-accessible constructor `H2Client::new_experimental_btls(endpoint, server_name, token, trusted_ca_pem)` for a single explicit CA PEM. The production application continues to instantiate `H2Client::new` (rustls), with no runtime switch, user-facing option, fallback or H3 change.

Within `H2Client::open_inner`, only the TLS → H2 connector varies:

- **rustls default:** unchanged pinned TLS 1.3 and ALPN h2 validation.
- **BoringSSL experimental:** `SslConnector::builder(SslMethod::tls())`, TLS1.3-only, `SslVerifyMode::PEER`, explicit X509 CA verification store, hostname verification, SNI and ALPN `h2,http/1.1` with strict **selected h2** check, GREASE and new ALPS 17613. No verification bypass or insecure fallback.
- Both feed the same standard `h2::client::Builder` (8 KiB max response-header list), same owned/abortable H2 driver, HTTP bearer header creation, HTTP 200/auth denial gate, SmartTheia `HELLO_ACK`/`OPEN_OK` and `Tunnel::relay`. No TLS handshake error can create a tunnel or authorize HTTP headers.
- Preserve the existing 60-second `open` and 30-second I/O timeout protections, 4096-byte relay buffer and bounded flow-control behavior.
- No external endpoints: native Linux and Windows required CI tests use ephemeral loopback CA/leaf with distinct subject names, production `server::serve` and an echo origin.

## Given / When / Then and adversarial verification

- Given explicit trusted CA, correct SAN, valid 32-byte canonical bearer, grant and test-only loopback destination allowance, when `new_experimental_btls().open()` connects to production `server::serve`, then it returns a tunnel only after HTTP authorization/HELLO_ACK/OPEN_OK. Relay 128 KiB exactly, preserve two half-closes and bounded flow control.
- Given wrong SAN / unrelated trusted root / wrong bearer / denied private destination / ALPN `http/1.1`, when `open()` is called, then error is returned and no authorized target TCP connection can be established.
- Given an unverified synthetic loopback TLS peer, when the actual **production** H2Client BoringSSL ClientHello is inspected, then it shows GREASE, ALPS 17613, TLS1.3, SNI and `h2,http/1.1`; the peer is rejected without sending application credentials and the raw handshake is immediately discarded, never logged.
- The full `ci-gate` requires a new native Linux/Windows `m3-4e-btls-production-feature` matrix job with `cargo test --locked --features experimental-btls-h2 --test client_btls_h2`, rustfmt and feature clippy `-D warnings`, alongside all existing browser/BBR/H3/production jobs.
- The root `Cargo.lock` gets regenerated in CI and pinned. The default build still excludes the native dependency in its dependency tree and uses rustls.

## Deliberate exclusions and risk

- **Not** a named TLS+H2 Chrome133 browser fingerprint, no H2 SETTINGS/pseudo-header ordering acceptance, no JA3/JA4 or matching cipher/extension sequences; prior Go uTLS reference is used to measure gaps. GREASE/ALPS alone never closes F-13.
- **Not** a QUIC crypto adapter: H3 and BBR behavior remain on quinn/rustls. Never fallback from certificate, auth, ALPN, transport protocol mismatch, or SmartTheia denial to another transport.
- **Not** a default backend or usable TOML `tls_profile`. The new constructor requires test code to supply PEM CA; no OS root store handling, cert-bundle merging or new system-proxy behavior.
- Native C/BoringSSL packaging/licensing/supply-chain audit and CPU/RSS/binary-size evidence remain required before switching the shipping default. Windows ABI must be validated by the required feature job, not inferred from Linux.
- Any compile/test failure keeps the feature hidden and PR unmerged. Rollback removes optional crates, the gated module and constructor, root lockfile changes and feature tests. No database, wire or config migrations.

Do not claim F-13 P0 or M5 completion after this experimental compatibility milestone.
