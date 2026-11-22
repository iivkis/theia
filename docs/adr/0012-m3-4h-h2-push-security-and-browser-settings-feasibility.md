# ADR-0012: M3.4h safe HTTP/2 push opt-out and isolated Chromium SETTINGS feasibility

**Date:** 2026-11-22  
**Status:** PR CI acceptance pending, not a named browser profile.  
**Context:** ADR-0009, ADR-0010, ADR-0011. **F-13 / F-11 / M5 remain BLOCKED.**

## Verified sources and threat model

Actual pinned Playwright Chromium 159.0.8154.6 emitted initial SETTINGS in this exact wire order:

- `(1,65536)`: maximum advertised response HPACK decoder table
- `(2,0)`: disable unsolicited server push
- `(4,6291456)`: initial per-stream receive window
- `(6,262144)`: maximum response header list size

Its first request had pseudo names `:method,:authority,:scheme,:path` and an observed pre-HEADERS `WINDOW_UPDATE`. Existing Theia H2 was `[(6,8192)]`, with pseudo names `:method,:scheme,:authority,:path`. Both TLS backends share `h2 0.4.19`, and both pass production SmartTheia HELLO/OPEN_OK-gated full-duplex tests.

Merely copying all four Chromium SETTINGS into production creates a larger peer-controlled decoding surface: response header allowance jumps from 8 KiB to 256 KiB (**32x**); each receiving stream window grows from 65,535 to 6,291,456 octets (over **96x**); advertising a 65,536-byte HPACK table also increases the peer's possible decoder state. On concurrent requests, those increases undermine bounded-memory assumptions and would need separate adversarial byte-limit/connection-count/RSS validation. The post-SETTINGS WINDOW_UPDATE connection credit and pseudo-header encoder order also remain different. Faking a Chrome fingerprint by breaking resource limits is prohibited.

## Decision

1. Make the **one safe independent HTTP/2 change** to the shared production `H2Client` builder: set `enable_push(false)`. The client does not support unsolicited server push. This advertises `SETTINGS_ENABLE_PUSH=0` at connection creation and forbids the server from pushing promised streams, without increasing receive buffers or changing the application protocol. It affects both default `rustls` and explicitly feature-gated `BoringSSL`.
2. Retain `max_header_list_size(8192)` and all existing default HTTP/2 receive windows, request-body flow control, timeouts, ownership, strict TLS1.3 CA/SAN/ALPN, bearer authorization, SmartTheia HELLO/OPEN_OK, target ACL and fail-closed H3→H2 fallback. Do not expose `tls_profile`, CLI/TOML switch or enable BoringSSL by default.
3. Update the **actual first-flight wire regression** to require `[(2,0),(6,8192)]` in that order. Native CI feature matrix must observe the same ordered SETTINGS from both TLS backends; the normal rustls test uses `cargo test --workspace --all-targets --locked`.
4. Add a **test-only** builder capability experiment: `h2::client::Builder` with `header_table_size(65536)`, `enable_push(false)`, `initial_window_size(6291456)`, `max_header_list_size(262144)` over bounded Tokio duplex. Read actual first SETTINGS bytes and compare ordered pairs to the independently captured Chromium159 values. This validates API/encoding feasibility, not safe resource budgets, not Chrome-like pseudo-header ordering, not a TLS profile, not actual browser authentication, and does not ship those large values.
5. Keep the mandatory Linux/Windows regression matrix unchanged: default native rust tests, native feature tests, strict PKI/auth/ACL and 128 KiB streaming/FIN, Chromium browser SOCKS5 E2E and loopback Chromium reference, H3/BBR comparisons, `rustfmt`, `clippy -D warnings` and exact-head `ci-gate`.

## Given / When / Then

- **Given** default `H2Client::new` and opt-in `new_experimental_btls`, **when** connecting over strict TLS1.3 and H2, **then** real decrypted first-flight is `SETTINGS [(2,0),(6,8192)]`, pseudo order remains unchanged, and the application never obtains a `Tunnel` from premature HTTP 403 or failed OPEN_OK.
- **Given** the real production server and 128 KiB echo origin, **when** BoringSSL is explicitly compiled and selected by CI test code, **then** full-duplex + both FINs + strict negative CA/SAN/token/ACL/ALPN regressions remain green; default `rustls` browser E2E remains unaffected.
- **Given** the high-risk test-only builder, **when** its first actual HTTP/2 SETTINGS frame is parsed, **then** its ordered wire parameters match captured Chromium159; none of its larger resource budgets are applied in the production constructor.
- **Given** malformed settings or a missing Playwright Chromium binary, **when** CI runs, **then** the relevant test fails rather than using handcrafted reference data or silently skipping.

## Explicit remaining blockers

- **NOT** a full Chrome159 profile: TLS ClientHello Go uTLS `HelloChrome_133` is a different reference/version, browser first-flight used GET while Theia uses duplex POST, HTTP/2 pseudo-header order is still different, SETTINGS 1/4/6 remain different in production, and observed browser WINDOW_UPDATE remains unimplemented as a profile.
- **NOT** a proof of 6 MiB stream windows or 256 KiB headers being resource-safe. Independent peak RSS, concurrent slow-reader, server-generated header bomb and parser/memory benchmarks are required before a profile can safely advertise them.
- **NOT** an H3 QUIC Initial fingerprint/crypto adapter; F-13 and M5 stay open, and F-11 needs release-grade performance evidence.

**Rollback:** remove `enable_push(false)`, restore production baseline regression and remove the test-only feasibility file/ADR. No config, wire-version or migration needed.
