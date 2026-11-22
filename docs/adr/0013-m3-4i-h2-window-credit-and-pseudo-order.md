# ADR-0013: M3.4i window credit observation and immutable h2 pseudo-header order

**Date:** 2026-11-22
**Status:** research-only measurement, exact-SHA native CI acceptance recorded in PR #37. F-13/F-11/M5 remain BLOCKED.
**Depends on:** ADR-0009 through ADR-0012.

## Evidence and trust boundary

M3.4g recorded the independently generated Chromium 159.0.8154.6 HTTP/2 first flight on native Linux/Windows: `SETTINGS [(1,65536),(2,0),(4,6291456),(6,262144)]`, first `WINDOW_UPDATE` (frame type 8) before HEADERS, HPACK pseudo names `:method,:authority,:scheme,:path`. Theia's real production `H2Client` after M3.4h uses `SETTINGS [(2,0),(6,8192)]` and pseudo order `:method,:scheme,:authority,:path`. Its default receive flow credit remains 65,535 bytes and every tunnel has a dedicated H2 connection.

The pinned [h2 v0.4.19 `src/frame/headers.rs` `Iter::next`](https://github.com/hyperium/h2/blob/v0.4.19/src/frame/headers.rs#L713-L750) serializes method, **scheme, authority**, path in a fixed order. Constructing HTTP `Request` fields in a different order does **not** reorder these encoder-controlled pseudo headers. A named browser-like match cannot be obtained merely by changing user headers, request URI construction, SETTINGS or User-Agent. Modifying or replacing `h2` would be a separate reviewed decision with standards/security interoperability tests. No custom HTTP/2 stack may be silently introduced.

The pinned [h2 v0.4.19 `client::Builder::initial_connection_window_size`](https://github.com/hyperium/h2/blob/v0.4.19/src/client.rs#L710-L743) changes **connection** receive credit and sends a WINDOW_UPDATE when the new target exceeds the default 65,535. This is independent of `initial_window_size` (per-stream SETTINGS id=4). Both limits increase potential peer-controlled, in-flight response data and are not safe to copy from Chromium without adversarial memory and slow-consumer evidence.

## Narrow decision (CI-only, no runtime/config/dependency changes)

1. Extend the bounded, test-only decrypted H2 first-flight observer with `connection_window_updates: Vec<u32>`. Validate every observed pre-HEADERS WINDOW_UPDATE: exactly four bytes, stream **zero**, flags zero, reserved high bit clear, **nonzero increment** and a hard cap on the number of updates. Preserve existing 64 KiB raw capture, 16 KiB per-frame and 32 KiB HPACK bounds and scrub raw header/authorization bytes. Never log secret payloads.
2. Measure the numeric connection WINDOW_UPDATE increment on the **actual Chromium 159** loopback TLS1.3/ALPN-h2 reference, on both native Linux/Windows. Log only numeric credit and frame types, not a full packet. Do **not** pin its presence relative to HEADERS, because that is timing-dependent, as with SETTINGS ACK. If present, validate and report its exact value.
3. Run a separate **test-only** `h2::client::Builder` on a 64 KiB bounded Tokio duplex with `initial_connection_window_size(15_728_640)`, while preserving Theia's `ENABLE_PUSH=0` and 8 KiB header budget in that test. Verify the actual first client SETTINGS are `[(2,0),(6,8192)]` and the next emitted frame is a connection-level WINDOW_UPDATE with increment `15_728_640 - 65_535 = 15_663_105`. That proves standard h2 can express this wire behavior; it does **not** establish it should be used in a production profile. The actual Chromium credit is independently measured, not assumed.
4. Keep the **production** `H2Client::start_h2` unchanged: default 65,535 connection/stream credit, 8 KiB response header cap, no server push, strict TLS CA/SAN/ALPN, bearer auth and SmartTheia HELLO/OPEN_OK/FIN. BoringSSL remains a non-default Cargo feature; no `tls_profile`, fallback or OS proxy change.
5. Run parser invalid WINDOW_UPDATE tests and real Chromium reference on every platform in native mandatory CI, and run the test-only builder experiment in the native Linux/Windows BoringSSL-feature CI job; default rustls tests, H3, BBR, Chromium SOCKS5, Go uTLS, formatting, Clippy and exact-head `ci-gate` remain mandatory.

## Given / When / Then

- **Given** one real Chromium TLS1.3/H2 test-only GET, **when** the decrypted first flight contains a connection WINDOW_UPDATE before HEADERS, **then** inspect the exact credit, reject malformed lengths/flags/stream IDs/reserved bit/zero and scrub the captured bytes.
- **Given** real default rustls or experimental BoringSSL production H2Client, **when** opening an authenticated SmartTheia POST to the reference server, **then** the initial SETTINGS and pseudonames remain the previously pinned values, and there is no unexpected pre-HEADERS WINDOW_UPDATE. The server HTTP 403 before EOF must still fail closed, without a Tunnel.
- **Given** a research-only h2 builder with a 15 MiB target, **when** its driver sends connection setup bytes, **then** the first SETTINGS are unchanged and next actual frame is a 4-byte stream-0 WINDOW_UPDATE credit 15,663,105. No production setting is modified.
- **Given** wrong TLS cert/ALPN/token/ACL and the real 128 KiB full-duplex FIN scenario, **when** mandatory CI runs, **then** the established strict negative/protocol tests remain green on Linux and Windows.

## Verified numeric Chromium159 WINDOW_UPDATE (CI evidence)

The initial independent native Linux and Windows Chromium reference runs both produced the **same actual HTTP/2 connection WINDOW_UPDATE increment**: `15_663_105` on stream zero (frame type 8). Combined with the standard initial connection window of `65_535`, Chromium's first observed target is exactly `15_728_640` bytes (15 MiB). The HTTP/2 first-flight in each case also had SETTINGS `[(1,65536),(2,0),(4,6291456),(6,262144)]` and pseudo names `:method,:authority,:scheme,:path`. The independent bounded `h2 0.4.19` test-only builder emitted the **same** `15_663_105` credit using its public `initial_connection_window_size(15_728_640)` API.

A new browser regression asserts the increment **if it appears before first HEADERS**, while allowing the entire WINDOW_UPDATE to occur later because network event ordering varies. It still rejects any malformed early WINDOW_UPDATE frame or unexpected increment. A timing-dependent absence never constitutes proof of identical Chrome/Theia browser fingerprint. These results are confirmed on **native Linux and Windows CI** and do not establish memory safety at 15 MiB.

## Risks and remaining blockers

- **Do not ship a 15 MiB connection window or 6 MiB per-stream credit without concurrent slow-reader, flooding, header-bomb and peak-RSS evidence.** This is a capacity and DoS boundary, not just a fingerprint field.
- A custom pseudo-order API is not exposed by pinned `h2` (see source link above). A full like-for-like browser POST reference, verified TLS ClientHello on the **same** Chrome version, and separate H3 QUIC Initial remain unimplemented; F-13 remains blocked.
- The research-only Chromium fixture's `ignore_https_errors` is deliberately limited to its ephemeral local reference certificate; it is not PKI acceptance. Theia itself never disables TLS verification.
- No release-grade F-11 BBR performance/peak RSS evidence or M5 acceptance is implied by this measurement.
- Rollback removes the test-only parser extension, h2 builder experiment, CI invocation and documentation. No production migration.

