# ADR-0057: F-13 actual named BoringSSL/H2 browser-style profile (partial)

**Date:** 2026-11-24. **Status:** proposed, native Linux/Windows CI required.

## Problem and decision

The current \`tls_profile = "default"\` H2 client uses rustls with strict TLS1.3/PKI/ALPN and emits \`SETTINGS=[(2,0),(6,8192)]\`. The independent pinned Chromium159 test control emits \`SETTINGS=[(1,65536),(2,0),(4,6291456),(6,262144)]\`, sends a connection WINDOW_UPDATE and orders pseudo names \`:method,:authority,:scheme,:path\` instead of Theia's \`:method,:scheme,:authority,:path\`. Optional BoringSSL client work already proves strict TLS1.3 certificate verification, GREASE, ALPS and full SmartTheia OPEN_OK but is not wired into real configurations. A profile name that silently selects rustls or pretends to clone Chromium would be false evidence.

Enable the already-pinned production \`btls/tokio-btls\` backend in the normal binary on **Linux and Windows**, while retaining \`default\` as rustls at **runtime**. Explicit typed \`tls_profile = "browser-h2-btls-v1"\` with \`transport = "h2"\` selects the BoringSSL TLS1.3/SNI/CA/ALPN-h2 connector with GREASE, permuted extensions and new ALPS codepoint, then the regular SmartTheia HTTP/2 POST/HELLO/OPEN_OK full-duplex engine. A different bounded H2 Builder profile sets:

- \`SETTINGS_HEADER_TABLE_SIZE = 65536\` (Chromium159 reference value)
- \`SETTINGS_ENABLE_PUSH = 0\` (same security behavior as default)
- \`SETTINGS_INITIAL_WINDOW_SIZE = 262144\` (**far below** Chromium159's 6MiB; at most 64 local sessions, <= 16MiB aggregate nominal per-stream receive-window budget)
- \`SETTINGS_MAX_HEADER_LIST_SIZE = 8192\` (strict original limit, NOT Chromium159's 256KiB)

The resulting **real measured H2 first flight** should therefore be \`[(1,65536),(2,0),(4,262144),(6,8192)]\`, with the library's unchanged pseudo-header order and no emulated Chromium connection WINDOW_UPDATE. The actual network-based test must pin these values and ensure HTTP403 never yields OPEN_OK. Only first-flight structural metadata (IDs/name order) may be logged; raw HPACK, bearer, TLS randomness, cert contents, payload and SNI are not persisted. The real compiled client must pass both HTTP CONNECT and SOCKS5/TCP echo on native Windows and Linux.

## Fail-closed contract

- Exact profile spelling is versioned: \`browser-h2-btls-v1\`. Unknown names are rejected by TOML validation. The profile is **H2-only**; \`auto\` and \`h3\` are explicitly invalid until QUIC-compatible backend/ref is measured. A build with \`--no-default-features\` must reject this profile rather than silently falling back to rustls. Default transport \`auto\` with \`tls_profile=default\` remains unchanged.
- PEM root trust stays independent of import; BoringSSL validates peer chain, SNI, hostname and ALPN=h2 before sending bearer/HTTP. Invalid CA, token, ACL, refused TCP/QUIC or protocol errors never produce OPEN_OK. The local proxy never opens Windows system proxy except via F-07's separate explicit command and manual TOML.
- No modification to SmartTheia framing, HTTP route, bearer format, H3/QUIC code, user grants, token storage, invite v1 or system trust defaults.

## What the evidence cannot claim

The profile is **not** a byte-exact Chromium impersonation. A Chromium GET with END_STREAM differs structurally from an authenticated Theia duplex POST. BoringSSL cipher-suite/extension vectors and random extension permutation are not proven equal to a pinned browser distribution; Chromium159 pseudo-header order, 6MiB stream credit, 256KiB header cap and connection WINDOW_UPDATE are explicitly unmatched for resource and encoder reasons. H3/QUIC Initial and QUIC transport-parameter fingerprint are not implemented or referenced by this H2-only named profile. The complete **F-13 P0 remains open** until an independently measured H3 reference/backend and full Windows/Linux network comparison plus resource/benchmark/security gates pass. No DPI-evading or TLS-in-TLS immunity claim follows.

A new dedicated H3 profile requires its own version, ALPN-h3, QUIC Initial and transport-parameter measurements, strict CA and no silent H2 downgrade on identity failures. Release tracking must not count this partial profile as closing F-13/M5.

## CI/Given-When-Then

1. Given the exact valid name, \`transport=h2\` and supported BoringSSL feature, config validation and TOML round-trip succeed. Given h3/auto/unknown name/disabled backend, reject without sockets.
2. Given a production H2Client configured with this name, a real TLS1.3 handshake and H2 first-flight observer must measure the exact bounded SETTINGS and default pseudo names, compare to pinned independent Chromium159 evidence and scrub captured values.
3. Given an independently trusted self-hosted fixture, the **compiled client binary** selected by ordinary TOML with this profile must perform real HTTP CONNECT and SOCKS5 via H2 and get SmartTheia OPEN_OK/byte-exact TCP relay on native Linux and Windows.
4. Given a bogus CA, hostname mismatch, denied user/token or unapproved target, the production client must never report a successful tunnel.
5. All 14 required CI jobs including \`ci-gate\` must succeed on the exact PR SHA before review/merge.

Related ADR-0003, ADR-0009, ADR-0010, ADR-0011, ADR-0012, ADR-0013 and docs/IMPLEMENTATION_SPEC.md F-13.
