# ADR-0011: M3.4g real Chromium HTTP/2 first-flight control

**Date:** 2026-11-22  
**Status:** experimental CI reference, not a browser-like production fingerprint; final exact-SHA CI pending.  
**Related:** ADR-0005, ADR-0009, ADR-0010. **F-13, F-11 and M5 remain BLOCKED.**

## Problem

M3.4f measures production H2Client over rustls and experimental BoringSSL on actual decrypted TLS1.3/H2 wire. Its initial SETTINGS are `[(6,8192)]` and its pseudo-header names occur `:method, :scheme, :authority, :path`. The existing pinned Go uTLS `HelloChrome_133` only replicates the **TLS ClientHello**; the hand-written Go H2 smoke probe has empty SETTINGS and static HPACK and must **not** be described as a Chrome HTTP/2 reference.

We need an independent HTTP/2 reference from an actual Chromium engine before choosing a named profile. H2 SETTINGS and header ordering are observed after the client TLS handshake, never inferred from `User-Agent`.

## Limited vertical slice

Use the already pinned **CI-only** Playwright `1.65.2` Chromium in the Linux/Windows `browser-e2e` job to navigate **exactly one** HTTPS URL on `127.0.0.1`. The reference Rust test `chromium_h2_reference.rs` creates an ephemeral, loopback-only TLS1.3 server with ALPN `h2` using `rustls` and a generated self-signed fixture leaf. It wraps the decrypted H2 server connection in the bounded first-flight metadata observer from ADR-0010.

The browser performs an actual GET, receives HTTP 200 with a fixture DOM marker, and closes cleanly. The observer captures and then scrubs all raw H2 bytes. Only the first SETTINGS ID/value list, intervening frame type IDs, optional server SETTINGS ACK flag, exact recognized HPACK pseudo-name ordering and ordinary header **count** appear in the CI log; no header values, key material, cookies, session tokens, or network-facing raw captures are stored.

The browser reference disables QUIC, background networking and external DNS; Playwright route interception blocks all requests except the one allowed loopback URL. No proxy, external service, production certificate or user browser profile is involved. The compiled `theia` app, configuration, TLS verifier, BoringSSL feature flag and binaries are unchanged.

### Strict research-only certificate trust exception

Because Chromium is only a **reference frame generator** and the server uses a disposable self-signed test-only leaf, that browser context sets `ignore_https_errors=True`. This is explicitly **not** X.509 validation evidence, is **not** a Theia TLS setting, and must **never** be copied to the shipping binary or the existing Theia strict CA/SAN/ALPN tests. The Theia TCP/TLS correctness tests remain independently mandatory and strictly verify trust. A future study could provision an ephemeral trusted private root into a disposable Chromium certificate store and remove this test-only browser exception. Do not infer whether Chrome's H2 behavior is identical across trust paths without that additional evidence.

## Given / When / Then

- Given native CI Chromium and a loopback-only TLS1.3/ALPN `h2` server, when a page navigates to `https://127.0.0.1:port/ci-chromium-h2-reference`, then the response must contain the exact fixture DOM marker, and the first **real Chromium-authored** HTTP/2 SETTINGS and header-name ordering are measured.
- Given bytes above 64 KiB, frames above 16 KiB, malformed SETTINGS/ACK, missing/duplicate pseudo fields, or unsupported HPACK name layout, then the metadata observer must error rather than log raw values or guess.
- Given the M3.4f Theia baseline `[(6,8192)]`, when the Chromium reference is obtained, then its SETTINGS are compared separately and its pseudo-name order is printed (names only). A differing browser profile is evidence of the gap, **not** evidence that Theia now matches Chrome.
- Given a browser test script or Chromium binary missing on either platform, the mandatory job fails rather than silently skipping. No CI job may be marked successful by a synthetic fixture that pretends to be Chromium.

## Confirmed actual Chromium reference (native Linux and Windows)

The first-pass Chromium reference test passed **on both OSes**, with Playwright `1.65.2` provisioning Chrome for Testing **159.0.8154.6**, headless Chromium revision `1255`. On each runner, the actual browser visited the isolated HTTPS origin, received the expected HTTP 200/DOM content and emitted:

| On-wire field | Chromium reference | Existing Theia production H2 baseline (M3.4f) |
| --- | --- | --- |
| First SETTINGS in wire order | `[(1,65536),(2,0),(4,6291456),(6,262144)]` | `[(6,8192)]` |
| Recognized pseudo-name order | `:method,:authority,:scheme,:path` | `:method,:scheme,:authority,:path` |
| Pre-first-HEADERS frame type observed | `[8]` (WINDOW_UPDATE) | `[]` (optional SETTINGS ACK excluded) |
| Ordinary headers, name count only | 14 | 2 |
| HEADERS END_STREAM | `true` (GET without body) | `false` (SmartTheia POST with open duplex body) |

The four ordered SETTINGS and four recognized pseudo names are now **exact regression assertions** on the Playwright 1.65.2/Chromium 159 reference. WINDOW_UPDATE timing and header **count** are observations only, not stable acceptance criteria: the browser GET and Theia POST are different workloads. Any Chromium revision bump requires deliberate comparison and test revision. A CI passing result on this reference does **not** establish browser-like Theia profile, TLS cipher-suite fidelity, X.509 trust for the browser, or H3/QUIC Initial.

## Release guards

No implementation of Chrome's exact SETTINGS/priority/window/HPACK policy, no TLS cipher-suite/extension equality, no H3/QUIC Initial profile, no default BoringSSL backend, no config migration. This experiment measures browser GET vs authenticated Theia POST, so header/END_STREAM differences due to **different request semantics** must not be interpreted as fingerprint gaps independent of workload. Later matching must use a like-for-like request and actual verified reference profile, with regression E2E across Linux and Windows. F-13 and M5 remain open.

Rollback: remove the test-only Rust/Python files, the added browser-e2e step and this ADR; production code unchanged.

## Follow-up safety alignment, ADR-0012 (M3.4h)

The original Chromium159 and Theia measurements in this ADR remain historical evidence of the pre-M3.4h production client. ADR-0012 changes exactly one **production** H2 setting to disable server push; the new Theia initial SETTINGS become `[(2,0),(6,8192)]`, while Chromium159 reference stays `[(1,65536),(2,0),(4,6291456),(6,262144)]`. Theia's 8KiB response header and default credit bounds remain unchanged. The independent first-flight tests enforce the new baseline and the full Chrome-like profile remains blocked.
