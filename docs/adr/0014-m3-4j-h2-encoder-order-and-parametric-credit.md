# ADR-0014: M3.4j actual h2 encoder invariance across HTTP requests and independent connection credit

**Date:** 2026-11-22  
**Status:** isolated additional CI acceptance pending, no shipping code change.  
**Depends on:** ADR-0012, ADR-0013 and merged PR #37. F-13/F-11/M5 remain BLOCKED.

## Motivation

Native Chromium159 research (PR #35, ADR-0011) measured SETTINGS `[(1,65536),(2,0),(4,6291456),(6,262144)]` and pseudo order `:method,:authority,:scheme,:path`. M3.4h (PR #36) safely disabled server push while keeping Theia's 8KiB header budget. M3.4i (PR #37) independently measured the browser's **connection** WINDOW_UPDATE increment **15,663,105 bytes**, corresponding to **15,728,640 bytes / 15MiB total credit**, and enforced strict first-flight frame bounds. It also established the underlying h2 0.4.19 HPACK pseudo encoder ordering constraint.

A separate unanswered empirical question is whether varying ordinary application HTTP header insertion order or GET versus POST can affect the pinned h2 encoder's pseudo-header order, and whether the connection window and SETTINGS can be configured independently with *other* values without changing production memory guards.

## Decision and acceptance

Add a **CI-only** `h2_client_shape.rs` test, built on the **already validated** bounded metadata inspector from PR #37. It drives real `h2::client::Builder` over Tokio duplex, never synthesizes request frames, never emits real bearer material, zeros the in-memory raw capture after metadata extraction, and has a 12-second deadline / 64KiB maximum first-flight transcript.

Given/when/then:
1. **Given shipping H2 bounds** (`enable_push(false)`, `max_header_list_size(8192)`, default flow windows), when the h2 encoder receives a POST with ordinary headers inserted in two opposite orders or a GET with a benign header, **then** it still emits the same initial SETTINGS `[(2,0),(6,8192)]`, no connection WINDOW_UPDATE, and pseudo order `:method,:scheme,:authority,:path`. This is not Chromium's `:method,:authority,:scheme,:path`, and ordinary header order is not a supported pseudo-header ordering control.
2. **Given test-only connection target 6,291,456 bytes (6MiB)** while the other shipping bounds remain unchanged, when the real h2 encoder writes the preface, **then** initial SETTINGS remain identical, but a stream-0 WINDOW_UPDATE with exactly **6,225,921 bytes** increment appears before HEADERS. This is a deliberately **smaller, independently selected value**, not the actual Chromium **15MiB** target from PR #37. It shows the two encoder controls are separate.
3. **Given Chromium159 four SETTINGS** in a test-only h2 Builder plus the separately chosen 6MiB connection credit, **then** actual on-wire SETTINGS match the Chromium capture and a WINDOW_UPDATE with 6,225,921 bytes is observed; the pseudo names **still** use the standard h2 order. This does **not** prove Chrome-like behavior or resource safety.
4. **Given native Linux and Windows** mandatory feature CI, the tests must pass alongside strict CA/SAN/ALPN, auth/ACL, SmartTheia OPEN_OK, H2/H3 duplex FIN, BBR, browser E2E, rustfmt, clippy `-D warnings` and exact-head `ci-gate=success`. Errors are not waived.

## Security boundary

No production `crates/theia/src` files, CLI, TOML, H3, user PKI, default rustls backend, optional BoringSSL configuration, dependency pins or Cargo.lock change. The experiment's 6MiB credit and Chromium's 256KiB headers remain **out of production**. Browser-like HPACK order would require supported, audited codec changes or a separate design; reimplementing HTTP/2 ad hoc is prohibited. The Chromium reference is GET over an isolated browser-only TLS fixture, whereas SmartTheia uses authenticated full-duplex POST. No release claim; F-13 and M5 remain BLOCKED.

Rollback removes the test-only module, one CI invocation and documentation. No migration.
