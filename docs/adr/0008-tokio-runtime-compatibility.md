# ADR-0008: isolated Tokio runtime pin upgrade for eventual M3.4 production TLS bridge

**Дата:** 2026-11-22  
**Статус:** отдельная совместимость runtime; финальная приёмка требует зелёного Linux/Windows CI на точном SHA.

## Problem

Shipping `crates/theia` has `tokio = "=1.48.0"`, while the independently verified `tokio-btls = 0.5.6` research adapter from M3.4b/c needs Tokio `>=1.52.1` (the isolated spike already pinned `=1.52.1`). Directly adding BoringSSL, modifying root `Cargo.lock` and changing production `H2Client` in one PR hides which change caused an HTTP/2, HTTP/3, BBR or Windows regression.

## Decision

For M3.4d, update **only** the production Tokio dependency to `=1.52.1` and regenerate root `Cargo.lock` with Cargo on a Linux CI runner. Preserve existing pinned versions of `h2`, `h3`, `quinn`, `rustls`, `tokio-rustls` and the independent `spikes/m3_4` workspace. No `tokio-btls` or `btls` is added to the shipping binary in this compatibility PR.

Verify on native Linux and Windows using the existing required `cargo test --workspace --all-targets --locked`, `fmt`, `clippy -D warnings`, H2 verified certificate and OPEN_OK-gate regressions, H3 QUIC/BBR, Playwright browser proxy E2E and synthetic BBR comparison. This is an infrastructure compatibility change, not a new transport, authorization rule, parser, wire version, or profile.

## Bounds and security behavior

- Strict client TLS1.3 certificate/SAN and ALPN h2 behavior is unchanged; fail-closed H3 fallback and authorized OPEN_OK semantics must remain green.
- Exactly one binary `theia`; no new user-configurable `tls_profile`, automatic OS proxy change, secret logging, fallback or user-visible behavior.
- No unsafe TLS verification and no new native BoringSSL build in production. The isolated spike still tests its own separate pinned Tokio workspace.
- Changes that accidentally require dependency graph mutation beyond the expected Tokio family must be inspected in CI generated `Cargo.lock` before merge.
- If any Linux/Windows test fails, restore old `crates/theia/Cargo.toml` pin and root `Cargo.lock` (simple dependency-only rollback).

## Explicitly not complete

This does **not** implement browser-like F-13 in Theia, H2 Chrome SETTINGS/pseudo-header fingerprints, production `H2Client` BoringSSL binding, H3 QUIC fingerprint or release BBR performance P0 thresholds. M5 stays blocked. A future narrow PR may add an opt-in experimental H2 backend only after actual production SmartTheia full-duplex/OPEN_OK/security E2E and audit of BoringSSL FFI/licensing/supply chain.
