# ADR-0074: actual browser reference policy and independent TLS interoperability

**Status:** proposed; pending full native CI.

Replace synthetic uTLS parity as a project requirement with actual pinned browser reference evidence. Existing Chromium H2 tests are retained; H3 browser reference is not implemented. Browser compatibility and equality of packet sequences are different claims. Existing measured discrepancies remain documented; no new fingerprint tuning, transport changes or claim of invisibility.

Retire Go/uTLS generator, comparison-only tests and setup steps. Keep actual Rust/rustls/BoringSSL baseline and strict PKI/auth/ACL checks. Replace independent uTLS interoperability with Python 3.12's standard OpenSSL TLS1.3 client against the same loopback Rust H2 server: verify CA/hostname/ALPN, GET/204, refuse wrong hostname and untrusted CA before sending H2 data. No external targets, trust bypass or browser emulation. Both native M0.1 jobs execute it. Existing browser, BBR, native and cross-host jobs remain mandatory. Historical ADRs are evidence at their original commit, not rewritten.

This migration is not H2/H3 browser parity acceptance. No new profile, no changes to release status or F-18/F-19. Full exact-head CI required; timing evidence will quantify savings after acceptance.
