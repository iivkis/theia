# ADR-0032: M4.5d, evidence-based TLS/H2 score and confidence in server TUI

**Date:** 2026-11-23. **Status:** implemented in isolated reviewable PR; exact-head Linux/Windows CI mandatory.

## Motivation

M4.5b can manually connect to one explicitly confirmed, locally assigned public IP:443 with verified TLS1.3, CA trust, SNI/SAN, expiry and ALPN=h2. It currently shows a binary success/failure without the F-18 specification's explainable source-backed score, confidence, blockers and freshness. Guessing a high DPI-bypass probability from ordinary TLS success would be especially misleading.

## Decision

- Reuse the *existing* `TlsEvidence::suitability(Transport::H2 | H3)` rubric with weights **15 TLS1.3 + 15 trusted chain + 15 SNI/SAN + 10 certificate validity + 10 reachability + 15 transport ALPN + 20 Theia fingerprint = 100**. It is an **evidence checklist score, not a DPI bypass probability**. `confidence` is the fraction of seven fields positively measured or explicitly rejected, never a subjective prediction.
- Only when `ProbePanel` receives `ProbeState::Complete(Ok(ProbeReport))` from the **strict M3.5b2a/b3 verified TLS/H2 pipeline** is the evidence score displayed. Verify `ProbeReport.connected_ip` still equals the selected, consented, exact public IP before attributing a success. Never credit a stale or different peer.
- Normal strict TLS/H2 success verifies TLS1.3, chain, SNI/SAN, expiry, reachability, H2 ALPN: **H2 score 80/100, confidence 85%, eligible NO** because the Theia/browser fingerprint remains Unknown. H3 remains unmeasured: **H3 score 65/100, confidence 71%, eligible NO** with H3 ALPN and fingerprint Unknown. Even this outcome does not verify QUIC/H3 capability, REALITY-like authentication, nested-TLS resistance, ownership or candidate applicability.
- Present bounded, hard-coded Russian reasons for each missing/rejected metric. No secret, certificate body, header or bearer is shown; no untrusted network-supplied reason text. The UI's confidence and score are always labeled as *partial evidence* with an explicit warning that no KPI is a probability of bypass.
- Record an in-memory monotonic `Instant` when the background result reaches TUI, show age in seconds (relative to UI reception), and clear it on any separately confirmed new TLS attempt. No disk persistence, external logs, retry history, or background network changes. This is observation freshness, not a claim about certificate history or assurance that the IP remains reachable.
- A timeout, rejected certificate, bad ALPN, worker failure, missing CA or mismatched `connected_ip` gets **score Unknown** and zero positive claims, regardless of fields that might have been tentatively observed during a failed handshake. Do not synthesize `TlsEvidence::Verified` from an error.
- No changes to the scanner, crypto handshake, wire, TOML v1, `theia://v1`, roots, proxy runtime, consent controls, safe CIDR review or system proxy.

## Given / When / Then regression tests

1. Given an explicitly injected presentation-layer fixture with six verified strict TLS/H2 facts and Unknown H3/fingerprint, when rendering success, then show **H2 80/100 confidence85% eligible NO**, **H3 65/100 confidence71% eligible NO**, exact missing reasons, handshake latency and relative freshness. These are presentation tests, *not* proof that an untrusted fixture performed TLS.
2. Given a mismatched `connected_ip` on an otherwise `Ok` report, when rendering, then do **not** display verified TLS success or positive score.
3. Given bad ALPN/timeout/CA error, when rendering, then return the original safe reason and **score Unknown**, not a fake 0%-to-100% measured success. Channel poll sets relative age; a new confirmation clears it. No network calls in TUI tests.
4. All existing native Linux+Windows loopback TLS PKI and ALPN tests of `camouflage_probe` and `camouflage_batch` continue to verify the underlying evidence's provenance, including wrong cert/SNI/timeout cases. The UI must not contact third-party domains or run CI network scanner jobs.

## Non-goals

Not a full F-18 selection/Apply transaction, not proof of client browser-like fingerprint, not authorization to scan externally discovered CIDRs, not H3/REALITY or F-19 anti-TLS-in-TLS. A raw transport success is **not release readiness**. Strict locked cargo tests/fmt/clippy, native Linux/Windows BBR/BoringSSL/smoke/Chromium E2E and exact-head `ci-gate` are required.
