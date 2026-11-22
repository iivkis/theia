# ADR-0028: M3.5b2b4, consented default dual-stack ipify endpoint

**Date:** 2026-11-23. **Status:** implemented as an opt-in library default; acceptance requires exact-head Linux/Windows GitHub CI.

## Background

M3.5b2b2 intentionally avoided preselecting a third-party HTTPS witness. For users who actively request public egress-IP discovery, the service must now have a predictable default. Official ipify documentation specifies `https://api64.ipify.org/` (not `.com`) as its dual-stack IPv4/IPv6 plain-text API; the chosen reported address family depends on the connection's IP family, so this is NOT guaranteed to return both IPv4 and IPv6 in one request. `https://api.ipify.org/` is IPv4-only and `https://api6.ipify.org/` is IPv6-only.

## Decision

- The default is the fixed HTTPS URL **`https://api64.ipify.org/`**, exposed through `DEFAULT_EGRESS_SERVICE_URL` and `DEFAULT_EGRESS_SERVICE_HOST`. `default_ipify_request(pinned_address)` prepares a real `EgressRequest` with the exact hostname, path `/` (text response) and up to 5 s deadline. No JSON decoder, no external JSON parser and no new runtime dependency.
- `observe_default_ipify(roots, IpifyConsent::Approved)` is the *only* opt-in DNS+TLS convenience entry point. `IpifyConsent::Denied` (the default) returns `NotApproved` before DNS/TCP. Empty CA roots return `NoTrustAnchors` before DNS. The calling UI/API must explicitly inform/ask the operator that connecting to ipify exposes the observed source IP to that service. Merely opening TUI or viewing offline plan never calls the provider.
- After consent, resolve the **fixed** host via Tokio DNS (not an arbitrary HTTP input). Select one plausible public address on **TCP/443**, pin the actual TCP connection to that IP and validate the official `api64.ipify.org` DNS name via normal rustls TLS 1.3 CA/SAN/expiry checks, with ALPN `http/1.1`. Do not try private/loopback/link-local/reserved DNS answers, follow redirects, trust DNS alone for identity, try HTTP fallback, retry different addresses or switch to `.com`. The 5 s outer timer includes DNS, TCP, TLS and bounded HTTP response.
- Retain all M3.5b2b2 response restrictions: success status HTTP/1.1 200, unique Content-Length, max 4 KiB header / 64 B body, plausible globally routable parsed IPv4/IPv6, and no positive result on errors. The returned address is an authenticated **witness claim**, not proof of NAT, ownership of a CIDR, inbound connectivity or authority to scan neighboring IPs. Downstream preview is always passive unless the operator separately approves a CIDR. This new default never creates scanner approval.
- `observe_public_egress` remains available for custom exact-pinned services/fixtures without DNS. This change does not change the TOML v1 schema, `theia://v1`, proxy runtime, TLS backend, keys or allowlist defaults. The default IP service is a library API, **not an auto-run TUI feature**.

## Given/When/Then, failure tests

- Given the stock configuration, expect exact host `api64.ipify.org`, URL `https://api64.ipify.org/`, text `/` path, TLS hostname and bound deadline.
- Given Denied, do not run DNS or open a socket, even with empty roots; return NotApproved. Given Approved but no roots, return NoTrustAnchors before DNS.
- Given a locally provisioned strict-TLS fixture with SAN `api64.ipify.org`, the exact preset Host/path must retrieve a plausible IPv4 or IPv6 text body, with the correct provenance. This tests the request's real TLS/HTTP behavior on both Linux and Windows **without contacting ipify in CI**.
- Given a private IP response, reject without positive evidence; continue to enforce existing wrong CA/SNI/ALPN, redirect, timeout and HTTP-injection rejection tests.
- Mandatory native Linux/Windows jobs: locked cargo tests, rustfmt, clippy, BoringSSL/PKI, browser E2E and exact-head ci-gate. A skipped/cancelled/failed job is not acceptance.

## Tradeoffs and limitations

An external ipify request and DNS resolution reveal the server's network path to chosen infrastructure and its DNS resolver; users must explicitly opt in. The implementation chooses one public DNS answer; broken IPv6 routing can cause a closed failure rather than automatic IPv4 fallback. The remote service may be unavailable or dishonest: TLS verifies its identity, not its claims. This is not a privacy/anonymity guarantee or a READY release feature. No live internet calls run in CI. A future TUI consent/persistence/audit path and standard CA-root provisioning are separate work.
