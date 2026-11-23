# ADR-0036: M4.5h, domain catalogue DNS consent and separately authorized H2+H3 pinned-IP checks

**Date:** 2026-11-23. **Status:** in-progress production TUI enhancement; native exact-head CI required.

## Motivation and trust boundaries

F-18 specifies that a candidate obtained from the HTTPS domain catalogue must be usable with both HTTP/2 over TCP TLS1.3 and HTTP/3 over UDP QUIC TLS1.3 on the **same exact pinned IP and SNI**. M4.5f has source-aware approved domain/IP pin probes and M4.5g has an individual-IP picker for CIDRs, but ordinary TUI users have no way to resolve one domain and select/approve its exact IP candidates. DNS lookup, network scanning, DNS answers and cryptographic REALITY eligibility are **four distinct operations**. A popular domain in the catalogue is never proof of delegated rights to active-check every address it returns.

## Decision / UI

From server `p → r → d`:

1. The 14-versioned static HTTPS seed names are displayed locally, no DNS/HTTP/QUIC/TCP. **j/k** selects one name. **Enter** discloses that a DNS A/AAAA request for **that one** domain may be visible to the OS resolver/upstream network and cannot establish ownership. **Only a separate y** launches one bounded background `tokio::net::lookup_host((domain, 443))` attempt, up to 5 seconds, with explicit denial (n/Esc). No bulk catalogue resolution or periodic checks.
2. Resolve results are **fully validated before exposing any IP to the active picker**: at most 64 answer records; if *any* reply is private, loopback, link-local, special-purpose, documentation, multicast, invalid or non-HTTPS port, reject the **entire set**, not only the offending element. Deduplicate; expose at most **eight** plausible public IPv4/IPv6 IPs. No DNS response data or errors are sent to logs; only fixed safe failure codes. Domain is from the exact static catalogue. The IP list is a **local observation**, not a permission.
3. Display every pinned IP:443 and original domain as **fixed TLS SNI**. j/k chooses, Space independently selects up to eight exact IPs. Enter opens **SECOND** disclosure listing **every selected exact socket/SNI pair**, CA/TLS1.3/ALPN h2 over TCP and QUIC/TLS1.3/ALPN h3 over UDP, 2 concurrent candidates, 5s each, 20s total. The operator must have independent active-checking rights for **each specific IP**. Only an additional **y** authorizes these handshakes. n/Esc cancel without opening a socket.
4. The batch uses the already verified `camouflage_dual_batch::probe_dual_batch`, `CandidateConsent::PinnedDomain {domain, pinned_ip}`, `ProbeApproval::public_https_ip(ip)` for each exact IP, and system native CA roots. The original domain must **exactly** match TLS SNI/SAN; TCP and UDP connect to the **pinned IP** without any second DNS query (no DNS rebinding inside Theia). Any private/unsafe/changed target fails the batch's all-target preflight. No fallback, redirect, HTTP application request, retry, blanket scanning, writable config/runtime/proxy or persisted consent.
5. The DNS snapshot expires **60 seconds** after reaching the TUI (monotonic `Instant`). Stale pins cannot open the second confirmation or start active probes. A new domain selection or Esc discards previous IP pins/consent entirely. UI runs DNS and the TLS batch in separately cancellable workers outside the 50ms event loop. Escape while a worker runs requests cancellation and returns immediately.
6. Display per-exact-IP H2 and H3 verified score/confidence or Unknown, and `dual_verified_count()/N`. A candidate with only one working transport does NOT qualify. Even a dual TLS success is NOT proof of working HTTP/3 requests/SETTINGS, Chrome-style first flight, REALITY-like cryptographic server identity/anti-replay, or F-19 TLS-in-TLS resistance. Overall **REALITY: НЕ готов** stays explicit. Score is not a probability of bypassing DPI.

## Given / When / Then

- Given the offline 14-domain seed list, when browsing or pressing y without prior Enter, then **zero DNS and zero TCP/UDP**. After Enter/y, only one selected DNS name is queried; n/Esc mean no query.
- Given a deterministic DNS answer fixture `93.184.216.10:443`, `[2606:4700::1111]:443`, duplicate, when vetting, then deduplicate to two IPs. Any mixed public+private, loopback, documentation, wrong port, or >64 replies **rejects the entire DNS batch**. Limit preview to 8.
- Given a successful DNS worker response, when the user hasn't checked an IP via Space, Enter/y still must not start probes. After Space and Enter, exactly the checked `IP:443/SNI` pairs are enumerated; n or Esc cancels. Never use DNS again on the TCP/UDP path.
- Given an IP observation older than 60s, reject confirmation and insist on a new explicit DNS lookup. A different catalog domain discards all pins and selected addresses.
- Given malformed/mismatched domain, denied approval, wrong trust roots, denied SNI/IP or only one successful transport, fail closed, unknown scores; no REALITY readiness. Existing native Linux/Windows `camouflage_dual_batch` loopback fixtures with a generated certificate SAN `google.com` exercise pinned-domain exact SNI and independent real TCP/H2 and UDP/H3 without any third-party DNS/network in CI.
- Unit tests for TUI state inject only synthetic channel values and never call public DNS, exercise cancel and expiry. Full native locked Linux/Windows tests, rustfmt, Clippy -D warnings, BBR/BoringSSL, Windows smoke, Chromium E2E and final exact-head `ci-gate` mandatory.

## Remaining P0

This **is not an automatic 14-domain scanner** and does not prove ownership of third-party sites. Separate domain ownership/delegation evidence, DNSSEC/CT enrichment where appropriate, audit/rate budgets for multi-domain discovery, broader anti-SSRF registry coverage, QUIC HTTP/3 application first-flight and fingerprint measurements, secure REALITY-like server identity with anti-replay, selection/validated Apply/IPC rollback, F-19 classifier/flow shaping, and Windows native interface collection remain unimplemented. No TOML/wire/invite migration is part of this step.
