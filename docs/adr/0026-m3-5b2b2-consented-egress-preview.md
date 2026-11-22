# ADR-0026: M3.5b2b2, consented HTTPS egress witness and safe offline preview

**Дата:** 2026-11-23. **Статус:** implementation in PR; CI evidence required on exact head SHA. This is a constrained library slice, **not** an automatic external public-IP detector, active range scanner, REALITY mode or full F-18/F-19.

## Problem, Given/When/Then and threats

M3.5b2b1 obtains Linux-local assigned interface addresses/masks. Behind NAT or a routed public egress those addresses may differ from the externally visible IP. Guessing a public address from `10.x`/route source, assuming ownership of a /24 around a public IP, or silently contacting a third-party IP-echo service are unacceptable. A malicious HTTPS witness, redirect, forged certificate, oversized HTTP reply or DNS-rebound target could falsify a result or create an SSRF risk.

- Given **no explicit witness approval**, When a caller requests egress detection, Then **no socket** is opened and `NotApproved` is returned.
- Given an explicitly permitted *single pinned public IP:443*, caller-owned nonempty RootCertStore and configured DNS name, When the TLS1.3/http/1.1 echo answers HTTP 200 with a short, plausible public IP, Then return `EgressObservation` with the observed IP, pinned endpoint, hostname and local observation timestamp. The remote witness' claim is not independently proven and never authorizes a CIDR.
- Given a local loopback fixture **only in isolated CI** with a matching exact socket, Then exercise real PKI/ALPN/HTTP and positive/negative cases using in-memory certificates. No public services in CI.
- Given invalid certificate, SAN/SNI mismatch, wrong ALPN, missing CA, private/doc/multicast IP reply, redirect, overly long body/header, invalid path/HTTP, timeout or wrong pinned target, Then return a typed error **without** partially positive evidence or retries.
- Given assigned Linux interface metadata and optional successful witness report, When `build_preview` runs, Then return the known public interfaces, 14 offline domain seeds, witness IP if available, explicit match/difference/unknown status and warnings. Do not expand neighboring CIDRs unless the caller separately supplies `PreviewScope::OperatorApprovedCidrs`; even then the previous /24-or-smaller, bounded/assigned-prefix gates stay in force. No probes in the preview path.
- Given an invalid/down/unassigned interface entry supplied to a pure model, Then it may not grant public prefix expansion. Native Linux uses getifaddrs; Windows native collector remains fail-closed Unsupported, while shared model/probe fixture tests execute on Windows.

## Decision

1. **Only opt-in HTTPS witness:** `camouflage_egress::observe_public_egress(request, trusted_roots, approval)` requires explicit `PublicHttpsIp(IP)` for the exact public TCP/443 peer. `Denied` is the default. `IsolatedLoopbackFixture(SocketAddr)` exists for exact loopback PKI tests, never broader private/IP ranges. No DNS, third-party default provider, redirects, proxies, bearer token or OS configuration changes. The supplied domain is TLS SNI/SAN and Host, not a resolution request.
2. **Strict protocol/quotas:** TLS1.3-only with normal certificate, hostname and expiry validation, ALPN `http/1.1`, no 0-RTT. Single HTTP GET with sanitized <=128-byte path; HTTP/1.1 200 and unique Content-Length required; header <=4096 bytes, body <=64 bytes. Reject Transfer-Encoding and non-200/redirects; constrain maximum total handshake+request+response to 5 seconds and process concurrency to two. Only public-plausible parsed IPv4/IPv6 results. No retry or fallback.
3. **Witness != ownership:** the outcome is a TLS-verified *claim by one external observer* about the outbound address. It does not attest to jurisdiction, which remote interface received the packet, NAT type, ownership or inbound reachability. `DiffersFromAssignedAddress` means **possible NAT or routing**, not proven NAT; `MatchesAssignedAddress` is not proof of control over that address or prefix. IP echo itself exposes client public IP to the selected operator-chosen service, so it requires separate explicit consent in future TUI. A local timestamp is not an external freshness signature.
4. **Offline composition:** `camouflage_workflow::{build_preview, collect_preview}` composes only `NativeInterfaces`, optional successful witness report and an explicit `PreviewScope`. `PassiveOnly` never expands CIDRs. Existing `camouflage_discovery::build_plan` retains 14 unprobed domain seeds, dedup, 256 limit, no IPv6 enumeration, /24 CIDR bound and full assigned-subnet checks. `NativeInterfaces::server_snapshot` rejects down or invalid-mask inputs, including when API-provided fixtures are wrong. No hidden active scanner or automatic approval based on IP-echo or RDAP/BGP.
5. **No new runtime dependencies:** existing pinned rustls/Tokio APIs; one Rust binary remains. No wire/TOML/invite changes or automatically enabled client/server features.

## Alternatives rejected

- Auto-contacting an unselected IP-echo provider: leaks the operator's IP and creates unwanted network I/O.
- Plain HTTP, DNS TXT, STUN or curl shell invocation: insufficiently constrained trust/consent and extra runtime/tool dependencies.
- Mapping any public echo result to automatically approved /24 or a provider BGP prefix: violates authorization and SSRF boundaries.
- Treating one TLS handshake to a witness as a real browser-like TLS fingerprint or REALITY mode: false release readiness.

## Tests, performance and remaining work

CI tests run **only** loopback TLS fixtures on native Linux/Windows, covering valid IPv4/IPv6, wrong CA/SNI/ALPN, nonpublic and malformed data, redirects, approval mismatch and timeouts. Pure previews cover passive/approved CIDRs, assigned prefix mismatch, invalid/down/private interfaces, Linux native path and Windows Unsupported. `cargo test --workspace --all-targets --locked`, `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, all required Linux/Windows jobs, browser E2E and exact-head `ci-gate` must pass. Cancellation or skipped mandatory job is not completion.

Unimplemented: OS-native Windows collector, operator UI/consent persistence, endpoint provisioning/PKI trust UI, automatic public egress lookup, confirmed ownership of delegated/routed blocks, passive DNS/CT/RDAP timestamped enrichment, bounded authorized batch scanner with cancellation and rate budgets, H3/QUIC probe, REALITY-like authenticated security mode, TLS-in-TLS mitigation, actual browser-like fingerprint and performance/classifier release gates.
