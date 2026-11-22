# ADR-0034: M4.5f, source-aware bounded dual H2+H3 candidate batch

**Date:** 2026-11-23. **Status:** experimental vertical slice, native exact-head Linux/Windows CI required; not a remote scanner or REALITY mode.

## Scope and authorization

M4.5e verifies both TCP/TLS1.3/ALPN=h2 and UDP/QUIC/TLS1.3/ALPN=h3 for one pinned operator-approved IP:443 and SNI. F-18 requires candidates from *authorized* IP ranges and domains to support **both** transports. The offline catalogue (14 popular names) and local interface CIDR planner must never automatically authorize Internet probes; merely listing a seed domain or a provider prefix proves no permission.

`CandidateConsent::PlannedIp` accepts only individually approved public IP:443 targets present in a caller-provided offline plan as ServerAddress or AuthorizedSubnet. An allowed CIDR never grants all neighbors permission to probe. `CandidateConsent::PinnedDomain {domain,pinned_ip}` separately binds one manually approved catalogued domain to a specific pinned IP:443 and exactly matching TLS SNI. The operator must also provide an exact per-socket `ProbeApproval`. Invalid DNS SNI, domain not present in catalogue, mismatched pinned address, no roots or denied exact target all refuse before network. No DNS is performed and no redirect is followed; CI supports only exact loopback fixture approval.

`validate_dual_target()` is a pure, side-effect-free preflight. `probe_dual_h2_h3()` continues to use PlannedIp by default; the new source-aware variant reuses two independent strict TLS/QUIC handshakes against the **same exact IP, port and SNI**. Results cannot substitute between protocols, and REALITY-like cryptographic identity, H3 HTTP semantics, browser fingerprint, anti-DPI suitability are never claimed.

## Bounded batch

`probe_dual_batch()` validates **all** targets before opening any TCP/UDP socket; rejects empty, duplicate exact (IP:443, SNI), any unapproved target or more than 8 entries, without partial network activity. After preflight it dispatches at most 2 simultaneous dual candidates (at most 4 TCP/UDP handshakes), max 5s per transport, total 20s batch deadline. Stable input order and per-transport positive/negative results are retained. Failure of H2 or H3 makes a candidate NOT dual verified. The batch never enumerates CIDRs, performs DNS or calls seed websites on its own, retries, or falls back. Debug output redacts addresses and SNI. `reality_ready()` remains false because no REALITY-like identity/fingerprint mode exists.

## Given/When/Then tests

- Empty, >8, duplicates and any denied target reject before sockets; no partial execution.
- Exact local test-only pinned `google.com` SAN with locally generated certificate and both a TCP/h2 and UDP/QUIC/h3 listener on the **same loopback socket address** yields dual transport verified, not REALITY ready. No Internet DNS/probes.
- Public IP unplanned, unsupported catalogue name, wrong SNI, mismatched pinned IP, no roots, denied approval fail closed before network.
- Real loopback tests and negative PKI/ALPN/deadline tests run on Linux and Windows; mandatory fmt/clippy, BBR/BoringSSL, browser E2E, Windows smoke and exact-head ci-gate are required.

## Not implemented

**No automatic CIDR/domain scanning, proof of ownership, DNS A/AAAA discovery/pinning and anti-rebinding, remote batch consent TUI, per-range/per-domain rate audit, QUIC HTTP/3 application check, browser fingerprint, REALITY-like authenticated security, anti-TLS-in-TLS flow shaping, transactional Apply/IPC, Windows native interface collector.** This is an explicit-target API only. No wire, invite or TOML changes, no new dependencies or binary.
