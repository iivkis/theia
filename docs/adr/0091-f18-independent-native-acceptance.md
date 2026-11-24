# ADR-0091 — F-18 independent native acceptance and review boundary

**Superseded by ADR-0094; historical record only. The production adapter described here is retired, not a supported configuration or implementation target.**

Status: submitted for full exact-head native CI. ADR-0089 implementation was merged via PR #118 after 13/13 checks (head 68773a4; workflow 45440123346). This ADR does not assert F-18 release acceptance or independent review.

## Changes

- The existing mandatory Linux VM/native Windows cross-host fixture gains an explicit fourth REALITY inbound. Standard OpenSSL-generated Ed25519 PKCS#8 DER remains inside the private Linux fixture directory (0600). Only canonical public profiles derived from RFC 8410 SPKI are transferred. A distinct wrong public identity is generated independently. The Windows binary imports a replacement v1 public invitation and independently provided CA and bearer, verifies full byte-exact CONNECT/SOCKS5 relay on H2/H3/auto, and refuses wrong key, PKI, bearer and the old pinned mode.
- Independent raw H2/H3 clients verify Ed25519 proof headers using the actual negotiated exporter and fixed transcript, check exact response cardinality and malformed query rejection, and test a four-by-four matrix of same/fresh/cross-transport signature substitution. The existing bounded one-admission connection state also has a race test for issuance and negative admission before issuance.
- Guarded local TUI preview reads the three bounded files once, validates both H2 and H3 builders, hashes their exact length-delimited bytes using a domain-separated SHA-256 and binds the review to that digest, alongside the existing config snapshot and identities. Confirmation re-reads and refuses changes even when the leaf and public key remain identical. This is an operator review guard, not a persistent key rotation or an atomic transaction spanning external files; runtime capture/restart is separate.

## Review checklist and remaining F-18 gates

The protocol uses verified TLS1.3, H2/H3-distinct exporter contexts, fixed-domain ring Ed25519 signatures, and exporter-bound HMAC admission. No custom crypto primitive, insecure TLS, downgrade or new invitation version. Check transcript scope, key separation, bounded storage, one-issuance concurrency, token ordering, same-connection pair admission, error paths and no unintended logging. Reviewer must be independent and record findings/acceptance; authors' tests cannot replace that review.

Candidate observations presently attest TLS/ALPN on consented pinned sockets, not actual HTTP/3 application semantics or remote identity ownership. Keep external candidate Apply blocked until those prerequisites and a separate safe transactional validation are satisfied. Local explicit provisioning is available. The public identity route is observable; one-response/bounded admission does not establish active-probing resistance. F-19 flow shaping and classifier/performance evidence are not part of this slice. No production, DPI-invisibility or full F-18 completion claim.

## Acceptance

Existing 13 mandatory jobs, including native Windows and Linux, cross-host F-14, browser and final ci-gate, remain unchanged in number. All tests in this change must pass at the actual head. No new dependencies, external services or network probes in CI.
