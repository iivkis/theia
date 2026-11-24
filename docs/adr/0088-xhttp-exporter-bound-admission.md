# ADR-0088 — TLS exporter-bound XHTTP admission

Status: implementation submitted for exact-head mandatory native acceptance.

## Decision and boundary

Require channel-bound HTTP admission on both explicit intermediate pinned profiles, after full TLS 1.3 CA/SAN/ALPN and exact leaf pin on the client. Server obtains exporter material once per accepted connection. Both use RFC TLS exporters with label EXPORTER-SmartTheia-XHTTP-Admission-v1, 32-byte output, context ASCII h2 or h3 respectively. The HMAC-SHA256 key is that exporter output. Request header theia-channel-proof contains canonical unpadded base64url HMAC of domain bytes SmartTheia/XHTTP/admission/v1 followed by NUL, then three fields (HTTP method, exact path, full Authorization bytes), each prefixed by its unsigned 32-bit big-endian byte length. The existing ring implementation provides HMAC; existing locked dependency moves from dev to production, no package version changes. The header is sensitive; no proof, exporter or bearer in diagnostics. Exporter failure is terminal, no fallback.

Retain strict route/method, single bearer header, grant, digest, peer and stream quotas. Before successful HTTP admission, require exactly one matching proof per request, including each leg of stream-up. The same logical session consumes one atomic per-connection slot. A copied proof cannot admit a different connection or leg, and a second use on the same connection fails. No global replay table, timestamp synchronization or unbounded state. Independent proof mismatch and replay produce refusal before OPEN/relay. Plain own TLS and explicit browser H2 profiles keep existing behavior, but reject unsolicited proof headers. Existing pinned clients without proof are refused; no compatibility path. QUIC network-only fallback derives a fresh H2 proof and preserves the pin and XHTTP mode.

This is channel binding, not an independent REALITY server-key signature or possession proof of a separate client key. A stolen bearer can still be used by its holder on a newly authenticated connection; an active unauthenticated peer can still observe ordinary TLS/HTTP rejection behavior. It does not claim resistance to active probing, traffic classification, or DPI. No homemade crypto or transport stack. Full F-18 identity/trust lifecycle, candidate Apply, F-19 and independent security review remain open.

## Acceptance

Pure negative tests: missing/duplicate proof, altered method/path/bearer, wrong exporter, same connection replay, distinct pair proofs and exactly one concurrent admission. Independent raw native H2 and H3 clients derive RFC exporter output and construct the wire witness, exercise first valid admission and copied proof on same/new connection, and observe refusal without opening a target. Existing real H2/H3 relay, stream-up, auto fallback, wrong pin/mode/bearer and cross-host binary tests run unchanged. CI-only; no new job, no reduced coverage and no performance claim.
