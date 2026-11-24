# ADR-0084: SmartTheia XHTTP and REALITY are native analogues

**State:** normative architecture, stream-up implementation pending native acceptance.

We do not replicate Xray REALITY, Xray XHTTP, VLESS/XTLS wire or configuration. SmartTheia XHTTP is the custom transport of SmartTheia over standard H2/TCP/TLS1.3 and H3/QUIC/TLS1.3; SmartTheia REALITY is a separate security adapter. The existing frame codec/FSM is common across both. Stream-one retains the existing single streaming POST. The new explicitly named stream-up carrier uses separate upload and download HTTP streams within one verified connection. Both must have exactly the same credential, validated together with one permit. One pair per connection, bounded pairing timeout, no cross-connection association. A clean empty GET request is required. No silent fallback between modes, pins or security profiles. Keep existing ACL, OPEN_OK gate, half-close, bounded flow control and session deadline.

The current pin is an additive standard PKI check, not the completed REALITY adapter. Third-party compatibility is not an acceptance requirement. Further identity/key lifecycle, replay/probing threat model, independent review and complete transactional wizard are still required. Native positive/negative H2/H3 tests and exact-head CI are mandatory. No claim of camouflage efficacy or release readiness.
