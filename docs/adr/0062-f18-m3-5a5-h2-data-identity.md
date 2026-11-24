# ADR-0062: F-18 M3.5a5 — real H2 DATA identity research

**Status:** CI-only experiment; pending verification and independent review. Not a production protocol.

## Context

ADR-0059's H2 test negotiated ALPN h2 but sent raw TLS application bytes. ADR-0060 exchanged real HTTP/3 DATA. This experiment closes the H2 framing evidence gap without changing production code or TLS verification.

## Given / When / Then

- Given a verified loopback TLS1.3 connection and a real HTTP/2 session, when a challenge has 31 or 33 bytes or is all zero, then the bounded research handler rejects it without returning an identity proof.
- Given the same connection after rejected streams, when a valid 32-byte challenge is sent across two DATA writes with END_STREAM, then a 96-byte research response carries the server nonce and Ed25519 proof. The client derives its own exporter, checks the independently pinned key and exact transcript, and rejects wrong pin, transport substitution, altered signature and duplicate proof.
- Given the existing ordinary production H2 listener, when no bearer or a wrong bearer is supplied, then HTTP 401 has no DATA body. A correct bearer can receive HTTP 200 before SmartTheia OPEN_OK; this is not proof of a tunnel.

The fixture limits socket lifetime to 20 seconds, accepts four streams, bounds received data, requires end of body, releases H2 flow-control credit and uses only ephemeral loopback certificates/keys. It does not implement a general HTTP endpoint or enable a new listener in the shipping binary.

## Limits and acceptance

Post-TLS proof cannot alter the first handshake or hide a service. Neither the research response nor the ordinary production H2 response establishes anti-probing, browser matching, runtime key provisioning, persistent replay, session resumption or a security review. Do not use it to relax CA/SAN/ALPN, bearer/grants or OPEN_OK. No wire or config migration. Require full exact-head native Linux/Windows CI and ci-gate; F-18 remains P0 blocked.
