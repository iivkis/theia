# ADR-0085: one transport, two explicit inbound security choices

**State:** normative product decision; implementation and native acceptance pending. Clarifies ADR-0084.

SmartTheia is the protocol. SmartTheia XHTTP is its one transport, with internal stream modes and a shared frame/FSM, no Xray wire compatibility. H2/TCP/TLS1.3 and H3/QUIC/TLS1.3 are underlying carriers, both on the same numeric inbound port.

The operator explicitly chooses exactly one security mode: SmartTheia REALITY (wizard or manual; same validated profile and Apply) or own TLS (manual only: paths to X.509 cert/chain and corresponding private key, verified DNS name). No automatic security choice, certificate generation or REALITY wizard in TLS mode.

QUIC-first in both modes; H2 is a new-connection network fallback only when QUIC is demonstrably unavailable. Preserve identity/endpoint, XHTTP mode, security mode, credentials and authorization. TLS, ALPN, key, authentication, version, protocol and policy failures fail closed. No live TCP migration or downgrade. H2-only/H3-only diagnostics do not add transports.

Legacy plain/pin profiles are compatibility paths, not a third product security mode or proof of completed REALITY. Versioned migration and independent security review are required. The vertical acceptance block includes both inbound security choices, REALITY wizard/manual parity, TLS manual pair validation, versioned client profiles/invitations, guarded persistence/transactional Apply and rollback, native positive/negative H2/H3 plus fallback E2E with common frame/FSM and byte-exact TCP. No acceptance without exact-head CI.
