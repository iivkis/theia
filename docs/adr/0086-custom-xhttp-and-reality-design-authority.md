# ADR-0086: custom SmartTheia XHTTP and REALITY, inspiration only

**State:** normative target, clarifying ADR-0084 and ADR-0085; implementation and release acceptance are separate.

SmartTheia is its own application protocol. SmartTheia XHTTP is its single custom transport, inspired by Xray XHTTP, **not a clone**. SmartTheia REALITY is its custom security adapter, inspired by Xray REALITY, **not a clone**. Xray is inspiration only. No requirement to implement Xray's complete features, modes, wire, keys, handshake, configuration, invitations, VLESS or XTLS compatibility. Own versioned contracts determine correctness. Internal XHTTP stream modes are not additional transports. Standard H3/QUIC/TLS1.3 and H2/TCP/TLS1.3 are required carriers, with QUIC-first network-only H2 fallback preserving identity/security/XHTTP/auth.

Exactly two explicit inbound security choices: SmartTheia REALITY (wizard or manual, same validated profile and Apply) or own TLS (manual only: X.509 cert/chain, matching private key, verified name). Pin experiments and legacy profiles do not establish a third product choice. No automatic downgrade or silent mode change.

Custom means application transport and independently reviewed security adapter using established crypto and protocol libraries, not hand-written cryptographic primitives or replacement HTTP/TLS/QUIC stacks. Reproducing the Xray first flight or handshake is not a design constraint; own security properties and independent H2/H3 evidence remain mandatory. Keep all prior P0 security, browser, resource and native acceptance requirements. No unverified claims of REALITY, DPI invisibility, or production readiness.

Source authority: spec v0.6 and ADR-0084/0085/0086 define the product target. Protocol/config docs specify implemented versioned wire/schema, STATUS records evidence. Historical ADR/research sections preserve context; they do not introduce Xray compatibility requirements. Any future architecture change requires a documented ADR and synchronized spec/tests.
