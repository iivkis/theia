# ADR-0093 — Own endpoint HTTP application readiness and guarded provisioning

Status: implementation submitted, full exact-head native acceptance pending. PR #119 was merged at ef5a97b after all thirteen mandatory CI checks on ce5aeac, including native Linux VM/Windows REALITY H2/H3/auto.

## Decision

The existing consented, bounded TLS/ALPN batch is not HTTP or identity evidence. Its review can select a fresh exact observation with successful independent H2/H3 only when the address was listed as an actually assigned server address, not a CIDR neighbor or catalogued domain. The selection retains the original observation time; navigation does not refresh it. The operator separately approves a single HEAD / per transport by pressing g. Before network I/O require the clean saved selected own inbound, matching SNI and both listener binds, matching address family, current assigned local interface, original <=60s observation and independent native CA roots. The server-side TLS leaf locally reviewed in the existing provisioning flow is an additional exact check on both transports before HTTP is sent.

The HTTP witness uses standard TLS1.3 H2 and QUIC H3 libraries, one exact socket each, five-second shared deadline, bounded headers, no arbitrary paths, DNS, credentials, redirects, retry or transport fallback. It requires two real final HTTP responses with empty HEAD bodies. A status such as 404 is application-protocol evidence, not a successful service request or a camouflage score. A QUIC handshake by itself cannot pass. Failed verification drops the staged private key.

Use the existing local Ed25519 staged review, exact material fingerprint and guarded TOML save. Final y rechecks the original observation age, local interface, saved configuration and key material. Cancel and definite failure remove a staged key; uncertain replace preserves it. No automatic runtime changes, user creation, credential disclosure or external identity adoption. The platform interface collector currently supports Linux; unsupported platforms fail closed on the own-address selection flow. Manual Y and local G remain available.

## Acceptance

Native isolated real HTTP H2/H3 tests verify exact certificate, both final responses, wrong trust/name/leaf rejection and refusal of QUIC ALPN without HTTP/3. Pure tests cover exact selection and freshness. No additional dependency or CI job. All existing mandatory exact-head native checks remain required.

This slice improves ordinary own-endpoint deployment verification, not traffic camouflage or anti-probing resistance. External candidate Apply, fully transactional runtime cutover for the selected profile and independent security review remain open; no full F-18 completion or F-19 claim.
