# ADR-0092 — Explicit local REALITY key provisioning

**Superseded by ADR-0094; historical record only. The production adapter described here is retired, not a supported configuration or implementation target.**

Status: implementation submitted; full exact-head native acceptance pending. Builds on ADR-0089 and ADR-0091.

## Decision

The existing operator-owned, saved and enabled inbound can use the manual Y path or G to generate a fresh independent Ed25519 PKCS#8 DER key. G is an explicit action, not a background operation or an automatic choice of security mode. It stages a fresh owner-private directory and create-new file using the existing native storage primitive (Unix 0700/0600, Windows explicit protected owner+SYSTEM DACL). No raw private key or path is rendered. Both paths use the same local identity validator, exact material fingerprint and guarded configuration save. The final y is explicit; preview does not write TOML or activate runtime.

The staged file guard is dropped on cancellation or definite failure. On success it is retained. An uncertain config replace retains the key to avoid making a possibly committed configuration unusable. Abrupt process exit may leave an unreferenced private file; no automatic orphan scanning, key deletion or rollback is claimed. Existing REALITY rotation requires the explicit manual path. The parent path must be trusted, as with existing private bearer storage.

## Acceptance and limits

Native key-storage tests validate exact permissions/DACL, distinct independent public keys, bounded DER read, cancellation and committed retention. Editor tests verify no TOML write at preview, cancellation cleanup, exact material drift refusal, committed reference and invitation export, and refusal of automatic rotation.

The previous head's native Linux CI failed at local proxy TCP connection reset before CONNECT; handle this alongside ConnectionRefused only within the existing bounded local handshake retry. Never retry remote TLS/auth/OPEN denial through H2; existing assertions remain.

This local provisioning wizard does not grant ownership of third-party candidates. External candidate Apply, candidate HTTP application evidence, independently reviewed security contract and resistance to active probing remain open. No claim of full F-18 closure or F-19 performance/traffic classification resistance. No additional dependencies or CI jobs.
