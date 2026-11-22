# ADR-0018: Portable connection invitations and separate server/client roles

**Date:** 2026-11-22
**Status:** Accepted as normative F-14 P0 design; M4.4a implementation pending CI.

## Decision

F-14 is upgraded P1 → **P0** because creating an inbound/user, exporting a working credential and importing it in the standalone Windows/Linux client is the primary user journey, not optional convenience. Both server and client panels ship in one per-OS binary but operate as independent roles on different machines. Remote server management, web panels and compatibility with other proxy wire protocols are not implied.

New versioned out-of-band `theia://v1/` URI is defined in docs/INVITATIONS.md. Strict TOML payload encoded as canonical URL-safe unpadded base64. Secretless export defaults; credential-bearing export requires explicit one-time issuance/rotation with CSPRNG and verified inbound grant/digest, not impossible reverse-hashing. Client import requires secure credential storage, duplicate checks, strict TLS/CA validation and separate active/connect/proxy actions. QR is optional P1.

## Threats and mitigations

Avoid CLI argv/history, logs, URI fetch/SSRF, unknown fields, oversized or noncanonical encodings, fake tokens, leaking token refs or TLS keys, disabled/ungranted users, incorrect endpoint with separate UDP/TCP port, insecure TLS trust and silently replacing an existing profile/secret. No implicit system proxy or runtime updates. The codec only prepares data; disk/Windows ACL, crash consistency, one-time views, clipboard and cross-host authorized tunnels require separate CI-proven slices.

## Consequences

Add M4.4a codec with grant/hash/typed validation, then M4.4b issuance/export, M4.4c import/credential store and M4.4d full Linux→Windows E2E. All are part of release gates, tracked independently of F-13 named browser fingerprint and F-11 benchmark. No TOML schema, SmartTheia frame, binary count or network/TLS data-plane migration.

## Validation

Mandatory Linux+Windows unit tests for genuine server selected inbound, correct digest/permissions, versioned deterministic encoding/decoding, disabled and unauthorized users, bad port pairing, invalid inputs and safe Debug. Existing CI rustfmt/clippy/network/browser tests must pass at exact PR SHA, without skipping jobs.
