# ADR-0087 — Replace v1 invitation with explicit SmartTheia XHTTP contract

Status: implementation submitted for mandatory exact-head native acceptance.

## Decision

The project is unreleased. By owner decision replace the previous v1 invitation completely, without legacy decoding or compatibility API. No v2 prefix. The sole URI is theia://v1/ with canonical unpadded base64url of strict UTF-8 TOML. version = 1; required carrier = "smarttheia-xhttp", security_mode = "own-tls" or "pinned-tls", xhttp_mode = "stream-one" or "stream-up". own-tls currently permits stream-one only and no leaf_sha256; pinned-tls requires a canonical 64-lowercase-hex SHA-256 of the whole DER leaf and either mode. Unsupported combinations, unknown/duplicate fields, former tls_profile wire field and old envelopes fail closed. The intermediate pin modes are not a third target product security choice or complete REALITY. Client TOML currently maps the typed combination to the exact existing runtime tls_profile; no network frames are changed.

One constructor/decoder/issuer; no dual-version codec or compatibility wrappers. Saved own certificate/key must validate for pinned export; same H2/H3 port, explicit grants, CSPRNG bearer and digest verification remain. Guarded durable save before one-time reveal/export, recheck current pinned identity at reveal. Independent CA is still mandatory for runtime; authenticated transfer and explicit pin verification, no TOFU. Credential-only refresh cannot change identity, CA or HTTP mode.

## Acceptance and limitations

Codec tests reject former v1/v2 envelopes, unsupported and missing fields, mixed security/pin/mode and noncanonical data; test roundtrip for H2, H3 and auto. Native editor tests cover guarded issuance/import/rotation/refresh and certificate drift. Real H2/H3 loopback relay uses decoded profiles. Extend the mandatory existing Windows + WSL2 Linux cross-host gate with actual pinned stream-one and stream-up inbounds, public invitation import, explicit per-run credential, CONNECT/SOCKS5 and wrong pin/mode refusals, including auto. No Linux private key is transferred. This is not a new cross-host confidential pinned issuance test (local editor tests cover that). No new CI job or dependency. Actual REALITY key proof/anti-probing/replay, complete candidate Apply, F-19 and independent review remain open. No performance or release claim.
