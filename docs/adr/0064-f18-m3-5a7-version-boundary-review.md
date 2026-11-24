# ADR-0064: F-18 M3.5a7 — version boundary and independent review entry

**Status:** proposed; production v1 export correction pending native CI. F-18 remains blocked.

## Decision and regression

The existing v1 invitation encoder always writes tls_profile=default. Previously public_from_profile discarded the input TLS profile before validating the invitation, allowing a caller to request an export of a named profile and obtain a different profile. Reject any non-default input before construction. Do not extend the v1 format or make v1 import accept a named profile. The default profile remains unchanged for each existing transport. The local named BoringSSL H2 profile remains selectable through typed TOML on a supported build only.

Given a non-default source profile, when requesting a v1 public export, then reject, not downgrade. Given a valid default profile, when exporting and importing, then preserve transport and default TLS profile without credentials. Given either valid public or issued v1 invite, when adding security identity, trust lifecycle or duplicate/nested fields or changing the version/profile, then reject before a typed profile is returned. Existing strict CA, grant, and OPEN_OK requirements remain mandatory.

## Independent review packet (not an independent review)

| Evidence | Scope | Remaining gap |
| --- | --- | --- |
| ADR-0021 / M3.5a0 | Real verified TLS1.3/H2 and QUIC/H3 exporter | Not early authentication |
| ADR-0059 / a1 | Test-only Ed25519 transcript and bounded replay | Independent cryptographic review; clock policy |
| ADR-0060 / a2 | Real H3 DATA and QUIC Initial metadata | No modified handshake or H3 browser match |
| ADR-0061 / a3 | QUIC Initial visibility and ordinary H3 auth baseline | No active-probing protection |
| M3.5a4 | Cross-session exporter rejection with reset cache | No resumption/0-RTT or durable replay |
| ADR-0062 / a5 | Real H2 DATA and ordinary H2 auth baseline | No shipping identity protocol |
| ADR-0063 / a6 | Local key rotation, deny-all and revocation model | No authenticated persistence, crash recovery, shared-key scope isolation |

M3.5a6 exact-head CI: [run 45384251480](https://github.com/iivkis/theia/actions/runs/45384251480), all 13 jobs successful. M3.5a7 requires a separate exact-head full native CI run.

## Release hold

Reviewers must independently assess the trust model, transcript domain separation and endpoint binding, replay and time assumptions, key compromise/recovery, persistent revocation, multi-inbound isolation, resource limits, downgrade behavior, version migration, and limitations of ordinary TLS/QUIC first flight. Require documented review findings and remediation evidence before introducing a new production security mode. No self-review may be labeled independent. No new trust field or runtime mode is enabled by this change; no claim of DPI invisibility, browser equivalence or anti-probing. F-19 is a separate P0 gate.

This correction and the regression matrix are one coherent CI block. No new dependencies or workflow changes.
