# ADR-0083: Explicit additional certificate identity for H2 and H3

**State:** proposed; native CI and review required. Not REALITY.

## Security boundary

Keep TLS1.3, strict certificate chain/hostname/ALPN and no 0-RTT. The additional pin is SHA-256 of the exact DER leaf; TLS proves possession of the corresponding key. This is not an independently generated Ed25519 REALITY key, alternate certificate verifier, altered TLS/QUIC first flight, active-probing resistance or DPI guarantee. Authenticated out-of-band pin provisioning is mandatory; never trust the first peer automatically. Rotation/reissue requires explicit client pin replacement. A server cannot establish that an arbitrary client actually checked its own pin.

## Versioned opt-in and compatibility

Add an optional typed inbound `security_mode` with values plain/default omission and pinned-cert-v1. Client uses explicit `tls_profile = "pinned-cert-v1:<64 lowercase hex>"` on the strict rustls backend, for H2/H3/auto. Unknown versions/fields remain fail-closed; older binaries reject the new field/profile. Existing TOML examples unchanged and plain output omits the new field. No frame schema or invitation v1 change; v1 public and secret export from pinned inbound/profile refused, not downgraded. Client checks pin before HTTP bearer/request, server restricts mutually exclusive path. The same pin is used on both auto branches; only existing observed pre-auth UDP silence permits fallback. No retry of an established session, no new replay protocol. Mode changes require explicit restart; cannot be smuggled through auth or same-port TLS-only Apply.

## Wizard

Discovery reports remain read-only and cannot authorize another server's identity. On saved local server config, a separate uppercase P preview validates the selected own inbound cert/key and same TCP/UDP port in a worker, displays public pin and exact endpoint, and y repeats checks against source/record/cert before guarded write. Foreign/stale config or cert refusal; uncertain-write state preserved. Save is not activation; separate restart, trusted manual client provisioning and migration required. A certificate changed after save causes pin refusal, never fallback to plain. No additional network, key generation or token export.

## Acceptance

Native real H2/H3 mode and pin matrix, trusted-but-different leaf rejection, wrong SAN/auth, no target dial, byte-exact relays; compiled auto client with working pinned H2 under UDP silence and verified H3 wrong pin terminal. Local guarded save, stale config/cert, invite and reload refusal. Existing TLS/auth/ACL/BBR and cross-host gates remain. No new package, no new CI job; independent crypto review and actual REALITY/F-19 remain open.
