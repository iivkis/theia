# Theia connection invitations: portable v1 (F-14, P0)

**Normative target, 2026-11-22.** M4.4a delivers the safe Rust domain codec and conversion, not an end-user TUI/CLI import/export workflow. Do not call F-14 complete until M4.4b–d have passing Linux/Windows CI.

## User model

One binary built per platform, with independent **server** and **client** roles. The server TUI runs on the remote Linux server (optionally via SSH) and manages local server settings; it is not a remote web dashboard. The local Windows/Linux client TUI manages imported profiles, its local proxy and optional explicitly confirmed system proxy. These roles exchange **connection data**, not control-plane credentials or network API permissions.

## Canonical versioned share URI

Use scheme prefix `theia://v1/` followed by **unpadded canonical base64url** (RFC 4648 URL-safe alphabet) of UTF-8 TOML data with `deny_unknown_fields`. Total URI max 4096 bytes; decoded payload max 3072 bytes. This is data, not an HTTP URL. Do not follow redirects, fetch hosts or auto-execute it.

Payload (illustrative **without bearer**; not a runnable server):

```toml
version = 1
id = "public"
endpoint = "edge.example.org:443"
server_name = "edge.example.org"
tls_profile = "default"
transport = "auto"
# token = "..." # ONLY for explicitly confirmed one-time confidential export
```

Fields: `version` must be 1, `id` a v1-compatible profile ID, `endpoint` a valid host:port or [IPv6]:port, `server_name` a valid TLS DNS SNI, `tls_profile` **default only** until F-13 proves an alternative, `transport` auto/h2/h3. Optional `token` is exactly 32 random raw bytes represented as canonical 43-character base64url without padding. The invite has no secret reference, key hash, TLS private key, ACL grant, OS settings, local listener binds, certificate override or arbitrary path. Unknown, duplicate or extra fields/versions, malformed UTF-8/base64, over-limit payload and invalid values fail closed. This URI version is independent of SmartTheia frame version and TOML config schema_version.

## Server: issuance and one-time export

- Server stores `users[].token_sha256` only. It **cannot** reconstruct the original 32-byte bearer from a digest. Every new confidential invite requires the raw CSPRNG token in memory at initial creation or explicit rotation (the latter revokes/changes existing access).
- To issue, require valid server config, enabled server/user, existing inbound and **explicit user ID in inbound.allowed_user_ids**. Verify the digest matches freshly supplied bytes in constant time. Never accept a digest as bearer.
- v1 shared endpoint uses `inbound.server_name` and the common numeric port of TCP/H2 and UDP/H3. If the port numbers differ, **reject auto invitation**, do not silently generate an unusable profile or disable fallback. This also assumes the publicly reachable address/port matches configured DNS and listener; proxies, NAT port mapping, split DNS and port overrides need an explicit future profile flow.
- Public/secretless export is default. Confidential export requires a separate explicit operator confirmation, can be viewed/copied/exported only once, and must be hidden/cleared when the view closes. QR of the same URI can be added as P1 opt-in. URI with a token is a credential; do not print in ordinary logs, crash dumps, shell history or default stdout. Protect exported files and clipboard.
- Server creation/rotation, TUI export and persisted secret handling are **M4.4b**, not M4.4a.

## Client: import and TLS trust

- Import from the paste buffer or a **local file**, with no automatic network fetch, shell args or web-admin API. Preview only id/endpoint/SNI/transport and whether a credential is present, **never token bytes**. Do not activate imported profiles, connect, reload, or enable system proxy without separate confirmation.
- The token must be written as exact canonical base64url (43 bytes, no trailing newline) in a unique trusted new file under a trusted directory (Unix 0600, Windows per-user ACL) or provisioned explicitly into an env reference. `client.profiles[].auth_token` must remain an `env:` or absolute `file:` reference, **never literal**. A public link requires explicit independent credential input. Existing profile IDs are never silently overwritten, no tokens in debug, audit or UI diagnostics.
- TLS trust is **not shipped or replaced by the share URI**. The client must obtain/verify its trusted certificate authority separately and verify the TLS SNI/chain exactly as for a manually configured client. If explicit `tls_ca` is needed for runtime, import without a trusted CA may save a non-connected draft but cannot claim ready to connect. No insecure verifier, silent downgrade, trust-on-first-use or arbitrary file import.
- Durable profile and credential-file writes need a tested transaction/rollback strategy; Windows ACL checks, crash and collision tests must pass before declaring P0. Safe preview must work with token masked.
- Client file import and TUI profile creation are **M4.4c**; real server-issue → file/link → Windows-client import → validated H3/H2 OPEN_OK E2E (and negative cases) is **M4.4d**.

## Security tests and limitations of M4.4a

The pure codec rejects wrong prefix/version, noncanonical/oversized base64, unknown fields, non-256-bit token, bad endpoint/SNI, unknown TLS profile, invalid env/file references and mismatched/disabled/ungranted server users. The computed full client profile is checked with the existing typed config validator; importing never trusts a provided CA path from the URI. The encoded token is held in memory for import, so the raw link and process memory must be treated as confidential. M4.4a has **no** CSPRNG issuance, file/clipboard UI, ACL, QR, import transaction, runtime reload or service connection; these remain open P0.
