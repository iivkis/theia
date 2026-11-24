# Theia connection invitations: portable v1 (F-14, P0)

**Нормативный контракт F-14; актуальный статус на 2026-11-24 см. [STATUS.md](STATUS.md).** M4.4a реализует codec, M4.4b1 серверную выдачу, M4.4b2a отключение, M4.4b2b1 подтверждённую ротацию bearer, а M4.4c локальный клиентский импорт с защищённым хранением (PR #80/#81, native Linux/Windows CI успешен). F-14 P0 ещё не завершён: защищённый экспорт, расширенная ACL/crash матрица и cross-host H2/H3 E2E остаются открытыми.

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

Fields: `version` must be 1, `id` a v1-compatible profile ID, `endpoint` a valid host:port or [IPv6]:port, `server_name` a valid TLS DNS SNI, `tls_profile` **default only** (including when the local binary supports a named F-13 profile; v1 cannot represent it), `transport` auto/h2/h3. Optional `token` is exactly 32 random raw bytes represented as canonical 43-character base64url without padding. The invite has no secret reference, key hash, TLS private key, ACL grant, OS settings, local listener binds, certificate override or arbitrary path. Unknown, duplicate or extra fields/versions, malformed UTF-8/base64, over-limit payload and invalid values fail closed. This URI version is independent of SmartTheia frame version and TOML config schema_version.

**No export downgrade:** `Invitation::public_from_profile` rejects every non-default TLS profile, including the locally supported H2 BoringSSL profile, instead of producing a default-profile URI. A future versioned invitation must explicitly represent and validate any additional profile. Existing default H2/H3/auto public shares and server-issued bearer links remain unchanged. See ADR-0064.

## Server: issuance and one-time export

- Server stores `users[].token_sha256` only. It **cannot** reconstruct the original 32-byte bearer from a digest. Every new confidential invite requires the raw CSPRNG token in memory at initial creation or explicit rotation (the latter revokes/changes existing access).
- To issue, require valid server config, enabled server/user, existing inbound and **explicit user ID in inbound.allowed_user_ids**. Verify the digest matches freshly supplied bytes in constant time. Never accept a digest as bearer.
- v1 shared endpoint uses `inbound.server_name` and the common numeric port of TCP/H2 and UDP/H3. If the port numbers differ, **reject auto invitation**, do not silently generate an unusable profile or disable fallback. This also assumes the publicly reachable address/port matches configured DNS and listener; proxies, NAT port mapping, split DNS and port overrides need an explicit future profile flow.
- Public/secretless export is default. Confidential export requires a separate explicit operator confirmation, can be viewed/copied/exported only once, and must be hidden/cleared when the view closes. QR of the same URI can be added as P1 opt-in. URI with a token is a credential; do not print in ordinary logs, crash dumps, shell history or default stdout. Protect exported files and clipboard.
- **M4.4b1 server issuance (merged):** on a valid clean server TOML, select inbound, press `u`, enter a unique ASCII ID, Enter and confirm `y`. Use the pinned rustls/ring SecureRandom provider to create a fresh 32-byte bearer, append SHA-256 digest user with `disabled=false` and an explicit grant on this inbound only. Strict document validation and existing background guarded atomic write must finish successfully before a separate `y` reveals the full `theia://v1/...` link exactly once. `n`/Esc abandons the unseen secret; Esc closes the shown secret. On conflict: `r` retries or `d` discards, with no link disclosure. This neither reloads runtime nor auto-enables a proxy.
- **Limitations:** серверные выдача, disable-only и ротация (M4.4b2b1) реализованы, а локальный клиентский импорт (M4.4c) проходит native Linux/Windows H2 E2E. Нет автоматического live Apply, hard revocation, re-enable, защищённого file/clipboard export, QR и cross-host H2/H3 E2E. Если оператор закрыл однократную ссылку до её сохранения, bearer нельзя восстановить из SHA-256 digest. Best-effort `zeroize` не гарантирует очистку всех serde/base64/TOML буферов или terminal/SSH scrollback.

## M4.4b2a: explicit existing-user disable (server TUI only)

On an explicitly loaded, clean server TOML, select an inbound and press `x`. Enter the **existing enabled user ID granted to this inbound**, press Enter to review, then separately `y` to disable it **globally on all inbounds**. `n`/Esc cancels before confirmation. The background editor validates the document and rejects externally edited/symlinked files before atomic save; failed save offers `r` retry or `d` discard. No raw bearer/digest is shown, and grants/token digests remain unchanged.

**Important:** this only updates `users[].disabled = true` in the saved TOML. It never calls IPC or reloads the server. A separate authorized, revisioned auth-only CAS Apply is needed to reject **new** admissions; already-authenticated H2/H3 tunnels continue. This is *not* hard revocation or token rotation. See [ADR-0053](adr/0053-m4-4b2a-explicit-existing-user-disable.md).

## M4.4b2b1: explicit existing enabled-user rotation (server TUI only)

In `theia tui --role server --config FILE`, select the inbound that already grants the active user, press `t`, enter that existing user ID, Enter and then `y` to explicitly confirm **global** bearer rotation. The old SHA-256 digest cannot recover the old secret; a fresh **32-byte ring CSPRNG token** replaces only `users[].token_sha256`. User ID, disabled state, all inbound grants and policy are preserved. Unknown/ungranted/disabled users, dirty editor, wrong client role, invalid auto H2/H3 ports and pending issuance are refused.

The new `theia://v1` link is offered only **after** strict document validation and successful guarded atomic TOML save; external file conflict blocks reveal. `y` separately shows the confidential URI once, `n/Esc` discards unseen bearer, Esc hides a shown bearer. No file, log, CLI argv, system proxy change or automatic runtime Apply. **Until separate native IPC auth-only CAS Apply, the running server still accepts the OLD bearer for new sessions**; after Apply it accepts the new bearer and refuses the old for new sessions across all inbounds, while **already-open tunnels continue**. No immediate hard revoke or implicit re-enable. See [ADR-0054](adr/0054-m4-4b2b1-confirmed-bearer-rotation.md).

**This is a bounded partial F-14 slice** (PR #80 merged after native CI). Protected file export, clipboard, disabled-user re-enable and cross-host H2/H3 E2E remain open; local client import with native H2 E2E has since been merged in PR #81.

## Client: import and TLS trust

- Import from the paste buffer or a **local file**, with no automatic network fetch, shell args or web-admin API. Preview only id/endpoint/SNI/transport and whether a credential is present, **never token bytes**. Do not activate imported profiles, connect, reload, or enable system proxy without separate confirmation.
- The token must be written as exact canonical base64url (43 bytes, no trailing newline) in a unique trusted new file under a trusted directory (Unix 0600, Windows per-user ACL) or provisioned explicitly into an env reference. `client.profiles[].auth_token` must remain an `env:` or absolute `file:` reference, **never literal**. A public link requires explicit independent credential input. Existing profile IDs are never silently overwritten, no tokens in debug, audit or UI diagnostics.
- TLS trust is **not shipped or replaced by the share URI**. The client must obtain/verify its trusted certificate authority separately and verify the TLS SNI/chain exactly as for a manually configured client. If explicit `tls_ca` is needed for runtime, import without a trusted CA may save a non-connected draft but cannot claim ready to connect. No insecure verifier, silent downgrade, trust-on-first-use or arbitrary file import.
- Durable profile and credential-file writes need a tested transaction/rollback strategy; Windows ACL checks, crash and collision tests must pass before declaring P0. Safe preview must work with token masked.
- Client file import and TUI profile creation are **M4.4c**; real server-issue → file/link → Windows-client import → validated H3/H2 OPEN_OK E2E (and negative cases) is **M4.4d**.

## M4.4c client-side local import (merged; native Linux/Windows CI passed)

With explicit \`theia tui --role client --config FILE\`, \`i\` accepts a pasted \`theia://v1\` URI or absolute local text-file path. Input is **never echoed**, including in error paths; preview shows only ID, endpoint, TLS SNI, transport and whether a token is included. Bracketed paste is enabled in the terminal. No remote URL, file from invitation, or automatic connect/system proxy.

An optional separate \`c\` step selects a **pre-trusted** \`file:/absolute/ca.pem\` validated as an actual PEM containing CA anchors. The import cannot silently weaken CA trust: without CA the new profile is saved but **not connectable** by the runtime. For a public secretless URI, a separate \`e\` step requires explicit \`env:NAME\` credential reference. For a confidential URI a fresh random private subdirectory under the trusted existing TOML parent stores canonical 43-byte token with Unix \`0700/0600\` and explicit protected Windows user SID + LocalSystem DACL on both directory and file. Only a \`file:\` reference enters TOML, never raw bearer. The existing profile list grows only with a **unique ID**, while \`active_profile\`, proxy settings and existing credential references remain unchanged.

After final \`y\` the importer reuses guarded typed TOML validation/atomic save in a background worker. External edits/failed saves roll back the new private token when safe. A post-rename fsync ambiguity preserves the file referenced by the observed committed TOML rather than deleting it and silently breaking configuration. Link input is dropped/zeroized best-effort; caller retains responsibility for source file, terminal/SSH scrollback and private folder. Import success is **not** a claim of TLS connection or token acceptance until a separately selected profile reaches real \`OPEN_OK\`.

Native Linux/Windows integration verifies the actual \`theia client run\` binary with imported private bearer, separately trusted CA, SOCKS5 and HTTP CONNECT over real authenticated H2 (including distinct user action to change active profile). M4.4c **does not** complete F-14: cross-host Linux→Windows/H3, full ACL/adversarial and crash/recovery matrix, and more protected export options remain release blockers. M4.3 WinINet is independently delivered in PR #82 with additional policy/VPN acceptance still open. [ADR-0055](adr/0055-f14-secure-client-import.md).

## Security tests and limitations of M4.4a

The pure codec rejects wrong prefix/version, noncanonical/oversized base64, unknown fields, non-256-bit token, bad endpoint/SNI, unknown TLS profile, invalid env/file references and mismatched/disabled/ungranted server users. The computed full client profile is checked with the existing typed config validator; importing never trusts a provided CA path from the URI. The encoded token is held in memory for import, so the raw link and process memory must be treated as confidential. M4.4a has **no** CSPRNG issuance, file/clipboard UI, ACL, QR, import transaction, runtime reload or service connection; these remain open P0.

## Будущие F-18/F-19 (не реализовано)

REALITY-подобный отдельный security mode и anti-TLS-in-TLS требуют **нового versioned invitation contract** с подтверждённой identity сервера, а не молчаливого расширения theia://v1. Текущий invite v1 разрешает только стандартный TLS с tls_profile=default и строгой проверкой cert/SNI; не принимает неизвестные поля. Новый scanner не экспортирует ключи сервера, bearer или пользовательские URL. См. docs/STEALTH_REALITY.md.
