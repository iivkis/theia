# ADR-0055: F-14 client invitation import, protected bearer store and live CONNECT regression

**Date:** 2026-11-24. **State:** implementation proposed, CI acceptance pending.

## Problem

The existing F-14 \`theia://v1\` codec and server TUI issuance are not useful for a remote Windows/Linux client until the client can safely import an independently received link without putting a token in TOML, command-line arguments, ordinary terminal output or the OS proxy. The prior editor could only modify three fields of existing profiles; it could not add a new profile or persist the credential.

## Decision

The client TUI with an explicitly selected \`--role client --config FILE\` gets one local-only \`i\` import workflow. It accepts (a) a **pasted** \`theia://v1\` string using bracketed-paste events or (b) an absolute path to a bounded local text file. The input string is a \`Zeroizing<String>\` and **never rendered**; the display reports only the byte length. No remote fetching, redirect, browser handler, clipboard writing or shell arguments.

A strict versioned decode precedes a review containing only **new profile ID, endpoint, TLS SNI, transport and presence of a credential**. No URI or token bytes appear in preview. The user may separately select a pre-trusted CA PEM via a locally typed absolute \`file:\` reference, validated as a readable PEM containing trusted certificate anchors. If no CA is set, the imported profile remains **non-connectable** by the existing runtime (no silent system trust or TOFU). Secretless public profiles require an **explicit independent** \`env:NAME\` reference; the import never invents an ambient default credential. Both variants require another \`y\` confirmation before any persistence.

For a confidential link the 32-byte bearer is encoded to exact 43-byte canonical base64url in a **fresh randomly named subdirectory** adjacent to the existing client TOML, with a \`create_new\` token file. Unix: directory 0700 and file 0600. Windows: Win32 \`CreateDirectoryW\` and \`CreateFileW(CREATE_NEW)\` each receive a **protected SDDL DACL** allowing full access only to the current TokenUser SID and LocalSystem. No world-readable inherited directory/file ACL. These paths are not accepted from a remotely supplied invitation; the operator's configured TOML parent is the trusted storage root.

The typed existing \`ClientDocument\` is cloned and the new validated \`Profile\` is **appended**; an existing profile ID fails closed. \`active_profile\`, loopback binds, OS proxy, current process, TLS transport and other profiles remain unchanged. The existing guarded editor save checks on-disk content and atomically commits TOML from a background worker. Before a failed replacement the private token file and its directory are removed via RAII. If a directory-fsync failure occurs **after the atomic rename**, the importer compares exact written TOML bytes and preserves the referenced secret while signalling uncertain durability. A crash before TOML commit can leave an unreferenced owner-only random directory; this is not a published credential but requires subsequent trusted local cleanup. No cross-file two-phase commit or journal is claimed.

Client TLS trust remains strict and independent of the invitation; no automatic connection or system proxy change. \`F-14\` completion still requires automated **real Linux-server → Windows-client** cross-host E2E for both H2 and H3, Windows native ACL attack tests and full recovery coverage.

## Given / When / Then

1. Given explicit client config and unrecognized valid invite ID, when the operator reviews and confirms, then only a new inactive profile and (for confidential URI) separate private token file are created. Existing active_profile is unchanged and the raw token is absent from TOML/rendering.
2. Given a public invite, missing/invalid independent env reference refuses persistence; a provided explicit reference permits a non-active draft.
3. Given a confidential URI and verified explicit CA, a **separate later explicit profile selection** permits native client binary HTTP CONNECT and SOCKS5 traffic to pass a real TLS/H2 authentication + SmartTheia OPEN_OK and byte-exact relay in the Linux/Windows CI matrix, without an env token.
4. Given a duplicate ID, dirty editor, external TOML mutation, malformed/oversized URI, missing/invalid CA, unsafe secret storage, symlink source or failed write, then no success or credential exposure. Confirmed writes have bounded sizes and no network side effect.

## Limitations

No clipboard system access, QR, remote config admin, direct import without explicit client config, automatic CA provisioning, remote certificate verification during preview, direct Windows system proxy activation or H3/QUIC cross-host E2E. This PR introduces no new wire type, TOML schema, database, runtime dependency or new executable.
