# ADR-0038: M4.2a Linux read-only management health/status over a private Unix socket

**Date:** 2026-11-23. **Status:** proposed until the exact-head native CI gate passes.

## Motivation

The server TUI can edit typed TOML, but cannot prove whether a headless server process is running or whether a saved document was activated. Before a transactional `Apply`/rollback, Theia needs a real local management channel, not a bogus button or unverified "runtime ready" flag. The M4.2 architecture requires a Unix-domain socket on Linux and ACL-restricted named pipes on Windows. This slice implements only an authenticated-by-local-OS **read-only** Linux status primitive and a no-network CLI. It does NOT implement reload or claim F-10 completion.

## Linux capability and access rules

- Opt-in only. An operator must explicitly provide `THEIA_CONTROL_DIR` as an **absolute existing private directory (0700) owned by the process effective UID**, for example under a service-managed `/run/user/<uid>/theia`. Theia never creates/chmods an arbitrary user-supplied parent. The directory path itself cannot be a symlink. Operators must provide a trusted parent path; world-writable parent or malicious same-UID processes remain external risks.
- Socket name: `theia-server.sock`, inside that private directory. Socket permissions: `0600`. Existing sockets/files/symlinks are never overwritten or deleted at bind time, including after crashes. A pre-existing path refuses startup rather than risking another process's data. The owned listener unlinks the path on graceful task drop **only when its original device/inode still match**, so it cannot destroy a replacement. After an unclean kill a stale path may require manual inspection and cleanup.
- If `THEIA_CONTROL_DIR` is absent, the existing server remains operational with **no** management listener; `server status` returns a nonzero `NotConfigured` error. If it is provided but unsafe or occupied, startup fails closed rather than silently running without management. The exact same opt-in directory is needed for the local CLI.
- Linux `server::run_document` prepares all TLS/TCP/QUIC listeners **before** opening the management socket; the socket is served only as part of the owned server task set. No administration TCP endpoint is opened. There is one status socket per runtime directory, not a multi-instance registry.

## Minimal bounded protocol

Client sends exactly one of `health\n`, `status\n` or `reload\n`, never credentials. Request length capped at 64 bytes; timeout 2 seconds includes complete read/write; at most 8 clients concurrently with immediate admission refusal under saturation. Unsupported/invalid commands return `ERR unsupported\n`. Responses are one short line, no target IPs, token hashes, secrets or file locations:

- `health` -> `theia-health-v1 ok`.
- `status` -> `theia-status-v1 running inbounds=N`, where N is the number of prepared inbounds, **not** a claim that a future config reload succeeded.
- `reload` -> `ERR unsupported`. Never modifies TOML or running services.

The client enforces a 128-byte response limit and exact typed protocol decoding. The CLI command `theia server status` queries this socket and returns nonzero on unavailable/invalid responses. A local same-UID process can still spoof a socket: no cryptographic process attestation is provided. This is strictly local service status, not remote control or a security mode credential.

## Given / When / Then

- Given an owner-private existing directory, when the real status service is bound, then the socket has mode `0600`, real `health/status` return bounded typed responses, and the compiled `theia server status` reports the observed inbound count.
- Given a group/world-accessible directory, symlink to a directory, preexisting socket or a regular file, when binding, then refuse with no unlink of the preexisting path and no false running status.
- Given missing service, malformed input, oversized input, or `reload`, when requesting, then fail/return unsupported within bounded time and never mutate configuration.
- Given server task cancellation, when dropping the listener, then only the originally owned socket inode is eligible for cleanup. Test uses an isolated localhost Unix socket; no external DNS/network.
- On Windows, the API denies read-only status as Unsupported until a native ACL-protected Named Pipe exists. Existing Windows H2/H3 runtime is unchanged. Native Linux/Windows CI, lint/fmt and full exact-head gate are required.

## Remaining work

M4.2b+: Windows Named Pipe DACL, hardened runtime directory naming, precise revision/health snapshot counters, TUI IPC integration, validated transactional reload without disruption, compare-and-swap revision and durable rollback; M4.5 real F-18 security mode, eligible candidate selection and independently verified Apply; M4.3 Windows system proxy. This slice does not apply or enable a REALITY-like profile, alter TOML v1/wire/invite, change OS proxy or create a control-plane network port.
