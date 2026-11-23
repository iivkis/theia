# ADR-0058: Bounded, default-on private trace diagnostics

**Status:** accepted for the experimental Theia implementation; native CI evidence is required before calling the slice completed.

## Context and decision

The existing architecture called for opt-in debug traces, while reproducing failures in unattended CI and headless client/server processes requires logs to be present **before** a failure. A general-purpose `Debug` dump of requests, configuration, tokens, destinations, or error chains would violate the stronger security requirements in `AGENTS.md` and `docs/SMARTTHEIA_PROTOCOL.md`.

Keep the privacy invariant and introduce a distinct, **default-enabled, safely structured trace recorder** independent of `management.log_level` (that legacy v1 TOML field remains accepted). This is a deliberate refinement to `docs/ARCHITECTURE.md`, not permission to enable raw packet/metadata logging. No TOML v1 migration or external control plane.

- Start from the first CLI action, including failed argument parsing and TUI entry, and from the first instrumented library operation. Record `unix_ms`, monotonic elapsed time, sequence number, PID, thread ID, source file/line, component, event and a local operation/session identifier. Cover selected H2/H3 connection, authorization, handshake, OPEN/OPEN_ERROR, QUIC fallback, TCP relay and orderly close/error stages.
- Fields have **only** three safe types: unsigned counters, booleans, and compile-time string labels. The logger has no public arbitrary-text or object-debug recording API. It never records server/client/target IP or DNS names, target ports, user IDs, authorization headers, hashes, tokens, URIs, file paths, config contents, TLS secrets, packet payloads or panic messages. Only local **listening port numbers** may be included as server startup metadata.
- One process writes two rotating segments of **25 MiB each**, max **50 MiB of active retained trace per process**. A new run receives a distinct PID/time-based filename, so it cannot overwrite another live process or previous crash evidence. Older runs are not garbage-collected: users/CI must implement retention policy for directories. This bound is explicitly **not** an aggregate machine-wide 50 MiB budget.
- Bounded `sync_channel(4096)` with `try_send` avoids blocking Tokio reactors on disk I/O. A dedicated thread writes/flushed lines and rotates atomically within its file set; overloads increment a counter and emit a `queue_overflow` marker when the writer catches up. Events may be lost if the queue stays full or the process/power dies abruptly. Successful normal CLI exit drains through an explicit flush barrier (up to 3 seconds).
- Linux: log directory must be a non-symlink private `0700` directory; created log files are `0600`. Windows: default `%LOCALAPPDATA%\\Theia\\logs` inherits the account ACL; an override must be a directory accessible only to the intended operator. No elevated rights or fallback to an unprotected file.
- Defaults: Linux `${XDG_STATE_HOME:-$HOME/.local/state}/theia/logs`; Windows `%LOCALAPPDATA%\\Theia\\logs`. Set `THEIA_TRACE_DIR` to an explicitly trusted private directory for CI/operations, or `THEIA_TRACE_OFF=1` to disable. If the file cannot be initialized, the application remains available and prints a path-free warning to stderr; diagnostics are incomplete rather than silently claiming success.
- Native CI uses isolated `${{ github.workspace }}/theia-traces` directories and uploads trace artifacts **on failure**, with short retention. Test output is not copied into the logs.

## Alternatives rejected

A raw, globally enabled `tracing::Debug` subscriber or wire-packet dump would accidentally serialize bearer credentials, destination metadata or secrets from third-party error types. Synchronous append from async handlers could stall the network. A single unbounded log or unlimited backups could exhaust storage during CI and outages. Silent event loss under pressure would make incident reconstruction misleading.

## Risks and remaining work

Trace I/O still has bounded CPU/queue overhead; successful `flush` is not `fsync`. Correlation IDs are process-local, not propagated across the wire, so client and server traces must be aligned by timestamps and protocol stages rather than a shared secret correlation header. Files from previous process runs require external retention management. Windows directory ACL validation is not yet as strict as Linux. These are limitations, **not** evidence that every CI or production failure can be diagnosed from traces.

## Acceptance

Native Linux and Windows tests must verify default-on behavior, no argument/secret leakage, off switch, bounded rotation and private file permissions on Unix, plus new H2/H3/client/server event coverage under existing E2E. CI artifacts must be available if a mandated native job fails. `ci-gate` must pass for the exact PR head before this ADR is marked fully verified.
