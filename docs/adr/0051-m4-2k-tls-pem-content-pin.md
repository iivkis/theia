# ADR-0051: M4.2k — verified, operator-pinned TLS PEM material snapshot

**Date:** 2026-11-23. **Status:** PR #76; requires exact-head native CI and review.

## Problem

M4.2h/2i restart Apply authenticated only the saved TOML SHA-256.
Paths tls_cert/tls_key refer to **external PEM files**, whose contents
might be replaced after readiness and before CAS. Previously both
readiness and the supervisor re-opened them at different times.
A valid but unauthorized replacement cert/key pair could therefore
become the actual H2/H3 identity with an unchanged TOML hash.

## Transaction contract

1. The operator saves the valid server TOML and uses trusted private PEM
   paths (Unix secret key mode 0600; Windows owner ACL). Independently
   calculate the SHA-256 of the EXACT saved TOML bytes. Separately run
   the local read-only tool:

       theia server tls fingerprint --config /path/to/server.toml

   It outputs only: theia-tls-pem-v1 sha256=LOWERCASE64HEX. It never
   sends keys, raw PEM or bearer tokens to stdout or IPC.
2. The confirmed command for BOTH same-port TLS rotation and fresh-port
   H2/H3 cutover now requires BOTH content digests:

       theia server restart --apply --expected-revision N --sha256 TOMLHEX --tls-sha256 PEMHEX --confirm

   The older TOML-only restart Apply syntax is rejected by the CLI and
   IPC, including scripts using an older client. This is an intentional
   operator interface migration, NOT a TOML schema change.
   Quota-only and auth-only CAS retain their own earlier protocols.
3. PEM fingerprint algorithm v1: SHA256 of a domain-separated sequence
   beginning with the literal bytes theia-tls-pem-snapshot-v1 and one NUL,
   followed by a big-endian u64 inbound count. For each inbound in
   CONFIGURED ORDER, append three length-prefixed blocks. Each block
   consists of its u64 big-endian byte count and original bytes:
   UTF-8 inbound ID, full certificate PEM bytes, full PRIVATE KEY PEM
   bytes. No ambiguous concatenation, reordering or cross-user swap.
4. Protected Linux Unix management socket / Windows per-user SID-DACL
   Named Pipe raises the maximum REQUEST size from 128 to 256 bytes
   solely to carry the second digest. Reply limit remains 128 bytes,
   with eight concurrent clients and a two-second IPC deadline.
   Canonical positive decimal revision and two strict 64-char
   lowercase hexadecimal digests are mandatory; no explicit
   confirmation means NO write or restart.
5. The worker reads bounded TOML ONCE (at most 1 MiB) and confirms its
   SHA-256. It then reads each referenced cert PEM and key PEM file
   ONCE (maximum 1 MiB each), validates strict TLS1.3 certificate
   SAN, matching private key and real H2+H3/BBR ALPN configurations,
   computes the PEM fingerprint, and checks equality in constant
   time with the operator-provided value.
   Raw loaded PEM buffers live in Zeroizing<Vec<u8>> and are erased
   on drop/error/cancellation. No disk or socket write in the worker.
6. Upon exact match the worker hands a single owned ServerDocument
   PLUS THE CAPTURED PEM BUFFER SET to the bounded supervisor channel.
   The supervisor classifies candidate TLS identities by hashes
   computed from THIS captured snapshot, not by reopening files.
   New H2/TLS and H3/QUIC server configs are built from these same
   captured bytes, even if on-disk paths subsequently change.
   All fresh-port prebinding and same-port swap/CAS safeguards from
   ADR-0048/0049 still apply. Wrong fingerprint, old revision,
   malformed PEM, changed hostname, bad TLS/port or rejected candidate
   leave the existing listeners and monotonic revision untouched.
7. Advisory restart --check may read candidate PEM independently;
   it never pins a future Apply or reserves ports. Recompute both
   digests after ANY edit. A lost acknowledgement is indeterminate:
   query server status before trying another transaction.

## Explicit limitations

- Protection covers *approval-to-apply PEM byte drift* and
  *worker-to-transport-build TOCTOU*. It does not prove initial
  file trust, prevent an already compromised operator/FS, pin client
  trust anchors, provide encrypted/secure-element private keys, or
  implement automatic post-commit rollback.
- A concurrent file writer may still change file contents DURING
  snapshot capture, but the accepted checksum must match precisely
  the captured byte sequence. Atomic versioned PEM-file deployment
  in a trusted directory is still strongly recommended.
- There is no global handshake barrier between TCP/H2 and QUIC/H3.
  Connections already accepted before the CAS may finish with the
  old TLS cert. Existing authenticated streams are never renamed,
  migrated or silently hard-revoked.
- The private key is not exposed in the CLI or IPC replies.
  Fingerprinting is a local explicit operator action. Avoid putting
  actual PEM material, bearer tokens or secret env values in argv,
  logs, test fixtures or public artifacts.
- This PR does not change user roster, grants, dynamic quotas,
  Windows proxy, wire protocol, or add an admin TCP port.
  The older restart command is intentionally incompatible and
  scripts must include a new, previously checked PEM fingerprint.

## CI acceptance

Unit tests: strict new CLI syntax and rejection of old syntax,
verified H2/H3 production TLS configs built from captured PEM
AFTER corruption of both on-disk PEM files, order-sensitive digest,
no debug printing of key/digest. Native compiled Linux and Windows
E2E: leave TOML unchanged; replace both external PEM files after
operator fingerprint with ANOTHER VALID cert/key pair; confirm
restart Apply is rejected while old H2/H3 server remains live and
revision unchanged. Restore approved PEM; complete real same-port
TLS swap and fresh-port cutover with verified H2/H3 handshakes.
Mandatory Windows cross-SID DACL, ConPTY, Rustfmt, Clippy,
Chromium both platforms, BBR/BoringSSL, uTLS and exact-head
14/14 final ci-gate must remain green before review.
