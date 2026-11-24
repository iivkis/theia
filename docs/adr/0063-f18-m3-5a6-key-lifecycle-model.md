# ADR-0063: F-18 M3.5a6 — local trusted key lifecycle model

**Status:** research-only, pending CI and independent review. No production trust protocol.

## Context

ADR-0059 proposed an independently pinned server identity after verified TLS; M3.5a4/a5 provide separate network and replay evidence. Before any shipping implementation, establish explicit testable rules for replacing locally trusted pins without falling back to plain TLS.

## Decision

The model consumes an already authorized local snapshot, never a network-provided key or generation. The scope is a local inbound ID plus expected DNS hostname and port; the expected transport must match the transcript. Each snapshot has a nonzero generation; replacement must advance exactly one, keep scope, contain zero to two distinct nonzero pins (an explicitly authorized empty set denies all proofs), and preserve or narrow existing key intervals. Verification requires both local time and signed issuance within the half-open pin interval. Removed keys enter bounded retired history and cannot re-enter within that model instance. Exhaustion fails closed; no eviction or partial update. A successful replacement preserves the existing replay window. Plain mode and unknown key are rejected rather than retried.

## Acceptance

- Both H2/H3: old pin works before retirement; explicit overlap admits new and old; old expiry and removal reject; new pin rejects before activation and backdated proof; old replay still fails after update.
- Scope and branch mismatch, missing trust, plain-mode request, generation rollback/gap, time rollback, duplicate key, lifetime extension and attempted retired-key reintroduction fail.
- Early revocation of an unexpired key, explicit deny-all, rejection of reintroducing the old pin, and recovery with a newly authorized key are tested on both branches.
- History saturation leaves the last authorized snapshot unchanged; a proof under that snapshot remains valid.
- Real Ed25519 verification uses the existing research helper with synthetic inputs. Native Linux/Windows locked cargo tests and full exact-head ci-gate are required.

## Limits

The inbound ID is local policy metadata, not a field of the existing signed transcript. This experiment does not prove isolation if operators reuse the same key across independently configured inbounds; production must prevent such reuse or cryptographically bind the scope in a reviewed protocol. Snapshot authenticity, durable monotonic generation and revocation across process restart, protected secret provisioning, concurrency, crash consistency, key rotation delivery, and recovery from history exhaustion are unresolved. The model's empty trust set rejects proof verification but is not an operational mechanism to stop a listener or revoke already open sessions. No new on-wire format, TOML/invite migration, TLS verifier, anti-probing mechanism, or production runtime. F-18 remains P0 blocked.
