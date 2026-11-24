# ADR-0068: guarded configuration transactions and uncertain replacement

**Status:** pending full native CI.

## Context

The existing editor compared its saved bytes before staging, with no shared serialization between editor processes. A failure after rename could delete a newly referenced bearer if readback failed or changed. Both are correctness and safety issues in existing F-14 storage, not a new F-18 identity store.

## Decision

Use the OS advisory file lock on a stable, empty sidecar for cooperating editors. Do not delete the lock file when releasing the handle. Under the lock compare the original bytes, stage and sync the candidate, compare again just before rename, then replace. Bounded opened-handle reads reject final symlink/reparse objects on supported Linux/Windows. The write result distinguishes pre-replacement failure from post-replacement directory sync uncertainty. On uncertainty preserve a potentially referenced new credential, suppress pending issuance, and block further edits from saving or applying until the editor is reopened. The generic atomic writer retains its existing public result contract.

## Given / When / Then

- Two loaded editors attempt different writes from the same bytes: at most one changed candidate is stored; busy or stale writer refuses.
- A held lock prevents another cooperating writer but does not affect another path; dropping the OS handle releases it. Native child processes verify a busy lock, acquisition after release, and lock release after process exit.
- An injected sync failure after rename is classified as uncertain, not rollback. The changed file remains, and the editor must reload before a subsequent save.
- Invalid/stale input is rejected before replacement; old bytes remain. Linux symlinked document and sidecar paths are refused.
- An injected pre-replacement import refusal deletes only the new credential. Post-replacement uncertainty retains the credential even when the destination cannot be reread. No new server issuance is revealed.
- Existing v1 import, independent CA and grants remain unchanged.

## Limits

Advisory lock only coordinates callers of guarded_write on the same destination, under a trusted parent directory. Noncooperating writers can still race the final check/rename; no universal CAS or hostile directory guarantees. Windows directory sync is not implemented. No power-loss guarantee, secure orphan cleanup, durable F-18 trust anchor, protocol or TLS changes. No new dependencies; mandatory CI remains unchanged.
