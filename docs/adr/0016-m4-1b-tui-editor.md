# ADR-0016: M4.1b explicitly selected typed configuration drafts

**Date:** 2026-11-22  
**Status:** Proposed in PR #40; exact-head native CI required.

## Motivation

M4.1a provides read-only server/client landing. The original TUI spec requires typed editing with dirty-state, validation, no implicit runtime reload and safe exit. A full inbound/user form or OS proxy workflow is too large for one verified slice.

## Decision

Only `theia tui --role server|client --config FILE` opens the editor. The role must match the existing, strictly valid v1 TOML document. Without a config path the terminal UI stays read-only; no default `/etc`, AppData or home file is searched or created.

- Server: first inbound's non-secret `server_name`. Client: active profile's non-secret `server` endpoint. Editing keys Enter/e, bounded printable text, Backspace, Enter to validate full typed draft, Esc to cancel.
- Ctrl+S checks validation, current path regular-file status and complete source-byte equality, then uses existing `config::atomic_write`. Display `Сохранено в TOML; runtime ещё не обновлён.` The service is never reloaded or started.
- Dirty transitions including quit require confirmation: `s` save and continue, `d` discard and continue, Esc stay. While typing, `q`, `1` and `2` are text, not hotkeys. Validation errors show only field and static reason; never file contents or secret references.
- Reject mismatched role, missing/invalid configuration, source symlink and externally changed files. No secret access, network/IPC/OS proxy changes, or automatic unsafe fallback.

## UI file I/O isolation

The initial config file is read before raw terminal mode. Actual save (full validation, conflict check and atomic fsync write) runs on a dedicated one-shot worker thread with channel-returned result; the terminal event loop continues to poll and draw a progress panel. Navigation after save resumes only when the worker confirms success. An uncatchable process termination can still interrupt persistence; no success is shown before confirmation.

## Threats and remaining gaps

The existing atomic store is not an atomic compare-and-swap with an external writer. Source-file byte comparison reduces accidental lost updates but not an adversarial race or hostile parent directory. The caller must supply a trusted config path/directory; production multiuser hardening remains open. Typed serialization does not preserve TOML comments. Rewriting a valid configuration does not imply that referenced certificates, CA or secrets exist or that runtime has accepted them. Full multi-field forms, multiple inbound/profile selection, secrets/user rotation, transactional reload and Windows system proxy remain out of scope. BBR/F-11, named browser fingerprint/F-13 and M5 remain blockers.

## Acceptance

- Positive client and server typed edits, persisted values and unchanged token references/user grants.
- Negative invalid input, token non-disclosure, symlink rejection, external conflict (original stays intact), no TTY, discarded drafts and dirty/exit confirmation, bounded text input.
- 60x18 / 80x24 / 120x40 screen render regressions, entire Linux/Windows workspace jobs, rustfmt, all-features clippy, experimental BoringSSL and browser E2E; `ci-gate=success` on exact head SHA.

## Rollback

Remove the TUI editor module, explicit CLI variant/route and UI dispatch. No schema migration or network changes.
