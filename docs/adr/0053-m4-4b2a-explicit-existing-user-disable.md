# ADR-0053: M4.4b2a explicit existing-user disable in server TUI

Status: proposed for review, 2026-11-24. This is a **narrow F-14 lifecycle slice**, not complete M4.4b2 or F-14.

## Given / When / Then

- **Given** a validated, clean, explicitly opened server TOML in the server TUI, **when** the operator selects an inbound, presses `x`, enters an existing enabled user ID granted to that inbound, and separately confirms `y`, **then** the TUI stages `server.users[ID].disabled = true`, validates the entire candidate and saves via the existing background atomic writer with external-file conflict detection.
- **When** save succeeds, **then** only the TOML file has changed. No hidden IPC apply/reload occurs. The UI explicitly instructs the operator to separately check the authorization revision and perform the existing confirmed auth-only CAS Apply to stop new H2/H3 admissions.
- **When** save fails, **then** no success is displayed. `r` retries the bounded save and `d` discards the draft. The user can cancel before confirmation. Existing grants and SHA-256 bearer digest stay byte-identical.
- **When** the user ID is missing, not granted on the selected inbound, already disabled, the editor is client-mode/editing/dirty or an issuance is pending, **then** the change is rejected. Client TUI never opens this modal.

## Threat model / decisions

- Disabling a user is **global across all inbound grants**, because `disabled` lives on the server user, not on a single inbound. Confirmation says this explicitly; the selected inbound and typed user ID are a guard against accidental selection, not a per-inbound disable.
- Revocation is **not hard revocation**. Neither saving TOML nor subsequent auth-only CAS terminates existing authenticated tunnels; they retain their current permissions. An operator requiring immediate disconnection must use separate operational procedures.
- The stored digest **cannot regenerate the old bearer**, and this change neither exports nor rotates it. No secret, token hash or file contents are displayed by the modal. No new IPC privilege, network listener, protocol or TOML schema.
- File-change conflict, symlink rejection, whole-document validation and file size limits are inherited from `Editor::save`. A lost future IPC acknowledgment remains indeterminate and requires status reconciliation.

## Acceptance

Native Linux/Windows CI must run:
- Editor tests for absent ID, dirty/editing/client role, one successful disable, preserved grants/digest, repeated disable rejection, external-file conflict.
- TUI keyboard test for `x` → ID → Enter → `y` → async durable save and explicit success, plus client/dirty shortcut denial and no credential display.
- Existing Rust test/fmt/Clippy, terminal E2E, H2/H3/security matrices and final required `ci-gate` for the **exact head**. No local-machine test is a substitute.

## Out of scope

Existing-user token rotation, re-enable, per-inbound grant editing, secure file/clipboard export, client-side import, user enumeration picker, instant session eviction and F-14 cross-host Linux→Windows E2E. All remain open.
