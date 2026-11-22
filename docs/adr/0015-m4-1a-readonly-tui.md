# ADR-0015: M4.1a read-only ratatui landing and terminal lifecycle

**Date:** 2026-11-22  
**Status:** PR acceptance pending; no config/network/system proxy behavior changes.  
**Next:** M4.1b configuration forms, M4.2 local IPC, M4.3 Windows proxy; F-13/F-11/M5 remain BLOCKED.

## Problem and boundary

After M3.4j Theia has real H2/H3 client/server runtimes and SmartTheia tunnels, but the documented TUI command still returned not implemented. The first vertical slice must establish two independent user-visible panels and deterministic keyboard/model tests without inventing service metrics, config editing or live state.

## Decision

- Pin ratatui 0.29.0 and crossterm 0.28.1 in the single existing Rust workspace; update and commit Cargo.lock.
- Route `theia tui [--role server|client]` to a real interactive renderer in the same binary. Both stdin and stdout must be TTY before any raw mode or alternate screen modification.
- Read-only UI model: Home, Server, Client, Help; keys `1`/`2`, Tab/Shift+Tab, Enter, Esc, `?`/F1 and q/Ctrl+C. Below width 80 cards stack, and tiny terminals show a bounded warning.
- Explicitly label runtime as unknown because no IPC probe exists. Show no invented inbound count, connection count or transport-established status. Never touch secrets, files, sockets, OS proxy, server/client runtimes or host-wide settings.
- RAII guard handles raw-mode/alternate-screen/cursor cleanup on success, normal IO failures and panic unwinding. An uncatchable process kill cannot be promised to restore the terminal.

## Acceptance and threats

- Given a role argument, the initial screen displays the corresponding role; without a role the landing shows both choices.
- Given Tab, role keys, help/back navigation and q, the pure state transition is deterministic, and a noninteractive CLI invocation rejects early without output or terminal mutation.
- Given 60x18, 80x24, 120x40 and undersized terminal fixture, ratatui TestBackend renders without panic or false 'connected' status.
- Given a terminal setup/draw/input error, guard attempts cleanup. No network dial, configuration apply, Windows proxy mutation or secret exposure is reachable from the read-only UI.
- CI Linux/Windows workspace tests, rustfmt, all-features clippy and exact head ci-gate mandatory. Release-grade interactive PTY/Windows console recovery and future dirty/save/apply acceptance remain open.

## Rollback

Remove the new module, its dependency pins and lockfile entries, CLI route/test updates and these docs. No TOML or runtime migrations.
