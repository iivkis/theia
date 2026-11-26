# TUI visual review

This branch is a Linux-only visual evidence gallery, not a product development branch.
The generator checks out the explicitly pinned dev commit (a0479d141cb5c94b6b50ba96e479fb0f0ced742b) and records real Ratatui draw buffers at one size: 120×40 columns/rows. PNGs use a fixed DejaVu Sans Mono font. No Windows job.

- Open [screenshots/README.md](screenshots/README.md) after a successful workflow.
- Read screenshots/manifest.json first: it identifies the exact source SHA, scenario names and file digests.
- Screens with the state- prefix use explicit synthetic presentation states. Action screenshots can contain errors when a fixture cannot perform the action. The gallery is not proof of network, management, or terminal-emulator acceptance.
- The workflow builds a fresh snapshot when this branch's review inputs change. For another dev revision, update the pinned source SHA in the workflow (including its manifest validation) and push to build/tui-review. A workflow_dispatch event is available only if GitHub recognizes the workflow on the default branch; the push route does not require that.
- No real user TOML, tokens, private keys, clipboard contents, or network probe confirmations are used. Missing asynchronous/live states must be added as safe fixtures, not fabricated screenshots.
- Publication replaces screenshots/ only after a successful capture. Failed runs leave the last successful snapshot intact.

The gallery now captures first-run self-contained REALITY import (masked key, trust review, saved profile and connection-mode choice) alongside the existing Own-TLS flow. The Own-TLS flow still requires an independently supplied CA; this is a known product limitation.

## Agent checklist

Check the source SHA before using screenshots. Review visual hierarchy, truncation, contrast, layout density, current focus, clear next action, understandable field descriptions, confirmations, and separate saved/runtime status. Report by screenshot filename and concrete visual defect. Do not equate a rendered preview with verified runtime operation.

The local proxy gallery waits for the actual status result and captures the explicit start confirmation without launching a listener.

Both REALITY and Own-TLS local proxy status and start confirmation are captured after the read-only check, with assertions for clear Russian labels, no internal profile ID in the connection view and the common confirmation layout.

The navigation review captures both horizontal role selections and the section, record, field and action focus reached through actual arrow keys, with independent tests for menu boundaries and no implicit execution. Shortcut aliases remain available but are not printed next to ordinary actions.

This review pins the unified vertical action layout and explicit confirmation choices (cancel selected initially), tests confirmation focus versus execution, direct profile selection and wrapped long addresses, and checks opt-in technical server status. The gallery captures actual keyboard-driven choices without starting real network listeners.

Review captures compact report-aligned choices, no single-step progress marker, safe save recovery, a separate private-link reveal confirmation, arrow-driven passive diagnostics, and actual registered REALITY server summary/technical views. All network consent is cancelled; status observation does not start listeners.

The gallery includes the revised first-run server wizard source selection and DNS consent screen; no external probes are approved.

The REALITY wizard gallery includes collapsed/expanded DNS consent, exact TLS target consent, partial checking, final recheck, ranked result with selected/reserve/rejected candidates, no eligible candidates, saving, storage error and uncertain publication. state-reality-* uses the production ranker and renderer with explicitly synthetic observations and channel outcomes; no external network or configuration save is started. Required screenshot names are checked before publishing.

The updated wizard adds required DNS progress, expanded TLS consent, compact and expanded ranking, a 40-candidate long report, expanded no-match results, read-only file inspection, success, extra source fields and the user picker. Success and key handoff now use the actual offline save/poll transition in a disposable synthetic configuration, without issuing a user key or starting a server. The gallery does not contact reference sites.

The gallery also requires the multi-line domain editor, the bottom of the 40-candidate report reached by normal PgDn (with repeated headers and the last row visible), and the explicit key-issuance handoff. No external sites are contacted; locally generated test identity materials remain in the temporary runner directory, never in the PNG or published gallery.

## Single-owner navigation

The gallery enumerates the actual seven server and six client sections, checks unique visible action keys, and opens ordinary operations by selecting the section action and pressing Enter. Overview routes to management/connection without starting anything; F2 focuses the existing navigation rather than a second command catalog. The disabled-user fixture captures recovery separately. The separate REALITY import, invitations page, client diagnostics page and duplicate command-menu screenshots are no longer generated. The last successful gallery remains intact until replacement passes the required-screen and obsolete-screen checks.
