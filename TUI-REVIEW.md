# TUI visual review

This branch is a Linux-only visual evidence gallery, not a product development branch.
The generator checks out the explicitly pinned dev commit (5b0cf126018fbfbd55812cdee502d60d6e84e309) and records real Ratatui draw buffers at one size: 120×40 columns/rows. PNGs use a fixed DejaVu Sans Mono font. No Windows job.

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

The gallery enumerates the actual eight server and eight client sections, checks unique visible action keys, and opens ordinary operations by selecting the section action and pressing Enter. Overview routes to management/connection without starting anything; F2 focuses the existing navigation rather than a second command catalog. The disabled-user fixture captures recovery separately. The separate REALITY import, invitations page and duplicate command-menu screenshots are no longer generated. The last successful gallery remains intact until replacement passes the required-screen and obsolete-screen checks.

The client diagnostics workspace is a required independent screen. The idle server statistics screen reports unavailable metrics rather than claiming a live data source. The inline import and process-local traffic monitor are rendered within their sections. Required screenshots include masked existing-profile import, expanded settings, a user with no grants and the explicit delete confirmation; the revoke-save failure must not contain the underlying workspace. No screenshot implies successful external-runtime access.

The diagnostic workspace includes synthetic offline states for source selection, input validation, fetching, consent, running, completed/partial results, details, policy blocking and failure. The gallery regression gate also verifies compact and advanced client profile navigation without writes, diagnostic consent and safe retry, and idle monitor rendering. Windows native lifecycle acceptance remains separate.

Diagnostic states use distinct successful, policy-blocked, interrupted and failed fixtures. Publication rejects duplicate diagnostic PNGs. Compact action layout and mouse selection without execution are regression-tested; profile ports remain intact across wrapped rows.

GeoSite/GeoIP picker screenshots use synthetic local category names, and the REALITY manual selection screenshots use synthetic H2 application-check durations. Navigation and role assignments never contact external sites; the real worker and persistence gates remain separate.

GeoData visual states cover visible form actions, compact search, all marked categories across filters, added draft values, empty search and missing pinned datasets. Named actions and mouse focus are regression-tested; no real download is initiated.

GeoData picker reloads existing selectors, synchronizes additions and removals (including an empty selection), preserves manual literal selectors, and refuses edits without a verified catalogue. Reopening and clearing states use synthetic pinned catalogue results.

GeoData visual contract additionally covers neutral unverified selectors, explicit default Enter action, added/removed counts, warning for clearing all, empty search with preselected categories, post-removal draft and obsolete category. The renderer approximates terminal DIM by blending foreground toward background at 48% intensity (including reversed cells); physical terminal rendering remains platform-dependent.
