# TUI visual review

This branch is a Linux-only visual evidence gallery, not a product development branch.
The generator checks out the explicitly pinned dev commit (3fcef3e13d352c069241d991092c239c53e910ee) and records real Ratatui draw buffers at one size: 120×40 columns/rows. PNGs use a fixed DejaVu Sans Mono font. No Windows job.

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
