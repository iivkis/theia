# TUI visual review

This branch is a Linux-only visual evidence gallery, not a product development branch.
The generator checks out the current dev commit and records real Ratatui draw buffers at one size: 120×40 columns/rows. PNGs use a fixed DejaVu Sans Mono font. No Windows job.

- Open [screenshots/README.md](screenshots/README.md) after a successful workflow.
- Read screenshots/manifest.json first: it identifies the exact source SHA, scenario names and file digests.
- Screens with the state- prefix use explicit synthetic presentation states. Action screenshots can contain errors when a fixture cannot perform the action. The gallery is not proof of network, management, or terminal-emulator acceptance.
- The workflow builds a fresh snapshot when this branch's review inputs change. For another dev revision, rerun the workflow (it resolves dev at execution), or push a change to tools/tui-review. A workflow_dispatch event is available only if GitHub recognizes the workflow on the default branch; the push route does not require that.
- No real user TOML, tokens, private keys, clipboard contents, or network probe confirmations are used. Missing asynchronous/live states must be added as safe fixtures, not fabricated screenshots.
- Publication replaces screenshots/ only after a successful capture. Failed runs leave the last successful snapshot intact.

## Agent checklist

Check the source SHA before using screenshots. Review visual hierarchy, truncation, contrast, layout density, current focus, clear next action, understandable field descriptions, confirmations, and separate saved/runtime status. Report by screenshot filename and concrete visual defect. Do not equate a rendered preview with verified runtime operation.
