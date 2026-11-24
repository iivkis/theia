# CI performance measurements and gates

This document is a **Markdown-only proof case** for the conservative CI scope
classifier introduced by [PR #93](https://github.com/iivkis/theia/pull/93).
Any modified source file, workflow, script, test fixture or lockfile must
still run the complete Linux/Windows matrix. Docs-only preflight must pass
the specification contracts and the explicit `ci-gate`; there are no
unconditional or silent success shortcuts.

## Measured baseline and first improvement (2026-11-24)

Durations below are derived from timestamps in GitHub Actions logs for
individual jobs; no extrapolation from a single run to all runners.

| Job / full workflow | Before ([PR #92, run 45331722970](https://github.com/iivkis/theia/actions/runs/45331722970)) | After ([PR #93, run 45333765292](https://github.com/iivkis/theia/actions/runs/45333765292)) |
| --- | ---: | ---: |
| Linux M0.1 API spike | 137 s | **34 s** |
| Linux full Rust tests + clippy | 80 s | 78 s |
| Windows smoke + real SID checks | 257 s | 269 s |
| Entire PR workflow (GitHub run create → completed, including queuing and gate) | 388 s | 378 s |

The isolated M0.1 job became **103 s (~75%) faster** because the
`fingerprint_h2` comparison moved into the Linux root test job where the
native harness had already been compiled. **This is not a 75% whole-pipeline
improvement**: Windows smoke and the dependent WSL2 cross-host job still
dominate the overall critical path. These timings are observations, not
performance service-level promises.

Other verified changes in PR #93:

- One immutable checked-out git tree goes into every native job. Rustfmt and
  gofmt are validated in the cheap specification stage **before** fan-out;
  format drift fails instead of producing a bot commit after CI.
- No `ci-formatted-source` archive is uploaded or downloaded repeatedly, no
  overlay is applied to independently checked-out source code, and no
  `persist-format` job mutates a successfully tested SHA.
- A **docs-only** PR/push can skip the native matrix only after a conservative
  Git diff proves every changed path is Markdown under `docs/` or an explicitly
  listed root Markdown document. Unknown base history, a mixed change, workflow,
  Rust/Go code, scripts or tests all require full native CI.
- On a full run, mandatory Windows SID/ConPTY, Linux PTY, real Linux→Windows
  H2/H3, BBR, BoringSSL, Chromium, TLS verification and the final gate remain
  mandatory. The Go uTLS reference is still generated and compared on Linux
  and Windows.

## Remaining high-cost critical path

The Windows native test/build stage and WSL2 deployment are sequential
prerequisites for the cross-host security E2E. They must not be disabled or
replaced with same-kernel loopback tests to improve an elapsed-time chart.
Potential future work needs **before/after** evidence and an explicit
explanation of runner-minute cost, not just wall-clock time:

1. Profile Windows Cargo compile/cache restore with clean and warm cache
   separately. Do not split mandatory Windows tests into independently
   compiling jobs unless the extra runner cost is measured.
2. Inspect Go 1.24 toolchain and uTLS reference setup on native Windows; do
   not replace pinned sources with stale, unauthenticated fixture bytes.
3. Inspect WSL2 VM provisioning and cross-host bootstrap separately. Do not
   loosen Linux-kernel, independent VM, native Windows-client or real H2/H3
   acceptance invariants.
4. Keep `ci-gate` fail-closed on a missing or unsuccessful native job, and
   test any future path classifier with actual negative Git histories.

## How to verify this Markdown-only fast path

The PR adding this document must record an Actions run in which
`specification` and `ci-gate` finish with **success** and all native jobs
finish with **skipped**, never with failure or a fabricated success. Its
`docs/`-only diff establishes the scope case. A future commit containing a
single `.rs`, `.go`, `.py`, `.yml`, `Cargo.lock` or an unknown file
must instead trigger the full native matrix.

A failed or cancelled check cannot be reported as green. This check is about
safe CI scope, not about weakening the F-18 / F-19 security release gates.

## Experiment: Windows MSVC test/dev line-table debug metadata (PR pending)

Native Windows `windows-smoke` spends approximately 140 seconds in
`cargo test --workspace --all-targets --locked` on the measured warm-cache
run. This includes real transport/TUI/security runtime, not just compiling.
The same runner repeatedly links a large collection of Rust integration
harnesses with Cargo's default full test/dev debugging information.

The **experimental** workflow overrides only Windows smoke's development
and test profile debug metadata with `line-tables-only`. Rust retains source
line locations for panic diagnostics but omits heavyweight full type/variable
debug information and associated Windows PDB work. `CARGO_INCREMENTAL=0`
remains unchanged, every test executes, the cross-SID second-account kernel
denial and ConPTY terminal scenario remain mandatory, the *same* CI-built
Windows executable goes to the real Linux/Windows H2/H3 cross-host test,
and the **release build profile is untouched**. Neither crypto features nor
TLS verification/runtime protocol change.

This is **not a proven speed-up yet**. Cargo fingerprint/cache keys change
for this profile; the first run may be a cold-build regression. Evaluate the
actual Windows smoke duration after the same profile has populated its
cache, benchmark against the 257–269-second warm-cache baseline, and
retain the change only if repeated CI shows a worthwhile improvement
without introducing test failures. Measure full CI wall time and runner
minutes separately. Never claim the whole pipeline was accelerated merely
because a binary is smaller.
