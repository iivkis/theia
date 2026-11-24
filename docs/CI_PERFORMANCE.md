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

## Verified Windows MSVC CI memory/time improvement (PR #95, 2026-11-24)

[PR #95](https://github.com/iivkis/theia/pull/95) keeps **all** mandatory
Windows native all-targets tests, WinINet rollback, cross-SID kernel DACL
denial, ConPTY, and real Linux VM → native Windows H2/H3 cross-host acceptance.
Only the Windows smoke job overrides Cargo **dev/test** debug metadata with
`line-tables-only` (retained source-line diagnostics, less expensive full MSVC
PDB/type/variable data). The release profile, binary semantics and transport
security remain unchanged. Exact-head [full native CI run
45336214208](https://github.com/iivkis/theia/actions/runs/45336214208)
passed, including a selectively rerun Windows job and its dependent cross-host
acceptance.

| Metric | Baseline warm cache (PR #93) | New cold cache (PR #95) | New warm cache (rerun only Windows + dependencies) |
| --- | ---: | ---: | ---: |
| Windows smoke total job | 269 s | 380 s | **209 s** |
| Windows `cargo test --workspace --all-targets --locked` step | ~140 s | ~282 s | **~104 s** |
| Restored Rust cache size | 742 MiB | none (new profile key) | **240 MiB** |
| Windows second-SID + native terminal E2E | mandatory, passed | mandatory, passed | mandatory, passed |

Measured sources: old Windows job in
[PR #93](https://github.com/iivkis/theia/actions/runs/45333765292/job/138241079317);
[PR #95 cold job](https://github.com/iivkis/theia/actions/runs/45336214208/job/138248932308);
[PR #95 warm job](https://github.com/iivkis/theia/actions/runs/45336214208/job/138252017848).
GitHub Actions timestamps show **60 s (~22%) faster Windows smoke** at
warm cache than the prior warm-cache baseline, and a **502 MiB (~68%)
smaller** Rust cache archive. The reduced archive also lowers transfer and
storage costs. The initial cold run was **111 s slower**, which is an explicit
one-off cache migration cost rather than a win.

**Scope of result:** this is an A/B observation of individual Windows jobs,
not a statistically calibrated performance guarantee or a claim that the
entire full CI became 22% faster. The dependent WSL2 cross-host step remains
mandatory and creates a lower bound on full CI wall time. Warm cache is only
usable when the matching Cargo/Rust/lockfile/profile hash is available;
changing dependencies, toolchain or runner images can restore cold timings.

Next bottlenecks: pinned Go 1.24 setup (~20–30 s on Windows), actual
second-user SID test and WSL2 guest provisioning (~50 s), both of which must
retain native/security correctness. Do not replace these with mocks or
unverified reusable fixtures just to reduce reported CI time.
