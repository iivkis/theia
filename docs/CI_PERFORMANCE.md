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

## Remove unused release compilation from ordinary CI (merged PR #97)

The optimized `cargo build --workspace --release --locked` had been executed
**on every main push**, twice, at the *end* of `rust-tests` (Linux) and
`windows-smoke` (Windows). Neither release binary was uploaded or consumed
by any CI/security/E2E job. The real F-14 Linux VM → native Windows client
acceptance explicitly consumes **debug/dev native compiled binaries** from
the two mandatory native jobs; releasing another optimized copy after those
tests only delayed the Windows prerequisite and burned runner time.

In [main run 45337912142](https://github.com/iivkis/theia/actions/runs/45337912142),
the last Linux release-build step ran approximately **17 s** and the Windows
release-build step approximately **257 s** (timestamped GitHub Actions logs).
The main push workflow took ~807 s including queues and cross-host E2E; its
Windows smoke job ran ~691 s, including a cold Cargo cache. These observations
are not a forecast for future warm-cache runs.

**New default:** PRs and pushes to `main` perform **all** mandatory native
Linux/Windows tests, pinned Go uTLS comparisons, Rustfmt/Clippy, SID-DACL,
WinINet CAS, real terminal tests, browser/BBR/BoringSSL matrix, cross-host
WSL2 H2/H3 and the fail-closed `ci-gate`. They do **not** recompile unused
release-mode binaries after all those checks.

**When explicitly needed:** GitHub Actions → `CI (tests first)` →
`Run workflow` (`workflow_dispatch`) still runs **the entire native
matrix and both Linux/Windows optimized release builds** for the selected
ref. Those manual builds are compile checks, not deployable artifacts, and
do not by themselves certify production release readiness. GitHub Actions
is still the only required execution environment; no local Rust toolchain
is necessary.

The CI DAG regression guard asserts exact manual-only conditions for
both release-build steps, preventing a later edit from silently restoring
the main-push expense or dropping release compile checks entirely.

### Verified full native CI after the merge

The exact-head code PR [run 45363429350](https://github.com/iivkis/theia/actions/runs/45363429350)
succeeded with **all 15 jobs**, including real cross-SID and real WSL2
cross-host acceptance. After [PR #97](https://github.com/iivkis/theia/pull/97)
merged, the [main push run 45364323549](https://github.com/iivkis/theia/actions/runs/45364323549)
also succeeded with **all 15 jobs**. GitHub Actions individually reported
both `Manual release compilation (Linux)` and
`Manual release compilation (Windows)` as **skipped** in that main-push
run. Neither production-mode security tests nor the final `ci-gate` were skipped.

| Measured result | Pre-change main [run 45337912142](https://github.com/iivkis/theia/actions/runs/45337912142) | Post-change main [run 45364323549](https://github.com/iivkis/theia/actions/runs/45364323549) |
| --- | ---: | ---: |
| Full workflow creation → completion | **807 s** (13m27s) | **323 s** (5m23s) |
| Windows smoke native job | **691 s** | **209 s** |
| Linux native Rust job | **112 s** | **85 s** |
| Native Windows → real Linux WSL2 cross-host | **74 s** | **76 s** |
| Windows release compile (step) | ~257 s executed | **skipped** |
| Linux release compile (step) | ~17 s executed | **skipped** |

Between these **two specific real runs**, the total workflow finished
**484 s (8m04s, ~60%) sooner**. Do **not** attribute all 484 seconds to
removing release builds: the older main run had a **cold Windows Cargo
cache** following a Rust profile change, while the new one restored a
warm matching cache. The directly deleted extra computation is the
previously measured ~257 s Windows release + ~17 s Linux release
(approximately **274 runner-seconds**) in addition to any cache effects.
Queue times and runner image/caches may also vary; this is not a
guaranteed speedup on every subsequent commit.

The main Windows smoke and cross-host still validated the same real OS
security and tunnel behavior. Manual `workflow_dispatch` retains
explicit verification of release compilation on both platforms.

## Eliminate seven duplicate formatting runs after the centralized preflight

The `specification` job already checks Rustfmt for **root, isolated M0.1,
and isolated M3.4 workspaces** and checks Go formatting for **all tracked Go
source files**. It also explicitly checks that its format validation has not
modified the SHA-pinned source tree. On non-Markdown code PRs this must
succeed **before** the Linux/Windows/Go/BoringSSL matrix fans out.

Previously seven extra formatter executions happened later despite that
successful fail-fast check:

- Linux root `rust-tests`: one `cargo fmt`
- Linux isolated M0.1 spike: one `cargo fmt` and one `gofmt -l`
- BoringSSL isolated M3.4 spike: one `cargo fmt` on **each** OS
- Experimental production BoringSSL feature job: one `cargo fmt` on **each** OS

Those redundant formatter invocations are removed. The `specification`
checks stay mandatory and fail-closed; **no** tests, security acceptance,
feature-specific Clippy, Go uTLS comparisons, or native binaries are skipped.
The CI graph regression test asserts the central format commands remain
present and that no native job re-adds them. This is modest runner-minute
hygiene rather than a claim of significant end-to-end wall-clock speedup;
real measurements must be compared after CI passes on the exact PR SHA.

## Remove duplicate M0.1 compilation runners for BBR/CUBIC evidence

The [pre-change full main run 45364323549](https://github.com/iivkis/theia/actions/runs/45364323549)
succeeded in **323 s**. Independent mandatory `m3-3-bbr-comparison`
Linux and Windows jobs occupied **44 s** and **55 s**, respectively.
They duplicated setup/cache and compilation of the same isolated
`spikes/m0_1` workspace that the already mandatory native M0.1 Linux
(**30 s**) and Windows (**89 s**) jobs compile.

Native BBR/CUBIC acceptance is **not removed**. Each existing M0.1 job
now also runs the same ignored
`comparison_records_all_controller_scenarios_ci_only` test: all
**16 real loopback trials** (2 controllers × 4 impairment conditions ×
2 repetitions) on its own operating system. It validates real CSV data
with the unchanged `tests/benchmark/check_bbr_comparison.py`,
and uploads the same `m3-3-quic-comparison-Linux` and
`m3-3-quic-comparison-Windows` artifact names. A missing CSV
fails the job. The `ci-gate` requires both full M0.1 jobs, now
including this BBR test and validator, so the native BBR security/transport
regression coverage is preserved.

The CI workflow now has **13 logical jobs** rather than 15, while
the original M0.1 tests and mandatory Rust, uTLS, WinINet, ConPTY,
Windows SID kernel isolation, Chromium and real WSL2 H2/H3 gates
remain. Release compilation is still explicitly manual-only.
A separate concurrent optimization in PR #99 centralized all Rustfmt and
gofmt checks in the fail-fast specification; this change preserves it
unchanged and does not install Go twice.

**Expected until measured:** fewer CI runner startups and no duplicate
M0.1 Cargo compilation in BBR-only jobs. Native BBR execution time
moves into the M0.1 jobs, so do not claim all 99 old runner-seconds were
saved or promise a whole-workflow speedup until exact-head CI and
follow-up warm-cache measurements confirm it.

## Measured baseline for milestone-sized PRs (2026-11-24)

Three successful ordinary first-attempt PR runs, with the same 13 required jobs:

| Metric (seconds) | #106 run 45391036352 | #107 run 45392909341 | #108 run 45395505034 |
|---|---:|---:|---:|
| Run created to updated (API metadata) | 295 | 333 | 321 |
| Windows smoke | 173 | 220 | 208 |
| Windows all-target tests | 90 | 108 | 108 |
| Windows Go setup | 15 | 25 | 23 |
| Windows cross-SID E2E | 20 | 25 | 25 |
| Windows F-14 binary staging | 1 | 1 | 1 |
| Linux build command for artifact | 0 | 0 | 1 |
| WSL2 cross-host | 88 | 80 | 78 |
| Specification | 19 | 21 | 21 |
| Specification Go setup | 8 | 3 | 9 |

Source: GitHub Actions REST run and jobs timestamps, rounded to integer seconds; zero denotes sub-second/timestamp resolution, not proof of no work. Run updated_at is metadata, not an exact last-job finish. The new timing helper uses last completed job instead. Do not remove artifact staging or native security tests: the former is already cheap and the latter is coverage. Windows smoke and its dependent cross-host remain critical path candidates.

### Next CI maintenance block

The format-only specification Go setup no longer restores or saves module/build cache because gofmt does not use it. All five Go-compiling setups retain the pinned cache and version. Native Windows M0.1 checks go mod verify and go test exit codes before running the next command. The DAG guard tests these distinctions. Expected: small reduction in preflight cache work, not a measured wall-time improvement yet. No job or coverage removed.

### Repeatable comparison

Save successful first-attempt ordinary run metadata and attempt-specific job JSON (with all 13 jobs) from the GitHub Actions API; use the same event type for both snapshots. Run the diagnostic in CI or on exported metadata:

`python3 scripts/ci-timing.py before-run.json before-jobs.json after-run.json after-jobs.json`

The script checks exact SHA/run/attempt identity, successful complete expected matrix, consistent timestamps, step completion and matching event. It rejects missing pages, docs-only, manual, failed and rerun snapshots. It reports wall-clock observation, sum of job durations (not billed runner minutes), and matching step timing; skipped and ambiguous repeated step labels are excluded. No API credentials or network access are needed. Synthetic fixtures validate the tool in the existing specification job. This is a diagnostic, not a substitute for the final gate, and cache/runner/queue differences still require interpretation.

The timing regression suite includes two sanitized actual first-attempt snapshots from runs 45395505034 and 45397074048. Only required run/job/step metadata is retained; no logs, runner names, credentials or environment values. This catches schema drift that synthetic fixtures alone miss. Run #109: Windows smoke 194 s, cross-host 82 s, Linux 86 s, specification 22 s (before the cache change). The 14 s Windows difference is observational, not attributed to the new CI block.

The Markdown-only scope classifier also checks raw Git modes/status: regular non-executable Markdown adds/modifies/deletes may use the cheap path; symlinks, executable mode changes, gitlinks, type changes or malformed raw data force full native CI. This narrows the optimization to genuine documentation edits; it does not introduce new skip paths.

**ADR-0074 migration (pending CI):** the earlier formatter-cache optimization is superseded by removing the Go toolchain altogether. Six setup-go occurrences and synthetic reference generation are retired; independent standard TLS/H2 PKI tests remain on both M0.1 jobs. No CI jobs removed. Measure actual before/after full first-attempt runs; do not infer savings from deleted setup durations alone.

### Go retirement: observed completed full PR evidence (2026-11-24)

| Metric (seconds) | Before: #109 run 45397074048 | After: #110 run 45401698499 | Delta |
|---|---:|---:|---:|
| Creation to last completed job | 312 | 310 | -2 |
| Sum of job durations (not billed minutes) | 954 | 849 | -105 |
| Specification | 22 | 7 | -15 |
| M0.1 Windows | 118 | 71 | -47 |
| M0.1 Linux | 55 | 75 | +20 |
| Windows smoke | 194 | 192 | -2 |
| Cross-host | 82 | 76 | -6 |

Source: completed first-attempt GitHub Actions job timestamps for both exact PR heads, same 13-job matrix. The aggregate job-duration observation decreases by 11.0%; wall clock decreases by 0.6%. This is not a controlled benchmark or billed-minutes saving. Multiple changes, cache state and runner scheduling differ. Windows smoke and WSL2 remain the dominant dependency path; retain coverage. No claim that each job became faster.

## Pre-native auto-format repair (ADR-0080)

The historical fail-fast-only policy is superseded for same-repository PRs: an isolated conditional repair job may commit a verified Rust-only direct child after a failed preflight, then dispatch full CI on the new SHA. The old run cannot pass; native jobs never test an overlay. Ordinary clean runs have 13 mandatory successful jobs and one skipped repair. The timing validator accepts historical 13-job snapshots and current snapshots with exactly one identity-verified skipped repair, but excludes automated dispatch, failed and partial runs from ordinary comparisons. No measured speedup claimed yet; this removes manual formatting intervention, not native coverage.
