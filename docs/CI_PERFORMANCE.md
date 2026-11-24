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
