#!/usr/bin/env python3
"""CI DAG performance guard: parallel tests, intact mandatory gates and independent TLS checks.

No YAML parser or network dependencies. Each assertion is an explicit check
against the current CI contract; a workflow refactor must update this test
when changing job names or structure.
"""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")


def require(value: bool, message: str) -> None:
    if not value:
        raise SystemExit("CI graph regression: " + message)


def job(name: str) -> str:
    pattern = r"(?ms)^  " + re.escape(name) + r":\n(.*?)(?=^  [a-z][a-z0-9-]*:\n|\Z)"
    matches = re.findall(pattern, workflow)
    require(len(matches) == 1, f"expected one job: {name}")
    return matches[0]


def needs(name: str) -> set[str]:
    match = re.search(r"(?m)^    needs:\s*(.+)$", job(name))
    require(match is not None, f"{name} has no dependency declaration")
    value = match.group(1).strip()
    if value.startswith("[") and value.endswith("]"):
        return {part.strip() for part in value[1:-1].split(",")}
    return {value}


mandatory = {
    "specification",
    "rust-tests",
    "windows-smoke",
    "f14-cross-host",
    "browser-e2e",
    "f14-build",
    "native-performance",
    "f19-performance",
    "m0-1-api-spike",
    "m0-1-windows-spike",
    "m3-4-btls-spike",
    "m3-4e-btls-production-feature",
    "coverage-native",
    "coverage-gate",
    "f15-driver-build",
}

require(needs("rust-tests") == {"specification"}, "Linux tests must await spec only")
for name in ("windows-smoke", "browser-e2e", "f14-build", "native-performance", "f19-performance"):
    require(
        needs(name) == {"specification"},
        f"{name} must run in parallel with Linux tests after specification",
    )
    require(
        "needs.specification.outputs.rust_ready == 'true'" in job(name),
        f"{name} must retain the Rust readiness precondition",
    )
require(needs("ci-gate") == mandatory, "ci-gate must depend on EVERY required job")
require(needs("f15-driver-build") == {"specification"}, "F-15 driver build must use exact tested source in parallel")
for term in ("make -C drivers/linux", "build-lab.ps1", "nuget restore drivers/windows/packages.config", "if-no-files-found: error"):
    require(term in job("f15-driver-build"), "missing F-15 driver build contract: " + term)
require("continue-on-error" not in job("f15-driver-build"), "driver compilation cannot be advisory")
require("F-15 isolated kernel capture and hard-kill recovery (mandatory)" in job("rust-tests")
        and "sudo -n unshare -n true" in job("rust-tests")
        and "scripts/f15-kernel-tests.py" in job("rust-tests"),
        "F-15 actual isolated kernel tests must execute on merged source")
require(needs("f14-cross-host") == {"specification", "f14-build"},
        "F-14 must use early native builds without waiting for browser or performance tests")
cross_host = job("f14-cross-host")
require("runs-on: windows-2025" in cross_host and "wsl-version: 2" in cross_host,
        "F-14 must connect native Windows client to real Linux WSL2 VM")
require("name: f14-linux-server" in cross_host and "name: f14-windows-compiled" in cross_host,
        "F-14 must consume both native OS binaries, never build on WSL runner")
require("scripts/f14-cross-os-ci.py" in cross_host
        and "--windows-client" in cross_host and "--windows-test" in cross_host
        and "cargo build" not in cross_host,
        "F-14 must execute prebuilt native Windows harness without duplicate compilation")
browser = job("browser-e2e")
f14_build = job("f14-build")
performance = job("native-performance")
f19_performance = job("f19-performance")
require("Build genuine Linux server for Windows cross-OS F-14 E2E\n        if: runner.os == 'Linux'" in f14_build
        and "name: f14-linux-server" in f14_build
        and "actions/upload-artifact@v4" in f14_build,
        "Linux Theia ELF must originate from mandatory early native Linux build")
require("Stage Windows E2E binaries from Cargo JSON artifact paths\n        if: runner.os == 'Windows'" in f14_build
        and "cargo build --workspace --locked --bin theia --message-format=json" in f14_build
        and "name: f14-windows-compiled" in f14_build,
        "Windows Theia and test harness must originate from mandatory early native Windows build")
require("name: f14-linux-server" not in job("rust-tests")
        and "name: f14-windows-compiled" not in job("windows-smoke"),
        "do not rebuild or upload F-14 binaries after unrelated suites")
require("python3 -m unittest discover -s tests/ci -p 'test_f14_*.py'" in job("specification"),
        "cheap F-14 WSL guest IP regression must precede expensive Rust builds")
require("continue-on-error" not in cross_host and "|| true" not in cross_host,
        "F-14 cross-OS acceptance cannot be made optional")

gate = job("ci-gate")
require("always() && github.event.pull_request.merged == true" in gate,
        "ci-gate must execute even on failure, but only for merged PRs")
require('results.get(name, {}).get("result") != "success"' in gate,
        "ci-gate must reject failed/skipped/cancelled prerequisites")
# Keep the gate's internal expected set aligned with actual dependencies.
match = re.search(r"expected = \{([^}]+)\}", gate)
require(match is not None, "ci-gate must declare the exact expected set")
expected_in_gate = set(re.findall(r'"([^"]+)"', match.group(1)))
require(expected_in_gate == mandatory, "ci-gate expected set drift")

windows = job("windows-smoke")
require("cargo nextest run --workspace --all-targets --locked --no-fail-fast" in windows,
        "native Windows all-target tests must stay mandatory")
require("Cross-logon Windows pipe kernel-denial E2E (mandatory)" in windows,
        "never remove or skip the cross-SID kernel security E2E")
require("windows-cross-sid-ci.ps1" in windows,
        "the second-SID test must actually run in CI")
require("pywinpty==3.0.5 pyte==0.8.2" in windows,
        "the ConPTY/VT test dependencies must be pinned")
require("THEIA_WINDOWS_PROXY_E2E_ALLOWED" in windows
        and "native_wininet_cas_recovery_and_foreign_override" in windows
        and "compiled_client_proxy_conpty_lifecycle -- --ignored --exact" in windows,
        "F-07 native and compiled ConPTY lifecycle must both run on disposable Windows")
require('CARGO_PROFILE_DEV_DEBUG: "line-tables-only"' in windows
        and 'CARGO_PROFILE_TEST_DEBUG: "line-tables-only"' in windows,
        "Windows test/dev binaries must retain diagnostic line numbers with bounded debug info")
require("CARGO_PROFILE_RELEASE_DEBUG" not in windows,
        "release profile must remain unchanged by the test-only optimization")

# Only a closed PR targeting main can trigger this workflow. Closing without
# merging creates at most an all-skipped run: no runner is allocated.
trigger = re.search(r"(?ms)^on:\n(.*?)(?=^[a-z])", workflow)
require(trigger is not None and trigger.group(1).strip() ==
        "pull_request:\n    branches: [main]\n    types: [closed]",
        "CI must be triggered only by PR closure targeting main")
dev_merge = "github.event.pull_request.merged == true && github.event.pull_request.head.ref == 'dev' && github.event.pull_request.head.repo.full_name == github.repository"
require("if: " + dev_merge in job("specification"),
        "only same-repository dev merges may allocate native runners")
require("always() && " + dev_merge in gate,
        "final gate must share the exact dev merge guard")
require(workflow.count("ref: ${{ github.event.pull_request.merge_commit_sha }}") == 1
        and workflow.count("actions/checkout@v4") ==
        3 + workflow.count("ref: ${{ needs.specification.outputs.tested_sha }}")
        and "ref: abbb89834a406b4c53be0f1ac0b3ab1a65e66f8d" in performance
        and "path: .perf-baseline" in performance
        and "ref: 917417b09f209334939c38551112081c480eb958" in f19_performance,
        "only specification checks out merge; all native jobs pin the exact published SHA")
require(workflow.count('--sha "${{ needs.specification.outputs.tested_sha }}"') == 2,
        "both coverage producers and gate must use the tested SHA")
require("test_ci_coverage.py" in job("specification"),
        "coverage regression tests must run before native fan-out")
coverage_native = job("coverage-native")
coverage_gate = job("coverage-gate")
require(needs("coverage-native") == {"specification"} and
        needs("coverage-gate") == {"specification", "coverage-native"},
        "coverage gate must consume both native jobs")
for term in ("os: [ubuntu-latest, windows-latest]", "llvm-tools-preview",
             "cargo llvm-cov nextest --workspace --all-targets --all-features --locked --no-report --no-fail-fast",
             "cargo llvm-cov report --json --include-build-script",
             "--no-report --lib -- windows_system_proxy::tests::native_wininet_cas_recovery_and_foreign_override --ignored --exact",
             "--no-report --test tui_real_terminal -- compiled_client_proxy_conpty_lifecycle --ignored --exact",
             "cargo llvm-cov clean --profraw-only", 'workspaces: ". -> target/llvm-cov-target"',
             "cache-targets: true", "cache-workspace-crates: false",
             "Instrumented real WinINet CAS and recovery failed or did not execute",
             "Instrumented real ConPTY lifecycle failed or did not execute",
             "THEIA_WINDOWS_PROXY_E2E_ALLOWED", "cargo llvm-cov report --lcov --include-build-script",
             "ci-coverage.py collect", "--llvm-json coverage-segments.json",
             "coverage-raw-failure-", "if: failure()", "coverage.lcov",
             "if-no-files-found: error"):
    require(term in coverage_native, "missing native coverage contract: " + term)
for term in ("coverage-Linux", "coverage-Windows", "ci-coverage.py gate",
             "THEIA_COVERAGE_SYNTAX_TESTS"):
    require(term in coverage_gate, "missing combined coverage contract: " + term)
require("continue-on-error" not in coverage_native + coverage_gate,
        "coverage collection and threshold may not be advisory")
# Real H2/H3 cases share one bounded, non-ignored native test. Both the
# ordinary and instrumented suites execute it; there is no separate soak job.
require("  native-liveness:" not in workflow, "obsolete long-running job must not return")
for name in ("rust-tests", "windows-smoke"):
    require("cargo nextest run --workspace --all-targets --locked --no-fail-fast" in job(name),
            f"{name}: real network matrix must execute in the full native suite")
require("cargo llvm-cov nextest --workspace --all-targets --all-features --locked --no-report --no-fail-fast" in coverage_native,
        "both instrumented native suites must execute the real network matrix")
liveness_source = (ROOT / "crates/theia/tests/tunnel_liveness.rs").read_text(encoding="utf-8")
require("async fn production_h2_h3_asymmetric_traffic_half_close_and_idle()" in liveness_source
        and "#[ignore" not in liveness_source
        and "for transport in [Transport::H2, Transport::H3]" in liveness_source
        and "cases.spawn(async move" in liveness_source
        and "Case::LongUpload," in liveness_source and "Case::LongDownload," in liveness_source
        and "(23, Duration::from_secs(2))" in liveness_source
        and "if long { 40 } else { 30 }" in liveness_source
        and "Duration::from_secs(55)" in liveness_source,
        "retain real concurrent H2/H3 byte progress, half-close and idle with a <60s deadline")
activity_source = (ROOT / "crates/theia/src/relay_liveness.rs").read_text(encoding="utf-8")
require("async fn sustained_progress_beyond_300_seconds_in_either_direction()" in activity_source
        and "#[tokio::test(start_paused = true)]" in activity_source
        and "for _ in 0..32" in activity_source
        and "Duration::from_secs(320)" in activity_source
        and "activity.run(progress, inactive" in activity_source
        and "activity.run(inactive, progress" in activity_source,
        "retain accelerated long-progress regression in both directions")
require("workflow_dispatch:" not in workflow and "  push:" not in workflow,
        "direct pushes, PR updates and manual dispatch must not start CI")
require("github.event.pull_request.merge_commit_sha" in job("specification")
        and 'test "$MERGED_SHA" = "$GITHUB_SHA"' in job("specification")
        and 'test "$(git rev-parse HEAD)" = "$MERGED_SHA"' in job("specification"),
        "CI must verify the exact merged commit, not a later main tip")
# Optional release-profile builds remain available in the same merge run.
for os, payload in (("Linux", job("rust-tests")), ("Windows", windows)):
    require(re.search(
        rf"(?m)^      - name: Requested release compilation \({os}\)\n"
        r"        if: contains\(github.event.pull_request.labels.\*\.name, 'release-build'\)\n"
        r"        run: cargo build --workspace --release --locked$",
        payload,
    ) is not None, f"{os}: optimized release build must stay available on a labelled merge")
require(workflow.count("run: cargo build --workspace --release --locked") == 2,
        "only the two labelled release compilations may exist")

require("python3 -m compileall -q scripts tests" in job("specification"),
        "cheap Python preflight must execute before Rust tests")
linux = job("rust-tests")
require("cargo nextest run --workspace --all-targets --locked --no-fail-fast" in linux,
        "mandatory Linux all-target tests must run")
require("cargo clippy --workspace --all-targets --all-features -- -D warnings" in linux,
        "mandatory Clippy warnings-as-errors must run")

# The 16 actual BBR/CUBIC impairment trials still run on BOTH native
# operating systems, but reuse the existing M0.1 compiled Rust workspace.
# Keep the validator and per-OS evidence artifacts as mandatory acceptance.
bbr_command = (
    "cargo test --manifest-path spikes/m0_1/Cargo.toml --locked "
    "--test quic_congestion_comparison "
    "comparison_records_all_controller_scenarios_ci_only "
    "-- --ignored --exact --nocapture"
)
for name, platform in (("m0-1-api-spike", "ubuntu-latest"),
                       ("m0-1-windows-spike", "windows-latest")):
    payload = job(name)
    require(bbr_command in payload, f"{name}: native BBR/CUBIC evidence must run")
    require("python tests/benchmark/check_bbr_comparison.py $env:THEIA_BBR_RESULTS_PATH" in payload,
            f"{name}: all 16 CSV scenarios must be validated")
    require(f"THEIA_BBR_RESULTS_PATH: ${{{{ github.workspace }}}}/theia-bbr-{platform}.csv" in payload,
            f"{name}: native BBR evidence CSV path is missing")
    require("name: m3-3-quic-comparison-${{ runner.os }}" in payload
            and "if: always()" in payload and "if-no-files-found: error" in payload,
            f"{name}: do not silently skip the CSV artifact on an error")
require("  m3-3-bbr-comparison:" not in workflow,
        "duplicate BBR Rust build runners must stay removed")
require("pyte==0.8.2" in linux, "the Linux real-PTY test needs its VT parser")


# One trusted post-merge Rustfmt-only publication; native jobs stay read-only.
spec = job("specification")
require("fetch-depth: 2" in spec, "merged commit checkout must be bounded")
require("steps.scope.outputs.native_required" in spec
        and 'echo "native_required=true"' in spec
        and "test_ci_scope.py" in spec,
        "every merged commit must take the full native path")
require("scripts/ci-format-repair.py prepare-merged" in spec
        and spec.count("scripts/ci-format-repair.py verify-merged") == 2
        and "test_ci_format_repair.py" in spec,
        "verified post-merge formatting and its safety regressions must precede fan-out")
require("tested_sha: ${{ steps.publish-format.outputs.tested_sha }}" in spec
        and 'echo "tested_sha=$FORMATTED_SHA"' in spec
        and 'git push --atomic origin "$FORMATTED_SHA:refs/heads/main" "$FORMATTED_SHA:refs/heads/dev"' in spec
        and 'git push origin "$FORMATTED_SHA:refs/heads/main"' in spec
        and '[[ "$tip" == "$MERGED_SHA" ]]' in spec
        and '[[ "$dev" == "$DEV_SHA" ]]' in spec
        and "git merge-base --is-ancestor" in spec,
        "format publication must be bound to the merge and only fast-forward unchanged dev")
require("gh workflow run" not in workflow and "--force" not in spec
        and "git push" not in "".join(job(name) for name in mandatory - {"specification"}),
        "never dispatch another CI or force-push; publication only in specification")
require("ci-formatted-source" not in workflow and "persist-format:" not in workflow,
        "never test a formatter overlay or mutate a green SHA")
for name in mandatory - {"specification"}:
    payload = job(name)
    require("cargo fmt " not in payload,
            f"{name}: formatting must run once in specification, not per native job")
for name in mandatory - {"specification"}:
    payload = job(name)
    require("needs.specification.outputs.native_required == 'true'" in payload,
            f"{name}: full matrix must run only when native scope is proven required")
    require("needs.specification.outputs.rust_ready == 'true'" in payload,
            f"{name}: Rust precondition must be explicit and fail closed")
    if name not in {"f14-cross-host", "coverage-gate"}:
        require("actions/download-artifact@v4" not in payload,
                f"{name}: no repeating CI format artifact downloads")
require("actions/download-artifact@v4" in job("f14-cross-host"),
        "cross-host still MUST use authenticated native OS binaries")
gate = job("ci-gate")
require("NATIVE_REQUIRED: ${{ needs.specification.outputs.native_required }}" in gate,
        "final gate must use exactly the preflight's scope")
require('native != "true"' in gate,
        "unknown or skipped native scope must fail closed")
require(workflow.count("contents: write") == 1 and "contents: write" in spec
        and "actions: write" not in workflow and "contents: read" in workflow,
        "only trusted specification may publish a Rustfmt-only child; no dispatch permission")
require("TESTED_SHA: ${{ needs.specification.outputs.tested_sha }}" in gate
        and "native CI passed on exact source" in gate,
        "final gate must report the exact tested source SHA")

require("actions/setup-go" not in workflow and "THEIA_UTLS" not in workflow
        and "utls_reference" not in workflow and "gofmt " not in workflow,
        "retired Go/uTLS toolchain must not return")
for name in ("m0-1-api-spike", "m0-1-windows-spike"):
    payload = job(name)
    require("actions/setup-python@v5" in payload and "python-version: '3.12'" in payload,
            f"{name}: independent TLS probe interpreter required")
    require("cargo test --manifest-path spikes/m0_1/Cargo.toml --locked --test independent_h2_loopback -- --ignored --nocapture" in payload,
            f"{name}: independent strict PKI/H2 test cannot be removed")
require("test_independent_h2_probe.py" in spec and "test_ci_timing.py" in spec,
        "cheap probe and timing regressions must run")
require("client_binary_chromium_socks5_over_h3 -- --ignored --exact" in job("browser-e2e"),
        "native browser functional navigation over explicit H3 must run")
require("run_f13_observations.py f13-observations" in browser,
        "real browser reference runner remains mandatory")

require(
    "concurrency:" in workflow
    and "ci-main-merge-${{ github.event.pull_request.merge_commit_sha || github.run_id }}" in workflow
    and "cancel-in-progress: false" in workflow,
    "different merged commits must never cancel one another",
)
# Cache privileges are separate from repository contents permissions.
# The privileged formatter and all non-producers remain read-only for caches.
require(re.search(r"(?m)^cache-mode: read$", workflow) is not None,
        "cache access defaults to read-only")
cache_writers = {"m0-1-api-spike", "m0-1-windows-spike", "rust-tests",
                 "windows-smoke", "m3-4-btls-spike",
                 "m3-4e-btls-production-feature", "coverage-native"}
for name in mandatory | {"ci-gate"}:
    payload = job(name)
    require(("    cache-mode: write" in payload) == (name in cache_writers),
            f"{name}: unexpected cache-write privilege")
    if name in cache_writers:
        require(needs(name) == {"specification"}
                and "if: " + dev_merge in payload
                and "cache-workspace-crates: false" in payload
                and "cache-bin: false" in payload,
                f"{name}: cache producer must be trusted and dependency-only")
require("rust-cache" not in spec and "actions/cache" not in spec,
        "never restore executable caches in the write-privileged source publisher")
for name in ("rust-tests", "windows-smoke", "browser-e2e", "f14-build", "native-performance", "f19-performance"):
    payload = job(name)
    require("shared-key: native-default-deps-v4" in payload
            and 'CARGO_PROFILE_DEV_DEBUG: "line-tables-only"' in payload
            and 'CARGO_PROFILE_TEST_DEBUG: "line-tables-only"' in payload
            and "cache-workspace-crates: false" in payload
            and "cache-bin: false" in payload,
            f"{name}: incompatible shared native cache or workspace output caching")
for name in ("browser-e2e", "f14-build", "native-performance", "f19-performance"):
    require("save-if: false" in job(name), f"{name}: restore-only cache consumer")
require("shared-key: native-default-deps-v4" not in coverage_native,
        "instrumented outputs must never share the default native target cache")
require(coverage_native.count("cargo llvm-cov report --lcov --include-build-script") == 1
        and coverage_native.index("Instrument real disposable Windows proxy and ConPTY lifecycle")
        < coverage_native.index("Export LCOV once after all native instrumented tests"),
        "export LCOV exactly once, after all mandatory instrumented cases")
require("$bins = @($testEvents | Where-Object" in f14_build
        and "if ($bins.Count -eq 0)" in f14_build
        and "$_.profile.test -eq $false" in f14_build
        and "$_.target.kind -contains 'bin'" in f14_build,
        "F-14 must reuse a genuine same-build Windows client, with explicit build fallback")
require("test_native_performance.py" in spec
        and "native_binary_performance_evidence_smoke" in performance
        and "check_native_performance.py native-performance.json" in performance
        and "--require-smoke" in performance
        and "native-performance-" in performance,
        "native paired performance smoke and evidence must remain mandatory")
require("test_classifier_evidence.py" in spec, "independent score evidence regressions remain mandatory")
require("test_f19_bundle.py" in spec, "exact-revision independent evidence join regressions remain mandatory")
require("native_binary_performance_comparison" in performance
        and "native-comparison.json" in performance
        and "--require-comparison --policy tests/benchmark/native-diagnostic-policy.json" in performance
        and "Build exact native baseline before candidate" in performance,
        "native baseline and candidate comparison remains mandatory")
f13_runner = (ROOT / "tests/benchmark/run_f13_observations.py").read_text(encoding="utf-8")
require(all(case in f13_runner for case in (
            "actual_native_h3_client_initial_reference",
            "real_default_h2_settings_and_pseudo_headers_are_measured",
            "actual_chromium_h2_settings_and_pseudo_order_reference",
            "actual_chromium_h3_initial_reference"))
        and "run_f13_observations.py f13-observations" in browser
        and "--samples 3" in browser
        and "check_f13_observations.py f13-observations --expected-revision" in browser
        and "test_f13_observations.py" in spec,
        "repeated exact-revision native and browser observation matrix must remain mandatory")
require("test_benchmark_ports.py" in spec and "test_benchmark_ports.py" in performance,
        "native benchmark transport-specific port reservation regressions remain mandatory")
require("native_clients_require_pki_and_exact_alpn -- --ignored --exact" in browser,
        "independent native-client TLS trust and ALPN matrix must remain mandatory")
require("ref: 917417b09f209334939c38551112081c480eb958" in f19_performance
        and "path: .f19-baseline" in f19_performance
        and "THEIA_F19_BASELINE_BIN" in f19_performance
        and "f19-comparison.json" in f19_performance
        and "--require-comparison --policy tests/benchmark/f19-diagnostic-policy.json" in f19_performance,
        "isolated exact pre-batch overhead comparison remains mandatory")
for name in ("browser-e2e", "f14-build", "native-performance", "f19-performance"):
    # The Linux ELF must target the exact WSL guest release for F-14.
    linux = "ubuntu-24.04" if name == "f14-build" else "ubuntu-latest"
    require(f"os: [{linux}, windows-latest]" in job(name)
            and "fail-fast: false" in job(name)
            and "continue-on-error" not in job(name),
            f"{name}: both native OS jobs remain mandatory")
require("distribution: Ubuntu-24.04" in cross_host,
        "F-14 Linux builder and WSL guest must use the same release")
require("f14-linux-server" not in browser and "f14-windows-compiled" not in browser,
        "F-14 artifacts must not depend on browser or measurements")
require("THEIA_PERF_BASELINE_SHA: abbb89834a406b4c53be0f1ac0b3ab1a65e66f8d" in performance
        and "THEIA_PERF_BASELINE_SHA: 917417b09f209334939c38551112081c480eb958" in f19_performance
        and "native-comparison-" in performance and "f19-comparison-" in f19_performance,
        "both isolated baseline jobs must produce their original evidence")
require("independent_aioquic_v1_v2_bidirectional_h3 -- --ignored --exact" in browser
        and "run_native_quic_comparison.py" in browser
        and "independent_external_reference_through_registered_reality_dispatchers" in browser,
        "native QUIC and external REALITY checks stay mandatory")
for name in ("rust-tests", "windows-smoke", "coverage-native"):
    require("tool: cargo-nextest@0.9.140" in job(name)
            and "--no-fail-fast" in job(name)
            and "--filter-expr" not in job(name),
            f"{name}: full native test inventory, pinned runner, no filters")
import tomllib
schedule = tomllib.loads((ROOT / ".config/nextest.toml").read_text(encoding="utf-8"))
profile = schedule["profile"]["default"]
require(profile["default-filter"] == "all()" and profile["retries"] == 0
        and profile["fail-fast"] is False and profile["test-threads"] == 4,
        "nextest must run every nonignored test once, with bounded parallelism")
require({entry["filter"]: entry["priority"] for entry in profile["overrides"]} == {
    "test(=compiled_dual_mode_tui_invitation_import_apply_and_rollback)": 100,
    "test(=production_h2_h3_asymmetric_traffic_half_close_and_idle)": 90,
}, "only scheduling priority may change, never security or liveness timeouts")
print("CI_GRAPH_PARALLEL_AND_NATIVE_CHECKS_OK")
