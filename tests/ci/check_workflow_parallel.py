#!/usr/bin/env python3
"""Fail-closed contract for the mandatory MVP and explicitly requested extended DAGs."""
from pathlib import Path
import re
import tomllib

ROOT = Path(__file__).resolve().parents[2]
workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
extended = (ROOT / ".github/workflows/extended-validation.yml").read_text(encoding="utf-8")


def require(ok, message):
    if not ok:
        raise SystemExit("CI graph regression: " + message)


def job(name, source=workflow):
    pattern = r"(?ms)^  " + re.escape(name) + r":\n(.*?)(?=^  [a-z][a-z0-9-]*:\n|\Z)"
    matches = re.findall(pattern, source)
    require(len(matches) == 1, f"expected one job: {name}")
    return matches[0]


def needs(name, source=workflow):
    match = re.search(r"(?m)^    needs:\s*(.+)$", job(name, source))
    require(match is not None, f"{name} must declare prerequisites")
    return set(match.group(1).strip("[]").replace(" ", "").split(","))


def jobs(source):
    return set(re.findall(r"(?m)^  ([a-z][a-z0-9-]*):\n", source.split("\njobs:\n", 1)[1]))


def contains(source, *terms):
    for term in terms:
        require(term in source, "missing CI contract: " + term)


def expected_set(payload):
    match = re.search(r"expected = \{([^}]+)\}", payload)
    require(match is not None, "missing gate inventory")
    return set(re.findall(r'"([^"]+)"', match.group(1)))


mandatory = {"specification", "rust-tests", "windows-smoke", "f14-build",
             "f14-cross-host", "coverage-native", "coverage-gate"}
deferred = {"m0-1-api-spike", "m0-1-windows-spike", "native-performance",
            "f19-performance", "m3-4-btls-spike", "m3-4e-btls-production-feature",
            "browser-e2e", "f15-driver-build", "f15-kernel", "release-profile"}
require(jobs(workflow) == mandatory | {"ci-gate"}, "ordinary MVP inventory changed")
require(jobs(extended) == deferred | {"specification", "extended-gate"}, "extended inventory changed")
require(needs("ci-gate") == expected_set(job("ci-gate")) == mandatory, "MVP gate must require all jobs")
require(needs("extended-gate", extended) == expected_set(job("extended-gate", extended))
        == deferred | {"specification"}, "extended gate must require all jobs")
for name in ("rust-tests", "windows-smoke", "coverage-native", "f14-build"):
    require(needs(name) == {"specification"}, f"{name} must run in parallel")
require(needs("f14-cross-host") == {"specification", "f14-build"}, "cross-host must use early native builds")
require(needs("coverage-gate") == {"specification", "coverage-native"}, "all native reports must arrive")
for name in deferred:
    require(needs(name, extended) == {"specification"}, "extended jobs must run independently")
for source, trigger in ((workflow, "pull_request:\n    branches: [main]\n    types: [closed]"),
                        (extended, "workflow_dispatch:")):
    match = re.search(r"(?ms)^on:\n(.*?)(?=^[a-z])", source)
    require(match is not None and match.group(1).strip() == trigger, "workflow trigger drift")
dev_merge = ("github.event.pull_request.merged == true && github.event.pull_request.head.ref == 'dev'"
             " && github.event.pull_request.head.repo.full_name == github.repository")
spec, gate = job("specification"), job("ci-gate")
contains(spec, "if: " + dev_merge, "fetch-depth: 2", 'test "$MERGED_SHA" = "$GITHUB_SHA"',
         'test "$(git rev-parse HEAD)" = "$MERGED_SHA"', "python3 -m compileall -q scripts tests",
         "python3 -m unittest discover -s tests/ci -p 'test_f14_*.py'", "test_ci_coverage.py",
         "test_ci_scope.py", "test_ci_timing.py", "test_independent_h2_probe.py",
         "test_ci_format_repair.py", "scripts/check-spec.sh", "scripts/ci-format-repair.py prepare-merged",
         'echo "native_required=true"', 'echo "tested_sha=$FORMATTED_SHA"',
         'git push --atomic origin "$FORMATTED_SHA:refs/heads/main" "$FORMATTED_SHA:refs/heads/dev"',
         'git push origin "$FORMATTED_SHA:refs/heads/main"', '[[ "$tip" == "$MERGED_SHA" ]]',
         '[[ "$dev" == "$DEV_SHA" ]]', "git merge-base --is-ancestor")
require(spec.count("scripts/ci-format-repair.py verify-merged") == 2, "format must be verified twice")
require("rust-cache" not in spec and "actions/cache" not in spec and "--force" not in spec,
        "privileged publication cannot restore executable caches or force-push")
contains(gate, "always() && " + dev_merge, 'results.get(name, {}).get("result") != "success"',
         'native != "true"', "TESTED_SHA:", "MERGED_SHA:", "native CI passed on exact source",
         "actions: read", 'repos/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID/attempts/$GITHUB_RUN_ATTEMPT',
         'run["created_at"]', 'run["run_started_at"]', "elapsed > 300",
         'failed.append("wall-clock budget (300s)")')
require(workflow.count("contents: write") == 1 and "contents: write" in spec
        and "contents: write" not in extended and "actions: write" not in workflow + extended,
        "only specification may write source")
require("gh workflow run" not in workflow + extended and "git push" not in extended,
        "no recursive dispatch or extended publication")
contains(extended, 'test "$GITHUB_REF" = refs/heads/main',
         'test "$(git rev-parse HEAD)" = "$GITHUB_SHA"', 'echo "tested_sha=$GITHUB_SHA"',
         "cache-mode: read")
require("cache-mode: write" not in extended and "continue-on-error" not in workflow + extended,
        "no advisory acceptance or extended cache write")
contains(workflow, "cache-mode: read", "cancel-in-progress: false",
         "ci-main-merge-${{ github.event.pull_request.merge_commit_sha || github.run_id }}")
writers = {"rust-tests", "windows-smoke", "coverage-native"}
for name in mandatory - {"specification"}:
    payload = job(name)
    contains(payload, "needs.specification.outputs.native_required",
             "needs.specification.outputs.rust_ready",
             "ref: ${{ needs.specification.outputs.tested_sha }}")
    require("git push" not in payload and "cargo fmt " not in payload, "publish only in specification")
    require(("    cache-mode: write" in payload) == (name in writers), "cache permission drift")
    if name in writers:
        contains(payload, "if: " + dev_merge, "cache-workspace-crates: false", "cache-bin: false",
                 "save-if: ${{ matrix.shard == 1 }}")
    if name in {"rust-tests", "windows-smoke", "f14-build"}:
        contains(payload, "shared-key: native-default-deps-v4",
                 'CARGO_PROFILE_DEV_DEBUG: "line-tables-only"',
                 'CARGO_PROFILE_TEST_DEBUG: "line-tables-only"')
require("CARGO_PROFILE_RELEASE_DEBUG" not in workflow, "release settings must not change")
for name in ("rust-tests", "windows-smoke"):
    payload = job(name)
    contains(payload, "shard: [1, 2]", "fail-fast: false", "tool: cargo-nextest@0.9.140",
             "cargo nextest run --workspace --all-targets --locked --no-fail-fast --partition count:${{ matrix.shard }}/2")
    require("--filter-expr" not in payload and "--retries" not in payload, "complete native inventory")
contains(job("rust-tests"), "cargo clippy --workspace --all-targets --all-features -- -D warnings", "pyte==0.8.2")
contains(job("windows-smoke"), "pywinpty==3.0.5 pyte==0.8.2",
         "Cross-logon Windows pipe kernel-denial E2E (mandatory)", "windows-cross-sid-ci.ps1",
         "cargo clippy --workspace --all-targets --features experimental-btls-h2 -- -D warnings")
f14, cross = job("f14-build"), job("f14-cross-host")
contains(f14, "os: [ubuntu-24.04, windows-latest]", "fail-fast: false",
         "cargo tree --locked -p theia -e normal,build",
         "Build genuine Linux server for Windows cross-OS F-14 E2E",
         "Stage Windows E2E binaries from Cargo JSON artifact paths",
         "name: f14-linux-server", "name: f14-windows-compiled",
         "$bins = @($testEvents | Where-Object", "if ($bins.Count -eq 0)",
         "$_.profile.test -eq $false", "$_.target.kind -contains 'bin'",
         "save-if: false", "actions/upload-artifact@v4")
contains(cross, "runs-on: windows-2025", "wsl-version: 2", "distribution: Ubuntu-24.04",
         "name: f14-linux-server", "name: f14-windows-compiled", "scripts/f14-cross-os-ci.py",
         "--windows-client", "--windows-test")
require("cargo build" not in cross and "|| true" not in cross, "cross-host must use native artifacts")
cov, cg = job("coverage-native"), job("coverage-gate")
contains(cov, "os: [ubuntu-latest, windows-latest]", "shard: [1, 2, 3, 4, 5, 6]",
         "fail-fast: false", "llvm-tools-preview", "cargo-llvm-cov@0.9.1", "tool: cargo-nextest@0.9.140",
         "cargo llvm-cov clean --profraw-only", 'workspaces: ". -> target/llvm-cov-target"',
         "cache-targets: true", "cargo llvm-cov nextest --workspace --all-targets --all-features --locked --no-report --no-fail-fast",
         "if: matrix.shard <= 2", "if: matrix.shard == 3", "--partition count:${{ matrix.shard }}/2",
         "--no-report --test tui_real_terminal -- compiled_dual_mode_tui_invitation_import_apply_and_rollback --ignored --exact",
         "THEIA_WINDOWS_PROXY_E2E_ALLOWED",
         "--no-report --lib -- windows_system_proxy::tests::native_wininet_cas_recovery_and_foreign_override --ignored --exact",
         "--no-report --test tui_real_terminal -- compiled_client_proxy_conpty_lifecycle --ignored --exact",
         "Instrumented real WinINet CAS and recovery failed or did not execute",
         "Instrumented real ConPTY lifecycle failed or did not execute",
         "if: runner.os == 'Windows' && matrix.shard == 6",
         "if: matrix.shard >= 4", "$_.shard -eq [int]$env:COVERAGE_SHARD",
         "No mandatory fixtures assigned to coverage shard", "$name --ignored --exact", "test result: ok",
         "cargo llvm-cov report --lcov --include-build-script",
         "cargo llvm-cov report --json --include-build-script",
         "ci-coverage.py collect", "--llvm-json coverage-segments.json",
         "--shard ${{ matrix.shard }} --shards 6", "name: coverage-shard-${{ runner.os }}-${{ matrix.shard }}",
         "coverage-raw-failure-", "if-no-files-found: error")
fixtures = {"client_binary_chromium_socks5": 4, "client_binary_chromium_socks5_over_h3": 4,
            "native_clients_require_pki_and_exact_alpn": 5,
            "independent_aioquic_v1_v2_bidirectional_h3": 5,
            "routing::packet_modify::tests::independent_aioquic_initial_modify_v1_v2": 5,
            "independent_aioquic_live_modify_v1_v2": 6,
            "udp_relay::tests::independent_quic_product_relay_v1_v2": 6,
            "server::hardening_tests::independent_external_reference_through_registered_reality_dispatchers": 6}
observed = re.findall(r"name = '([^']+)'; shard = (\d+) \}", cov)
require(len(observed) == len(fixtures) and {n: int(s) for n, s in observed} == fixtures,
        "every independent MVP fixture must execute once per platform")
require("shared-key: native-default-deps-v4" not in cov and "--filter-expr" not in cov,
        "instrumentation must be isolated and complete")
require(cov.count("cargo llvm-cov report --lcov --include-build-script") == 1, "export once per shard")
for name in ("Instrument real dual-mode TUI", "Instrument real disposable Windows",
             "Instrument independent protocol and browser interoperability"):
    require(cov.index(name) < cov.index("Export LCOV once"), "fixture must precede export")
contains(cg, "pattern: coverage-shard-*", "merge-multiple: false",
         "ci-coverage.py gate --reports-dir coverage-shards --shards 6",
         "THEIA_COVERAGE_SYNTAX_TESTS", "coverage-summary")
require(workflow.count('--sha "${{ needs.specification.outputs.tested_sha }}"') == 2, "exact coverage SHA")
contains((ROOT / "scripts/ci-coverage.py").read_text(encoding="utf-8"), "MIN_PERCENT = 80",
         "read_shards", "identity in seen", 'report["inventory"] != expected',
         "Production sources missing executable evidence", "max(combined[name].get(number, 0), hits)")
tui = (ROOT / "crates/theia/tests/tui_real_terminal.rs").read_text(encoding="utf-8")
contains(tui, '#[ignore = "mandatory dedicated native coverage shard: real startup replay guard"]',
         "async fn compiled_dual_mode_tui_invitation_import_apply_and_rollback()",
         "sleep(Duration::from_secs(121)).await")
live = (ROOT / "crates/theia/tests/tunnel_liveness.rs").read_text(encoding="utf-8")
contains(live, "async fn production_h2_h3_asymmetric_traffic_half_close_and_idle()",
         "for transport in [Transport::H2, Transport::H3]", "cases.spawn(async move", "Case::LongUpload,",
         "Case::LongDownload,", "(23, Duration::from_secs(2))", "if long { 40 } else { 30 }", "Duration::from_secs(55)")
require("#[ignore" not in live, "real liveness remains mandatory")
contains((ROOT / "crates/theia/src/relay_liveness.rs").read_text(encoding="utf-8"),
         "async fn sustained_progress_beyond_300_seconds_in_either_direction()",
         "#[tokio::test(start_paused = true)]", "for _ in 0..32", "Duration::from_secs(320)",
         "activity.run(progress, inactive", "activity.run(inactive, progress, \"idle\")")
profile = tomllib.loads((ROOT / ".config/nextest.toml").read_text(encoding="utf-8"))["profile"]["default"]
require(profile["default-filter"] == "all()" and profile["retries"] == 0
        and profile["fail-fast"] is False and profile["test-threads"] == 4,
        "bounded scheduling without exclusions or retries")
for term in ("run_f13_observations.py f13-observations", "run_native_quic_comparison.py",
             "native_binary_performance_comparison", "comparison_records_all_controller_scenarios_ci_only",
             "drivers/windows/windivert/test-package.ps1", "scripts/f15-kernel-tests.py",
             "cargo build --workspace --release --locked"):
    require(term not in workflow, "deferred work returned to critical path: " + term)
    contains(extended, term)
contains(job("f15-kernel", extended), "sudo -n unshare -n true", "f15-coverage-build.json --coverage",
         "cargo llvm-cov show-env --sh", "scripts/f15-kernel-tests.py --verify-coverage coverage.json")
contains(job("f15-driver-build", extended), "make -C drivers/linux",
         "drivers/windows/windivert/test-package.ps1", "OfficialPackageVerified=$false", "if-no-files-found: error")
for name in ("m0-1-api-spike", "m0-1-windows-spike"):
    contains(job(name, extended), "comparison_records_all_controller_scenarios_ci_only",
             "check_bbr_comparison.py", "--test independent_h2_loopback -- --ignored")
contains(job("native-performance", extended), "abbb89834a406b4c53be0f1ac0b3ab1a65e66f8d",
         "check_native_performance.py", "--require-comparison", "--require-smoke")
contains(job("f19-performance", extended), "917417b09f209334939c38551112081c480eb958",
         "THEIA_F19_BASELINE_BIN", "f19-comparison.json", "--require-comparison")
contains(job("browser-e2e", extended), "run_f13_observations.py", "--samples 3",
         "check_f13_observations.py", "run_native_quic_comparison.py")
print("CI_MVP_SHARDS_EXTENDED_SCOPE_AND_SECURITY_CONTRACT_OK")
