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
    "m0-1-api-spike",
    "m0-1-windows-spike",
    "m3-4-btls-spike",
    "m3-4e-btls-production-feature",
    "coverage-native",
    "coverage-gate",
}

require(needs("rust-tests") == {"specification"}, "Linux tests must await spec only")
for name in ("windows-smoke", "browser-e2e"):
    require(
        needs(name) == {"specification"},
        f"{name} must run in parallel with Linux tests after specification",
    )
    require(
        "needs.specification.outputs.rust_ready == 'true'" in job(name),
        f"{name} must retain the Rust readiness precondition",
    )
require(needs("ci-gate") == mandatory, "ci-gate must depend on EVERY required job")
require(needs("f14-cross-host") == {"specification", "rust-tests", "windows-smoke"},
        "F-14 must consume verified Linux and Windows CI-built executable artifacts")
cross_host = job("f14-cross-host")
require("runs-on: windows-2025" in cross_host and "wsl-version: 2" in cross_host,
        "F-14 must connect native Windows client to real Linux WSL2 VM")
require("name: f14-linux-server" in cross_host and "name: f14-windows-compiled" in cross_host,
        "F-14 must consume both native OS binaries, never build on WSL runner")
require("scripts/f14-cross-os-ci.py" in cross_host
        and "--windows-client" in cross_host and "--windows-test" in cross_host
        and "cargo build" not in cross_host,
        "F-14 must execute prebuilt native Windows harness without duplicate compilation")
require("Build genuine Linux server for Windows cross-OS F-14 E2E" in job("rust-tests")
        and "actions/upload-artifact@v4" in job("rust-tests"),
        "Linux Theia ELF must originate from mandatory Linux native build")
require("Stage Windows E2E binaries from Cargo JSON artifact paths" in job("windows-smoke")
        and "cargo build --workspace --locked --bin theia --message-format=json" in job("windows-smoke")
        and "name: f14-windows-compiled" in job("windows-smoke"),
        "Windows Theia and test harness must originate from mandatory Windows smoke")
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
require("cargo test --workspace --all-targets --locked" in windows,
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
        1 + workflow.count("ref: ${{ needs.specification.outputs.tested_sha }}"),
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
             "cargo llvm-cov --workspace --all-targets --all-features --locked --lcov",
             "cargo llvm-cov report --json --include-build-script",
             "ci-coverage.py collect", "--llvm-json coverage-segments.json",
             "if-no-files-found: error"):
    require(term in coverage_native, "missing native coverage contract: " + term)
for term in ("coverage-Linux", "coverage-Windows", "ci-coverage.py gate",
             "THEIA_COVERAGE_SYNTAX_TESTS"):
    require(term in coverage_gate, "missing combined coverage contract: " + term)
require("continue-on-error" not in coverage_native + coverage_gate,
        "coverage collection and threshold may not be advisory")
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
require("cargo test --workspace --all-targets --locked" in linux,
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
require("actual_chromium_h2_settings_and_pseudo_order_reference" in job("browser-e2e"),
        "real browser H2 reference remains mandatory")

require(
    "concurrency:" in workflow
    and "ci-main-merge-${{ github.event.pull_request.merge_commit_sha || github.run_id }}" in workflow
    and "cancel-in-progress: false" in workflow,
    "different merged commits must never cancel one another",
)
print("CI_GRAPH_PARALLEL_AND_NATIVE_CHECKS_OK")
