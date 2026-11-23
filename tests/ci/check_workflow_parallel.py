#!/usr/bin/env python3
"""CI DAG performance guard: parallel tests, intact mandatory gates and safe Go caches.

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
    "m3-3-bbr-comparison",
    "m3-4-btls-spike",
    "m3-4e-btls-production-feature",
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
        "cross-OS Windows job must consume both Linux and Windows CI-built executables")
cross_host = job("f14-cross-host")
require("needs.specification.outputs.rust_ready == 'true'" in cross_host,
        "cross-OS acceptance must not run on specification-only PRs")
require("runs-on: windows-2025" in cross_host,
        "cross-OS acceptance must use a real native Windows runner")
require("name: f14-linux-server" in cross_host
        and "name: f14-windows-compiled" in cross_host
        and cross_host.count("actions/download-artifact@v4") == 2,
        "cross-OS must retrieve both natively compiled Linux and Windows binaries")
require("Vampire/setup-wsl@4c48163d9f981914dd8caa0fc335fe19cca5bff4" in cross_host
        and "wsl-version: 2" in cross_host,
        "Linux must run under a pinned, real WSL2 VM")
require("scripts/f14-cross-os-ci.py" in cross_host
        and "--windows-test" in cross_host
        and "--windows-client" in cross_host
        and "cargo build" not in cross_host
        and "rust-toolchain" not in cross_host,
        "cross-OS must execute precompiled Windows test harness without rebuilding Rust")
require("Stage Windows E2E binaries already compiled by all-targets" in job("windows-smoke")
        and "f14-windows-compiled" in job("windows-smoke")
        and "actions/upload-artifact@v4" in job("windows-smoke"),
        "Windows E2E binaries must come from the mandatory native Windows smoke job")
require("python3 -m compileall -q scripts tests" in job("specification")
        and "python3 -m unittest discover -s tests/ci -p 'test_f14_*.py'" in job("specification"),
        "fast Python syntax and guest IPv4 regressions must execute before native tests")
require("continue-on-error" not in cross_host and "|| true" not in cross_host,
        "mandatory Linux/Windows integration cannot be optional")
require("Build genuine Linux server for Windows cross-OS F-14 E2E" in job("rust-tests")
        and "actions/upload-artifact@v4" in job("rust-tests"),
        "Linux executable must be built natively on Ubuntu and uploaded")
gate = job("ci-gate")
require("always()" in gate, "ci-gate must execute even when mandatory jobs fail")
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
linux = job("rust-tests")
require("cargo test --workspace --all-targets --locked" in linux,
        "mandatory Linux all-target tests must run")
require("cargo fmt --all -- --check" in linux,
        "mandatory Rust formatting must run")
require("cargo clippy --workspace --all-targets --all-features -- -D warnings" in linux,
        "mandatory Clippy warnings-as-errors must run")
require("pyte==0.8.2" in linux, "the Linux real-PTY test needs its VT parser")

require((ROOT / "spikes/m0_1/utls_reference/go.sum").is_file(),
        "pinned uTLS Go module dependency lock must exist")
go_steps = re.findall(
    r"(?m)^      - uses: actions/setup-go@v5\n        with:\n((?:          [^\n]+\n)+)",
    workflow,
)
require(len(go_steps) == 3, "all three test-only Go setup steps must be audited")
for step in go_steps:
    require("cache: true" in step,
            "Go module/build cache must be enabled for recurring CI")
    require("cache-dependency-path: spikes/m0_1/utls_reference/go.sum" in step,
            "Go cache must use the pinned uTLS lockfile, not an unscoped key")

require(
    "concurrency:" in workflow and "cancel-in-progress: true" in workflow,
    "outdated PR runs must still be cancelled",
)
print("CI_GRAPH_PARALLEL_AND_GO_CACHE_OK")
