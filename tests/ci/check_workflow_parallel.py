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
require("Real Windows live Theia H2 fingerprint vs pinned Go uTLS" in windows
        and "cargo test --workspace --locked --test fingerprint_h2" in windows,
        "Windows fingerprint must reuse the previously compiled root workspace")
require(windows.index("Native Windows tests")
        < windows.index("Real Windows live Theia H2 fingerprint vs pinned Go uTLS"),
        "fingerprint must run after native Windows root build")
require("cargo test --workspace --locked --test fingerprint_h2" not in job("m0-1-windows-spike"),
        "isolated Windows M0.1 job must not repeat the whole root workspace build")
require("go mod verify" in windows and "go run . $hello" in windows,
        "native Windows fingerprint must generate its pinned uTLS reference")
require("python3 -m compileall -q scripts tests" in job("specification"),
        "cheap Python preflight must execute before Rust tests")
linux = job("rust-tests")
require("cargo test --workspace --all-targets --locked" in linux,
        "mandatory Linux all-target tests must run")
require("cargo fmt --all -- --check" in linux,
        "mandatory Rust formatting must run")
require("cargo clippy --workspace --all-targets --all-features -- -D warnings" in linux,
        "mandatory Clippy warnings-as-errors must run")
require("pyte==0.8.2" in linux, "the Linux real-PTY test needs its VT parser")

# The specification is now the ONLY formatting gate.  Every native job
# tests the checked-out commit byte-for-byte, with no format overlay, post-green
# bot push, or extra untested SHA. Syntax/format errors abort before the matrix.
spec = job("specification")
require("fetch-depth: 2" in spec,
        "PR merge base and previous push commit must be available for scope proof")
require("steps.scope.outputs.native_required" in spec,
        "specification must publish fail-closed native CI scope")
require("scripts/ci-scope.py --base" in spec
        and "test_ci_scope.py" in spec,
        "scope detector and its negative-history tests must run before any skip")
require("cargo fmt --all -- --check" in spec
        and "cargo fmt --manifest-path spikes/m0_1/Cargo.toml --all -- --check" in spec
        and "cargo fmt --manifest-path spikes/m3_4/Cargo.toml --all -- --check" in spec,
        "all Rust workspaces must be checked BEFORE native CI fan-out")
require("gofmt -l" in spec and "git diff --exit-code" in spec,
        "Go formatting and unmodified source tree are required")
require("gofmt -w" not in spec and "ci-formatted-source" not in workflow
        and "persist-format:" not in workflow,
        "never change PR SHA after successful CI or upload/download formatter overlays")
for name in mandatory - {"specification"}:
    payload = job(name)
    require("needs.specification.outputs.native_required == 'true'" in payload,
            f"{name}: full matrix must run only when native scope is proven required")
    require("needs.specification.outputs.rust_ready == 'true'" in payload,
            f"{name}: Rust precondition must be explicit and fail closed")
    if name != "f14-cross-host":
        require("actions/download-artifact@v4" not in payload,
                f"{name}: no repeating CI format artifact downloads")
require("actions/download-artifact@v4" in job("f14-cross-host"),
        "cross-host still MUST use authenticated native OS binaries")
gate = job("ci-gate")
require("NATIVE_REQUIRED: ${{ needs.specification.outputs.native_required }}" in gate,
        "final gate must use exactly the preflight's scope")
require('native not in {"true", "false"}' in gate,
        "unset native scope must fail closed")
require('("success" if name == "specification" else "skipped")' in gate,
        "docs-only path must require a successful spec and skipped native matrix")
require("contents: write" not in workflow,
        "normal CI must never receive repository contents write permission")

require((ROOT / "spikes/m0_1/utls_reference/go.sum").is_file(),
        "pinned uTLS Go module dependency lock must exist")
go_steps = re.findall(
    r"(?m)^      - uses: actions/setup-go@v5\n(?:        if: [^\n]+\n)?        with:\n((?:          [^\n]+\n)+)",
    workflow,
)
require(len(go_steps) == 5, "all five pinned Go toolchains must be audited; post-green formatter Go was removed")
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
