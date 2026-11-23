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

# Every OS/job variant runs against the *same* read-only formatting artifact.
# Rustfmt and gofmt execute once before any expensive build/test starts.
spec = job("specification")
require("python3 tests/ci/test_format_artifact.py" in spec,
        "format artifact source/path isolation tests must run before fan-out")
require("cargo fmt --all" in spec
        and "cargo fmt --manifest-path spikes/m0_1/Cargo.toml --all" in spec
        and "cargo fmt --manifest-path spikes/m3_4/Cargo.toml --all" in spec,
        "all Rust workspaces must be autoformatted first")
require("gofmt -w" in spec and "scripts/ci-format.py" in spec,
        "Go helpers must be formatted and the bounded artifact packaged")
require("name: ci-formatted-source" in spec and "actions/upload-artifact@v4" in spec,
        "specification must publish the canonical source artifact")
for name in mandatory - {"specification"}:
    payload = job(name)
    require("actions/download-artifact@v4" in payload
            and "name: ci-formatted-source" in payload
            and "Use canonical formatted sources for all tests" in payload,
            f"{name} must apply the shared formatting artifact")
    require(payload.index("Use canonical formatted sources for all tests")
            < payload.index("cargo test") if "cargo test" in payload else True,
            f"{name} must autoformat BEFORE compiling/running tests")
require("persist-format" not in mandatory,
        "autoformat persistence must never replace a required test job")
persist = job("persist-format")
require(needs("persist-format") == {"ci-gate"},
        "source persistence must wait for the full green CI gate")
require("needs.ci-gate.result == 'success'" in persist,
        "failed tests must not permit autoformat commits")
require("github.event_name == 'pull_request'" in persist
        and "github.event.pull_request.head.repo.full_name == github.repository" in persist,
        "no privileged writes for forks or untrusted events")
require("ref: ${{ github.event.pull_request.head.sha }}" in persist
        and 'test "$(git rev-parse HEAD)" = "$EXPECTED_HEAD"' in persist,
        "never persist formatting against a stale or guessed PR head")
require('git push origin "HEAD:refs/heads/$HEAD_REF"' in persist
        and 'gh workflow run ci.yml --ref "$HEAD_REF"' in persist,
        "each autoformat commit must explicitly trigger exact-new-head CI")
require("contents: write" in persist and "actions: write" in persist,
        "isolated post-green job needs scoped permissions to push and dispatch")
require("contents: read" in workflow.split("jobs:", 1)[0],
        "normal test jobs must remain read-only")

require((ROOT / "spikes/m0_1/utls_reference/go.sum").is_file(),
        "pinned uTLS Go module dependency lock must exist")
go_steps = re.findall(
    r"(?m)^      - uses: actions/setup-go@v5\n(?:        if: [^\n]+\n)?        with:\n((?:          [^\n]+\n)+)",
    workflow,
)
require(len(go_steps) == 5, "all test-only and formatter Go toolchains must be audited")
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
