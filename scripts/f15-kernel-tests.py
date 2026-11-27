#!/usr/bin/env python3
"""Run the exact compiled F-15 library harness as root on a disposable Linux CI runner.

The Rust tests create their own isolated network namespaces and refuse the
host namespace. No skip on absent kernel capabilities, no test-name guessing.
"""
import json
import os
from pathlib import Path
import re
import subprocess
import sys

TESTS = (
    "routing::linux_rules::tests::kernel_install_and_recovery_in_new_namespace",
    "routing::linux_rules::tests::kernel_hard_kill_keeps_capture_fail_closed_until_explicit_recovery",
    "routing::linux_rules::tests::kernel_socket_queue_proves_descriptor_not_just_destination",
    "routing::linux_rules::tests::kernel_dynamic_carrier_lease_revokes_exact_socket_and_recycles",
    "routing::packet_modify::tests::kernel_tcp_split_emits_two_real_ipv4_packets",
    "routing::packet_modify::tests::kernel_live_tcp_split_retransmission_and_ack",
)


def test_executable(path: Path) -> Path:
    candidates = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        msg = json.loads(line)
        if (
            msg.get("reason") == "compiler-artifact"
            and msg.get("profile", {}).get("test") is True
            and msg.get("target", {}).get("name") == "theia"
            and msg.get("target", {}).get("kind") == ["lib"]
            and msg.get("executable")
        ):
            candidates.add(Path(msg["executable"]).resolve(strict=True))
    if len(candidates) != 1:
        raise SystemExit("F-15: expected exactly one native Theia library test executable")
    executable = candidates.pop()
    root = Path.cwd().resolve()
    if not executable.is_relative_to(root / "target") or not executable.is_file():
        raise SystemExit("F-15: unexpected test binary outside workspace target")
    return executable


def verify_coverage(path: Path) -> None:
    """Check execution evidence, not merely successful privileged exit codes."""
    report = json.loads(path.read_text(encoding="utf-8"))
    if report.get("platform") != "Linux":
        raise SystemExit("F-15: expected Linux native coverage")
    sentinels = (
        ("crates/theia/src/routing/linux_rules.rs", "self.admissions = next_admissions;"),
        ("crates/theia/src/routing/linux_carrier.rs", "set_mark(&lease.fd, mark)?;"),
        ("crates/theia/src/routing/linux_rules.rs", "journal.restored = true;"),
    )
    for source, anchor in sentinels:
        lines = Path(source).read_text(encoding="utf-8").splitlines()
        hits = [str(index) for index, line in enumerate(lines, 1)
                if line.strip() == anchor]
        if len(hits) != 1 or report["files"].get(source, {}).get(hits[0]) != 1:
            raise SystemExit(f"F-15: missing actual kernel coverage: {source}: {anchor}")
    print("F-15: actual kernel execution present in normalized LLVM evidence", flush=True)


def main() -> None:
    if sys.platform != "linux":
        raise SystemExit("F-15: Linux CI required")
    if len(sys.argv) == 3 and sys.argv[1] == "--verify-coverage":
        verify_coverage(Path(sys.argv[2]))
        return
    if len(sys.argv) != 2 and not (len(sys.argv) == 3 and sys.argv[2] == "--coverage"):
        raise SystemExit("F-15: exact cargo JSON path required")
    executable = test_executable(Path(sys.argv[1]))
    sudo = ["sudo", "-n"]
    target = None
    if len(sys.argv) == 3:
        # The privileged binary and its profile must share the exact
        # cargo-llvm-cov report directory, never the default Cargo target.
        target = (Path.cwd().resolve() / "target" / "llvm-cov-target").resolve(strict=True)
        profile = os.environ.get("LLVM_PROFILE_FILE")
        if not profile or Path(profile).parent.resolve() != target or not executable.is_relative_to(target):
            raise SystemExit("F-15: binary/profile target does not match coverage report target")
        sudo.append("--preserve-env=LLVM_PROFILE_FILE")
    for index, test in enumerate(TESTS):
        env = None
        pattern = None
        if target is not None:
            prefix = f"theia-f15-{index}-"
            pattern = f"{prefix}*.profraw"
            if any(target.glob(pattern)):
                raise SystemExit(f"F-15: stale profile evidence for {test}")
            env = dict(os.environ, LLVM_PROFILE_FILE=str(target / f"{prefix}%p-%m.profraw"))
        run = subprocess.run(
            [*sudo, str(executable), "--ignored", "--exact", test, "--nocapture", "--test-threads=1"],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            encoding="utf-8",
            timeout=60,
            check=False,
        )
        print(run.stdout, flush=True)
        if run.returncode != 0 or not re.search(
            r"(?m)^test result: ok\. 1 passed; 0 failed; 0 ignored;", run.stdout
        ):
            raise SystemExit(f"F-15 kernel acceptance failed or did not execute: {test}")
        if target is not None and not any(p.is_file() and p.stat().st_size > 0
                                         for p in target.glob(pattern)):
            raise SystemExit(f"F-15: no fresh LLVM profile for {test}")
    print("F-15: all isolated kernel scenarios executed successfully", flush=True)


if __name__ == "__main__":
    main()
