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


def main() -> None:
    if sys.platform != "linux" or (len(sys.argv) != 2 and
                                      not (len(sys.argv) == 3 and sys.argv[2] == "--coverage")):
        raise SystemExit("F-15: Linux CI and exact cargo JSON path required")
    executable = test_executable(Path(sys.argv[1]))
    sudo = ["sudo", "-n"]
    if len(sys.argv) == 3:
        # Preserve only the compiler runtime's profile destination, not
        # arbitrary caller environment or loader configuration.
        profile = os.environ.get("LLVM_PROFILE_FILE")
        if not profile:
            raise SystemExit("F-15: instrumented profile destination required")
        destination = Path(profile)
        if not destination.is_absolute() or not destination.is_relative_to(Path.cwd().resolve() / "target"):
            raise SystemExit("F-15: profile destination must be inside the workspace target")
        destination.parent.mkdir(parents=True, exist_ok=True)
        sudo.append("--preserve-env=LLVM_PROFILE_FILE")
    for test in TESTS:
        run = subprocess.run(
            [*sudo, str(executable), "--ignored", "--exact", test, "--nocapture", "--test-threads=1"],
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
    print("F-15: all isolated kernel scenarios executed successfully", flush=True)


if __name__ == "__main__":
    main()
