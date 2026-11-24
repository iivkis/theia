#!/usr/bin/env python3
"""Fail-closed rustfmt preflight and one-commit repair on an exact PR head.

No credentials or network access. Only a later, separately scoped CI step
can push the verified child. A syntax/tool failure is not repairable drift.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import subprocess
import sys

FORMATS = (
    ("cargo", "fmt", "--all"),
    ("cargo", "fmt", "--manifest-path", "spikes/m0_1/Cargo.toml", "--all"),
    ("cargo", "fmt", "--manifest-path", "spikes/m3_4/Cargo.toml", "--all"),
)


class RepairError(RuntimeError):
    pass


def git(*args: str) -> bytes:
    return subprocess.check_output(["git", *args])


def changed_rust_paths(status: bytes, raw: bytes) -> set[bytes]:
    """Only unstaged modifications of tracked, ordinary .rs files are allowed."""
    if not status and not raw:
        return set()
    if not status.endswith(b"\0") or not raw.endswith(b"\0"):
        raise RepairError("Incomplete git diff")
    paths = set()
    for entry in status[:-1].split(b"\0"):
        if not entry.startswith(b" M ") or not entry[3:].endswith(b".rs"):
            raise RepairError("Formatting changed non-Rust or non-modified paths")
        path = entry[3:]
        if path in paths:
            raise RepairError("Duplicate path in status")
        paths.add(path)
    fields = raw[:-1].split(b"\0")
    if len(fields) % 2:
        raise RepairError("Unexpected raw diff")
    verified = set()
    for meta, path in zip(fields[::2], fields[1::2]):
        if not re.fullmatch(rb":(100644|100755) \1 [0-9a-f]+ [0-9a-f]+ M", meta):
            raise RepairError("Formatting changed a mode, symlink or non-regular file")
        if path in verified:
            raise RepairError("Duplicate raw diff")
        verified.add(path)
    if paths != verified:
        raise RepairError("Git status and raw diff disagree")
    return paths


def changes() -> set[bytes]:
    return changed_rust_paths(
        git("status", "--porcelain=v1", "-z", "--untracked-files=all"),
        git("diff", "--raw", "-z", "--no-renames"),
    )


def format_all(check=False) -> None:
    for command in FORMATS:
        subprocess.run([*command, *(["--", "--check"] if check else [])], check=True)


def execute(mode: str) -> int:
    if changes():
        raise RepairError("Expected clean checkout before formatting")
    if mode == "repair":
        expected = os.environ["PR_HEAD_SHA"]
        if not re.fullmatch(r"[0-9a-f]{40}", expected) or git("rev-parse", "HEAD").strip().decode() != expected:
            raise RepairError("PR head changed")
    format_all()
    paths = changes()
    if mode == "probe":
        if not paths:
            print("Rust formatting clean")
            return 0
        # Set only after successful formatting and safe diff validation.
        with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
            output.write("format_drift=true\n")
        print(f"::error::Rustfmt changed {len(paths)} file(s); native CI must test the repaired SHA")
        return 1
    if not paths:
        raise RepairError("PR head is already formatted; merge-tree drift requires branch sync")
    format_all(check=True)
    if changes() != paths:
        raise RepairError("Formatting is not idempotent")
    subprocess.run(["git", "add", "-u", "--", "*.rs"], check=True)
    if git("diff", "--name-only", "-z", "--cached") != b"":
        subprocess.run([
            "git", "-c", "core.hooksPath=/dev/null",
            "-c", "user.name=github-actions[bot]",
            "-c", "user.email=41898282+github-actions[bot]@users.noreply.github.com",
            "commit", "-m", "style: apply rustfmt before native CI",
        ], check=True)
    else:
        raise RepairError("No staged formatting changes")
    if git("rev-parse", "HEAD^").strip().decode() != expected or changes():
        raise RepairError("Repair commit is not a clean direct child")
    print("Rustfmt-only repair commit prepared")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("probe", "repair"))
    try:
        sys.exit(execute(parser.parse_args().mode))
    except (RepairError, subprocess.CalledProcessError, OSError, KeyError) as error:
        print(f"::error::Formatting preflight/repair refused: {error}", file=sys.stderr)
        sys.exit(1)
