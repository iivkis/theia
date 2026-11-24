#!/usr/bin/env python3
"""Fail-closed Rustfmt-only repair and exact-source verification.

No credentials or network access. Only the subsequent trusted post-merge
publication step may push the verified child. A syntax/tool failure is not
repairable drift. Legacy probe/repair modes remain offline testable.
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


def exact_sha(name: str) -> str:
    value = os.environ[name]
    if not re.fullmatch(r"[0-9a-f]{40}", value):
        raise RepairError("Invalid exact source SHA")
    return value


def verify_merged(merged: str, tested: str) -> None:
    """The accepted SHA is the merge itself or its Rust-only direct child."""
    if git("rev-parse", "HEAD").strip().decode() != tested or changes():
        raise RepairError("Tested SHA is not the clean checkout")
    if tested == merged:
        return
    if git("show", "-s", "--format=%P", tested).strip().decode() != merged:
        raise RepairError("Formatted SHA is not a single-parent child of the merge")
    raw = git("diff", "--raw", "-z", "--no-renames", merged, tested)
    names = git("diff", "--name-status", "-z", "--no-renames", merged, tested)
    if not names.endswith(b"\0"):
        raise RepairError("Empty or malformed format commit")
    fields = names[:-1].split(b"\0")
    if len(fields) % 2 or any(kind != b"M" for kind in fields[::2]):
        raise RepairError("Format commit adds, removes or renames paths")
    status = b"".join(b" M " + path + b"\0" for path in fields[1::2])
    if not changed_rust_paths(status, raw):
        raise RepairError("Expected a nonempty Rust-only format commit")


def output_sha(tested: str) -> None:
    with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
        output.write(f"tested_sha={tested}\n")


def execute(mode: str) -> int:
    if mode == "verify-merged":
        verify_merged(exact_sha("MERGED_SHA"), exact_sha("TESTED_SHA"))
        return 0
    if changes():
        raise RepairError("Expected clean checkout before formatting")
    expected = None
    if mode in {"repair", "prepare-merged"}:
        expected = exact_sha("MERGED_SHA" if mode == "prepare-merged" else "PR_HEAD_SHA")
        if git("rev-parse", "HEAD").strip().decode() != expected:
            raise RepairError("Source head changed")
        if mode == "prepare-merged" and os.environ.get("GITHUB_SHA") != expected:
            raise RepairError("Not the exact merged event SHA")
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
        if mode == "prepare-merged":
            output_sha(expected)
            return 0
        raise RepairError("PR head is already formatted; merge-tree drift requires branch sync")
    format_all(check=True)
    if changes() != paths:
        raise RepairError("Formatting is not idempotent")
    subprocess.run(["git", "add", "-u", "--", "*.rs"], check=True)
    staged = git("diff", "--name-only", "-z", "--cached")
    if not staged.endswith(b"\0") or set(staged[:-1].split(b"\0")) != paths:
        raise RepairError("Staged files differ from verified Rust-only diff")
    subprocess.run([
        "git", "-c", "core.hooksPath=/dev/null",
        "-c", "commit.gpgsign=false",
        "-c", "user.name=github-actions[bot]",
        "-c", "user.email=41898282+github-actions[bot]@users.noreply.github.com",
        "commit", "-m", "style: apply rustfmt after merge" if mode == "prepare-merged"
        else "style: apply rustfmt before native CI",
    ], check=True)
    if git("rev-parse", "HEAD^").strip().decode() != expected or changes():
        raise RepairError("Repair commit is not a clean direct child")
    if mode == "prepare-merged":
        tested = git("rev-parse", "HEAD").strip().decode()
        verify_merged(expected, tested)
        output_sha(tested)
    print("Rustfmt-only repair commit prepared")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("probe", "repair", "prepare-merged", "verify-merged"))
    try:
        sys.exit(execute(parser.parse_args().mode))
    except (RepairError, subprocess.CalledProcessError, OSError, KeyError) as error:
        print(f"::error::Formatting preflight/repair refused: {error}", file=sys.stderr)
        sys.exit(1)
