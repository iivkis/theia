#!/usr/bin/env python3
"""Conservative native-CI scope classification.

Only Markdown-documentation-only changes may skip expensive Rust/Go/Windows
jobs. Unexpected events, unavailable history, malformed SHA, empty diffs,
renames from outside docs, and ANY non-Markdown source fail CLOSED to full CI.

The specification and ci-gate always run. No network, GitHub API, or secrets.
"""
from __future__ import annotations

import argparse
from pathlib import PurePosixPath
import re
import subprocess
import sys

SHA = re.compile(r"[0-9a-f]{40}\Z")
ROOT_DOCS = frozenset({"README.md", "CHANGELOG.md", "CONTRIBUTING.md"})


def documentation_only(paths: list[str]) -> bool:
    if not paths:
        return False
    for name in paths:
        path = PurePosixPath(name)
        if (
            path.is_absolute()
            or ".." in path.parts
            or not name.endswith(".md")
            or ("\0" in name)
        ):
            return False
        if name not in ROOT_DOCS and (
            not name.startswith("docs/") or len(path.parts) < 2
        ):
            return False
    return True


def regular_markdown_paths(raw: bytes) -> list[str] | None:
    """Accept only regular non-executable file changes, with exact raw records.

    Markdown-named symlinks, gitlinks, executable files and type changes
    are not documentation-only. No rename inference is allowed.
    """
    if not raw:
        return []
    parts = raw.split(b"\0")
    if parts[-1] != b"" or len(parts) % 2 != 1:
        return None
    paths = []
    for index in range(0, len(parts) - 1, 2):
        header, name = parts[index:index + 2]
        match = re.fullmatch(
            rb":(000000|100644) (000000|100644) [0-9a-f]+ [0-9a-f]+ ([AMD])",
            header,
        )
        if match is None:
            return None
        old, new, status = match.groups()
        if (old, new) != {
            b"A": (b"000000", b"100644"),
            b"M": (b"100644", b"100644"),
            b"D": (b"100644", b"000000"),
        }[status]:
            return None
        if not name:
            return None
        paths.append(name.decode("utf-8", "strict"))
    return paths


def changed_paths(base: str, head: str = "HEAD") -> list[str] | None:
    if not SHA.fullmatch(base):
        return None
    try:
        # The PR checkout is a merge commit. Its parent is the actual
        # event base SHA. Reject disconnected refs rather than guessing.
        subprocess.run(
            ["git", "merge-base", "--is-ancestor", base, head],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        changed = subprocess.check_output(
            ["git", "-c", "core.quotePath=false", "diff", "--no-ext-diff",
             "--no-renames", "--raw", "--no-abbrev", "-z", base, head, "--"],
            stderr=subprocess.DEVNULL,
        )
        return regular_markdown_paths(changed)
    except (OSError, ValueError, UnicodeError, subprocess.CalledProcessError):
        return None


def native_required(base: str, head: str = "HEAD") -> bool:
    paths = changed_paths(base, head)
    return paths is None or not documentation_only(paths)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", default="HEAD")
    args = parser.parse_args()
    required = native_required(args.base, args.head)
    print(f"native_required={'true' if required else 'false'}")
    print(
        "CI_SCOPE=full-native" if required else "CI_SCOPE=markdown-docs-only",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
