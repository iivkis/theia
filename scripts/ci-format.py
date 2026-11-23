#!/usr/bin/env python3
"""Archive only deterministic, tracked rustfmt/gofmt edits for CI fan-out.

The archive is created on a read-only runner, after formatting and before
expensive builds. A zero-diff run still emits a valid empty tar. Never archive
untracked files, build products, private credentials or arbitrary symlinks.
"""
from __future__ import annotations

import argparse
from io import BytesIO
from pathlib import Path, PurePosixPath
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_TOTAL_BYTES = 16 * 1024 * 1024


def format_changes(archive: Path, *, repo: Path = ROOT) -> list[str]:
    paths_raw = subprocess.check_output(
        ["git", "diff", "--name-only", "-z", "--", "*.rs", "*.go"], cwd=repo
    )
    paths = sorted(path.decode("utf-8") for path in paths_raw.split(b"\0") if path)
    if len(paths) > 2048:
        raise ValueError("too many modified source files")
    total = 0
    archive.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive, "w", format=tarfile.PAX_FORMAT) as bundle:
        for path in paths:
            parts = PurePosixPath(path)
            if (
                parts.is_absolute()
                or ".." in parts.parts
                or not path.endswith((".rs", ".go"))
                or any(part in {"", "."} for part in parts.parts)
            ):
                raise ValueError("unsafe formatter path")
            source = repo.joinpath(*parts.parts)
            if not source.is_file() or source.is_symlink():
                raise ValueError("formatter changed a missing or symbolic file")
            size = source.stat().st_size
            if size > MAX_FILE_BYTES or total + size > MAX_TOTAL_BYTES:
                raise ValueError("formatter output exceeds size budget")
            data = source.read_bytes()
            if len(data) != size:
                raise ValueError("source changed during packaging")
            info = tarfile.TarInfo(path)
            info.size = len(data)
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mode = 0o644
            bundle.addfile(info, BytesIO(data))
            total += size
    return paths


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path)
    args = parser.parse_args()
    changed = format_changes(args.archive)
    print(f"FORMAT_SOURCE_ARCHIVED={len(changed)}")
    for path in changed:
        print(f"  {path}")


if __name__ == "__main__":
    main()
