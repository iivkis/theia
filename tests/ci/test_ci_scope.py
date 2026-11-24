#!/usr/bin/env python3
"""Native CI is skippable ONLY for verified Markdown-only diffs."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "scripts" / "ci-scope.py"
spec = importlib.util.spec_from_file_location("ci_scope", SOURCE)
assert spec is not None and spec.loader is not None
scope = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scope)


def git(directory: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", *args], cwd=directory, stderr=subprocess.DEVNULL
    ).decode("ascii").strip()


class ScopeTests(unittest.TestCase):
    def test_only_markdown_documentation_skips_native_ci(self) -> None:
        for paths in [
            ["docs/adr/0061-research.md"],
            ["docs/STEALTH_REALITY.md", "README.md"],
            ["CHANGELOG.md", "CONTRIBUTING.md"],
        ]:
            self.assertTrue(scope.documentation_only(paths), paths)

        for paths in [
            [],
            [".github/workflows/ci.yml"],
            ["crates/theia/src/client.rs"],
            ["docs/fixtures/reference.json"],
            ["README.md", "scripts/ci-scope.py"],
            ["docs/subdir/example.rs"],
            ["docs/../README.md"],
            ["unknown.md"],
            ["docs/example.md", "Cargo.lock"],
            ["docs/bad\0.md"],
        ]:
            self.assertFalse(scope.documentation_only(paths), paths)

    def test_raw_modes_and_status_are_conservative(self) -> None:
        for old, new, status in [
            ("000000", "100644", "A"),
            ("100644", "100644", "M"),
            ("100644", "000000", "D"),
        ]:
            record = f":{old} {new} abc def {status}".encode()
            raw = record + b"\0docs/readme.md\0"
            self.assertEqual(scope.regular_markdown_paths(raw), ["docs/readme.md"])
        for old, new, status in [
            ("100644", "120000", "T"),
            ("000000", "120000", "A"),
            ("000000", "160000", "A"),
            ("100644", "100755", "M"),
            ("100644", "100644", "R100"),
            ("100644", "100644", "A"),
        ]:
            record = f":{old} {new} abc def {status}".encode()
            self.assertIsNone(scope.regular_markdown_paths(record + b"\0docs/a.md\0"))
        for raw in [b"bad", b"bad\0", b":100644 100644 abc def M\0\0"]:
            self.assertIsNone(scope.regular_markdown_paths(raw))

    def test_unknown_or_malformed_history_runs_full_native_matrix(self) -> None:
        for base in ["", "deadbeef", "z" * 40, "0" * 40]:
            self.assertTrue(scope.native_required(base))

    def test_real_git_diff_and_rename_are_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = Path(temp)
            git(repo, "init", "-q")
            git(repo, "config", "user.name", "CI Test")
            git(repo, "config", "user.email", "ci-test@example.invalid")
            (repo / "docs").mkdir()
            (repo / "docs" / "guide.md").write_text("initial\n")
            (repo / "main.rs").write_text("fn main() {}\n")
            git(repo, "add", ".")
            git(repo, "commit", "-qm", "initial")
            base = git(repo, "rev-parse", "HEAD")
            (repo / "docs" / "guide.md").write_text("updated\n")
            git(repo, "add", ".")
            git(repo, "commit", "-qm", "docs only")
            head = git(repo, "rev-parse", "HEAD")
            previous = Path.cwd()
            try:
                import os
                os.chdir(repo)
                self.assertEqual(scope.changed_paths(base), ["docs/guide.md"])
                self.assertFalse(scope.native_required(base))
                self.assertTrue(scope.native_required(head, base))
                # A Markdown path with executable mode is not docs-only.
                git(repo, "update-index", "--chmod=+x", "docs/guide.md")
                git(repo, "commit", "-qm", "executable docs path")
                self.assertTrue(scope.native_required(head))
                git(repo, "update-index", "--chmod=-x", "docs/guide.md")
                git(repo, "commit", "-qm", "restore ordinary mode")
                head = git(repo, "rev-parse", "HEAD")
                git(repo, "mv", "main.rs", "docs/moved.md")
                git(repo, "commit", "-qm", "rename code into docs")
                self.assertTrue(scope.native_required(head))
            finally:
                os.chdir(previous)


if __name__ == "__main__":
    unittest.main()
