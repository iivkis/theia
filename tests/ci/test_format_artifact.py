#!/usr/bin/env python3
"""Regression coverage for safe autoformat artifact contents.

Runs in the read-only specification gate, without Rust builds or network.
"""
from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
FORMATTER = ROOT / "scripts" / "ci-format.py"


def git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", *args], cwd=repo, check=True, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


class FormatArtifactTests(unittest.TestCase):
    def test_only_changed_tracked_sources_are_packaged(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            git(repo, "init", "-q")
            (repo / "src").mkdir()
            (repo / "src" / "sample.rs").write_text("fn main() {}\n", encoding="utf-8")
            (repo / "sample.go").write_text("package sample\n", encoding="utf-8")
            (repo / "readme.md").write_text("original\n", encoding="utf-8")
            git(repo, "add", ".")
            git(
                repo, "-c", "user.name=ci",
                "-c", "user.email=ci@example.invalid",
                "commit", "-qm", "fixture",
            )
            (repo / "src" / "sample.rs").write_text(
                "fn main() { println!(\"ok\"); }\n", encoding="utf-8"
            )
            (repo / "readme.md").write_text("modified\n", encoding="utf-8")
            (repo / "untracked.rs").write_text("secret\n", encoding="utf-8")
            archive = repo / "formatted.tar"
            command = [
                sys.executable, str(FORMATTER), str(archive)
            ]
            # The actual CI script operates on its own repository. Import the
            # pure function to inject this isolated Git fixture instead.
            import importlib.util
            spec = importlib.util.spec_from_file_location("ci_formatter", FORMATTER)
            self.assertIsNotNone(spec)
            module = importlib.util.module_from_spec(spec)
            assert spec.loader is not None
            spec.loader.exec_module(module)
            changed = module.format_changes(archive, repo=repo)
            self.assertEqual(changed, ["src/sample.rs"])
            with tarfile.open(archive, "r") as bundle:
                self.assertEqual(bundle.getnames(), ["src/sample.rs"])
                member = bundle.getmember("src/sample.rs")
                self.assertTrue(member.isfile())
                self.assertEqual(member.mode, 0o644)
                self.assertEqual(member.mtime, 0)
            # Empty diff must still yield a valid artifact for all other jobs.
            git(repo, "checkout", "--", "src/sample.rs", "readme.md")
            empty_archive = repo / "empty.tar"
            self.assertEqual(module.format_changes(empty_archive, repo=repo), [])
            with tarfile.open(empty_archive, "r") as bundle:
                self.assertEqual(bundle.getnames(), [])


if __name__ == "__main__":
    unittest.main()
