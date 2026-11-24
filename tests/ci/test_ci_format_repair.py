#!/usr/bin/env python3
"""Offline Git fixtures for the Rust-only repair contract; no real pushes."""
from contextlib import contextmanager
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[2] / "scripts" / "ci-format-repair.py"
spec = importlib.util.spec_from_file_location("ci_format_repair", SOURCE)
assert spec is not None and spec.loader is not None
repair = importlib.util.module_from_spec(spec)
spec.loader.exec_module(repair)


@contextmanager
def repository():
    old = Path.cwd()
    with tempfile.TemporaryDirectory() as directory:
        os.chdir(directory)
        try:
            subprocess.run(["git", "init", "-q"], check=True)
            subprocess.run(["git", "config", "user.name", "Fixture"], check=True)
            subprocess.run(["git", "config", "user.email", "fixture@example.invalid"], check=True)
            Path("fixture.rs").write_text("fn main() {}\n")
            Path("notes.md").write_text("notes\n")
            subprocess.run(["git", "add", "."], check=True)
            subprocess.run(["git", "commit", "-qm", "fixture"], check=True)
            yield repair.git("rev-parse", "HEAD").strip().decode()
        finally:
            os.chdir(old)


class FormatRepairTests(unittest.TestCase):
    def test_real_git_diff_only_regular_modified_rust(self):
        with repository():
            self.assertEqual(repair.changes(), set())
            Path("fixture.rs").write_text("fn main() { }\n")
            self.assertEqual(repair.changes(), {b"fixture.rs"})
            Path("notes.md").write_text("changed\n")
            with self.assertRaises(repair.RepairError):
                repair.changes()

    def test_unsafe_status_and_raw_records_are_refused(self):
        for status, raw in [
            (b"?? extra.rs\0", b""),
            (b" M file.rs\0", b":100644 100755 a b M\0file.rs\0"),
            (b" M file.rs\0", b":120000 120000 a b M\0file.rs\0"),
            (b" D file.rs\0", b":100644 000000 a b D\0file.rs\0"),
            (b"M  file.rs\0", b""),
            (b" M file.rs\0", b":100644 100644 a b M\0other.rs\0"),
        ]:
            with self.subTest(status=status, raw=raw):
                with self.assertRaises(repair.RepairError):
                    repair.changed_rust_paths(status, raw)

    def test_probe_and_repair_create_one_clean_direct_child(self):
        def formatter(check=False):
            if not check:
                Path("fixture.rs").write_text("fn main() {\n}\n")

        with tempfile.TemporaryDirectory() as output_dir, repository() as head:
            output = Path(output_dir) / "output"
            with patch.dict(os.environ, {"GITHUB_OUTPUT": str(output), "PR_HEAD_SHA": head}):
                with patch.object(repair, "format_all", side_effect=formatter):
                    self.assertEqual(repair.execute("probe"), 1)
                    self.assertEqual(output.read_text(), "format_drift=true\n")
                    self.assertEqual(repair.git("rev-parse", "HEAD").strip().decode(), head)
                    subprocess.run(["git", "restore", "fixture.rs"], check=True)
                    self.assertEqual(repair.execute("repair"), 0)
                    self.assertEqual(repair.git("rev-parse", "HEAD^").strip().decode(), head)
                    self.assertEqual(repair.changes(), set())
                    self.assertEqual(repair.git("diff", "--name-only", "HEAD^", "HEAD").strip(), b"fixture.rs")

    def test_clean_probe_and_failed_formatter_never_request_repair(self):
        with tempfile.TemporaryDirectory() as output_dir, repository():
            output = Path(output_dir) / "output"
            with patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}):
                with patch.object(repair, "format_all"):
                    self.assertEqual(repair.execute("probe"), 0)
                self.assertFalse(output.exists())
                with patch.object(repair, "format_all", side_effect=subprocess.CalledProcessError(1, "cargo fmt")):
                    with self.assertRaises(subprocess.CalledProcessError):
                        repair.execute("probe")
                self.assertFalse(output.exists())

    def test_non_rust_formatter_change_cannot_create_commit(self):
        def formatter(check=False):
            Path("notes.md").write_text("changed\n")

        with tempfile.TemporaryDirectory() as output_dir, repository() as head:
            output = Path(output_dir) / "output"
            with patch.dict(os.environ, {"GITHUB_OUTPUT": str(output), "PR_HEAD_SHA": head}):
                with patch.object(repair, "format_all", side_effect=formatter):
                    with self.assertRaises(repair.RepairError):
                        repair.execute("probe")
                    self.assertFalse(output.exists())
                    subprocess.run(["git", "restore", "notes.md"], check=True)
                    with self.assertRaises(repair.RepairError):
                        repair.execute("repair")
                    self.assertEqual(repair.git("rev-parse", "HEAD").strip().decode(), head)

    def test_merged_format_publishes_exact_child_or_original_sha(self):
        def formatter(check=False):
            if not check:
                Path("fixture.rs").write_text("fn main() {\n}\n")

        with tempfile.TemporaryDirectory() as output_dir, repository() as merged:
            output = Path(output_dir) / "output"
            env = {"GITHUB_OUTPUT": str(output), "MERGED_SHA": merged, "GITHUB_SHA": merged}
            with patch.dict(os.environ, env):
                with patch.object(repair, "format_all"):
                    self.assertEqual(repair.execute("prepare-merged"), 0)
                    self.assertEqual(output.read_text(), f"tested_sha={merged}\n")
                output.unlink()
                with patch.object(repair, "format_all", side_effect=formatter):
                    self.assertEqual(repair.execute("prepare-merged"), 0)
                tested = repair.git("rev-parse", "HEAD").strip().decode()
                self.assertNotEqual(tested, merged)
                self.assertEqual(output.read_text(), f"tested_sha={tested}\n")
                repair.verify_merged(merged, tested)
                with self.assertRaises(repair.RepairError):
                    repair.verify_merged(merged, merged)

    def test_merged_format_rejects_wrong_event_and_non_rust_child(self):
        with repository() as merged:
            with patch.dict(os.environ, {"MERGED_SHA": merged, "GITHUB_SHA": "0" * 40}):
                with patch.object(repair, "format_all") as formatter:
                    with self.assertRaises(repair.RepairError):
                        repair.execute("prepare-merged")
                    formatter.assert_not_called()
            Path("notes.md").write_text("unsafe change\n")
            subprocess.run(["git", "commit", "-qam", "non-format child"], check=True)
            tested = repair.git("rev-parse", "HEAD").strip().decode()
            with self.assertRaises(repair.RepairError):
                repair.verify_merged(merged, tested)

    def test_wrong_head_and_empty_repair_refuse(self):
        with repository() as head:
            with patch.object(repair, "format_all"), patch.dict(os.environ, {"PR_HEAD_SHA": "0" * 40}):
                with self.assertRaises(repair.RepairError):
                    repair.execute("repair")
            with patch.object(repair, "format_all"), patch.dict(os.environ, {"PR_HEAD_SHA": head}):
                with self.assertRaises(repair.RepairError):
                    repair.execute("repair")


if __name__ == "__main__":
    unittest.main()
