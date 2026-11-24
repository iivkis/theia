#!/usr/bin/env python3
"""Regression tests for the merge-only coverage evidence gate."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("ci_coverage", ROOT / "scripts/ci-coverage.py")
cov = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cov)

SHA = "1" * 40
A = "crates/theia/src/lib.rs"
B = "crates/theia/src/windows.rs"
FILES = {A: "a" * 64, B: "b" * 64}
LENGTHS = {A: 10, B: 10}
EXCLUDED = {A: {6}, B: set()}


def report(platform, files, sha=SHA):
    return {"schema": 1, "platform": platform, "sha": sha, "inventory": FILES.copy(), "files": files}


class CoverageTests(unittest.TestCase):
    def test_union_not_average_and_exact_threshold(self):
        linux = report("Linux", {A: {"1": 1, "2": 0, "3": 1, "6": 1}})
        windows = report("Windows", {A: {"1": 0, "2": 1, "3": 0}, B: {"1": 1, "2": 0}})
        result = cov.combine([linux, windows], FILES, SHA, EXCLUDED, LENGTHS)
        self.assertEqual((result["covered"], result["total"]), (4, 5))
        self.assertTrue(result["passed"])
        windows["files"][B]["1"] = 0
        self.assertFalse(cov.combine([linux, windows], FILES, SHA, EXCLUDED, LENGTHS)["passed"])

    def test_missing_platform_file_stale_and_invalid_evidence_fail_closed(self):
        linux = report("Linux", {A: {"1": 1}})
        cases = [
            [linux],
            [linux, report("Linux", {B: {"1": 1}})],
            [linux, report("Windows", {A: {"1": 1}})],
            [linux, report("Windows", {B: {"1": 1}}, "2" * 40)],
            [linux, report("Windows", {B: {"11": 1}})],
            [linux, report("Windows", {B: {"1": True}})],
            [linux, report("Windows", {B: {"1": 2}})],
            [linux, report("Windows", {B: {}})],
        ]
        for reports in cases:
            with self.subTest(reports=reports), self.assertRaises(cov.EvidenceError):
                cov.combine(reports, FILES, SHA, EXCLUDED, LENGTHS)

    def test_lcov_rejects_truncation_wrong_counts_and_duplicate_lines(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            text = f"TN:\nSF:{root / A}\nDA:1,3\nDA:2,0\nLF:2\nLH:1\nend_of_record\n"
            self.assertEqual(cov.read_lcov(text, root, FILES), {A: {"1": 1, "2": 0}})
            for bad in (text.replace("end_of_record\n", ""), text.replace("LF:2", "LF:3"),
                        text.replace("LH:1", "LH:2"), text.replace("DA:2,0", "DA:1,0"), text + text):
                with self.subTest(bad=bad), self.assertRaises(cov.EvidenceError):
                    cov.read_lcov(bad, root, FILES)

    def test_duplicate_json_keys_are_rejected(self):
        with self.assertRaises(cov.EvidenceError):
            cov.strict_object([("a", 1), ("a", 0)])

    def test_exclude_only_test_only_rust_syntax(self):
        try:
            import tree_sitter
            import tree_sitter_rust
        except ImportError:
            if os.environ.get("THEIA_COVERAGE_SYNTAX_TESTS") == "required":
                raise
            self.skipTest("syntax parser installed in coverage-gate")
        source = b"""fn production() -> u32 { 1 }
#[cfg(not(test))]
fn live() -> u32 { 2 }
#[cfg(test)]
mod tests {
    #[test]
    fn test_it() { assert_eq!(1, 1); }
}
#[tokio::test]
async fn test_async() {}
#[cfg(any(test, windows))]
fn maybe_live() {}
"""
        self.assertEqual(cov.test_only_lines(source), set(range(4, 11)))
        self.assertFalse(cov.test_only_attribute(b"#[cfg(not(test))]"))
        self.assertFalse(cov.test_only_attribute(b"#[cfg(any(test, windows))]"))
        self.assertTrue(cov.test_only_attribute(b'#[cfg(all(target_os = "linux", test))]'))
        self.assertTrue(cov.test_only_attribute(b"#[cfg(not(any(not(test), windows)))]"))
        self.assertFalse(cov.test_only_attribute(b"#[cfg(all(not(test), windows))]"))
        self.assertFalse(cov.test_only_attribute(b"#[custom::test]"))


if __name__ == "__main__":
    unittest.main()
