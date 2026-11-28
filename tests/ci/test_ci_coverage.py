#!/usr/bin/env python3
"""Regression tests for the merge-only coverage evidence gate."""
import importlib.util
import json
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
    def test_kernel_coverage_verifier_rejects_missing_or_zero_actual_counts(self):
        kernel_spec = importlib.util.spec_from_file_location(
            "f15_kernel_tests", ROOT / "scripts/f15-kernel-tests.py")
        kernel = importlib.util.module_from_spec(kernel_spec)
        kernel_spec.loader.exec_module(kernel)
        anchors = [
            ("crates/theia/src/routing/linux_rules.rs", "self.admissions = next_admissions;"),
            ("crates/theia/src/routing/linux_carrier.rs", "set_mark(&lease.fd, mark)?;"),
            ("crates/theia/src/routing/linux_rules.rs", "journal.restored = true;"),
            ("crates/theia/src/routing/linux_rules.rs", "journal.restored = true; // old-boot absence reconciliation"),
            ("crates/theia/src/routing/packet_modify.rs", "assert_eq!(count, 3);"),
            ("crates/theia/src/routing/linux_ingress.rs", "Ok(TransparentTcp { stream, key })"),
        ]
        evidence = {"platform": "Linux", "files": {}}
        locations = []
        for source, anchor in anchors:
            lines = (ROOT / source).read_text(encoding="utf-8").splitlines()
            numbers = [str(n) for n, line in enumerate(lines, 1) if line.strip() == anchor]
            self.assertEqual(len(numbers), 1)
            evidence["files"].setdefault(source, {})[numbers[0]] = 1
            locations.append((source, numbers[0]))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "coverage.json"
            path.write_text(json.dumps(evidence), encoding="utf-8")
            kernel.verify_coverage(path)
            for source, line in locations:
                for value in (0, None):
                    if value is None:
                        evidence["files"][source].pop(line)
                    else:
                        evidence["files"][source][line] = value
                    path.write_text(json.dumps(evidence), encoding="utf-8")
                    with self.assertRaises(SystemExit):
                        kernel.verify_coverage(path)
                    evidence["files"][source][line] = 1

    def test_union_not_average_and_exact_threshold(self):
        linux = report("Linux", {A: {"1": 1, "2": 0, "3": 1, "6": 1}})
        windows = report("Windows", {A: {"1": 0, "2": 1, "3": 0}, B: {"1": 1, "2": 0, "3": 0, "4": 0, "5": 0}})
        result = cov.combine([linux, windows], FILES, SHA, EXCLUDED, LENGTHS)
        self.assertEqual(result["minimum_percent"], 50)
        self.assertEqual((result["covered"], result["total"]), (4, 8))
        self.assertEqual(result["percent"], 50.0)
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

    def test_shard_matrix_union_and_artifact_identity(self):
        from copy import deepcopy
        reports = []
        for platform in sorted(cov.PLATFORMS):
            for shard in (1, 2):
                value = report(platform, {A: {"1": int(shard == 1), "2": int(shard == 2)},
                                          B: {"1": int(platform == "Windows")}})
                value.update(schema=2, shard=shard, shards=2)
                reports.append(value)
        result = cov.combine(reports, FILES, SHA, EXCLUDED, LENGTHS, shards=2)
        self.assertEqual((result["covered"], result["total"]), (3, 3))
        self.assertEqual(result["shards_per_platform"], 2)
        for mutate in ("missing", "duplicate", "stale", "wrong-count", "boolean", "inventory"):
            broken = deepcopy(reports)
            if mutate == "missing":
                broken.pop()
            elif mutate == "duplicate":
                broken[-1] = deepcopy(broken[0])
            elif mutate == "stale":
                broken[0]["sha"] = "2" * 40
            elif mutate == "wrong-count":
                broken[0]["shards"] = 3
            elif mutate == "boolean":
                broken[0]["shard"] = True
            else:
                broken[0]["inventory"].pop(A)
            with self.subTest(mutate=mutate), self.assertRaises(cov.EvidenceError):
                cov.combine(broken, FILES, SHA, EXCLUDED, LENGTHS, shards=2)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for value in reports:
                folder = root / f"coverage-shard-{value['platform']}-{value['shard']}"
                folder.mkdir()
                (folder / "coverage.json").write_text(json.dumps(value), encoding="utf-8")
            self.assertEqual(len(cov.read_shards(root, 2)), 4)
            wrong = root / "coverage-shard-Linux-1" / "coverage.json"
            wrong.write_text(json.dumps(reports[1]), encoding="utf-8")
            with self.assertRaises(cov.EvidenceError):
                cov.read_shards(root, 2)

    def test_lcov_rejects_truncation_wrong_counts_and_duplicate_lines(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            text = f"TN:\nSF:{root / A}\nDA:1,3\nDA:2,0\nLF:2\nLH:1\nend_of_record\n"
            self.assertEqual(cov.read_lcov(text, root, FILES), {A: {"1": 1, "2": 0}})
            for bad in (text.replace("end_of_record\n", ""), text.replace("LF:2", "LF:3"),
                        text.replace("LH:1", "LH:2"), text.replace("DA:2,0", "DA:1,0"), text + text):
                with self.subTest(bad=bad), self.assertRaises(cov.EvidenceError):
                    cov.read_lcov(bad, root, FILES)

    def test_llvm_file_union_can_differ_from_function_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / A
            source.parent.mkdir(parents=True)
            source.write_text("first\nsecond\nthird\n", encoding="utf-8")
            record = {
                "filename": str(source),
                "segments": [[1, 1, 3, True, True, False],
                             [2, 1, 0, True, True, False],
                             [2, 5, 0, False, False, False]],
                "summary": {"lines": {"count": 3, "covered": 2}},
            }
            export = {"type": "llvm.coverage.json.export", "version": "2.0.1",
                      "data": [{"files": [record]}]}
            for version in ("2.0.1", "3.1.0"):
                export["version"] = version
                llvm = cov.read_llvm_export(export, root, FILES)
                self.assertEqual(llvm[A], ({"1": 1, "2": 1}, 3, 2))
            for version in ("3.2.0", "4.0.0", "invalid", None):
                with self.subTest(version=version), self.assertRaises(cov.EvidenceError):
                    cov.read_llvm_export({**export, "version": version}, root, FILES)
            for bad in ({"type": "other"}, {"data": []}, {"data": [{"files": None}]}):
                with self.subTest(bad=bad), self.assertRaises(cov.EvidenceError):
                    cov.read_llvm_export({**export, **bad}, root, FILES)
            text = f"SF:{source}\nDA:1,3\nDA:2,3\nLF:3\nLH:2\nend_of_record\n"
            self.assertEqual(cov.read_lcov(text, root, FILES, llvm), {A: {"1": 1, "2": 1}})
            for bad in (text.replace("DA:2,3\n", ""), text.replace("DA:2,3", "DA:2,0"),
                        text.replace("LF:3", "LF:2"), text.replace("end_of_record\n", ""),
                        text + text):
                with self.subTest(bad=bad), self.assertRaises(cov.EvidenceError):
                    cov.read_lcov(bad, root, FILES, llvm)
            with self.assertRaises(cov.EvidenceError):
                cov.read_lcov(text, root, FILES, {**llvm, B: ({}, 0, 0)})
            with self.assertRaises(cov.EvidenceError):
                cov.llvm_segment_lines([[1, 1, 0, True, True, False],
                                       [1, 1, 0, False, False, False]], 3)

    def test_llvm_segment_skips_gaps_and_tracks_wrapped_regions(self):
        segments = [[1, 1, 0, True, True, False],
                    [3, 1, 0, False, True, False],
                    [4, 1, 7, True, True, False],
                    [5, 1, 0, False, True, False],
                    [5, 2, 0, True, True, True],
                    [6, 1, 0, False, False, False]]
        self.assertEqual(cov.llvm_segment_lines(segments, 6),
                         {"1": 0, "2": 0, "4": 1, "5": 1, "6": 0})

    def test_llvm_zero_length_skipped_segment_can_share_position(self):
        segments = [[1, 1, 5, True, True, False],
                    [2, 3, 0, False, True, False],
                    [2, 3, 5, True, False, False],
                    [4, 1, 0, False, False, False]]
        # A skipped entry at the start of line 2 suppresses mapping on that
        # line; the resumed region supplies the wrapped count on line 3.
        self.assertEqual(cov.llvm_segment_lines(segments, 4),
                         {"1": 1, "3": 1, "4": 1})
        for bad in ([segments[0], segments[2], segments[1]],
                    [segments[2], segments[0]], [segments[0], segments[0]]):
            with self.subTest(bad=bad), self.assertRaises(cov.EvidenceError):
                cov.llvm_segment_lines(bad, 4)

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


    def test_module_indexes_and_test_only_files_keep_inventory_without_fake_lines(self):
        try:
            import tree_sitter
            import tree_sitter_rust
        except ImportError:
            if os.environ.get("THEIA_COVERAGE_SYNTAX_TESTS") == "required":
                raise
            self.skipTest("syntax parser installed in coverage-gate")
        for source in (b"//! module index\npub(crate) mod tls;\nmod error;\n",
                       b"#![cfg(test)]\nuse super::*;\nfn helper() {}\n"):
            self.assertTrue(cov.zero_executable_source(source))
        for source in (b"mod inline { fn live() {} }", b"mod tls;\nfn live() {}",
                       b"#![cfg(any(test, windows))]\nfn live() {}",
                       b"#[cfg(test)]\nfn helper() {}\nfn live() {}",
                       b'include!("generated.rs");', b"macro_rules! live { () => {} }"):
            self.assertFalse(cov.zero_executable_source(source))
        self.assertEqual(cov.test_only_lines(b"#![cfg(test)]\nfn helper() {}\n"), {1, 2})
        linux = report("Linux", {A: {"1": 1}})
        windows = report("Windows", {A: {"1": 1}})
        with self.assertRaises(cov.EvidenceError):
            cov.combine([linux, windows], FILES, SHA, EXCLUDED, LENGTHS)
        result = cov.combine([linux, windows], FILES, SHA, EXCLUDED, LENGTHS, {B})
        self.assertEqual(result["files"][B], {"covered": 0, "total": 0})
        self.assertEqual((result["covered"], result["total"]), (1, 1))
        windows["files"][B] = {"1": 0}
        result = cov.combine([linux, windows], FILES, SHA, EXCLUDED, LENGTHS, {B})
        self.assertEqual((result["covered"], result["total"]), (1, 2))


if __name__ == "__main__":
    unittest.main()
