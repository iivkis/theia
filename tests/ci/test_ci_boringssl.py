from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[2] / "scripts" / "ci-boringssl.py"
spec = importlib.util.spec_from_file_location("ci_boringssl", SOURCE)
bssl = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bssl)


class BoringSSLBundleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        original = bssl.ROOT
        self.addCleanup(setattr, bssl, "ROOT", original)
        bssl.ROOT = self.root
        self.out = self.root / "target/debug/build/btls-sys-123/out"
        self.lib = self.out / "build/Debug"
        self.lib.mkdir(parents=True)
        for name in ("crypto.lib", "ssl.lib"):
            (self.lib / name).write_bytes(b"!<arch>\n" + name.encode())
        self.header = self.out / "boringssl/include/openssl/x509v3.h"
        self.header.parent.mkdir(parents=True)
        self.header.write_text("/* fixture header */")
        self.expected = {
            "schema": 1, "sha": "a" * 40, "target": bssl.TARGET,
            "rustc": "fixture compiler", "lock_sha256": "b" * 64,
            "package_id": "registry+https://github.com/rust-lang/crates.io-index#btls-sys@0.5.6",
            "crate_checksum": "c" * 64, "features": ["default"],
        }
        self.events = [
            {"reason": "compiler-artifact", "package_id": self.expected["package_id"],
             "target": {"kind": ["lib"]}, "features": ["default"]},
            {"reason": "build-script-executed", "package_id": self.expected["package_id"],
             "out_dir": str(self.out), "linked_paths": ["native=" + str(self.lib)]},
            {"reason": "build-finished", "success": True},
        ]

    def stage(self, events=None, name="bundle"):
        path = self.root / "events.jsonl"
        path.write_text("\n".join(json.dumps(e) for e in
                                  (self.events if events is None else events)),
                        encoding="utf-8")
        bundle = self.root / name
        bssl.stage(path, bundle, self.expected)
        return bundle

    def test_cargo_command_uses_strict_utf8_not_windows_ansi(self):
        with patch.object(bssl.subprocess, "check_output", return_value='{"name":"日本語"}\n') as run:
            self.assertEqual(bssl.command("cargo", "metadata"), '{"name":"日本語"}')
            run.assert_called_once_with(("cargo", "metadata"), cwd=bssl.ROOT,
                                        encoding="utf-8", errors="strict")

    def test_exact_native_bundle_round_trip(self):
        bundle = self.stage()
        bssl.verify(bundle, self.expected)
        self.assertEqual((bundle / "lib/crypto.lib").read_bytes(),
                         (self.lib / "crypto.lib").read_bytes())
        self.assertEqual((bundle / "include/openssl/x509v3.h").read_bytes(),
                         self.header.read_bytes())

    def test_stale_features_source_and_compiler_are_rejected(self):
        bundle = self.stage()
        for field in ("sha", "target", "rustc", "lock_sha256", "package_id",
                      "crate_checksum", "features"):
            wrong = {**self.expected, field: "different"}
            with self.subTest(field=field), self.assertRaises(ValueError):
                bssl.verify(bundle, wrong)

    def test_tampering_and_unexpected_files_are_rejected(self):
        bundle = self.stage()
        rogue = bundle / "lib/rogue.lib"
        rogue.write_bytes(b"rogue")
        with self.assertRaises(ValueError):
            bssl.verify(bundle, self.expected)
        rogue.unlink()
        (bundle / "lib/ssl.lib").write_bytes(b"!<arch>\nchanged")
        with self.assertRaises(ValueError):
            bssl.verify(bundle, self.expected)

    def test_failed_or_ambiguous_cargo_build_never_stages(self):
        for mutation in ("failed", "duplicate", "features", "outside"):
            events = deepcopy(self.events)
            if mutation == "failed":
                events[-1]["success"] = False
            elif mutation == "duplicate":
                events.insert(1, deepcopy(events[1]))
            elif mutation == "features":
                events[0]["features"].append("different")
            else:
                events[1]["linked_paths"].append("native=" + str(self.root))
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.stage(events, mutation)
            self.assertFalse((self.root / mutation).exists())

    def test_missing_native_headers_and_invalid_archive_fail(self):
        self.header.unlink()
        with self.assertRaises(ValueError):
            self.stage(name="missing")
        self.header.write_text("fixture")
        (self.lib / "crypto.lib").write_bytes(b"not an archive")
        with self.assertRaises(ValueError):
            self.stage(name="invalid")


if __name__ == "__main__":
    unittest.main()
