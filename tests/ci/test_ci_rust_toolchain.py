import importlib.util
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[2] / "scripts" / "ci-rust-toolchain.py"
spec = importlib.util.spec_from_file_location("ci_rust_toolchain", SOURCE)
rust = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rust)
RELEASE = "1.100.1"
COMMIT = "a" * 40
HOST = "x86_64-pc-windows-msvc"
VERSION = f"rustc {RELEASE}\nrelease: {RELEASE}\ncommit-hash: {COMMIT}\nhost: {HOST}"
INSTALLED = "\n".join(f"{name}-{HOST}" for name in ("cargo", "rustc", "llvm-tools"))


class ToolchainTests(unittest.TestCase):
    def test_strict_stable_identity(self):
        self.assertEqual(rust.compiler(VERSION), (RELEASE, COMMIT, HOST))
        for value in (VERSION.replace(RELEASE, "nightly"),
                      VERSION.replace(COMMIT, "bad"),
                      VERSION + "\nrelease: 1.2.3",
                      VERSION.replace(f"host: {HOST}", "")):
            with self.subTest(value=value), self.assertRaises(ValueError):
                rust.compiler(value)

    def test_existing_exact_compiler_and_component_can_be_reused(self):
        with patch.object(rust, "command", side_effect=[VERSION, INSTALLED]):
            self.assertTrue(rust.ready("stable", (RELEASE, COMMIT), ["llvm-tools-preview"]))
        with patch.object(rust, "command", side_effect=[VERSION, INSTALLED]):
            self.assertFalse(rust.ready("stable", (RELEASE, COMMIT), ["clippy"]))
        with patch.object(rust, "command", return_value=VERSION):
            self.assertFalse(rust.ready("stable", (RELEASE, "b" * 40), []))
        with patch.object(rust, "command", side_effect=subprocess.CalledProcessError(1, ["rustup"])):
            self.assertFalse(rust.ready("stable", (RELEASE, COMMIT), []))

    def test_ready_toolchain_does_not_trigger_install(self):
        with patch.object(rust, "ready", return_value=True), \
                patch.object(rust, "command", side_effect=[VERSION, "cargo 1.100.1"]), \
                patch.object(rust.subprocess, "run") as run:
            rust.prepare((RELEASE, COMMIT), [])
            run.assert_called_once_with(["rustup", "default", "stable"], check=True)

    def test_moving_stable_falls_back_to_exact_release(self):
        with patch.object(rust, "ready", side_effect=[False, False, False, True]), \
                patch.object(rust, "command", side_effect=[VERSION, "cargo 1.100.1"]), \
                patch.object(rust.subprocess, "run") as run:
            rust.prepare((RELEASE, COMMIT), ["clippy"])
            self.assertEqual(run.call_args_list[0].args[0][3], "stable")
            self.assertEqual(run.call_args_list[1].args[0][3], RELEASE)
            self.assertEqual(run.call_args_list[2].args[0], ["rustup", "default", RELEASE])

    def test_wrong_active_compiler_is_not_accepted(self):
        with patch.object(rust, "ready", return_value=True), \
                patch.object(rust, "command", return_value=VERSION.replace(COMMIT, "b" * 40)), \
                patch.object(rust.subprocess, "run"):
            with self.assertRaises(ValueError):
                rust.prepare((RELEASE, COMMIT), [])


if __name__ == "__main__":
    unittest.main()
