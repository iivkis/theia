#!/usr/bin/env python3
"""Cheap dependency-free F-14 guest-network preflight.

In particular ipaddress.ip_address(...).is_loopback is a boolean *property*,
not a callable. This regression previously cost over 6 minutes of Rust build.
"""
from __future__ import annotations

import hashlib
import importlib.util
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import TestCase, main
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "f14-cross-os-ci.py"
spec = importlib.util.spec_from_file_location("theia_f14_cross_os_ci", SCRIPT)
assert spec is not None and spec.loader is not None
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)

guest_server_path = ROOT / "scripts" / "f14-wsl-server.py"
guest_spec = importlib.util.spec_from_file_location("theia_f14_wsl_server", guest_server_path)
assert guest_spec is not None and guest_spec.loader is not None
guest_server = importlib.util.module_from_spec(guest_spec)
guest_spec.loader.exec_module(guest_server)


class LinuxGuestAddressTests(TestCase):
    def test_accepts_native_guest_ipv4(self) -> None:
        self.assertIsNone(guest_server.require_guest_ipv4("172.25.17.8"))

    def test_rejects_loopback_unspecified_ipv6_and_invalid(self) -> None:
        for candidate in ("127.0.0.1", "0.0.0.0", "::1", "not-an-ip"):
            with self.subTest(address=candidate):
                with self.assertRaisesRegex(RuntimeError, "guest IPv4"):
                    guest_server.require_guest_ipv4(candidate)


class LinuxCertificateTests(TestCase):
    def test_fixture_cert_must_be_tls_server_leaf_not_ca(self) -> None:
        # Strict rustls trust checks rejected the old CA:TRUE/keyCertSign
        # self-signed certificate as an end-entity during real cross-OS E2E.
        with TemporaryDirectory() as directory:
            cert, key = guest_server.certificate(Path(directory), "server")
            self.assertTrue(key.is_file())
            details = subprocess.run(
                ["openssl", "x509", "-in", str(cert), "-noout", "-text"],
                capture_output=True,
                text=True,
                check=True,
                timeout=12,
            ).stdout
            self.assertIn("CA:FALSE", details)
            self.assertIn("TLS Web Server Authentication", details)


class GuestIpTests(TestCase):
    def test_selects_non_loopback_virtual_nic(self) -> None:
        with patch.object(driver, "linux", return_value="127.0.0.1 ::1 172.25.17.8 192.168.0.1"):
            self.assertEqual(driver.guest_ip(), "172.25.17.8")

    def test_rejects_loopback_invalid_and_ipv6_only(self) -> None:
        with patch.object(driver, "linux", return_value="not-an-ip 127.0.0.1 ::1"):
            with self.assertRaisesRegex(RuntimeError, "non-loopback IPv4"):
                driver.guest_ip()


class StreamedGuestArtifactTests(TestCase):
    def test_streams_exact_bytes_to_linux_and_checks_sha256(self) -> None:
        data = b"ELF-like compiled test fixture"
        with TemporaryDirectory() as directory:
            source = Path(directory) / "theia-test"
            source.write_bytes(data)
            reply = SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
            with patch.object(driver.subprocess, "run", return_value=reply) as run, patch.object(
                driver, "linux", return_value=hashlib.sha256(data).hexdigest() + "  /tmp/theia"
            ):
                driver.copy_into_guest(source, "/tmp/theia")
            self.assertEqual(run.call_args.kwargs["input"], data)
            self.assertIn("dd", run.call_args.args[0])
            self.assertNotIn("sh", run.call_args.args[0])
            self.assertNotIn("wslpath", run.call_args.args[0])

    def test_rejects_changed_guest_artifact_and_empty_source(self) -> None:
        with TemporaryDirectory() as directory:
            source = Path(directory) / "theia-test"
            source.write_bytes(b"ELF-like source")
            reply = SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
            with patch.object(driver.subprocess, "run", return_value=reply), patch.object(
                driver, "linux", return_value="0" * 64 + "  /tmp/theia"
            ):
                with self.assertRaisesRegex(RuntimeError, "differs"):
                    driver.copy_into_guest(source, "/tmp/theia")
            source.write_bytes(b"")
            with self.assertRaisesRegex(RuntimeError, "empty or oversized"):
                driver.copy_into_guest(source, "/tmp/theia")


if __name__ == "__main__":
    main()
