#!/usr/bin/env python3
"""Cheap dependency-free F-14 guest-network preflight.

In particular ipaddress.ip_address(...).is_loopback is a boolean *property*,
not a callable. This regression previously cost over 6 minutes of Rust build.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
from unittest import TestCase, main
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "f14-cross-os-ci.py"
spec = importlib.util.spec_from_file_location("theia_f14_cross_os_ci", SCRIPT)
assert spec is not None and spec.loader is not None
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


class GuestIpTests(TestCase):
    def test_selects_non_loopback_virtual_nic(self) -> None:
        with patch.object(driver, "linux", return_value="127.0.0.1 ::1 172.25.17.8 192.168.0.1"):
            self.assertEqual(driver.guest_ip(), "172.25.17.8")

    def test_rejects_loopback_invalid_and_ipv6_only(self) -> None:
        with patch.object(driver, "linux", return_value="not-an-ip 127.0.0.1 ::1"):
            with self.assertRaisesRegex(RuntimeError, "non-loopback IPv4"):
                driver.guest_ip()


if __name__ == "__main__":
    main()
