"""Cheap negative tests for independent loopback-only TLS probe."""
import importlib.util
from pathlib import Path
import unittest

source = Path(__file__).resolve().parents[2] / "scripts" / "independent-h2-probe.py"
spec = importlib.util.spec_from_file_location("independent_probe", source)
assert spec is not None and spec.loader is not None
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class ProbeTests(unittest.TestCase):
    def test_only_numeric_loopback_allowed(self):
        self.assertEqual(probe.validate_loopback("127.0.0.1:443"), ("127.0.0.1", 443))
        self.assertEqual(probe.validate_loopback("[::1]:443"), ("::1", 443))
        for address in ("example.org:443", "192.0.2.1:443", "[2001:db8::1]:443",
                        "127.0.0.1:0", "127.0.0.1:65536", "127.0.0.1"):
            with self.subTest(address=address), self.assertRaises(ValueError):
                probe.validate_loopback(address)

    def test_frame_bounds(self):
        self.assertEqual(probe.frame(4, 0, 0), bytes([0, 0, 0, 4, 0, 0, 0, 0, 0]))
        with self.assertRaises(ValueError):
            probe.frame(0, 0, 1, bytes(probe.MAX_FRAME + 1))
        with self.assertRaises(ValueError):
            probe.frame(0, 0, 2**31)


if __name__ == "__main__":
    unittest.main()
