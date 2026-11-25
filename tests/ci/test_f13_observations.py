import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    "f13_observations", Path(__file__).resolve().parents[1] / "benchmark" / "check_f13_observations.py")
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class ObservationTests(unittest.TestCase):
    def fixture(self, directory):
        observations = {
            "h2-tls": dict(legacy_version=771, cipher_count=5, extension_count=10, group_count=3,
                           grease=False, alps=False, sni_present=True, tls13=True, alpn_h2=True),
            "h2-http": dict(settings=[[2,0],[6,8192]], frames_before_headers=[],
                            connection_window_updates=[], pseudo_headers=[":method",":scheme",":authority",":path"],
                            ordinary_fields=2, request_end_stream=False),
            "h3-initial": dict(version=1, destination_cid_len=8, source_cid_len=8, token_len=0,
                               packet_len=1200, datagram_len=1200),
        }
        for variant in ("native","browser"):
            for name, data in observations.items():
                (directory / (variant+"-"+name+".json")).write_text(json.dumps(data), encoding="utf-8")

    def test_identical_partial_observations_never_claim_parity(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            self.fixture(directory)
            result = checker.compare(directory)
            self.assertEqual(result["acceptance"], "not_evaluated")
            self.assertEqual(result["full_parity"], "not_established")
            self.assertEqual(len(result["pairs"]), 3)

    def test_difference_missing_and_malformed(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            self.fixture(directory)
            path = directory / "browser-h2-tls.json"
            doc = json.loads(path.read_text())
            doc["grease"] = True
            path.write_text(json.dumps(doc))
            self.assertEqual(checker.compare(directory)["pairs"][0]["differing_fields"], ["grease"])
            doc["tls13"] = False
            path.write_text(json.dumps(doc))
            with self.assertRaises(ValueError):
                checker.compare(directory)
            path.unlink()
            with self.assertRaises(FileNotFoundError):
                checker.compare(directory)


if __name__ == "__main__":
    unittest.main()
