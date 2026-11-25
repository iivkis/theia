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
            "h3-session": dict(alpn_h3=True, sni_present=True, ordinary_fields=2),
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
            self.assertEqual(len(result["pairs"]), 4)

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
            with self.assertRaises(ValueError):
                checker.compare(directory)

    def test_manifest_binds_samples_to_revision_platform_and_digests(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            manifest = dict(schema=1, revision="a"*40, platform="linux",
                            playwright=checker.PLAYWRIGHT, chromium=checker.CHROMIUM, samples=[])
            for i in range(3):
                base = directory / ("sample-%02d" % i)
                base.mkdir()
                self.fixture(base)
                manifest["samples"].append(dict(directory=base.name,
                    sha256={name: checker.read_json(base / name, 16384)[1] for name in checker.FILES}))
            (directory / "manifest.json").write_text(json.dumps(manifest))
            report = checker.compare_run(directory, "a"*40, "Linux")
            self.assertEqual(report["full_parity"], "not_established")
            self.assertEqual(len(report["samples"]), 3)
            for revision, os_name in (("b"*40, "Linux"), ("a"*40, "Windows")):
                with self.assertRaises(ValueError):
                    checker.compare_run(directory, revision, os_name)
            path = directory / "sample-00" / "native-h3-session.json"
            path.write_text(path.read_text() + " ")
            with self.assertRaises(ValueError):
                checker.compare_run(directory, "a"*40, "Linux")

    def test_reject_unbounded_and_wrongly_typed_fields(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            self.fixture(directory)
            path = directory / "native-h2-http.json"
            original = json.loads(path.read_text())
            for key, value in (("settings", [[2, 0], [2, 1]]), ("ordinary_fields", True),
                               ("frames_before_headers", [256]), ("request_end_stream", 1)):
                doc = dict(original, **{key: value})
                path.write_text(json.dumps(doc))
                with self.assertRaises(ValueError):
                    checker.compare(directory)


if __name__ == "__main__":
    unittest.main()
