import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    "native_performance", Path(__file__).resolve().parents[1] / "benchmark" / "check_native_performance.py")
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


def fixture():
    revision = "a" * 40
    document = dict(schema=1, scope="controlled-loopback", mode="smoke",
                    platform="linux", machine="x86_64", python="3.12",
                    revisions={"baseline": revision, "candidate": revision},
                    binaries_sha256={"baseline": "b" * 64, "candidate": "b" * 64},
                    accounting="carrier-socket-payload-excludes-ip-and-tcp-retransmissions",
                    rss="sampled-sum-client-server-10ms", conditions=["clean", "udp-loss", "relay-delay"],
                    repetitions=2, rows=[])
    for transport in ("h2", "h3"):
        for condition in document["conditions"]:
            if transport == "h2" and condition == "udp-loss":
                continue
            for workload, (streams, count, size) in checker.WORKLOADS.items():
                for trial in range(2):
                    for variant in ("baseline", "candidate"):
                        app = 2 * streams * count * size
                        document["rows"].append(dict(
                            transport=transport, condition=condition, workload=workload,
                            trial=trial, variant=variant, application_bytes=app, duration_s=1.0,
                            cpu_s=.2, sampled_peak_rss_bytes=10000, latency_ms=[1.0] * (streams * count),
                            open_ms=[2.0] * streams, stream_bps=[1000.0] * streams, errors=0,
                            fallback=0, carrier_bytes=app + 100, observed_units=40,
                            dropped_datagrams=2 if condition == "udp-loss" else 0,
                            delayed_units=40 if condition == "relay-delay" else 0,
                            forwarded_bytes=app + (50 if condition == "udp-loss" else 100)))
    return document


class NativeEvidenceTests(unittest.TestCase):
    def test_complete_and_descriptive_only(self):
        result = checker.summarize(fixture(), "a" * 40, "Linux")
        self.assertEqual(result["acceptance"], "not_evaluated")
        self.assertEqual(len(result["summary"]), 30)
        self.assertTrue(all(v["fairness"] == 1.0 for v in result["summary"]))
        self.assertEqual(checker.percentile([1, 2, 3, 100], .99), 100)

    def test_incomplete_and_duplicate(self):
        for change in (lambda d: d["rows"].pop(),
                       lambda d: d["rows"].__setitem__(0, d["rows"][1])):
            doc = fixture()
            change(doc)
            with self.assertRaises(ValueError):
                checker.summarize(doc)

    def test_bad_metrics_and_accounting(self):
        for field, value in (("duration_s", 0), ("cpu_s", float("nan")),
                             ("latency_ms", []), ("application_bytes", 1),
                             ("carrier_bytes", 0), ("errors", 1), ("fallback", 1),
                             ("trial", True), ("forwarded_bytes", 1), ("delayed_units", 1)):
            doc = fixture()
            doc["rows"][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                checker.summarize(doc)

    def test_exact_revision_platform_mode(self):
        doc = fixture()
        for revision, platform in (("c" * 40, "linux"), ("a" * 40, "windows")):
            with self.assertRaises(ValueError):
                checker.summarize(doc, revision, platform)
        doc["mode"] = "comparison"
        with self.assertRaises(ValueError):
            checker.summarize(doc)
        doc = fixture()
        doc["revisions"]["baseline"] = "c" * 40
        with self.assertRaises(ValueError):
            checker.summarize(doc)

    def test_diagnostic_policy_rejects_smoke_and_reports_regression(self):
        policy = checker.load(Path(__file__).resolve().parents[1] / "benchmark" / "native-diagnostic-policy.json")
        with self.assertRaises(ValueError):
            checker.compare(checker.summarize(fixture()), policy)
        doc = fixture()
        doc["mode"] = "comparison"
        doc["revisions"]["baseline"] = policy["baseline_revision"]
        doc["binaries_sha256"]["baseline"] = "c" * 64
        doc["repetitions"] = 3
        extra = [dict(row, trial=2) for row in doc["rows"] if row["trial"] == 1]
        doc["rows"].extend(extra)
        result = checker.summarize(doc)
        self.assertEqual(checker.compare(result, policy)["status"], "within_diagnostic_guardrails")
        for row in result["summary"]:
            if row["variant"] == "candidate":
                row["throughput_bps"] *= .1
        self.assertEqual(checker.compare(result, policy)["status"], "regression_observed")

    def test_json_duplicate_keys(self):
        with self.assertRaises(ValueError):
            checker.unique_object([("rows", []), ("rows", [])])


if __name__ == "__main__":
    unittest.main()
