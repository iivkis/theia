import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    "performance_evidence",
    Path(__file__).resolve().parents[1] / "benchmark" / "check_performance_evidence.py",
)
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class EvidenceTests(unittest.TestCase):
    def rows(self):
        return [
            dict(zip(checker.FIELDS, (
                "linux", "h3", "fixture", str(i), variant, "1",
                "1000", "1100", "10", "0.5", "2000",
            )))
            for i in range(2) for variant in ("baseline", "candidate")
        ]

    def policy(self):
        return dict(min_pairs=2, required_groups=[["linux", "h3", "fixture"]],
                    max_candidate_latency_ms=15, min_candidate_throughput_bps=7000,
                    max_candidate_cpu_s=1, max_candidate_peak_rss_bytes=4000,
                    max_candidate_wire_overhead=0.2)

    def test_complete_paired_fixture(self):
        result = checker.summarize(checker.aggregate(self.rows()))
        self.assertEqual(result[0]["pairs"], 2)
        self.assertTrue(checker.evaluate(result, self.policy()))
        policy = self.policy()
        policy["max_candidate_latency_ms"] = 5
        self.assertFalse(checker.evaluate(result, policy))
        policy["required_groups"].append(["windows", "h3", "fixture"])
        with self.assertRaises(ValueError):
            checker.evaluate(result, policy)

    def test_rejects_duplicate_missing_and_mismatched_pairs(self):
        rows = self.rows()
        for bad in (rows[:-1], rows[1:], rows + rows[:1]):
            with self.assertRaises(ValueError):
                checker.aggregate(bad)
        rows[1]["application_bytes"] = "999"
        with self.assertRaises(ValueError):
            checker.aggregate(rows)

    def test_rejects_invalid_measurements(self):
        for field, value in (("duration_s", "0"), ("cpu_s", "nan"),
                             ("wire_bytes", "999"), ("peak_rss_bytes", "0"),
                             ("latency_ms", "inf")):
            rows = self.rows()
            rows[0][field] = value
            with self.assertRaises(ValueError):
                checker.aggregate(rows)


if __name__ == "__main__":
    unittest.main()
