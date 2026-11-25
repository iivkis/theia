import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    "classifier_evidence", Path(__file__).resolve().parents[1] / "benchmark" / "check_classifier_evidence.py")
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


def example():
    rows = []
    for i in range(400):
        rows.append(dict(platform="linux", transport="h2", group=f"{i+100:064x}",
                         **{"class": "reference"}, variant="reference", score=.1))
    for variant, score in (("off", .9), ("on", .1)):
        rows.append(dict(platform="linux", transport="h2", group=f"{600:064x}",
                         **{"class": "tunnel"}, variant=variant, score=score))
    return dict(schema=1, model_sha256="a"*64, calibration_sha256="b"*64,
                baseline_revision="1"*40, candidate_revision="2"*40,
                corpus_sha256="d"*64, review_report_sha256="e"*64,
                threshold=.5, excluded_groups=["c"*64], required_strata=[["linux","h2"]], rows=rows)


class ClassifierEvidenceTests(unittest.TestCase):
    def test_descriptive_frozen_threshold(self):
        result = checker.report(example())
        self.assertEqual(result["acceptance"], "not_evaluated")
        row = result["strata"][0]
        self.assertTrue(row["fpr_upper_within_one_percent"])
        self.assertEqual(row["delta_tpr"], -1)
        self.assertEqual(row["paired_outcomes"], dict(off_only=1,on_only=0,both=0,neither=0))
        self.assertGreater(row["true_positive_on"]["upper95"], 0)

    def test_provenance_and_full_matrix_are_required_when_requested(self):
        doc = example()
        with self.assertRaises(ValueError):
            checker.report(doc, expected_candidate="3"*40)
        with self.assertRaises(ValueError):
            checker.report(doc, expected_baseline="3"*40)
        with self.assertRaises(ValueError):
            checker.report(doc, full_matrix=True)
        doc["candidate_revision"] = doc["baseline_revision"]
        with self.assertRaises(ValueError):
            checker.report(doc)

    def test_small_sample_does_not_prove_low_false_positive_rate(self):
        d = example()
        d["rows"] = d["rows"][:1] + d["rows"][-2:]
        self.assertFalse(checker.report(d)["strata"][0]["fpr_upper_within_one_percent"])

    def test_reject_leakage_duplicate_unpaired_and_invalid_score(self):
        for change in (
            lambda d: d["excluded_groups"].append(d["rows"][0]["group"]),
            lambda d: d["rows"].append(d["rows"][0]),
            lambda d: d["rows"].pop(),
            lambda d: d["rows"][0].update(score=float("nan")),
            lambda d: d["required_strata"].append(["windows","h3"]),
        ):
            d = example()
            change(d)
            with self.assertRaises(ValueError):
                checker.report(d)


if __name__ == "__main__":
    unittest.main()
