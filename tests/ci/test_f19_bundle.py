import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "benchmark"))
import check_f19_bundle as bundle
from test_classifier_evidence import example
from test_native_performance import fixture


def write(path, value):
    raw = json.dumps(value, sort_keys=True, allow_nan=False).encode("utf-8")
    path.write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


class BundleTests(unittest.TestCase):
    def make(self, path, *, sufficient=True):
        baseline, candidate = "1"*40, "2"*40
        # Fabricated examples are schema tests, not independent measurements.
        doc = example()
        doc["required_strata"] = [[p,t] for p in ("linux", "windows") for t in ("h2", "h3")]
        doc["rows"] = []
        group = 1000
        for platform, transport in doc["required_strata"]:
            for _ in range(400):
                group += 1
                doc["rows"].append(dict(platform=platform, transport=transport, group=f"{group:064x}",
                    **{"class": "reference"}, variant="reference", score=.1))
            for _ in range(100 if sufficient else 1):
                group += 1
                for variant, score in (("off", .9), ("on", .1)):
                    doc["rows"].append(dict(platform=platform, transport=transport, group=f"{group:064x}",
                        **{"class": "tunnel"}, variant=variant, score=score))
        review_report_sha = write(path / "review-report.json", {"fixture": "synthetic-schema-test"})
        doc["review_report_sha256"] = review_report_sha
        artifacts = {"review-report.json": review_report_sha,
                     "scores.json": write(path / "scores.json", doc)}
        identity = {}
        for i, platform in enumerate(("linux", "windows")):
            perf = fixture()
            perf["platform"] = platform
            perf["mode"] = "comparison"
            perf["revisions"] = dict(baseline=baseline, candidate=candidate)
            perf["binaries_sha256"] = dict(baseline=str(3+i)*64, candidate=str(5+i)*64)
            identity[platform] = perf["binaries_sha256"]
            perf["repetitions"] = 3
            perf["rows"].extend([dict(row, trial=2) for row in perf["rows"] if row["trial"] == 1])
            artifacts[platform + ".json"] = write(path / (platform + ".json"), perf)
        policy = dict(schema=1,
            classifier=dict(schema=1, baseline_revision=baseline, candidate_revision=candidate,
                model_sha256=doc["model_sha256"], calibration_sha256=doc["calibration_sha256"],
                threshold=.5, min_reference_groups_per_stratum=400,
                min_tunnel_pairs_per_stratum=100, max_upper95_fpr=.01, min_absolute_tpr_reduction=.1),
            overhead=dict(schema=1, scope="diagnostic-only", baseline_revision=baseline,
                min_pairs=3, conditions=["clean","relay-delay","udp-loss"], min_throughput_ratio=.8,
                max_latency_p99_delta_ms=10, max_open_p99_delta_ms=50, max_cpu_delta_s=.1,
                max_rss_delta_bytes=16777216, max_carrier_overhead_delta=.1, max_fairness_drop=.05))
        policy_sha = write(path / "policy.json", policy)
        review_sha = write(path / "review-manifest.json", dict(schema=1, policy_sha256=policy_sha,
            baseline_revision=baseline, candidate_revision=candidate, artifacts=artifacts, binary_identity=identity))
        return policy_sha, review_sha, baseline, candidate

    def test_complete_numeric_bundle_does_not_confer_release_acceptance(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            args = self.make(path)
            result = bundle.verify(path, *args)
            self.assertEqual(result["status"], "controlled_numeric_prerequisites_met")
            self.assertEqual(result["acceptance"], "not_evaluated")
            self.assertEqual(set(result["overhead"]), {"linux", "windows"})

    def test_small_samples_and_regression_fail_numeric_prerequisites(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            args = self.make(path, sufficient=False)
            self.assertEqual(bundle.verify(path, *args)["status"], "controlled_numeric_prerequisites_not_met")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            policy_sha, _, baseline, candidate = self.make(path)
            linux = json.loads((path / "linux.json").read_bytes())
            for row in linux["rows"]:
                if row["variant"] == "candidate":
                    row["duration_s"] *= 10
            review = json.loads((path / "review-manifest.json").read_bytes())
            review["artifacts"]["linux.json"] = write(path / "linux.json", linux)
            review_sha = write(path / "review-manifest.json", review)
            self.assertEqual(bundle.verify(path, policy_sha, review_sha, baseline, candidate)["status"],
                             "controlled_numeric_prerequisites_not_met")

    def test_wrong_hash_or_revision_and_tampered_artifact_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            policy_sha, review_sha, baseline, candidate = self.make(path)
            for args in (("0"*64, review_sha, baseline, candidate),
                         (policy_sha, "0"*64, baseline, candidate),
                         (policy_sha, review_sha, "0"*40, candidate)):
                with self.assertRaises(ValueError):
                    bundle.verify(path, *args)
            raw = (path / "windows.json").read_bytes()
            (path / "windows.json").write_bytes(raw + b" ")
            with self.assertRaises(ValueError):
                bundle.verify(path, policy_sha, review_sha, baseline, candidate)

    def test_matching_hashes_do_not_excuse_wrong_baseline_or_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            policy_sha, _, baseline, candidate = self.make(path)
            review = json.loads((path / "review-manifest.json").read_bytes())
            windows = json.loads((path / "windows.json").read_bytes())
            windows["revisions"]["baseline"] = "9"*40
            review["artifacts"]["windows.json"] = write(path / "windows.json", windows)
            review_sha = write(path / "review-manifest.json", review)
            with self.assertRaises(ValueError):
                bundle.verify(path, policy_sha, review_sha, baseline, candidate)
            windows["revisions"]["baseline"] = baseline
            windows["binaries_sha256"]["candidate"] = "9"*64
            review["artifacts"]["windows.json"] = write(path / "windows.json", windows)
            review_sha = write(path / "review-manifest.json", review)
            with self.assertRaises(ValueError):
                bundle.verify(path, policy_sha, review_sha, baseline, candidate)


if __name__ == "__main__":
    unittest.main()
