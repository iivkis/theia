#!/usr/bin/env python3
"""Join externally reviewed classifier scores with exact-revision overhead.

The expected policy and review-manifest hashes must be authenticated outside
this program. The bundle holds only pre-scored pseudonymous groups and bounded
aggregate measurements; it never consumes raw traffic or fits a classifier.
Controlled loopback debug measurements are not release-profile wire evidence.
"""
import argparse
import hashlib
import json
from pathlib import Path

import check_classifier_evidence as classifier
import check_native_performance as performance

FILES = {
    "scores.json": classifier.MAX_DOCUMENT,
    "linux.json": performance.MAX_DOCUMENT,
    "windows.json": performance.MAX_DOCUMENT,
    "review-report.json": 1024 * 1024,
    "policy.json": 65536,
    "review-manifest.json": 65536,
}
REVIEW_FIELDS = {"schema", "policy_sha256", "baseline_revision", "candidate_revision",
                 "artifacts", "binary_identity"}
POLICY_FIELDS = {"schema", "classifier", "overhead"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read(path, limit):
    require(path.is_file() and not path.is_symlink(), "missing regular bundle file")
    with path.open("rb") as f:
        data = f.read(limit + 1)
    require(len(data) <= limit, "bundle file exceeds size limit")
    return data, hashlib.sha256(data).hexdigest()


def reject_constant(_):
    raise ValueError("non-finite JSON constant")


def parse(raw):
    return json.loads(raw, object_pairs_hook=classifier.object_pairs,
                      parse_constant=reject_constant)


def verify(directory, trusted_policy_sha256, trusted_review_sha256,
           expected_baseline, expected_candidate):
    require(classifier.digest(trusted_policy_sha256) and classifier.digest(trusted_review_sha256),
            "independently authenticated policy and review manifest digests required")
    require(performance.digest(expected_baseline, 40) and performance.digest(expected_candidate, 40)
            and expected_baseline != expected_candidate, "distinct exact off/on revisions required")
    require(directory.is_dir() and not directory.is_symlink(), "invalid bundle root")
    require({p.name for p in directory.iterdir()} == set(FILES), "unexpected or missing bundle files")
    raw = {name: read(directory / name, limit) for name, limit in FILES.items()}
    require(raw["policy.json"][1] == trusted_policy_sha256, "frozen policy digest mismatch")
    require(raw["review-manifest.json"][1] == trusted_review_sha256, "review manifest digest mismatch")
    policy = parse(raw["policy.json"][0])
    review = parse(raw["review-manifest.json"][0])
    require(isinstance(policy, dict) and set(policy) == POLICY_FIELDS
            and type(policy["schema"]) is int and policy["schema"] == 1, "incorrect policy envelope")
    require(isinstance(review, dict) and set(review) == REVIEW_FIELDS
            and type(review["schema"]) is int and review["schema"] == 1, "incorrect review manifest")
    require(review["policy_sha256"] == trusted_policy_sha256 and
            review["baseline_revision"] == expected_baseline and
            review["candidate_revision"] == expected_candidate, "review identity mismatch")
    expected_artifacts = {"scores.json", "linux.json", "windows.json", "review-report.json"}
    require(isinstance(review["artifacts"], dict) and set(review["artifacts"]) == expected_artifacts
            and all(review["artifacts"][name] == raw[name][1] for name in expected_artifacts),
            "reviewed artifact digest mismatch")
    require(isinstance(review["binary_identity"], dict) and
            set(review["binary_identity"]) == {"linux", "windows"}, "missing reviewed binary identity")
    score_doc = parse(raw["scores.json"][0])
    report = classifier.report(score_doc, expected_candidate=expected_candidate,
                               expected_baseline=expected_baseline, full_matrix=True)
    require(report["review_report_sha256"] == raw["review-report.json"][1],
            "classifier review report digest mismatch")
    numeric = classifier.evaluate_predeclared_policy(report, policy["classifier"])
    comparisons = {}
    for name in ("linux", "windows"):
        measured = performance.summarize(parse(raw[name + ".json"][0]),
                                         expected_candidate, name)
        require(measured["mode"] == "comparison" and
                measured["revisions"]["baseline"] == expected_baseline,
                "overhead does not compare the same off/on revisions")
        require(review["binary_identity"][name] == measured["binaries_sha256"],
                "reviewed overhead binary identity mismatch")
        comparisons[name] = performance.compare(measured, policy["overhead"])
    within = (numeric["status"] == "numeric_prerequisites_met" and all(
        v["status"] == "within_diagnostic_guardrails" for v in comparisons.values()))
    return dict(schema=1, baseline_revision=expected_baseline, candidate_revision=expected_candidate,
                policy_sha256=trusted_policy_sha256, review_manifest_sha256=trusted_review_sha256,
                status="controlled_numeric_prerequisites_met" if within
                       else "controlled_numeric_prerequisites_not_met",
                classifier=numeric, overhead=comparisons, acceptance="not_evaluated",
                independence="external_review_required",
                limitations=["authentication of supplied digests is outside the program",
                             "controlled carrier socket byte accounting is not full wire accounting",
                             "sampled RSS is not exact peak RSS",
                             "release profile and physical-network measurement not established"])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    parser.add_argument("--trusted-policy-sha256", required=True)
    parser.add_argument("--trusted-review-manifest-sha256", required=True)
    parser.add_argument("--expected-baseline", required=True)
    parser.add_argument("--expected-candidate", required=True)
    args = parser.parse_args()
    result = verify(args.directory, args.trusted_policy_sha256,
                    args.trusted_review_manifest_sha256,
                    args.expected_baseline, args.expected_candidate)
    print(json.dumps(result, indent=2, allow_nan=False))
    if result["status"] != "controlled_numeric_prerequisites_met":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
