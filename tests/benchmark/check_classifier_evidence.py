#!/usr/bin/env python3
"""Describe independent pre-scored holdout evidence, never train or tune a model.

The evaluator accepts only aggregate scores and pseudonymous group identifiers.
No packet captures, payload, target names, keys or credentials are inputs.
The frozen threshold and provenance are supplied by the independent reviewer.
A valid report does not itself establish the truth of those provenance claims,
or confer release acceptance.
"""
import argparse
import json
import math
import re
from pathlib import Path

MAX_DOCUMENT = 16 * 1024 * 1024
MAX_GROUPS = 100_000
Z95 = 1.959963984540054
Z_BONFERRONI = 2.241402727604947
FIELDS = {"schema", "model_sha256", "calibration_sha256", "threshold",
          "baseline_revision", "candidate_revision", "corpus_sha256", "review_report_sha256",
          "excluded_groups", "required_strata", "rows"}
ROW_FIELDS = {"platform", "transport", "group", "class", "variant", "score"}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def object_pairs(pairs):
    out = {}
    for k, v in pairs:
        require(k not in out, "duplicate JSON key")
        out[k] = v
    return out


def digest(value):
    return isinstance(value, str) and re.fullmatch("[0-9a-f]{64}", value) is not None


def score(value):
    require(type(value) in (int, float) and math.isfinite(value) and 0 <= value <= 1,
            "invalid classifier score")
    return float(value)


def wilson(k, n, z=Z95):
    require(n > 0 and 0 <= k <= n, "missing independent groups")
    p = k / n
    d = 1 + z**2 / n
    mid = (p + z**2 / (2*n)) / d
    radius = z * math.sqrt(p * (1-p)/n + z**2/(4*n*n)) / d
    return dict(positive=k, total=n, rate=p, lower95=max(0., mid-radius),
                upper95=min(1., mid+radius))


def report(doc, *, expected_candidate=None, expected_baseline=None, full_matrix=False):
    require(isinstance(doc, dict) and set(doc) == FIELDS and type(doc["schema"]) is int
            and doc["schema"] == 1, "invalid evidence schema")
    require(digest(doc["model_sha256"]) and digest(doc["calibration_sha256"])
            and doc["model_sha256"] != doc["calibration_sha256"], "missing frozen model/calibration identity")
    for name in ("baseline_revision", "candidate_revision"):
        require(isinstance(doc[name], str) and re.fullmatch("[0-9a-f]{40}", doc[name]) is not None,
                "invalid source revision")
    require(doc["baseline_revision"] != doc["candidate_revision"], "off/on revisions must differ")
    require(digest(doc["corpus_sha256"]) and digest(doc["review_report_sha256"]),
            "missing independent corpus/review document identity")
    if expected_candidate is not None:
        require(doc["candidate_revision"] == expected_candidate, "wrong tested candidate revision")
    if expected_baseline is not None:
        require(doc["baseline_revision"] == expected_baseline, "wrong baseline revision")
    threshold = score(doc["threshold"])
    require(0 < threshold < 1, "threshold must be frozen inside score range")
    excluded = doc["excluded_groups"]
    require(isinstance(excluded, list) and 0 < len(excluded) <= MAX_GROUPS
            and all(digest(g) for g in excluded) and len(set(excluded)) == len(excluded),
            "missing or duplicate training/calibration group identity")
    excluded = set(excluded)
    required = doc["required_strata"]
    require(isinstance(required, list) and required and len(required) <= 4
            and all(isinstance(r, list) and len(r) == 2 and r[0] in ("linux","windows")
                    and r[1] in ("h2","h3") for r in required), "invalid strata")
    strata = {tuple(r) for r in required}
    require(len(strata) == len(required), "duplicate strata")
    if full_matrix:
        require(strata == {(p,t) for p in ("linux","windows") for t in ("h2","h3")}, "missing required OS/carrier stratum")
    rows = doc["rows"]
    require(isinstance(rows, list) and 0 < len(rows) <= MAX_GROUPS * 2, "invalid holdout size")
    groups = {}
    for row in rows:
        require(isinstance(row, dict) and set(row) == ROW_FIELDS, "invalid score row")
        stratum = (row["platform"], row["transport"])
        require(stratum in strata and digest(row["group"]) and row["group"] not in excluded,
                "unexpected stratum or training/calibration leakage")
        label, variant = row["class"], row["variant"]
        require((label == "reference" and variant == "reference") or
                (label == "tunnel" and variant in ("off","on")), "invalid class/variant")
        group = groups.setdefault(row["group"], (stratum, label, {}))
        require(group[:2] == (stratum, label) and variant not in group[2],
                "reused group or duplicate score")
        group[2][variant] = score(row["score"]) >= threshold
    buckets = {stratum: {"reference": [], "off": [], "on": []} for stratum in strata}
    paired = {stratum: {"off_only": 0, "on_only": 0, "both": 0, "neither": 0} for stratum in strata}
    for stratum, label, variants in groups.values():
        require(set(variants) == ({"reference"} if label == "reference" else {"off","on"}),
                "missing paired tunnel variants")
        if label == "tunnel":
            off, on = variants["off"], variants["on"]
            outcome = "both" if off and on else "off_only" if off else "on_only" if on else "neither"
            paired[stratum][outcome] += 1
        for variant, decision in variants.items():
            buckets[stratum][variant].append(decision)
    results = []
    for stratum, bucket in sorted(buckets.items()):
        rates = {name: wilson(sum(values), len(values)) for name, values in bucket.items()}
        # Paired difference is P(on-only) - P(off-only). Bonferroni
        # simultaneous Wilson intervals give a conservative approximate 95%
        # interval without treating the off/on scores as independent.
        n = len(bucket["off"])
        gained = wilson(paired[stratum]["on_only"], n, Z_BONFERRONI)
        lost = wilson(paired[stratum]["off_only"], n, Z_BONFERRONI)
        delta_interval = [max(-1., gained["lower95"] - lost["upper95"]),
                          min(1., gained["upper95"] - lost["lower95"])]
        results.append(dict(platform=stratum[0], transport=stratum[1],
                            false_positive=rates["reference"], true_positive_off=rates["off"],
                            true_positive_on=rates["on"],
                            fpr_upper_within_one_percent=rates["reference"]["upper95"] <= .01,
                            paired_outcomes=paired[stratum],
                            delta_tpr=rates["on"]["rate"]-rates["off"]["rate"],
                            paired_delta_tpr_interval95_approx=delta_interval))
    return dict(model_sha256=doc["model_sha256"], calibration_sha256=doc["calibration_sha256"],
                baseline_revision=doc["baseline_revision"], candidate_revision=doc["candidate_revision"],
                corpus_sha256=doc["corpus_sha256"], review_report_sha256=doc["review_report_sha256"],
                frozen_threshold=threshold, acceptance="not_evaluated",
                independence="requires_external_review", strata=results)


POLICY_FIELDS = {"schema", "baseline_revision", "candidate_revision", "model_sha256",
                 "calibration_sha256", "threshold", "min_reference_groups_per_stratum",
                 "min_tunnel_pairs_per_stratum", "max_upper95_fpr",
                 "min_absolute_tpr_reduction"}


def evaluate_predeclared_policy(result, policy):
    """Evaluate numerical prerequisites only, never attest independent provenance.

    The caller must authenticate the frozen policy digest through a separate
    trusted channel before collecting scores. No default release thresholds.
    """
    require(isinstance(policy, dict) and set(policy) == POLICY_FIELDS
            and type(policy["schema"]) is int and policy["schema"] == 1, "invalid predeclared policy")
    for key in ("baseline_revision", "candidate_revision", "model_sha256", "calibration_sha256"):
        require(policy[key] == result[key], "policy/evidence identity mismatch")
    require(score(policy["threshold"]) == result["frozen_threshold"], "policy threshold mismatch")
    for name in ("min_reference_groups_per_stratum", "min_tunnel_pairs_per_stratum"):
        require(type(policy[name]) is int and 1 <= policy[name] <= MAX_GROUPS, "invalid sample floor")
    max_fpr = score(policy["max_upper95_fpr"])
    reduction = score(policy["min_absolute_tpr_reduction"])
    require(0 < max_fpr <= .01 and 0 < reduction <= 1, "invalid acceptance thresholds")
    require({(r["platform"], r["transport"]) for r in result["strata"]} ==
            {(p,t) for p in ("linux","windows") for t in ("h2","h3")}, "full matrix required")
    checks = []
    for row in result["strata"]:
        failures = []
        if row["false_positive"]["total"] < policy["min_reference_groups_per_stratum"]:
            failures.append("insufficient_reference_groups")
        if row["true_positive_off"]["total"] < policy["min_tunnel_pairs_per_stratum"]:
            failures.append("insufficient_tunnel_pairs")
        if row["false_positive"]["upper95"] > max_fpr:
            failures.append("fpr_confidence_bound")
        if row["paired_delta_tpr_interval95_approx"][1] > -reduction:
            failures.append("paired_improvement_confidence_bound")
        checks.append(dict(platform=row["platform"], transport=row["transport"], failures=failures))
    return dict(status="numeric_prerequisites_not_met" if any(c["failures"] for c in checks)
                else "numeric_prerequisites_met",
                acceptance="not_evaluated", independence="requires_external_review",
                overhead="requires_separate_exact_revision_measurements", strata=checks)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("evidence", type=Path)
    p.add_argument("--expected-candidate")
    p.add_argument("--expected-baseline")
    p.add_argument("--full-matrix", action="store_true")
    p.add_argument("--policy", type=Path)
    p.add_argument("--trusted-policy-sha256")
    args = p.parse_args()
    with args.evidence.open("rb") as f:
        raw = f.read(MAX_DOCUMENT + 1)
    require(len(raw) <= MAX_DOCUMENT, "evidence size limit")
    result = report(json.loads(raw, object_pairs_hook=object_pairs),
                    expected_candidate=args.expected_candidate, expected_baseline=args.expected_baseline,
                    full_matrix=args.full_matrix)
    if args.policy is not None or args.trusted_policy_sha256 is not None:
        import hashlib
        require(args.policy is not None and digest(args.trusted_policy_sha256),
                "explicit independently obtained frozen policy digest required")
        with args.policy.open("rb") as f:
            policy_raw = f.read(65537)
        require(len(policy_raw) <= 65536 and hashlib.sha256(policy_raw).hexdigest() == args.trusted_policy_sha256,
                "untrusted policy bytes")
        result["numeric_policy"] = evaluate_predeclared_policy(
            result, json.loads(policy_raw, object_pairs_hook=object_pairs))
    print(json.dumps(result, allow_nan=False, indent=2))


if __name__ == "__main__":
    main()
