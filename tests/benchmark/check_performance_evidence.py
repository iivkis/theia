#!/usr/bin/env python3
"""Validate paired controlled performance trials, never infer camouflage efficacy.

Inputs are aggregate measurements from a controlled harness, not user traffic.
No threshold is supplied implicitly: acceptance requires an explicit reviewed
policy document. No absolute claim follows from a synthetic fixture.
"""
import argparse
import csv
import json
import math
import re
import statistics
from pathlib import Path

FIELDS = (
    "platform", "transport", "workload", "trial", "variant", "duration_s",
    "application_bytes", "wire_bytes", "latency_ms", "cpu_s", "peak_rss_bytes",
)
METRICS = ("throughput_bps", "latency_ms", "cpu_s", "peak_rss_bytes", "wire_overhead")
NAME = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
MAX_ROWS = 100_000


def number(raw, *, positive=False):
    value = float(raw)
    if not math.isfinite(value) or value < 0 or (positive and value == 0):
        raise ValueError("non-finite or out-of-range measurement")
    return value


def aggregate(rows):
    trials = {}
    for i, row in enumerate(rows):
        if i >= MAX_ROWS or set(row) != set(FIELDS):
            raise ValueError("invalid evidence columns or row limit")
        platform, transport, workload, trial, variant = (row[k] for k in FIELDS[:5])
        if platform not in ("linux", "windows") or transport not in ("h2", "h3"):
            raise ValueError("invalid platform or transport")
        if not NAME.fullmatch(workload) or not NAME.fullmatch(trial) or variant not in ("baseline", "candidate"):
            raise ValueError("invalid trial key")
        key = (platform, transport, workload, trial, variant)
        if key in trials:
            raise ValueError("duplicate trial")
        duration = number(row["duration_s"], positive=True)
        app = int(row["application_bytes"])
        wire = int(row["wire_bytes"])
        if app <= 0 or wire < app:
            raise ValueError("invalid byte accounting")
        trials[key] = (
            app, {
                "throughput_bps": number(app * 8 / duration, positive=True),
                "latency_ms": number(row["latency_ms"], positive=True),
                "cpu_s": number(row["cpu_s"]),
                "peak_rss_bytes": number(row["peak_rss_bytes"], positive=True),
                "wire_overhead": number((wire - app) / app),
            }
        )
    if not trials:
        raise ValueError("missing evidence")
    groups = {}
    for key, (app, values) in trials.items():
        if key[-1] != "baseline":
            if (*key[:-1], "baseline") not in trials:
                raise ValueError("candidate without paired baseline")
            continue
        candidate = trials.get((*key[:-1], "candidate"))
        if candidate is None or candidate[0] != app:
            raise ValueError("missing or mismatched paired workload")
        groups.setdefault(key[:3], []).append((values, candidate[1]))
    return groups


def summarize(groups):
    return [
        {
            "platform": key[0], "transport": key[1], "workload": key[2],
            "pairs": len(pairs),
            "baseline": {m: statistics.median(a[m] for a, _ in pairs) for m in METRICS},
            "candidate": {m: statistics.median(b[m] for _, b in pairs) for m in METRICS},
        }
        for key, pairs in sorted(groups.items())
    ]


def evaluate(summary, policy):
    if set(policy) != {"min_pairs", "required_groups", "max_candidate_latency_ms",
                      "min_candidate_throughput_bps", "max_candidate_cpu_s",
                      "max_candidate_peak_rss_bytes", "max_candidate_wire_overhead"}:
        raise ValueError("explicit reviewed policy required")
    minimum = policy["min_pairs"]
    if type(minimum) is not int or minimum < 2:
        raise ValueError("at least two paired trials required")
    required = policy["required_groups"]
    if not isinstance(required, list) or not required:
        raise ValueError("explicit workload matrix required")
    keys = {(r["platform"], r["transport"], r["workload"]) for r in summary}
    if {tuple(r) for r in required} != keys or len(required) != len(keys):
        raise ValueError("incomplete or unexpected workload matrix")
    limits = {
        "latency_ms": number(policy["max_candidate_latency_ms"], positive=True),
        "cpu_s": number(policy["max_candidate_cpu_s"], positive=True),
        "peak_rss_bytes": number(policy["max_candidate_peak_rss_bytes"], positive=True),
        "wire_overhead": number(policy["max_candidate_wire_overhead"]),
    }
    throughput = number(policy["min_candidate_throughput_bps"], positive=True)
    return all(
        row["pairs"] >= minimum
        and row["candidate"]["throughput_bps"] >= throughput
        and all(row["candidate"][k] <= v for k, v in limits.items())
        for row in summary
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--policy", type=Path)
    args = parser.parse_args()
    with args.evidence.open(encoding="utf-8", newline="") as source:
        reader = csv.DictReader(source)
        if tuple(reader.fieldnames or ()) != FIELDS:
            raise SystemExit("unexpected evidence columns")
        summary = summarize(aggregate(reader))
    result = {"summary": summary, "acceptance": "not_evaluated"}
    if args.policy is not None:
        with args.policy.open(encoding="utf-8") as source:
            accepted = evaluate(summary, json.load(source))
        result["acceptance"] = "pass" if accepted else "fail"
    print(json.dumps(result, indent=2, allow_nan=False))
    if result["acceptance"] == "fail":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
