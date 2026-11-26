#!/usr/bin/env python3
"""Compare matched two-host JSON reports (standalone or simultaneous).

For competition, start two separately pinned benchmark servers on the
same bottleneck and run the two client commands concurrently on one host.
Use different ports, the same payload/count/revision/network label and
a sufficiently long workload. This script reports completed-work goodput
(includes gaps between requests), not saturated single-flow fairness.
No acceptance thresholds are inferred.
"""
import argparse
import json
from pathlib import Path


def load(path):
    report = json.loads(path.read_text(encoding="utf-8"))
    if report["role"] != "client" or report["profile"] != "release":
        raise ValueError("requires release client report")
    if len(report["samples"]) != report["expected_samples"]:
        raise ValueError("incomplete sample matrix")
    return report


def compare(a, b, competition):
    for key in ("revision", "binary_sha256", "platform", "cpu", "network_label", "bytes", "expected_samples"):
        if a[key] != b[key]:
            raise ValueError(f"unmatched benchmark: {key}")
    result = {"revision": a["revision"], "network_label": a["network_label"],
              "backends": [a["backend"], b["backend"]], "diagnostic_only": True}
    if not competition:
        result["relative_to_first"] = {
            key: {p: b["summary"][key][p] / a["summary"][key][p]
                  for p in ("p50", "p95", "p99")}
            for key in ("handshake_us", "open_us", "relay_us", "duplex_mbps")
        }
        return result

    # Wall timestamps are comparable only on the same client host. Reject
    # clock discontinuities by comparing each wall duration to the monotonic
    # measured relay duration, with 10ms or 2% tolerance.
    for report in (a, b):
        previous = 0
        for row in sorted(report["samples"], key=lambda row: row["sample"]):
            start, end = row["wall_start_ns"], row["wall_end_ns"]
            elapsed = row["relay_us"] * 1000
            if start < previous or end <= start or abs(end - start - elapsed) > max(10_000_000, elapsed // 50):
                raise ValueError("non-monotone or inconsistent wall timestamps")
            previous = end
    begin = max(min(row["wall_start_ns"] for row in r["samples"]) for r in (a, b))
    end = min(max(row["wall_end_ns"] for row in r["samples"]) for r in (a, b))
    if end <= begin:
        raise ValueError("no concurrent measurement interval")
    completed = [[row for row in report["samples"]
                  if row["wall_start_ns"] >= begin and row["wall_end_ns"] <= end]
                 for report in (a, b)]
    result["overlap_seconds"] = (end - begin) / 1e9
    result["complete_samples"] = [len(rows) for rows in completed]
    if min(map(len, completed)) < 3:
        result["status"] = "insufficient_overlap"
        return result
    rates = [16 * sum(row["bytes"] for row in rows) / ((end - begin) / 1000)
             for rows in completed]
    result.update(status="measured_diagnostic", duplex_goodput_mbps=rates,
                  jain_index=sum(rates)**2 / (2 * sum(rate*rate for rate in rates)))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--first", type=Path, required=True)
    parser.add_argument("--second", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--competition", action="store_true")
    args = parser.parse_args()
    result = compare(load(args.first), load(args.second), args.competition)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
