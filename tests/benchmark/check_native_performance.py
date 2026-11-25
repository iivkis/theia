#!/usr/bin/env python3
"""Fail-closed validation and descriptive summaries of controlled native trials."""
import argparse
import json
import math
import re
import statistics
from pathlib import Path

WORKLOADS = {"interactive": (1, 16, 256), "bulk": (1, 8, 65536), "parallel": (4, 8, 8192)}
CONDITIONS = {"clean", "relay-delay", "udp-loss"}
VARIANTS = {"baseline", "candidate"}
FIELDS = {"schema", "scope", "mode", "platform", "machine", "python", "revisions",
          "binaries_sha256", "accounting", "rss", "conditions", "repetitions", "rows"}
ROW_FIELDS = {"transport", "condition", "workload", "trial", "variant", "application_bytes",
              "duration_s", "cpu_s", "sampled_peak_rss_bytes", "latency_ms", "open_ms",
              "stream_bps", "errors", "fallback", "carrier_bytes", "observed_units",
              "dropped_datagrams", "delayed_units", "forwarded_bytes"}
MAX_DOCUMENT = 8 * 1024 * 1024


def require(ok, message):
    if not ok:
        raise ValueError(message)


def exact_keys(obj, keys):
    require(isinstance(obj, dict) and set(obj) == keys, "unexpected evidence schema")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def load(path):
    with path.open("rb") as source:
        data = source.read(MAX_DOCUMENT + 1)
    require(len(data) <= MAX_DOCUMENT, "evidence exceeds size limit")
    return json.loads(data, object_pairs_hook=unique_object)


def integer(value, minimum=0, maximum=2**53):
    require(type(value) is int and minimum <= value <= maximum, "invalid integer metric")
    return value


def number(value, positive=False):
    require(type(value) in (float, int) and math.isfinite(value) and
            (value > 0 if positive else value >= 0), "invalid numeric metric")
    return float(value)


def digest(value, size):
    return isinstance(value, str) and re.fullmatch("[0-9a-f]{%d}" % size, value) is not None


def vector(value, length):
    require(isinstance(value, list) and len(value) == length, "missing measurement samples")
    return [number(v, True) for v in value]


def percentile(values, p):
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * p) - 1)]


def summarize(document, expected_revision=None, expected_platform=None):
    exact_keys(document, FIELDS)
    require(document["schema"] == 1 and document["scope"] == "controlled-loopback",
            "unsupported measurement scope")
    require(document["platform"] in ("linux", "windows"), "unsupported platform")
    if expected_platform is not None:
        require(document["platform"] == expected_platform.lower(), "incorrect native platform")
    for field in ("machine", "python"):
        require(isinstance(document[field], str) and 0 < len(document[field]) <= 128,
                "missing runner metadata")
    require(document["accounting"] == "carrier-socket-payload-excludes-ip-and-tcp-retransmissions"
            and document["rss"] == "sampled-sum-client-server-10ms",
            "unrecognized measurement boundary")
    revisions, binaries = document["revisions"], document["binaries_sha256"]
    exact_keys(revisions, VARIANTS)
    exact_keys(binaries, VARIANTS)
    require(all(digest(v, 40) for v in revisions.values()) and
            all(digest(v, 64) for v in binaries.values()), "invalid build identity")
    if expected_revision is not None:
        require(revisions["candidate"] == expected_revision, "incorrect tested revision")
    identical = binaries["baseline"] == binaries["candidate"]
    require(document["mode"] == ("smoke" if identical else "comparison"), "invalid run mode")
    require((revisions["baseline"] == revisions["candidate"]) == identical,
            "build identity and revision do not agree")
    conditions = document["conditions"]
    require(isinstance(conditions, list) and all(isinstance(v, str) for v in conditions)
            and len(conditions) == len(set(conditions)) and "clean" in conditions
            and set(conditions) <= CONDITIONS, "invalid conditions")
    reps = integer(document["repetitions"], 2, 30)
    expected = {(t, c, w, i, v) for t in ("h2", "h3") for c in conditions
                if not (t == "h2" and c == "udp-loss") for w in WORKLOADS
                for i in range(reps) for v in VARIANTS}
    rows = document["rows"]
    require(isinstance(rows, list) and len(rows) == len(expected), "incomplete trial matrix")
    observed, grouped = set(), {}
    for row in rows:
        exact_keys(row, ROW_FIELDS)
        key = tuple(row[k] for k in ("transport", "condition", "workload", "trial", "variant"))
        require(type(row["trial"]) is int and key in expected and key not in observed,
                "unexpected or duplicate trial")
        observed.add(key)
        t, c, w, _, variant = key
        streams, count, size = WORKLOADS[w]
        app = integer(row["application_bytes"], 1)
        require(app == 2 * streams * count * size, "workload size changed")
        carrier = integer(row["carrier_bytes"], app)
        forwarded = integer(row["forwarded_bytes"], app, carrier)
        units = integer(row["observed_units"], 1)
        dropped = integer(row["dropped_datagrams"], 0, units)
        delayed = integer(row["delayed_units"], 0, units)
        require((dropped > 0) == (c == "udp-loss") and
                (delayed > 0) == (c == "relay-delay"), "impairment was not exercised")
        require((forwarded < carrier) == (dropped > 0), "inconsistent byte accounting")
        require(dropped == (units // 20 if c == "udp-loss" else 0),
                "incorrect deterministic drop schedule")
        require(delayed == (units if c == "relay-delay" else 0), "incorrect delay count")
        require(integer(row["errors"]) == 0 and integer(row["fallback"]) == 0,
                "failed or fallback trial cannot establish explicit transport performance")
        duration = number(row["duration_s"], True)
        cpu = number(row["cpu_s"])
        rss = integer(row["sampled_peak_rss_bytes"], 1)
        latency = vector(row["latency_ms"], streams * count)
        opened = vector(row["open_ms"], streams)
        rates = vector(row["stream_bps"], streams)
        fairness = (sum(rates) ** 2) / (streams * sum(r * r for r in rates))
        grouped.setdefault((t, c, w, variant), []).append({
            "throughput_bps": app * 8 / duration,
            "cpu_s": cpu, "sampled_peak_rss_bytes": rss,
            "carrier_overhead": (carrier - app) / app, "fairness": fairness,
            "latency_ms": latency, "open_ms": opened})
    require(observed == expected, "incomplete paired matrix")
    summary = []
    for (t, c, w, variant), trials in sorted(grouped.items()):
        samples = {name: [x for trial in trials for x in trial[name]]
                   for name in ("latency_ms", "open_ms")}
        metrics = {name: statistics.median(trial[name] for trial in trials)
                   for name in ("throughput_bps", "cpu_s", "sampled_peak_rss_bytes",
                                "carrier_overhead", "fairness")}
        for name, values in samples.items():
            for p in (50, 95, 99):
                metrics[f"{name}_p{p}"] = percentile(values, p / 100)
        summary.append(dict(transport=t, condition=c, workload=w, variant=variant,
                            trials=len(trials), **metrics))
    return dict(platform=document["platform"], mode=document["mode"], revisions=revisions,
                binaries_sha256=binaries, acceptance="not_evaluated", summary=summary)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--expected-revision")
    parser.add_argument("--expected-platform")
    parser.add_argument("--require-smoke", action="store_true")
    args = parser.parse_args()
    result = summarize(load(args.evidence), args.expected_revision, args.expected_platform)
    if args.require_smoke:
        require(result["mode"] == "smoke", "expected native same-binary smoke")
    print(json.dumps(result, allow_nan=False, indent=2))


if __name__ == "__main__":
    main()
