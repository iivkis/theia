"""Run and verify the native version and default-runtime loopback diagnostic at exact HEAD.

The raw sample matrix is not a release benchmark: no cross-host, RSS,
CPU isolation, loss shaping or approved performance thresholds.
"""
import argparse
import csv
import json
from pathlib import Path
import platform
import statistics
import subprocess


def parse_samples(output):
    header = "backend,stream_up,sample,bytes,open_us,relay_us"
    # Rust's test harness may prefix the first uncaptured line with
    # the test name and ellipsis. Normalize only that exact prefix.
    prefix = "test native_xhttp_version_comparison_samples ... "
    lines = [line.removeprefix(prefix) for line in output.splitlines()]
    if lines.count(header) != 1:
        raise ValueError("missing or duplicate comparison header")
    rows = []
    observed = set()
    for line in lines[lines.index(header) + 1:]:
        if not line.startswith(("native-default,", "native-v1,", "native-v2,")):
            continue
        backend, split, sample, size, opened, relay = next(csv.reader([line]))
        sample, size, opened, relay = map(int, (sample, size, opened, relay))
        key = backend, split, sample
        if key in observed or size != 256 * 1024 or min(opened, relay) <= 0:
            raise ValueError(f"invalid or duplicate sample: {key}")
        observed.add(key)
        rows.append(dict(backend=backend, stream_up=split == "true", sample=sample,
                         bytes=size, open_us=opened, relay_us=relay))
    expected = {(backend, split, sample)
                for backend in ("native-default", "native-v1", "native-v2")
                for split in ("false", "true") for sample in range(5)}
    if observed != expected:
        raise ValueError("incomplete comparison matrix")
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--revision", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--release", action="store_true")
    args = parser.parse_args()
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    if revision != args.revision:
        raise ValueError("wrong tested revision")
    cmd = ["cargo", "test", "--workspace", "--locked"]
    if args.release:
        cmd.append("--release")
    cmd += ["--test", "h3_server", "native_xhttp_version_comparison_samples",
            "--", "--ignored", "--exact", "--nocapture"]
    output = subprocess.run(cmd, check=True, text=True, stdout=subprocess.PIPE,
                            timeout=1200).stdout
    rows = parse_samples(output)
    summary = []
    for backend in ("native-default", "native-v1", "native-v2"):
        for split in (False, True):
            group = [row for row in rows if row["backend"] == backend and row["stream_up"] == split]
            summary.append(dict(backend=backend, stream_up=split, count=len(group),
                                median_open_us=statistics.median(r["open_us"] for r in group),
                                median_relay_us=statistics.median(r["relay_us"] for r in group)))
    result = dict(revision=revision, platform=platform.system(),
                  profile="release" if args.release else "test", diagnostic_only=True,
                  samples=rows, summary=summary)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
