#!/usr/bin/env python3
"""Validate raw data emitted by the mandatory BBR/CUBIC CI experiment.

Checks experimental coverage and actual impairment, never performance winners.
"""
import csv
import math
import statistics
import sys
from collections import defaultdict

if len(sys.argv) != 2:
    raise SystemExit("Usage: check_bbr_comparison.py PATH.csv")

with open(sys.argv[1], encoding="utf-8", newline="") as source:
    rows = list(csv.DictReader(source))

conditions = {
    "baseline": (0, 0, 0),
    "loss_5pct_attempts": (20, 0, 0),
    "delay_jitter": (0, 8, 8),
    "loss_delay_jitter": (20, 8, 8),
}
expected = {(cc, name, repetition) for cc in ("bbr", "cubic")
            for name in conditions for repetition in (0, 1)}
observed = {(row["controller"], row["condition"], int(row["repetition"]))
            for row in rows}
if len(rows) != len(expected) or observed != expected:
    raise SystemExit(f"Missing or duplicated comparison trials: {len(rows)} rows, "
                     f"missing={sorted(expected - observed)}, unexpected={sorted(observed - expected)}")

samples = defaultdict(list)
for row in rows:
    name = row["condition"]
    drop_every, delay_ms, jitter_ms = conditions[name]
    numeric = ("payload_bytes", "drop_every", "delay_ms", "jitter_ms",
               "attempted_datagrams", "injected_drops", "delayed_datagrams",
               "sent_packets", "lost_packets", "congestion_events", "rtt_us")
    values = {key: int(row[key]) for key in numeric}
    if (values["payload_bytes"] != 512 * 1024
            or values["drop_every"] != drop_every
            or values["delay_ms"] != delay_ms
            or values["jitter_ms"] != jitter_ms
            or values["sent_packets"] < 1
            or values["attempted_datagrams"] < values["injected_drops"]
            or bool(values["injected_drops"]) != bool(drop_every)
            or bool(values["delayed_datagrams"]) != bool(delay_ms)):
        raise SystemExit(f"Failed impairment/byte-integrity evidence: {row}")
    rate = float(row["throughput_mbps"])
    if not math.isfinite(rate) or rate <= 0:
        raise SystemExit(f"Invalid measured throughput: {row}")
    samples[name, row["controller"]].append(rate)

print("CI exploratory QUIC comparison, Mbps (medians of 2 non-independent trials):")
for name in conditions:
    bbr = statistics.median(samples[name, "bbr"])
    cubic = statistics.median(samples[name, "cubic"])
    print(f"  {name:20} BBR={bbr:.3f} CUBIC={cubic:.3f}")
print("Experiment integrity PASS; no relative performance ranking or release acceptance implied.")
