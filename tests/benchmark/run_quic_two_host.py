#!/usr/bin/env python3
"""Run the explicitly provisioned release-profile benchmark on one node.

Build first: cargo test -p theia --locked --release --test native_quic_network --no-run
Pass the resulting test executable to this script. Run one server and one
client for each backend. No automatic network setup, root privileges, or
acceptance claim. CPU/RSS are process evidence on Unix only.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import subprocess
import time

def percentile(values, p):
    values = sorted(values)
    return values[max(0, math.ceil(len(values) * p) - 1)]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--role", choices=("server", "client"), required=True)
    parser.add_argument("--backend", choices=("quinn", "native-v1", "native-v2"), required=True)
    parser.add_argument("--bind", required=True)
    parser.add_argument("--peer", required=True)
    parser.add_argument("--samples", type=int, default=30)
    parser.add_argument("--bytes", type=int, default=262144)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--network-label", required=True)
    args = parser.parse_args()
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    if revision != args.revision:
        raise ValueError("wrong revision")
    if subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=no"], text=True).strip():
        raise ValueError("tracked working tree is not clean")
    if not 1 <= args.samples <= 100 or not 1 <= args.bytes <= 8 * 1024 * 1024:
        raise ValueError("invalid bounded workload")
    env = dict(os.environ, THEIA_BENCH_BACKEND=args.backend, THEIA_BENCH_ROLE=args.role,
               THEIA_BENCH_BIND=args.bind, THEIA_BENCH_PEER=args.peer,
               THEIA_BENCH_SAMPLES=str(args.samples), THEIA_BENCH_BYTES=str(args.bytes))
    binary = args.binary.resolve(strict=True)
    sha = hashlib.sha256(binary.read_bytes()).hexdigest()
    start = time.monotonic()
    with subprocess.Popen([str(binary), "native_quic_two_host_release", "--ignored", "--exact", "--nocapture"],
                          env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True) as proc:
        # The Rust harness has its own absolute deadline.
        lines = []
        for line in proc.stdout:
            print(line, end="", flush=True)
            lines.append(line)
        if proc.wait() != 0:
            raise RuntimeError("benchmark executable failed")
    metrics = {}
    if os.name == "posix":
        import resource
        usage = resource.getrusage(resource.RUSAGE_CHILDREN)
        # This process ran git and the test, not the compiler; git CPU time
        # and child maxrss can still affect small samples.
        metrics = {"child_user_s": usage.ru_utime, "child_system_s": usage.ru_stime,
                   "child_maxrss_bytes": usage.ru_maxrss * (1 if platform.system() == "Darwin" else 1024)}
    rows = []
    for line in lines:
        if not line.startswith("BENCH_SAMPLE,"):
            continue
        _, backend, sample, size, handshake, opened, relay = line.strip().split(",")
        if backend != args.backend or int(size) != args.bytes:
            raise ValueError("unexpected workload")
        rows.append(dict(sample=int(sample), bytes=int(size), handshake_us=int(handshake),
                         open_us=int(opened), relay_us=int(relay),
                         duplex_mbps=16 * int(size) / int(relay)))
    if args.role == "client" and (len(rows) != args.samples or {r["sample"] for r in rows} != set(range(args.samples))):
        raise ValueError("incomplete or duplicate sample matrix")
    if args.role == "server" and f"BENCH_COMPLETE,{args.samples}" not in "".join(lines):
        raise ValueError("server did not complete expected sample count")
    summary = {k: {f"p{int(p*100)}": percentile([r[k] for r in rows], p)
                   for p in (0.50, 0.95, 0.99)}
               for k in ("handshake_us", "open_us", "relay_us", "duplex_mbps")} if rows else {}
    result = dict(revision=revision, binary_sha256=sha, profile="release",
                  platform=platform.platform(), cpu=platform.processor(), role=args.role,
                  backend=args.backend, network_label=args.network_label,
                  bytes=args.bytes, expected_samples=args.samples,
                  elapsed_s=time.monotonic() - start, samples=rows, summary=summary,
                  process_metrics=metrics, diagnostic_only=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")

if __name__ == "__main__":
    main()
