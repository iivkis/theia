#!/usr/bin/env python3
"""Run fresh loopback-only browser and native test sessions, bound to tested SHA."""
import argparse
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import subprocess

from check_f13_observations import CHROMIUM, FILES, PLAYWRIGHT, compare, read_json, require

CASES = [
    ("h2_wire_fingerprint", "real_default_h2_settings_and_pseudo_headers_are_measured", False),
    ("f18_h3_first_flight", "actual_native_h3_client_initial_reference", False),
    ("chromium_h2_reference", "actual_chromium_h2_settings_and_pseudo_order_reference", True),
    ("f18_h3_first_flight", "actual_chromium_h3_initial_reference", True),
]


def run(directory, revision, samples):
    root = Path(__file__).resolve().parents[2]
    actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    require(actual == revision, "wrong tested checkout")
    require(3 <= samples <= 10, "bounded fresh session count")
    os_name = platform.system().lower()
    require(os_name in ("linux", "windows"), "unsupported native platform")
    require(importlib.metadata.version("playwright") == PLAYWRIGHT, "wrong Playwright version")
    directory = directory.resolve()
    directory.mkdir()
    manifest = dict(schema=1, revision=revision, platform=os_name,
                    playwright=PLAYWRIGHT, chromium=CHROMIUM, samples=[])
    for index in range(samples):
        base = directory / ("sample-%02d" % index)
        base.mkdir()
        env = dict(os.environ, THEIA_F13_EVIDENCE_DIR=str(base))
        for target, case, ignored in CASES:
            command = ["cargo", "test", "--workspace", "--locked", "--test", target,
                       case, "--", "--exact", "--nocapture"]
            if ignored:
                command.append("--ignored")
            subprocess.run(command, cwd=root, env=env, check=True, timeout=240)
        compare(base)
        manifest["samples"].append(dict(directory=base.name,
            sha256={name: read_json(base / name, 16384)[1] for name in sorted(FILES)}))
    with (directory / "manifest.json").open("x", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, allow_nan=False)
        f.write("\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--samples", type=int, default=3)
    args = parser.parse_args()
    run(args.directory, args.revision, args.samples)
