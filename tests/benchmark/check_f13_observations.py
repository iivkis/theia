#!/usr/bin/env python3
"""Report actual controlled browser/native measurements, not a parity claim."""
import argparse
import hashlib
import json
from pathlib import Path
import re

SCHEMAS = {
    "h2-tls": {"legacy_version", "cipher_count", "extension_count", "group_count",
               "grease", "alps", "sni_present", "tls13", "alpn_h2"},
    "h2-http": {"settings", "frames_before_headers", "connection_window_updates",
                "pseudo_headers", "ordinary_fields", "request_end_stream"},
    "h3-initial": {"version", "destination_cid_len", "source_cid_len", "token_len",
                   "packet_len", "datagram_len"},
    "h3-session": {"alpn_h3", "sni_present", "ordinary_fields"},
}
PLAYWRIGHT = "1.65.2"
CHROMIUM = "159.0.8154.6"
FILES = {variant + "-" + schema + ".json" for variant in ("native", "browser") for schema in SCHEMAS}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def integer(v, lo, hi):
    return type(v) is int and lo <= v <= hi


def unique(pairs):
    result = {}
    for k, v in pairs:
        require(k not in result, "duplicate observation key")
        result[k] = v
    return result


def reject_constant(_):
    raise ValueError("non-finite JSON number")


def read_json(path, limit):
    require(path.is_file() and not path.is_symlink(), "expected regular evidence file")
    with path.open("rb") as source:
        raw = source.read(limit + 1)
    require(len(raw) <= limit, "oversized observation")
    return json.loads(raw, object_pairs_hook=unique, parse_constant=reject_constant), hashlib.sha256(raw).hexdigest()


def load(path, schema):
    doc, _ = read_json(path, 16384)
    require(isinstance(doc, dict) and set(doc) == SCHEMAS[schema], "incorrect observation schema")
    return doc


def vector(values, lo, hi, limit):
    return isinstance(values, list) and len(values) <= limit and all(integer(v, lo, hi) for v in values)


def validate(observation, schema):
    if schema == "h2-tls":
        require(observation["tls13"] is True and observation["alpn_h2"] is True
                and integer(observation["legacy_version"], 771, 771), "unexpected TLS reference")
        require(all(integer(observation[key], 1, 65536) for key in
                    ("cipher_count", "extension_count", "group_count")), "invalid ClientHello dimensions")
        require(all(type(observation[key]) is bool for key in ("grease", "alps", "sni_present")),
                "invalid TLS flag")
    elif schema == "h2-http":
        pseudo = observation["pseudo_headers"]
        require(isinstance(pseudo, list) and len(pseudo) == 4 and all(type(x) is str for x in pseudo)
                and set(pseudo) == {":method", ":scheme", ":authority", ":path"}, "invalid pseudo fields")
        settings = observation["settings"]
        require(isinstance(settings, list) and 0 < len(settings) <= 128
                and all(isinstance(x, list) and len(x) == 2 and integer(x[0], 0, 65535)
                        and integer(x[1], 0, 2**32-1) for x in settings), "invalid H2 settings")
        require(len({x[0] for x in settings}) == len(settings), "duplicate settings")
        require(vector(observation["frames_before_headers"], 0, 255, 1024)
                and vector(observation["connection_window_updates"], 1, 2**31-1, 1024)
                and integer(observation["ordinary_fields"], 0, 65536)
                and type(observation["request_end_stream"]) is bool, "invalid H2 frame observation")
    elif schema == "h3-initial":
        require(integer(observation["version"], 1, 1)
                and integer(observation["destination_cid_len"], 0, 20)
                and integer(observation["source_cid_len"], 0, 20)
                and integer(observation["datagram_len"], 1200, 65536)
                and integer(observation["packet_len"], 1, observation["datagram_len"])
                and integer(observation["token_len"], 0, observation["packet_len"]), "invalid visible QUIC Initial")
    else:
        require(observation["alpn_h3"] is True and type(observation["sni_present"]) is bool
                and integer(observation["ordinary_fields"], 0, 65536), "invalid negotiated H3 session")


def compare(directory):
    require({p.name for p in directory.iterdir()} == FILES, "incomplete or unexpected observation inventory")
    pairs = []
    for schema in SCHEMAS:
        native = load(directory / ("native-" + schema + ".json"), schema)
        browser = load(directory / ("browser-" + schema + ".json"), schema)
        for observation in (native, browser):
            validate(observation, schema)
        pairs.append(dict(observation=schema, native=native, browser=browser,
                          differing_fields=[k for k in sorted(native) if native[k] != browser[k]]))
    return dict(acceptance="not_evaluated", full_parity="not_established", pairs=pairs)


def compare_run(directory, expected_revision, expected_platform):
    manifest, manifest_sha = read_json(directory / "manifest.json", 65536)
    require(isinstance(manifest, dict) and set(manifest) == {
        "schema", "revision", "platform", "playwright", "chromium", "samples"}, "incorrect run manifest")
    require(integer(manifest["schema"], 1, 1)
            and isinstance(manifest["revision"], str) and re.fullmatch("[0-9a-f]{40}", manifest["revision"])
            and manifest["revision"] == expected_revision
            and manifest["platform"] in ("linux", "windows")
            and manifest["platform"] == expected_platform.lower()
            and manifest["playwright"] == PLAYWRIGHT and manifest["chromium"] == CHROMIUM,
            "wrong run identity")
    samples = manifest["samples"]
    require(isinstance(samples, list) and 3 <= len(samples) <= 10, "insufficient independent fresh sessions")
    names = ["sample-%02d" % i for i in range(len(samples))]
    require({p.name for p in directory.iterdir()} == {"manifest.json", *names}, "unexpected run inventory")
    reports = []
    for name, sample in zip(names, samples):
        require(isinstance(sample, dict) and set(sample) == {"directory", "sha256"}
                and sample["directory"] == name and isinstance(sample["sha256"], dict)
                and set(sample["sha256"]) == FILES, "incorrect sample inventory")
        base = directory / name
        require(base.is_dir() and not base.is_symlink(), "invalid sample directory")
        for filename, digest in sample["sha256"].items():
            _, actual = read_json(base / filename, 16384)
            require(actual == digest, "observation digest mismatch")
        reports.append(compare(base))
    fields = []
    for schema, keys in SCHEMAS.items():
        pairs = [next(p for p in report["pairs"] if p["observation"] == schema) for report in reports]
        fields.append(dict(observation=schema, samples=len(pairs),
                           differing_sample_counts={k: sum(k in p["differing_fields"] for p in pairs)
                                                    for k in sorted(keys)}))
    return dict(revision=expected_revision, platform=manifest["platform"], manifest_sha256=manifest_sha,
                acceptance="not_evaluated", full_parity="not_established",
                limitations=["QUIC encrypted handshake/control stream not decoded",
                             "controlled loopback and ephemeral browser SPKI exception",
                             "browser GET and tunnel POST are different workloads",
                             "run metadata is not independent provenance"],
                summary=fields, samples=reports)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    parser.add_argument("--expected-revision", required=True)
    parser.add_argument("--expected-platform", required=True)
    args = parser.parse_args()
    print(json.dumps(compare_run(args.directory, args.expected_revision, args.expected_platform),
                     indent=2, allow_nan=False))
