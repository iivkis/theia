#!/usr/bin/env python3
"""Report bounded actual browser/native measurements; no equivalence claim."""
import json
from pathlib import Path
import sys

SCHEMAS = {
    "h2-tls": {"legacy_version", "cipher_count", "extension_count", "group_count",
               "grease", "alps", "sni_present", "tls13", "alpn_h2"},
    "h2-http": {"settings", "frames_before_headers", "connection_window_updates",
                "pseudo_headers", "ordinary_fields", "request_end_stream"},
    "h3-initial": {"version", "destination_cid_len", "source_cid_len", "token_len",
                   "packet_len", "datagram_len"},
}


def load(path, schema):
    with path.open("rb") as source:
        raw = source.read(16385)
    if len(raw) > 16384:
        raise ValueError("oversized observation")
    def unique(pairs):
        result = {}
        for k, v in pairs:
            if k in result:
                raise ValueError("duplicate observation key")
            result[k] = v
        return result
    doc = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(doc, dict) or set(doc) != SCHEMAS[schema]:
        raise ValueError("incorrect observation schema")
    return doc


def compare(directory):
    pairs = []
    for schema in SCHEMAS:
        native = load(directory / ("native-" + schema + ".json"), schema)
        browser = load(directory / ("browser-" + schema + ".json"), schema)
        for observation in (native, browser):
            if schema == "h2-tls":
                if (observation["tls13"] is not True or observation["alpn_h2"] is not True
                        or observation["legacy_version"] != 771):
                    raise ValueError("unexpected TLS reference")
                for key in ("cipher_count", "extension_count", "group_count"):
                    if type(observation[key]) is not int or not 0 < observation[key] <= 65536:
                        raise ValueError("invalid ClientHello dimensions")
                for key in ("grease","alps","sni_present"):
                    if type(observation[key]) is not bool:
                        raise ValueError("invalid TLS flag")
            elif schema == "h2-http":
                if (set(observation["pseudo_headers"]) != {":method",":scheme",":authority",":path"}
                        or len(observation["pseudo_headers"]) != 4
                        or not observation["settings"]):
                    raise ValueError("missing actual HTTP/2 first flight")
            else:
                if (observation["version"] != 1
                        or not 0 <= observation["destination_cid_len"] <= 20
                        or not 0 <= observation["source_cid_len"] <= 20
                        or not 1200 <= observation["datagram_len"] <= 65536
                        or not 1 <= observation["packet_len"] <= observation["datagram_len"]
                        or not 0 <= observation["token_len"] <= observation["packet_len"]):
                    raise ValueError("invalid visible QUIC Initial")
        pairs.append(dict(observation=schema, native=native, browser=browser,
                          differing_fields=[k for k in sorted(native) if native[k] != browser[k]]))
    return dict(acceptance="not_evaluated", full_parity="not_established",
                limitations=["H3 encrypted handshake/control stream not decoded",
                             "one controlled fixture per observation",
                             "browser reference uses isolated test trust exception",
                             "application GET vs tunnel POST are different workloads"], pairs=pairs)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: check_f13_observations.py DIRECTORY")
    print(json.dumps(compare(Path(sys.argv[1])), indent=2, allow_nan=False))
