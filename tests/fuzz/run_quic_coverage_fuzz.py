#!/usr/bin/env python3
"""Opt-in coverage-guided native QUIC parser fuzzing using the existing lockfile.

Requires rustup component add llvm-tools-preview. No network sockets, no
additional Rust dependencies, no CI or release acceptance claim.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import random
import subprocess
import tempfile

LIMIT = 65527
MAX_CORPUS = 4096
TEST = "quic_core::mutation_tests::coverage_guided_input"
ROOT = Path(__file__).resolve().parents[2]


def run(command, *, timeout=60, env=None, capture=True):
    return subprocess.run(command, cwd=ROOT, env=env, timeout=timeout, check=True,
                          stdout=subprocess.PIPE if capture else None,
                          stderr=subprocess.PIPE if capture else None)


def build(target):
    env = dict(os.environ, CARGO_TARGET_DIR=str(target), CARGO_INCREMENTAL="0")
    env.pop("CARGO_ENCODED_RUSTFLAGS", None)
    env["RUSTFLAGS"] = "-C instrument-coverage"
    output = run(["cargo", "test", "--locked", "-p", "theia", "--lib",
                  "--no-run", "--message-format=json"], env=env, timeout=1800).stdout
    binaries = []
    for line in output.splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if (event.get("reason") == "compiler-artifact"
                and event.get("target", {}).get("name") == "theia"
                and event.get("profile", {}).get("test")
                and event.get("executable")):
            binaries.append(Path(event["executable"]))
    if len(set(binaries)) != 1:
        raise RuntimeError("could not identify exactly one instrumented library test executable")
    return binaries[0]


def llvm_tools():
    sysroot = Path(run(["rustc", "--print", "sysroot"]).stdout.decode().strip())
    host = next(line.split(": ", 1)[1] for line in
                run(["rustc", "-vV"]).stdout.decode().splitlines() if line.startswith("host: "))
    directory = sysroot / "lib" / "rustlib" / host / "bin"
    suffix = ".exe" if os.name == "nt" else ""
    tools = tuple(directory / (name + suffix) for name in ("llvm-profdata", "llvm-cov"))
    if not all(path.is_file() for path in tools):
        raise RuntimeError("install matching llvm-tools-preview for the current toolchain")
    return tools


def features(document):
    found = set()
    for unit in document["data"]:
        for source in unit["files"]:
            name = source["filename"].replace("\\", "/")
            if "/quic_core/" not in name or name.endswith("/mod.rs"):
                continue
            for line, col, count, has_count, region_entry, *_ in source["segments"]:
                if has_count and region_entry and count > 0:
                    found.add((name, line, col))
    return found


def mutate(data, rng):
    output = bytearray(data)
    for _ in range(rng.randint(1, 8)):
        action = rng.randrange(5)
        if action == 0 and output:
            i = rng.randrange(len(output))
            output[i] ^= 1 << rng.randrange(8)
        elif action == 1 and output:
            i = rng.randrange(len(output))
            output[i:i + rng.randint(1, 32)] = b""
        elif action == 2:
            i = rng.randrange(len(output) + 1)
            output[i:i] = rng.randbytes(rng.randint(1, 32))
        elif action == 3 and output:
            i = rng.randrange(len(output))
            output[i] = rng.choice((0, 1, 3, 0x40, 0x80, 0xff))
        else:
            output.extend(rng.randbytes(rng.randint(1, 64)))
        del output[LIMIT:]
    return bytes(output)


def save(directory, data):
    path = directory / (hashlib.sha256(data).hexdigest() + ".bin")
    path.write_bytes(data)
    return path


def measure(binary, profdata, cov, data, sources, crash, scratch):
    input_path = scratch / "input.bin"
    input_path.write_bytes(data)
    env = dict(os.environ, THEIA_QUIC_FUZZ_INPUT=str(input_path),
               LLVM_PROFILE_FILE=str(scratch / "input-%p.profraw"))
    for raw in scratch.glob("*.profraw"):
        raw.unlink()
    try:
        run([str(binary), TEST, "--ignored", "--exact", "--nocapture"],
            env=env, timeout=5)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        path = save(crash, data)
        raise RuntimeError(f"fuzz input crashed or timed out: {path}") from error
    raws = sorted(scratch.glob("*.profraw"))
    if not raws:
        raise RuntimeError("no per-input instrumentation profile")
    profile = scratch / "input.profdata"
    run([str(profdata), "merge", "-sparse", *map(str, raws), "-o", str(profile)])
    document = json.loads(run([str(cov), "export", str(binary),
                               "-instr-profile=" + str(profile),
                               *map(str, sources)]).stdout)
    return features(document)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--iterations", type=int, default=1000)
    parser.add_argument("--seed", type=int, default=20261127)
    parser.add_argument("--target-dir", type=Path, default=ROOT / "target/quic-fuzz")
    args = parser.parse_args()
    if not 1 <= args.iterations <= 1_000_000:
        parser.error("iterations must be in 1..1000000")
    output = args.output.resolve()
    corpus_dir = output / "corpus"
    crash = output / "failures"
    corpus_dir.mkdir(parents=True, exist_ok=True)
    crash.mkdir(parents=True, exist_ok=True)
    profdata, cov = llvm_tools()
    binary = build(args.target_dir.resolve())
    sources = sorted(p for p in (ROOT / "crates/theia/src/quic_core").glob("*.rs")
                     if p.name != "mod.rs")
    revision = run(["git", "rev-parse", "HEAD"]).stdout.decode().strip()
    rng = random.Random(args.seed)
    seeds = [b"", b"\x01", b"\x02\x00\x00\x00\x00", b"\x40" + bytes(63),
             b"\xc0" + bytes(1199), bytes(1200), bytes([255]) * 64]
    for path in sorted(corpus_dir.glob("*.bin"))[:MAX_CORPUS - len(seeds)]:
        if path.stat().st_size <= LIMIT:
            seeds.append(path.read_bytes())
    corpus = []
    seen = set()
    with tempfile.TemporaryDirectory(prefix="quic-fuzz-") as directory:
        scratch = Path(directory)
        for index in range(len(seeds) + args.iterations):
            data = seeds[index] if index < len(seeds) else mutate(rng.choice(corpus), rng)
            observed = measure(binary, profdata, cov, data, sources, crash, scratch)
            if not corpus or observed - seen:
                seen.update(observed)
                if len(corpus) < MAX_CORPUS:
                    corpus.append(data)
                    save(corpus_dir, data)
                if index % 20 == 0:
                    print(f"input={index} corpus={len(corpus)} regions={len(seen)}", flush=True)
    if not seen:
        raise RuntimeError("no observed QUIC coverage regions")
    result = {"revision": revision, "seed": args.seed, "iterations": args.iterations,
              "inputs": len(seeds) + args.iterations, "corpus": len(corpus),
              "regions": len(seen), "diagnostic_only": True}
    (output / "summary.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
