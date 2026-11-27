#!/usr/bin/env python3
"""Stage and verify the current F-14 Windows build's BoringSSL dependencies.

Never consume a third-party binary or a previous run's bundle. Cargo's own
locked build chooses the package, features, native search paths and headers.
Clippy uses the supported btls-sys prebuilt-path input only after validation.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[1]
TARGET = "x86_64-pc-windows-msvc"


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def command(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def identity(sha):
    require(len(sha) == 40 and all(c in "0123456789abcdef" for c in sha),
            "invalid tested SHA")
    require(command("git", "rev-parse", "HEAD") == sha, "wrong source revision")
    compiler = command("rustc", "-vV")
    require(f"host: {TARGET}" in compiler.splitlines(), "wrong Rust host")
    lock_path = ROOT / "Cargo.lock"
    lock = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    locked = [p for p in lock["package"] if p["name"] == "btls-sys"]
    require(len(locked) == 1 and locked[0].get("checksum")
            and locked[0].get("source", "").startswith("registry+"),
            "ambiguous or unpinned BoringSSL dependency")
    package = locked[0]
    metadata = json.loads(command("cargo", "metadata", "--locked", "--format-version",
                                  "1", "--filter-platform", TARGET))
    packages = [p for p in metadata["packages"] if p["name"] == "btls-sys"]
    require(len(packages) == 1 and packages[0]["version"] == package["version"]
            and packages[0]["source"] == package["source"], "wrong resolved btls-sys")
    package_id = packages[0]["id"]
    nodes = [node for node in metadata["resolve"]["nodes"] if node["id"] == package_id]
    require(len(nodes) == 1, "missing resolved features")
    features = sorted(nodes[0]["features"])
    require("fips" not in features and "fips-link-precompiled" not in features,
            "unsupported FIPS bundle; require a normal source build")
    return {
        "schema": 1, "sha": sha, "target": TARGET, "rustc": compiler,
        "lock_sha256": digest(lock_path), "package_id": package_id,
        "crate_checksum": package["checksum"], "features": features,
    }


def regular_files(directory):
    require(directory.is_dir() and not directory.is_symlink(), "invalid directory")
    result = {}
    for path in sorted(directory.rglob("*")):
        require(not path.is_symlink() and not getattr(path, "is_junction", lambda: False)(), "unexpected link in bundle")
        if path.is_file():
            result[path.relative_to(directory).as_posix()] = digest(path)
        else:
            require(path.is_dir(), "unexpected non-regular file in bundle")
    return result


def stage(events, directory, expected):
    require(not directory.exists(), "bundle destination already exists")
    events = [json.loads(line) for line in events.read_text(encoding="utf-8-sig").splitlines()
              if line.strip()]
    require(any(e.get("reason") == "build-finished" and e.get("success") is True
                for e in events), "Cargo did not complete successfully")
    relevant = [e for e in events if e.get("package_id") == expected["package_id"]]
    builds = [e for e in relevant if e.get("reason") == "build-script-executed"]
    libs = [e for e in relevant if e.get("reason") == "compiler-artifact"
            and "lib" in e.get("target", {}).get("kind", [])]
    require(len(builds) == 1 and len(libs) == 1, "ambiguous native build identity")
    require(sorted(libs[0]["features"]) == expected["features"],
            "compiled btls-sys features differ from resolved features")
    out = Path(builds[0]["out_dir"]).resolve(strict=True)
    require(out.is_relative_to((ROOT / "target" / "debug" / "build").resolve()),
            "native build output outside expected Cargo target tree")
    search = set()
    for item in builds[0]["linked_paths"]:
        if item.startswith("native="):
            path = Path(item.removeprefix("native=")).resolve()
            require(path.is_relative_to(out), "foreign native search path")
            search.add(path)
    sources = {}
    for name in ("crypto.lib", "ssl.lib"):
        matches = {path.joinpath(name).resolve(strict=True)
                   for path in search if path.joinpath(name).is_file()}
        require(len(matches) == 1, f"missing or ambiguous {name}")
        source = matches.pop()
        require(source.is_relative_to(out) and source.stat().st_size > 0,
                f"invalid {name}")
        with source.open("rb") as stream:
            require(stream.read(8) == b"!<arch>\n", f"{name} is not a COFF archive")
        sources[name] = source
    # Match the include-path order of the locked btls-sys build script.
    includes = [out / "boringssl" / "include", out / "boringssl" / "src" / "include"]
    header = next((p for p in includes if (p / "openssl" / "x509v3.h").is_file()), None)
    require(header is not None, "patched BoringSSL headers missing")
    regular_files(header)
    (directory / "lib").mkdir(parents=True)
    for name, source in sources.items():
        shutil.copyfile(source, directory / "lib" / name)
    shutil.copytree(header, directory / "include")
    files = regular_files(directory)
    (directory / "manifest.json").write_text(
        json.dumps({**expected, "files": files}, sort_keys=True) + "\n", encoding="utf-8")


def verify(directory, expected):
    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    require(isinstance(manifest, dict), "invalid bundle manifest")
    files = manifest.pop("files")
    require(manifest == expected, "native bundle source/compiler/feature mismatch")
    observed = regular_files(directory)
    observed.pop("manifest.json")
    require(files == observed, "native bundle file digest mismatch")
    require(set(p for p in files if p.startswith("lib/")) == {"lib/crypto.lib", "lib/ssl.lib"},
            "unexpected native libraries")
    require("include/openssl/x509v3.h" in files
            and all(p.startswith(("lib/", "include/")) for p in files),
            "unexpected bundle contents")
    for name in ("crypto.lib", "ssl.lib"):
        with (directory / "lib" / name).open("rb") as stream:
            require(stream.read(8) == b"!<arch>\n", "invalid COFF archive")
    print("Verified same-run BoringSSL archive, compiler, lockfile, features and headers")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["stage", "verify"])
    parser.add_argument("--sha", required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--events", type=Path)
    args = parser.parse_args()
    expected = identity(args.sha)
    if args.command == "stage":
        require(args.events is not None, "Cargo events required")
        stage(args.events, args.bundle, expected)
    else:
        require(args.events is None, "unexpected Cargo events")
        verify(args.bundle, expected)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        sys.exit(f"BoringSSL evidence rejected: {error}")
