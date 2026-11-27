#!/usr/bin/env python3
"""Reuse hosted Rust only if it matches the trusted specification compiler."""
import argparse
import os
import re
import subprocess
import sys


def command(*args):
    return subprocess.check_output(args, encoding="utf-8", errors="strict").strip()


def compiler(output):
    fields = {}
    for line in output.splitlines():
        key, sep, value = line.partition(": ")
        if sep:
            if key in fields:
                raise ValueError("duplicate rustc identity field")
            fields[key] = value
    release, commit = fields.get("release", ""), fields.get("commit-hash", "")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", release):
        raise ValueError("expected stable numeric Rust release")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("invalid Rust commit hash")
    if not fields.get("host"):
        raise ValueError("missing compiler host")
    return release, commit, fields["host"]


def ready(toolchain, expected, components):
    try:
        version = compiler(command("rustup", "run", toolchain, "rustc", "-vV"))
        if version[:2] != expected:
            return False
        installed = set(command("rustup", "component", "list", "--toolchain",
                                toolchain, "--installed").splitlines())
        host = version[2]
        for component in ("cargo", "rustc", *components):
            names = {component, component + "-" + host}
            if component == "llvm-tools-preview":
                names |= {"llvm-tools", "llvm-tools-" + host}
            if not names & installed:
                return False
        return True
    except (OSError, ValueError, subprocess.CalledProcessError):
        return False


def prepare(expected, components):
    release, commit = expected
    # Validate workflow output before passing it to rustup.
    compiler(f"release: {release}\ncommit-hash: {commit}\nhost: requested")
    chosen = "stable"
    if not ready(chosen, expected, components):
        # The hosted image can be stale by one or more patch releases.
        # Update the existing stable installation once, without fetching a
        # new rustup installer. A mid-run stable release must not change SHA.
        args = ["rustup", "toolchain", "install", chosen, "--profile", "minimal",
                "--no-self-update"]
        for component in components:
            args += ["--component", component]
        subprocess.run(args, check=True)
        if not ready(chosen, expected, components):
            chosen = release
            args[3] = chosen
            if not ready(chosen, expected, components):
                subprocess.run(args, check=True)
    if not ready(chosen, expected, components):
        raise ValueError("exact specification Rust compiler/components unavailable")
    subprocess.run(["rustup", "default", chosen], check=True)
    if compiler(command("rustc", "-vV"))[:2] != expected:
        raise ValueError("active Rust compiler differs from specification")
    command("cargo", "--version")
    print(f"Verified Rust {release} ({commit}) with {', '.join(components) or 'base tools'}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["record", "prepare"])
    parser.add_argument("--component", action="append", default=[],
                        choices=["clippy", "llvm-tools-preview"])
    args = parser.parse_args()
    if args.action == "record":
        release, commit, _ = compiler(command("rustc", "-vV"))
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
            output.write(f"release={release}\ncommit={commit}\n")
    else:
        prepare((os.environ["CI_RUST_RELEASE"], os.environ["CI_RUST_COMMIT"]),
                args.component)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        sys.exit(f"Native Rust toolchain rejected: {error}")
