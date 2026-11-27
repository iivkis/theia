#!/usr/bin/env python3
"""Prove native Cargo target selectors cover the whole workspace.

Unlike nextest count partitions, target selectors avoid compiling every
integration harness twice. Any new unsupported target type fails closed.
"""
import json
import subprocess
import sys


def groups(metadata):
    if not isinstance(metadata, dict):
        raise ValueError("invalid cargo metadata")
    members = metadata.get("workspace_members")
    packages = metadata.get("packages")
    if (not isinstance(members, list) or not members
            or not all(isinstance(item, str) for item in members)
            or len(set(members)) != len(members) or not isinstance(packages, list)):
        raise ValueError("invalid workspace inventory")
    seen = set()
    result = {"unit": [], "integration": []}
    allowed = {"lib": "unit", "bin": "unit", "test": "integration"}
    for package in packages:
        if not isinstance(package, dict) or not isinstance(package.get("id"), str):
            raise ValueError("invalid package identity")
        identity = package["id"]
        if identity not in members:
            continue
        if identity in seen:
            raise ValueError("duplicate workspace package")
        seen.add(identity)
        targets = package.get("targets")
        if not isinstance(targets, list) or not targets:
            raise ValueError("missing package targets")
        names = set()
        for target in targets:
            if not isinstance(target, dict):
                raise ValueError("invalid Cargo target")
            kind = target.get("kind")
            name = target.get("name")
            if (not isinstance(kind, list) or len(kind) != 1
                    or not isinstance(kind[0], str) or not isinstance(name, str) or not name):
                raise ValueError("unknown target shape")
            key = (kind[0], name)
            if key in names:
                raise ValueError("duplicate Cargo target")
            names.add(key)
            if kind == ["custom-build"]:
                continue
            if kind[0] not in allowed:
                raise ValueError(f"unassigned Cargo target: {identity} {key}")
            result[allowed[kind[0]]].append((identity, *key))
    if seen != set(members) or not all(result.values()):
        raise ValueError("incomplete workspace target inventory")
    if not {"lib", "bin"} <= {kind for _, kind, _ in result["unit"]}:
        raise ValueError("missing native library or binary harness")
    return result


def main():
    try:
        metadata = json.loads(subprocess.check_output(
            ["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"],
            text=True,
        ))
        grouped = groups(metadata)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        sys.exit(f"Native target partition rejected: {error}")
    for name, targets in sorted(grouped.items()):
        print(f"Native {name}: {len(targets)} Cargo targets")
        for identity, kind, target in sorted(targets):
            print(f"  {identity}: {kind} {target}")


if __name__ == "__main__":
    main()
