#!/usr/bin/env python3
"""Fail-closed production Rust line coverage for the exact merged commit.

Use the union of executable line identities from native Linux and Windows
LLVM reports. A line is covered if either platform executed it. Never average
percentages or count a source file twice. Exclude only test-only syntax and
non-product sources (integration tests, dependency and research spike code).
Missing production files, incomplete evidence and stale reports fail the gate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
PLATFORMS = {"Linux", "Windows"}
SHA = re.compile(r"[0-9a-f]{40}\Z")
MIN_PERCENT = 80


class EvidenceError(ValueError):
    pass


def inventory(root: Path) -> dict[str, str]:
    raw = subprocess.check_output(["git", "ls-files", "-z"], cwd=root)
    sources = {}
    for item in raw.split(b"\0"):
        if not item:
            continue
        name = item.decode("utf-8")
        path = PurePosixPath(name)
        if path.suffix != ".rs":
            continue
        parts = path.parts
        if len(parts) >= 4 and parts[0] == "crates" and parts[2] == "src":
            pass
        elif len(parts) == 3 and parts[0] == "crates" and parts[2] == "build.rs":
            pass
        elif parts[0] in {"spikes", "tests"} or (
            len(parts) >= 4 and parts[0] == "crates" and parts[2] in {"tests", "benches", "examples"}
        ):
            continue
        else:
            raise EvidenceError(f"Unclassified tracked Rust source: {name}")
        file = root / name
        if file.is_symlink() or not file.is_file():
            raise EvidenceError(f"Source is not a regular file: {name}")
        # Git on Windows may check out CRLF; line identities remain the same.
        sources[name] = hashlib.sha256(file.read_bytes().replace(b"\r\n", b"\n")).hexdigest()
    if not sources:
        raise EvidenceError("Empty production source inventory")
    return sources


def exact_head(root: Path, sha: str) -> None:
    actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    if not SHA.fullmatch(sha) or actual != sha:
        raise EvidenceError("Coverage does not belong to the checked-out merge SHA")
    subprocess.run(["git", "diff", "--quiet", "HEAD", "--", "crates"], cwd=root, check=True)


def source_name(raw: str, root: Path) -> str | None:
    path = Path(raw)
    if not path.is_absolute():
        path = root / path
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return None  # External dependency, not an owned source.


def llvm_segment_lines(segments: list, max_line: int) -> dict[str, int]:
    """Reconstruct LLVM file-level LineCoverageStats from export segments.

    The line summary is calculated per function group, not from these unique
    file lines. Match the actual LCOV DA records instead of equating counts.
    """
    if not isinstance(segments, list):
        raise EvidenceError("Missing LLVM file segments")
    grouped = {}
    previous = (0, 0)
    for segment in segments:
        if (not isinstance(segment, list) or len(segment) != 6
                or any(type(value) is not int for value in segment[:3])
                or any(type(value) is not bool for value in segment[3:])):
            raise EvidenceError("Malformed LLVM coverage segment")
        line, column, hits, has_count, entry, gap = segment
        if not 1 <= line <= max_line + 1 or column < 1 or hits < 0 or (line, column) <= previous:
            raise EvidenceError("Invalid or unordered LLVM coverage segment")
        previous = (line, column)
        grouped.setdefault(line, []).append(segment)
    result = {}
    wrapped = None
    for line in range(1, previous[0] + 1):
        current = grouped.get(line, [])
        starts = [s for s in current if s[3] and s[4] and not s[5]]
        skipped = bool(current and not current[0][3] and current[0][4])
        mapped = (not skipped and ((wrapped is not None and wrapped[3]) or bool(starts))
                  or any(s[3] and s[4] for s in current))
        if mapped:
            if line > max_line:
                raise EvidenceError("LLVM mapped line outside tracked source")
            count = max([wrapped[2] if wrapped is not None else 0] + [s[2] for s in starts])
            result[str(line)] = int(count > 0)
        if current:
            wrapped = current[-1]
    return result


def read_llvm_export(data: dict, root: Path, expected: dict[str, str]) -> dict:
    if (not isinstance(data, dict) or data.get("type") != "llvm.coverage.json.export"
            or not isinstance(data.get("version"), str)
            or not re.fullmatch(r"2\.\d+\.\d+", data["version"])
            or not isinstance(data.get("data"), list) or len(data["data"]) != 1
            or not isinstance(data["data"][0], dict)
            or not isinstance(data["data"][0].get("files"), list)):
        raise EvidenceError("Unsupported or incomplete LLVM JSON export")
    result = {}
    for record in data["data"][0]["files"]:
        if not isinstance(record, dict) or not isinstance(record.get("filename"), str):
            raise EvidenceError("Malformed LLVM file record")
        name = source_name(record["filename"], root)
        if name not in expected:
            continue
        if name in result:
            raise EvidenceError(f"Duplicate LLVM production source: {name}")
        summary = record.get("summary", {}).get("lines", {})
        lf, lh = summary.get("count"), summary.get("covered")
        if type(lf) is not int or type(lh) is not int or not 0 <= lh <= lf:
            raise EvidenceError(f"Malformed LLVM line summary: {name}")
        length = len((root / name).read_bytes().splitlines())
        lines = llvm_segment_lines(record.get("segments"), length)
        result[name] = (lines, lf, lh)
    if not result:
        raise EvidenceError("Empty LLVM production export")
    return result


def read_lcov(text: str, root: Path, expected: dict[str, str],
              llvm: dict | None = None) -> dict[str, dict[str, int]]:
    files: dict[str, dict[str, int]] = {}
    active = False
    source = None
    lines: dict[str, int] = {}
    lf = lh = None
    for raw in text.splitlines():
        if raw.startswith("SF:"):
            if active:
                raise EvidenceError("LCOV record missing end_of_record")
            active = True
            source = source_name(raw[3:], root)
            lines = {}
            lf = lh = None
        elif raw.startswith("DA:"):
            if not active:
                raise EvidenceError("LCOV line outside a source record")
            fields = raw[3:].split(",")
            if len(fields) not in {2, 3} or not all(v.isascii() and v.isdecimal() for v in fields[:2]):
                raise EvidenceError("Malformed LCOV DA")
            number, hits = map(int, fields[:2])
            if number < 1 or str(number) in lines:
                raise EvidenceError("Invalid or duplicate executable line")
            lines[str(number)] = int(hits > 0)
        elif raw.startswith(("LF:", "LH:")):
            if not active or not raw[3:].isascii() or not raw[3:].isdecimal():
                raise EvidenceError("Malformed LCOV line summary")
            if raw.startswith("LF:"):
                if lf is not None:
                    raise EvidenceError("Duplicate LF")
                lf = int(raw[3:])
            else:
                if lh is not None:
                    raise EvidenceError("Duplicate LH")
                lh = int(raw[3:])
        elif raw == "end_of_record":
            if not active or lf is None or lh is None or not 0 <= lh <= lf:
                raise EvidenceError(f"Incomplete or inconsistent LCOV record: {source}")
            if llvm is None:
                if lf != len(lines) or lh != sum(lines.values()):
                    raise EvidenceError(f"Inconsistent LCOV line counts: {source}")
            elif source in expected:
                # LLVM LF/LH are summed per function group. DA is the union
                # of unique mapped lines in the file. Verify both against the
                # second export from the exact same instrumented profiles.
                if llvm.get(source) != (lines, lf, lh):
                    raise EvidenceError(f"LCOV/LLVM segment or summary mismatch: {source}")
            if source in expected:
                if source in files:
                    raise EvidenceError(f"Duplicate production source record: {source}")
                files[source] = lines
            active = False
        elif raw and not raw.startswith(("TN:", "FN:", "FNDA:", "FNF:", "FNH:", "BRDA:", "BRF:", "BRH:", "VER:")):
            raise EvidenceError("Unrecognized LCOV record")
    if active or not files:
        raise EvidenceError("Incomplete or empty native coverage report")
    if llvm is not None and set(files) != set(llvm):
        raise EvidenceError("LCOV/LLVM production source inventory mismatch")
    return files


def cfg_production_values(expression: bytes) -> set[bool]:
    """Conservative Boolean analysis with test=false; other cfg atoms unknown."""
    token_re = re.compile(rb'[A-Za-z_][A-Za-z_0-9]*|"(?:\\.|[^"\\])*"|[(),=]')
    tokens = token_re.findall(expression)
    if b"".join(tokens) != expression:
        raise EvidenceError("Unrecognized cfg expression")
    pos = 0

    def take():
        nonlocal pos
        if pos >= len(tokens):
            raise EvidenceError("Incomplete cfg predicate")
        token = tokens[pos]
        pos += 1
        return token

    def predicate():
        nonlocal pos
        name = take()
        if not re.fullmatch(rb"[A-Za-z_][A-Za-z_0-9]*", name):
            raise EvidenceError("Invalid cfg predicate")
        if pos < len(tokens) and tokens[pos] == b"=":
            pos += 1
            if not take().startswith(b'"'):
                raise EvidenceError("Invalid cfg value")
            return {False, True}
        if pos >= len(tokens) or tokens[pos] != b"(":
            return {False} if name == b"test" else {False, True}
        pos += 1
        args = []
        while pos < len(tokens) and tokens[pos] != b")":
            args.append(predicate())
            separator = take()
            if separator == b")":
                pos -= 1
                break
            if separator != b",":
                raise EvidenceError("Invalid cfg arguments")
        if take() != b")":
            raise EvidenceError("Unclosed cfg expression")
        if name == b"not" and len(args) == 1:
            return {not value for value in args[0]}
        if name == b"all":
            result = {True}
            for arg in args:
                result = {left and right for left in result for right in arg}
            return result
        if name == b"any":
            result = {False}
            for arg in args:
                result = {left or right for left in result for right in arg}
            return result
        return {False, True}

    values = predicate()
    if pos != len(tokens):
        raise EvidenceError("Trailing cfg tokens")
    return values


def test_only_attribute(raw: bytes) -> bool:
    compact = re.sub(rb"\s+", b"", raw)
    if compact.startswith(b"#[cfg(") and compact.endswith(b")]"):
        try:
            return True not in cfg_production_values(compact[6:-2])
        except EvidenceError:
            # Never exclude code based on a predicate we cannot prove test-only.
            return False
    return re.fullmatch(rb"#\[(?:test|tokio::test)(?:\(.*\))?\]", compact) is not None


def test_only_lines(source: bytes) -> set[int]:
    # Use the Rust syntax tree, not regex brace matching or a file allowlist.
    # Exclude a line only if the test-only item occupies the entire line;
    # shared production/test lines remain in the denominator.
    from tree_sitter import Language, Parser
    import tree_sitter_rust

    root = Parser(Language(tree_sitter_rust.language())).parse(source).root_node
    if root.has_error:
        raise EvidenceError("Rust syntax parser cannot classify test-only code")
    result: set[int] = set()
    source_lines = source.splitlines()

    def exclude(first, last):
        start = first.start_point.row
        end = last.end_point.row
        for row in range(start, end + 1):
            if row >= len(source_lines):
                continue
            if row == start and source_lines[row][:first.start_point.column].strip():
                continue
            if row == end and source_lines[row][last.end_point.column:].strip():
                continue
            result.add(row + 1)

    def visit(node):
        pending = []
        for child in node.named_children:
            if child.type == "attribute_item":
                pending.append(child)
                continue
            if child.type in {"line_comment", "block_comment"}:
                continue
            if pending and any(test_only_attribute(source[a.start_byte:a.end_byte]) for a in pending):
                exclude(pending[0], child)
            else:
                visit(child)
            pending = []

    visit(root)
    return result


def strict_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise EvidenceError("Duplicate JSON key in coverage evidence")
        value[key] = item
    return value


def read_report(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=strict_object)


def combine(reports: list[dict], expected: dict[str, str], sha: str,
            excluded: dict[str, set[int]], lengths: dict[str, int]) -> dict:
    if len(reports) != 2:
        raise EvidenceError("Exactly two native reports are required")
    seen = set()
    combined = {name: {} for name in expected}
    for report in reports:
        if not isinstance(report, dict) or set(report) != {"schema", "sha", "platform", "inventory", "files"}:
            raise EvidenceError("Unknown or missing native evidence fields")
        platform = report["platform"]
        if type(report["schema"]) is not int or report["schema"] != 1 or report["sha"] != sha:
            raise EvidenceError("Stale or incompatible coverage evidence")
        if platform not in PLATFORMS or platform in seen or report["inventory"] != expected:
            raise EvidenceError("Wrong platform, duplicate platform or source inventory mismatch")
        seen.add(platform)
        files = report["files"]
        if not isinstance(files, dict) or not files or not set(files) <= set(expected):
            raise EvidenceError("Missing or unexpected native coverage source")
        for name, lines in files.items():
            if not isinstance(lines, dict):
                raise EvidenceError("Malformed native line mapping")
            for number, hits in lines.items():
                if (not isinstance(number, str) or not number.isascii() or not number.isdecimal()
                    or number.startswith("0") or not 1 <= int(number) <= lengths[name]
                    or type(hits) is not int or hits not in {0, 1}):
                    raise EvidenceError("Malformed coverage line identity")
                if int(number) not in excluded[name]:
                    combined[name][number] = max(combined[name].get(number, 0), hits)
    if seen != PLATFORMS:
        raise EvidenceError("Both native platforms must be measured")
    missing = [name for name, lines in combined.items() if not lines]
    if missing:
        raise EvidenceError("Production sources missing executable evidence: " + ", ".join(sorted(missing)))
    files = {name: {"covered": sum(lines.values()), "total": len(lines)}
             for name, lines in sorted(combined.items())}
    covered = sum(value["covered"] for value in files.values())
    total = sum(value["total"] for value in files.values())
    return {"schema": 1, "sha": sha, "platforms": sorted(seen), "minimum_percent": MIN_PERCENT,
            "covered": covered, "total": total, "percent": covered * 100 / total,
            "passed": covered * 100 >= MIN_PERCENT * total, "files": files}


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    collect = commands.add_parser("collect")
    collect.add_argument("--lcov", type=Path, required=True)
    collect.add_argument("--llvm-json", type=Path, required=True)
    collect.add_argument("--platform", choices=sorted(PLATFORMS), required=True)
    gate = commands.add_parser("gate")
    gate.add_argument("--linux", type=Path, required=True)
    gate.add_argument("--windows", type=Path, required=True)
    for command in (collect, gate):
        command.add_argument("--sha", required=True)
        command.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    exact_head(ROOT, args.sha)
    expected = inventory(ROOT)
    if args.command == "collect":
        llvm = read_llvm_export(read_report(args.llvm_json), ROOT, expected)
        files = read_lcov(args.lcov.read_text(encoding="utf-8"), ROOT, expected, llvm)
        write_json(args.output, {"schema": 1, "sha": args.sha, "platform": args.platform,
                                 "inventory": expected, "files": files})
        return 0
    sources = {name: (ROOT / name).read_bytes() for name in expected}
    excluded = {name: test_only_lines(source) for name, source in sources.items()}
    lengths = {name: len(source.splitlines()) for name, source in sources.items()}
    summary = combine([read_report(args.linux), read_report(args.windows)], expected,
                      args.sha, excluded, lengths)
    write_json(args.output, summary)
    print(f'Production line coverage: {summary["covered"]}/{summary["total"]} '
          f'({summary["percent"]:.2f}%), required {MIN_PERCENT}%')
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (EvidenceError, OSError, ValueError, subprocess.CalledProcessError, ImportError, TypeError) as error:
        sys.exit(f"Coverage evidence rejected: {error}")
