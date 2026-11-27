#!/usr/bin/env python3
"""Compare complete GitHub Actions timing evidence without network or tokens.

Input is a run JSON and its corresponding jobs JSON from the attempt-specific
REST endpoint. This is a diagnostic, never a merge gate or a release verdict.
"""
from __future__ import annotations

import argparse
from datetime import datetime
import json
from pathlib import Path
import re

EXPECTED_JOBS = frozenset({
    "specification", "rust-tests (Linux)", "windows-smoke",
    "m0-1-api-spike (Linux)", "m0-1-api-spike (Windows)",
    "browser-e2e (ubuntu-latest)", "browser-e2e (windows-latest)",
    "m3-4-btls-spike (ubuntu-latest)", "m3-4-btls-spike (windows-latest)",
    "m3-4e-btls-production-feature (ubuntu-latest)",
    "m3-4e-btls-production-feature (windows-latest)",
    "F-14 Linux VM server to native Windows client", "ci-gate",
})

MERGED_JOBS = EXPECTED_JOBS | frozenset({
    "Coverage instrumented (ubuntu-latest)",
    "Coverage instrumented (windows-latest)",
    "Production line coverage >= 80%",
})

SHARDED_MERGED_JOBS = MERGED_JOBS | frozenset({
    "F-14 native build (ubuntu-latest)", "F-14 native build (windows-latest)",
    "Native performance (ubuntu-latest)", "Native performance (windows-latest)",
    "F-19 native performance (ubuntu-latest)", "F-19 native performance (windows-latest)",
})

# The fast MVP matrix still contains every native test partition and every
# exact-SHA coverage producer. Historical matrices remain diagnostic only.
MVP_MERGED_JOBS = frozenset({
    "specification", "ci-gate", "Production line coverage >= 80%",
    "F-14 Linux VM server to native Windows client",
    "F-14 native build (ubuntu-24.04)", "F-14 native build (windows-latest)",
    *(f"rust-tests (Linux, shard {n}/2)" for n in (1, 2)),
    *(f"windows-smoke (shard {n}/2)" for n in (1, 2)),
    *(f"Coverage instrumented ({os}, shard {n}/6)"
      for os in ("ubuntu-latest", "windows-latest") for n in range(1, 7)),
})

# Distinct target compilation and independent lints/cross-SID checks.
TARGET_GROUP_MVP_JOBS = MVP_MERGED_JOBS | frozenset({
    "Native prerequisite (linux-clippy)",
    "Native prerequisite (windows-clippy)",
    "Native prerequisite (windows-cross-sid)",
})


class EvidenceError(ValueError):
    """Incomplete or incomparable timing evidence."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise EvidenceError(message)


def stamp(value: object) -> datetime:
    require(isinstance(value, str) and value.endswith("Z"), "missing UTC timestamp")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise EvidenceError("invalid UTC timestamp") from None


def positive_int(value: object) -> bool:
    return type(value) is int and value > 0


def summarize(run: dict, response: dict) -> dict:
    require(isinstance(run, dict) and isinstance(response, dict), "expected JSON objects")
    require(run.get("status") == "completed" and run.get("conclusion") == "success",
            "run is not successful and complete")
    workflow = run.get("name")
    require(workflow in {"CI (tests first)", "CI (merged dev)"}, "unexpected workflow")
    merged = workflow == "CI (merged dev)"
    expected_jobs = MERGED_JOBS if merged else EXPECTED_JOBS
    require(run.get("event") in ({"pull_request"} if merged else {"push", "pull_request"}),
            "not ordinary CI")
    sha = run.get("head_sha")
    require(isinstance(sha, str) and re.fullmatch(r"[0-9a-f]{40}", sha) is not None,
            "missing exact head SHA")
    run_id = run.get("id")
    attempt = run.get("run_attempt")
    require(positive_int(run_id) and positive_int(attempt), "missing run identity")
    # A partial rerun reuses older job outcomes. Do not sum it as a whole
    # run or compare it to a fresh full matrix.
    require(attempt == 1, "partial/rerun evidence is not a comparable full run")
    created = stamp(run.get("created_at"))
    started = stamp(run.get("run_started_at"))
    updated = stamp(run.get("updated_at"))
    require(created <= started <= updated, "inconsistent run timestamps")

    jobs = response.get("jobs")
    if merged and isinstance(jobs, list):
        names = {job.get("name") for job in jobs if isinstance(job, dict)
                 and isinstance(job.get("name"), str)}
        if names == TARGET_GROUP_MVP_JOBS:
            expected_jobs = TARGET_GROUP_MVP_JOBS
        elif names == MVP_MERGED_JOBS:
            expected_jobs = MVP_MERGED_JOBS
        elif len(jobs) == len(SHARDED_MERGED_JOBS):
            expected_jobs = SHARDED_MERGED_JOBS
    require(isinstance(jobs, list) and response.get("total_count") == len(jobs)
            and len(jobs) in ({len(expected_jobs)} if merged else
                              {len(expected_jobs), len(expected_jobs) + 1}),
            "incomplete or unexpected job matrix")
    # Old successful snapshots predate the optional repair job. Current clean
    # runs may contain exactly one skipped repair; it is not runner time.
    repair_jobs = [job for job in jobs
                   if isinstance(job, dict) and job.get("name") == "format-repair"]
    require(len(repair_jobs) <= (0 if merged else 1), "unexpected format repair")
    for repair in repair_jobs:
        require(repair.get("run_id") == run_id and repair.get("head_sha") == sha
                and repair.get("run_attempt") == attempt, "repair job identity mismatch")
        require(repair.get("status") == "completed" and repair.get("conclusion") == "skipped",
                "successful ordinary CI cannot execute format repair")
    jobs = [job for job in jobs if job not in repair_jobs]
    require(len(jobs) == len(expected_jobs), "incomplete required job matrix")
    timings = {}
    steps = {}
    first = None
    last = None
    for job in jobs:
        require(isinstance(job, dict), "invalid job entry")
        name = job.get("name")
        require(isinstance(name, str) and name in expected_jobs and name not in timings,
                "unknown or duplicate job")
        require(job.get("run_id") == run_id and job.get("head_sha") == sha
                and job.get("run_attempt") == attempt, "job identity mismatch")
        require(job.get("status") == "completed" and job.get("conclusion") == "success",
                "job is not successful and complete")
        begin, end = stamp(job.get("started_at")), stamp(job.get("completed_at"))
        require(created <= begin <= end <= updated, "job outside run interval")
        timings[name] = int((end - begin).total_seconds())
        first = begin if first is None else min(first, begin)
        last = end if last is None else max(last, end)

        job_steps = job.get("steps")
        require(isinstance(job_steps, list) and bool(job_steps), "missing job steps")
        measured = {}
        for step in job_steps:
            require(isinstance(step, dict), "invalid step entry")
            number = step.get("number")
            label = step.get("name")
            require(positive_int(number) and number not in measured
                    and isinstance(label, str) and bool(label), "invalid step identity")
            require(step.get("status") == "completed", "incomplete step")
            if step.get("conclusion") == "skipped":
                measured[number] = (label, None)
                continue
            require(step.get("conclusion") == "success", "non-successful executed step")
            left, right = stamp(step.get("started_at")), stamp(step.get("completed_at"))
            require(begin <= left <= right <= end, "step outside job interval")
            measured[number] = (label, int((right - left).total_seconds()))
        steps[name] = measured

    require(set(timings) == expected_jobs, "incomplete required job names")
    return {
        "id": run_id, "sha": sha, "event": run["event"], "workflow": workflow,
        "creation_to_last_job_s": int((last - created).total_seconds()),
        "first_to_last_job_s": int((last - first).total_seconds()),
        "runner_job_seconds": sum(timings.values()),
        "jobs": timings, "steps": steps,
    }


def compare(before: dict, after: dict) -> str:
    require(before["event"] == after["event"], "do not compare PR with push")
    require(before["id"] != after["id"], "same run is not a comparison")
    require(before["workflow"] == after["workflow"]
            and set(before["jobs"]) == set(after["jobs"]),
            "different required job matrices are not comparable")
    lines = [
        f"Before: run {before['id']} ({before['sha']})",
        f"After: run {after['id']} ({after['sha']})",
        "",
        "| Metric | Before (s) | After (s) | Delta (s) |",
        "|---|---:|---:|---:|",
    ]
    for key, label in [
        ("creation_to_last_job_s", "Creation to last job completion"),
        ("first_to_last_job_s", "First job start to last completion"),
        ("runner_job_seconds", "Sum of job durations (not billed minutes)"),
    ]:
        a, b = before[key], after[key]
        lines.append(f"| {label} | {a} | {b} | {b - a:+d} |")
    for name in sorted(before["jobs"]):
        a, b = before["jobs"][name], after["jobs"][name]
        lines.append(f"| {name} | {a} | {b} | {b - a:+d} |")
    lines += ["", "Step timings (matching unique names only):",
              "", "| Job / step | Before (s) | After (s) | Delta (s) |",
              "|---|---:|---:|---:|"]
    for name in sorted(before["jobs"]):
        def unique_steps(snapshot: dict) -> dict:
            entries = list(snapshot["steps"][name].values())
            return {label: seconds for label, seconds in entries
                    if sum(other == label for other, _ in entries) == 1}
        old, new = unique_steps(before), unique_steps(after)
        for label in sorted(old.keys() & new.keys()):
            a, b = old[label], new[label]
            if a is None or b is None:
                continue
            # Escape Markdown table delimiters and newlines in API labels.
            safe = label.replace("|", "&#124;").replace("\r", " ").replace("\n", " ")
            lines.append(f"| {name} / {safe} | {a} | {b} | {b - a:+d} |")
    lines += ["", "Observational timing only. Cache warmth, runner image and queue effects",
              "are not controlled. A negative delta is not proof of causal speedup.",
              "Successful snapshots do not replace exact-head merge/release checks."]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("before_run", "before_jobs", "after_run", "after_jobs"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    try:
        data = [json.loads(path.read_text(encoding="utf-8")) for path in
                (args.before_run, args.before_jobs, args.after_run, args.after_jobs)]
        print(compare(summarize(data[0], data[1]), summarize(data[2], data[3])))
    except (OSError, ValueError, TypeError, KeyError):
        parser.exit(2, "CI timing evidence rejected: missing, malformed or incomparable snapshot\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
