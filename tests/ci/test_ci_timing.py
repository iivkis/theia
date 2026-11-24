#!/usr/bin/env python3
"""Offline CI timing evidence tests; no API calls or live credentials."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import unittest

SOURCE = Path(__file__).resolve().parents[2] / "scripts" / "ci-timing.py"
spec = importlib.util.spec_from_file_location("ci_timing", SOURCE)
assert spec is not None and spec.loader is not None
timing = importlib.util.module_from_spec(spec)
spec.loader.exec_module(timing)


def snapshot(run_id=1, sha="a" * 40, event="pull_request"):
    run = {
        "id": run_id, "run_attempt": 1, "head_sha": sha, "event": event,
        "name": "CI (tests first)", "status": "completed", "conclusion": "success",
        "created_at": "2026-11-24T12:00:00Z",
        "run_started_at": "2026-11-24T12:00:01Z",
        "updated_at": "2026-11-24T12:02:00Z",
    }
    jobs = [{
        "name": name, "run_id": run_id, "run_attempt": 1, "head_sha": sha,
        "status": "completed", "conclusion": "success",
        "started_at": "2026-11-24T12:00:10Z",
        "completed_at": "2026-11-24T12:01:10Z",
        "steps": [{
            "number": 1, "name": "Native check", "status": "completed",
            "conclusion": "success", "started_at": "2026-11-24T12:00:15Z",
            "completed_at": "2026-11-24T12:00:45Z",
        }, {
            "number": 2, "name": "Manual release compilation", "status": "completed",
            "conclusion": "skipped", "started_at": None, "completed_at": None,
        }],
    } for name in sorted(timing.EXPECTED_JOBS)]
    return run, {"total_count": len(jobs), "jobs": jobs}


class TimingTests(unittest.TestCase):
    def test_real_sanitized_api_snapshots_match_observed_durations(self):
        path = SOURCE.parents[1] / "tests" / "ci" / "fixtures" / "timing-snapshots.json"
        snapshots = json.loads(path.read_text(encoding="utf-8"))
        before, after = [timing.summarize(s["run"], s["jobs"]) for s in snapshots]
        self.assertEqual(before["id"], 45395505034)
        self.assertEqual(after["id"], 45397074048)
        self.assertEqual(before["jobs"]["windows-smoke"], 208)
        self.assertEqual(after["jobs"]["windows-smoke"], 194)
        self.assertIn("| windows-smoke | 208 | 194 | -14 |", timing.compare(before, after))

    def test_parallel_durations_are_not_wall_time_or_billing(self):
        result = timing.summarize(*snapshot())
        self.assertEqual(result["runner_job_seconds"], 13 * 60)
        self.assertEqual(result["creation_to_last_job_s"], 70)
        self.assertEqual(result["first_to_last_job_s"], 60)
        self.assertEqual(result["steps"]["specification"][1], ("Native check", 30))
        self.assertEqual(result["steps"]["specification"][2][1], None)

    def test_report_is_comparable_and_skips_unexecuted_steps(self):
        before = timing.summarize(*snapshot())
        run, jobs = snapshot(2, "b" * 40)
        jobs["jobs"][0]["completed_at"] = "2026-11-24T12:01:00Z"
        report = timing.compare(before, timing.summarize(run, jobs))
        self.assertIn("| Sum of job durations (not billed minutes) | 780 | 770 | -10 |", report)
        self.assertIn("Native check", report)
        self.assertNotIn("Manual release compilation", report)
        self.assertIn("not proof of causal speedup", report)

    def test_run_identity_and_completion_are_required(self):
        for field, value in [
            ("head_sha", "short"), ("run_attempt", 2), ("event", "workflow_dispatch"),
            ("name", "other"), ("status", "in_progress"), ("conclusion", "failure"),
            ("id", None), ("created_at", "bad"), ("updated_at", "2026-11-24T11:00:00Z"),
        ]:
            with self.subTest(field=field):
                run, jobs = snapshot()
                run[field] = value
                with self.assertRaises(timing.EvidenceError):
                    timing.summarize(run, jobs)

    def test_missing_duplicate_and_failed_jobs_are_rejected(self):
        run, jobs = snapshot()
        for change in ("missing", "duplicate", "count", "unknown"):
            with self.subTest(change=change):
                broken = deepcopy(jobs)
                if change == "missing":
                    broken["jobs"].pop()
                elif change == "duplicate":
                    broken["jobs"][0] = broken["jobs"][1]
                elif change == "count":
                    broken["total_count"] += 1
                else:
                    broken["jobs"][0]["name"] = "different"
                with self.assertRaises(timing.EvidenceError):
                    timing.summarize(run, broken)
        for field, value in [
            ("run_id", 2), ("head_sha", "b" * 40), ("run_attempt", 2),
            ("conclusion", "skipped"), ("conclusion", "failure"),
            ("completed_at", "2026-11-24T12:00:01Z"), ("steps", []),
        ]:
            with self.subTest(field=field, value=value):
                broken = deepcopy(jobs)
                broken["jobs"][0][field] = value
                with self.assertRaises(timing.EvidenceError):
                    timing.summarize(run, broken)

    def test_optional_repair_must_be_skipped_and_exact_identity(self):
        run, jobs = snapshot()
        repair = {
            "name": "format-repair", "run_id": run["id"], "head_sha": run["head_sha"],
            "run_attempt": 1, "status": "completed", "conclusion": "skipped",
            "started_at": None, "completed_at": None, "steps": [],
        }
        jobs["jobs"].append(repair)
        jobs["total_count"] += 1
        self.assertEqual(timing.summarize(run, jobs)["runner_job_seconds"], 780)
        for field, value in (("conclusion", "success"), ("head_sha", "b" * 40),
                             ("status", "in_progress")):
            broken = deepcopy(jobs)
            broken["jobs"][-1][field] = value
            with self.assertRaises(timing.EvidenceError):
                timing.summarize(run, broken)

    def test_bad_step_data_cannot_be_reported(self):
        run, jobs = snapshot()
        for field, value in [
            ("status", "in_progress"), ("conclusion", "failure"),
            ("started_at", None), ("number", 2),
            ("completed_at", "2026-11-24T12:03:00Z"),
        ]:
            with self.subTest(field=field):
                broken = deepcopy(jobs)
                broken["jobs"][0]["steps"][0][field] = value
                with self.assertRaises(timing.EvidenceError):
                    timing.summarize(run, broken)

    def test_no_pr_push_or_self_comparison(self):
        before = timing.summarize(*snapshot())
        for after in [before, timing.summarize(*snapshot(2, event="push"))]:
            with self.assertRaises(timing.EvidenceError):
                timing.compare(before, after)

    def test_step_names_do_not_break_table_and_duplicates_are_excluded(self):
        run, jobs = snapshot()
        jobs["jobs"][0]["steps"][0]["name"] = "one|two\nthree"
        before = timing.summarize(run, jobs)
        run2, jobs2 = snapshot(2)
        jobs2["jobs"][0]["steps"][0]["name"] = "one|two\nthree"
        after = timing.summarize(run2, jobs2)
        self.assertIn("one&#124;two three", timing.compare(before, after))
        jobs2["jobs"][0]["steps"][1]["name"] = "one|two\nthree"
        after = timing.summarize(run2, jobs2)
        self.assertNotIn("one&#124;two three", timing.compare(before, after))


if __name__ == "__main__":
    unittest.main()
