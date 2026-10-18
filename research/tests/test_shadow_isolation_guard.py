"""
Guard Tests for Findings AH, AI, AJ, AK (Shadow Log Isolation & Audit Integrity).

Verifies:
1. Real Subprocess Differential Test Isolation (Finding AI): Running real differential
   test modules via subprocess with mock HOME and no PAI_SHADOW_LOG NEVER alters or truncates
   the default shadow log. SHA-256 checksum remains strictly identical before and after.
2. Real Subprocess Windows Parity Runner Isolation (Finding AI): Running tools/windows_parity_run.py
   via subprocess with mock HOME and no PAI_SHADOW_LOG NEVER alters or truncates the default log.
3. Mutation Check (Finding AI): When test log isolation is explicitly disabled
   (PAI_DISABLE_TEST_LOG_ISOLATION=1), running operations without isolation DOES mutate the default log,
   proving the guard test is discriminating and catches leaks deterministically.
4. Fail-Closed Telemetry Source Default (Finding AH): Module default of _CURRENT_TELEMETRY_SOURCE
   is 'unknown'. In unconfigured processes, get_telemetry_source() returns 'unknown'.
   Comparisons recorded with default source tag 'unknown' do not increment cli_comparisons,
   and window_started remains False.
5. Safe Archiving & Confirmation (Finding AD): `pai clear-shadow` refuses without `--yes`,
   and archives existing logs with timestamps upon confirmation.
6. Source Separation (Finding AE): Comparisons from tests, runners, doctor, and unknown sources
   do not increment `cli_comparisons`.
7. Corrupt Lines Detection (Finding AF): Malformed non-JSON lines disqualify active window.
8. Log Write Failure Handling (Finding AK): Failure to write discrepancy to disk is tracked in
   log_write_failures and invalidates active window.
9. Audit Completion Metric (Finding AK): `window_complete` boolean strictly evaluates quotas,
   7-day span, discrepancies, and write failures.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any, Dict
from unittest import mock

_tests_dir = os.path.dirname(os.path.abspath(__file__))
_research_dir = os.path.dirname(_tests_dir)
_repo_root = os.path.dirname(_research_dir)
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)
if _research_dir not in sys.path:
    sys.path.insert(0, _research_dir)
if _tests_dir not in sys.path:
    sys.path.insert(0, _tests_dir)

import _bootstrap  # noqa: F401
import pai_core_bridge
from pai import main


def _compute_file_sha256(path: Path) -> str:
    """Computes SHA-256 hexdigest of the specified file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


class TestShadowIsolationGuard(unittest.TestCase):
    def setUp(self):
        pai_core_bridge.clear_shadow_log()
        self.tmpdir = tempfile.TemporaryDirectory()
        self.mock_home = Path(self.tmpdir.name) / "home"
        self.mock_default_dir = self.mock_home / ".pai"
        self.mock_default_dir.mkdir(parents=True, exist_ok=True)
        self.default_log_file = self.mock_default_dir / "shadow_discrepancies.jsonl"

        # Seed with 5 canary lines (simulating the reviewer's reproduction setup)
        self.canary_records = [
            {"timestamp": 1700000001.0, "type": "comparison", "op": "ingest_file", "source": "cli"},
            {"timestamp": 1700000002.0, "type": "comparison", "op": "ingest_file", "source": "cli"},
            {"timestamp": 1700000003.0, "type": "comparison", "op": "ingest_folder", "source": "cli"},
            {"timestamp": 1700000004.0, "type": "comparison", "op": "verify_verdict_frame", "source": "cli"},
            {"timestamp": 1700000005.0, "type": "comparison", "op": "verify_release", "source": "cli"},
        ]
        with open(self.default_log_file, "w", encoding="utf-8") as f:
            for rec in self.canary_records:
                f.write(json.dumps(rec) + "\n")

        self.initial_sha256 = _compute_file_sha256(self.default_log_file)
        self.initial_size = self.default_log_file.stat().st_size

    def tearDown(self):
        pai_core_bridge.clear_shadow_log()
        self.tmpdir.cleanup()

    def _build_sub_env(self) -> Dict[str, str]:
        env = os.environ.copy()
        env["HOME"] = str(self.mock_home)
        env["USERPROFILE"] = str(self.mock_home)
        env["PAI_DIR"] = str(self.mock_default_dir)
        env.pop("PAI_SHADOW_LOG", None)
        env.pop("PAI_TELEMETRY_SOURCE", None)
        env.pop("PAI_DISABLE_TEST_LOG_ISOLATION", None)
        pypath = env.get("PYTHONPATH", "")
        paths = [_research_dir, _tests_dir, _repo_root]
        if pypath:
            paths.append(pypath)
        env["PYTHONPATH"] = os.pathsep.join(paths)
        return env

    def test_default_log_immutability_during_test_suites(self):
        """
        Finding AI: Executes real differential test module in a separate subprocess
        with a mock HOME, mock USERPROFILE, and NO PAI_SHADOW_LOG in environment.
        Verifies that _bootstrap.py redirects the log and the seeded default log's
        SHA-256 checksum remains strictly identical before and after execution.
        """
        env = self._build_sub_env()
        cmd = [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_ingest_differential.py"]
        proc = subprocess.run(cmd, cwd=_research_dir, env=env, capture_output=True, text=True, encoding="utf-8", errors="replace")
        self.assertEqual(proc.returncode, 0, f"Differential test module failed:\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}")

        final_sha256 = _compute_file_sha256(self.default_log_file)
        self.assertEqual(
            final_sha256,
            self.initial_sha256,
            "Default shadow log SHA-256 checksum changed during test execution! (Finding AI)",
        )
        self.assertEqual(
            self.default_log_file.stat().st_size,
            self.initial_size,
            "Default shadow log file size altered during test execution! (Finding AI)",
        )

    def test_default_log_immutability_during_parity_runner(self):
        """
        Finding AI: Executes real tools/windows_parity_run.py in a separate subprocess
        with a mock HOME, mock USERPROFILE, and NO PAI_SHADOW_LOG in environment.
        Verifies that the parity runner isolates its log and the seeded default log's
        SHA-256 checksum remains strictly identical before and after execution.
        """
        env = self._build_sub_env()
        runner_script = Path(_repo_root) / "tools" / "windows_parity_run.py"
        proc = subprocess.run([sys.executable, str(runner_script)], cwd=_repo_root, env=env, capture_output=True, text=True, encoding="utf-8", errors="replace")
        # On Windows or Linux/CI, runner completes 0 (or 5 if nested inside a restricted sandbox positive control)
        self.assertIn(proc.returncode, (0, 5), f"Parity runner failed with returncode {proc.returncode}:\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}")

        final_sha256 = _compute_file_sha256(self.default_log_file)
        self.assertEqual(
            final_sha256,
            self.initial_sha256,
            "Default shadow log SHA-256 altered by parity runner operations! (Finding AI)",
        )
        self.assertEqual(
            self.default_log_file.stat().st_size,
            self.initial_size,
            "Default shadow log file size altered during parity runner execution! (Finding AI)",
        )

    def test_shadow_isolation_mutation_check(self):
        """
        Finding AI: Mutation check verifying that when test isolation is disabled
        (PAI_DISABLE_TEST_LOG_ISOLATION=1), running a differential operation without
        isolation DOES mutate the default log, altering its SHA-256 checksum.
        This proves the guard test is discriminating and reliably catches isolation failure.
        """
        mut_env = self._build_sub_env()
        mut_env["PAI_DISABLE_TEST_LOG_ISOLATION"] = "1"
        code = (
            "import _bootstrap\n"
            "import pai_core_bridge\n"
            "pai_core_bridge.record_shadow_comparison('ingest_file')\n"
        )
        proc = subprocess.run([sys.executable, "-c", code], cwd=_research_dir, env=mut_env, capture_output=True, text=True, encoding="utf-8", errors="replace")
        self.assertEqual(proc.returncode, 0, f"Mutation subprocess failed:\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}")

        mutated_sha256 = _compute_file_sha256(self.default_log_file)
        self.assertNotEqual(
            mutated_sha256,
            self.initial_sha256,
            "Mutation check failed: Un-isolated test run failed to alter default log checksum!",
        )
        self.assertGreater(
            self.default_log_file.stat().st_size,
            self.initial_size,
            "Mutation check failed: Un-isolated test run did not increase default log size!",
        )

    def test_default_telemetry_source_is_unknown_and_safe(self):
        """
        Finding AH: Verifies that in a plain Python process without _bootstrap and
        without PAI_TELEMETRY_SOURCE in environment, get_telemetry_source() defaults
        to 'unknown'. Calling record_shadow_comparison() records source='unknown',
        does NOT increment cli_comparisons, and window_started remains False on a clean log.
        """
        fresh_log = self.mock_home / ".pai" / "fresh_test_log.jsonl"
        env = self._build_sub_env()
        env["PAI_SHADOW_LOG"] = str(fresh_log)
        code = (
            "import pai_core_bridge\n"
            "src = pai_core_bridge.get_telemetry_source()\n"
            "assert src == 'unknown', f'Expected default source unknown, got {src}'\n"
            "pai_core_bridge.record_shadow_comparison('ingest_file')\n"
            "summary = pai_core_bridge.get_shadow_telemetry_summary()\n"
            "assert summary['cli_comparisons'] == 0, f'Expected 0 cli_comparisons, got {summary[\"cli_comparisons\"]}'\n"
            "assert summary['window_started'] is False, 'Window should not start on unknown source'\n"
            "assert summary['sources']['unknown']['comparisons'] == 1, 'Unknown source comparison should be counted'\n"
            "print('OK')\n"
        )
        proc = subprocess.run([sys.executable, "-c", code], cwd=_research_dir, env=env, capture_output=True, text=True, encoding="utf-8", errors="replace")
        self.assertEqual(proc.returncode, 0, f"Default telemetry source check failed:\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}")
        self.assertEqual(proc.stdout.strip(), "OK")

    def test_clear_shadow_requires_yes_flag(self):
        """
        Finding AD: `pai clear-shadow` and `pai doctor --clear-shadow` must fail closed
        with exit code 1 if --yes is omitted, preserving the log intact.
        """
        with mock.patch("pathlib.Path.home", return_value=self.mock_home):
            with mock.patch.dict(os.environ, {"PAI_SHADOW_LOG": str(self.default_log_file)}):
                # 1. `pai clear-shadow` without --yes
                f_err = io.StringIO()
                with redirect_stderr(f_err):
                    rc = main(["clear-shadow"])
                self.assertEqual(rc, 1)
                self.assertIn("Pass --yes to confirm", f_err.getvalue())
                self.assertEqual(_compute_file_sha256(self.default_log_file), self.initial_sha256)

                # 2. `pai doctor --clear-shadow` without --yes
                f_err_doc = io.StringIO()
                with redirect_stderr(f_err_doc):
                    rc_doc = main(["doctor", "--clear-shadow"])
                self.assertEqual(rc_doc, 1)
                self.assertIn("Pass --yes to confirm", f_err_doc.getvalue())
                self.assertEqual(_compute_file_sha256(self.default_log_file), self.initial_sha256)

    def test_clear_shadow_archives_log_when_confirmed(self):
        """
        Finding AD: Confirmed clearing archives the existing file with a timestamp
        rather than silently truncating, preserving historical audit trails.
        """
        with mock.patch("pathlib.Path.home", return_value=self.mock_home):
            with mock.patch.dict(os.environ, {"PAI_SHADOW_LOG": str(self.default_log_file)}):
                f_out = io.StringIO()
                with redirect_stdout(f_out):
                    rc = main(["clear-shadow", "--yes"])
                self.assertEqual(rc, 0)
                out_msg = f_out.getvalue()
                self.assertIn("Shadow log archived to", out_msg)

                # Default log file should now either be empty or deleted (ready for new window)
                if self.default_log_file.exists():
                    self.assertEqual(self.default_log_file.stat().st_size, 0)

                # An archived file should exist in the same parent directory
                archived_files = list(self.mock_default_dir.glob("shadow_discrepancies_archived_*.jsonl"))
                self.assertEqual(len(archived_files), 1)
                archived_sha = _compute_file_sha256(archived_files[0])
                self.assertEqual(archived_sha, self.initial_sha256)

    def test_source_separation_quota_accounting(self):
        """
        Finding AE: Verifies that only records with source='cli' count toward cli_comparisons,
        and that the evaluation window status correctly reflects starting conditions.
        """
        test_log = Path(self.tmpdir.name) / "test_sources.jsonl"
        mixed_records = [
            {"timestamp": 1700000010.0, "type": "comparison", "op": "ingest_file", "source": "doctor"},
            {"timestamp": 1700000020.0, "type": "comparison", "op": "ingest_file", "source": "runner"},
            {"timestamp": 1700000030.0, "type": "comparison", "op": "ingest_folder", "source": "test"},
            {"timestamp": 1700000040.0, "type": "comparison", "op": "verify_verdict_frame", "source": "cli"},
            {"timestamp": 1700000050.0, "type": "comparison", "op": "ingest_file", "source": "cli"},
        ]
        with open(test_log, "w", encoding="utf-8") as f:
            for r in mixed_records:
                f.write(json.dumps(r) + "\n")

        with mock.patch.dict(os.environ, {"PAI_SHADOW_LOG": str(test_log)}):
            pai_core_bridge.clear_shadow_log()
            # Re-write since clear_shadow_log archived the test_log
            with open(test_log, "w", encoding="utf-8") as f:
                for r in mixed_records:
                    f.write(json.dumps(r) + "\n")
            summary = pai_core_bridge.get_shadow_telemetry_summary()
            self.assertEqual(summary["total_comparisons"], 5)
            self.assertEqual(summary["cli_comparisons"], 2)
            self.assertEqual(summary["cli_discrepancies"], 0)
            self.assertTrue(summary["window_started"])
            self.assertTrue(summary["window_active"])
            self.assertEqual(summary["sources"]["doctor"]["comparisons"], 1)
            self.assertEqual(summary["sources"]["runner"]["comparisons"], 1)
            self.assertEqual(summary["sources"]["test"]["comparisons"], 1)
            self.assertEqual(summary["sources"]["cli"]["comparisons"], 2)

    def test_window_not_started_without_cli_comparisons(self):
        """
        Finding AE: If only synthetic (doctor, runner, test, unknown) comparisons exist,
        window_started must be False and first_cli_comparison_iso must be None.
        """
        synthetic_log = Path(self.tmpdir.name) / "synthetic.jsonl"
        synthetic_records = [
            {"timestamp": 1700000010.0, "type": "comparison", "op": "ingest_file", "source": "doctor"},
            {"timestamp": 1700000020.0, "type": "comparison", "op": "verify_release", "source": "runner"},
            {"timestamp": 1700000030.0, "type": "comparison", "op": "ingest_folder", "source": "unknown"},
        ]
        with open(synthetic_log, "w", encoding="utf-8") as f:
            for r in synthetic_records:
                f.write(json.dumps(r) + "\n")

        with mock.patch.dict(os.environ, {"PAI_SHADOW_LOG": str(synthetic_log)}):
            pai_core_bridge.clear_shadow_log()
            with open(synthetic_log, "w", encoding="utf-8") as f:
                for r in synthetic_records:
                    f.write(json.dumps(r) + "\n")
            summary = pai_core_bridge.get_shadow_telemetry_summary()
            self.assertEqual(summary["total_comparisons"], 3)
            self.assertEqual(summary["cli_comparisons"], 0)
            self.assertFalse(summary["window_started"])
            self.assertFalse(summary["window_active"])
            self.assertIsNone(summary["first_cli_comparison_iso"])

    def test_corrupt_lines_detected_and_invalidate_window(self):
        """
        Finding AF: Non-JSON / corrupt lines in the shadow log must be reported in
        corrupt_lines, treated as discrepancies, and disqualify window_active.
        """
        corrupt_log = Path(self.tmpdir.name) / "corrupt.jsonl"
        with open(corrupt_log, "w", encoding="utf-8") as f:
            f.write(json.dumps({"timestamp": 1700000010.0, "type": "comparison", "op": "ingest_file", "source": "cli"}) + "\n")
            f.write("CORRUPT_NON_JSON_LINE_GARBAGE\n")
            f.write(json.dumps({"timestamp": 1700000020.0, "type": "comparison", "op": "ingest_file", "source": "cli"}) + "\n")

        with mock.patch.dict(os.environ, {"PAI_SHADOW_LOG": str(corrupt_log)}):
            pai_core_bridge.clear_shadow_log()
            with open(corrupt_log, "w", encoding="utf-8") as f:
                f.write(json.dumps({"timestamp": 1700000010.0, "type": "comparison", "op": "ingest_file", "source": "cli"}) + "\n")
                f.write("CORRUPT_NON_JSON_LINE_GARBAGE\n")
                f.write(json.dumps({"timestamp": 1700000020.0, "type": "comparison", "op": "ingest_file", "source": "cli"}) + "\n")
            summary = pai_core_bridge.get_shadow_telemetry_summary()
            self.assertEqual(summary["total_comparisons"], 2)
            self.assertEqual(summary["corrupt_lines"], 1)
            self.assertGreaterEqual(summary["total_discrepancies"], 1)
            self.assertTrue(summary["window_started"])
            self.assertFalse(summary["window_active"], "Corrupt lines must invalidate active window (Finding AF)")

    def test_log_write_failure_invalidates_window(self):
        """
        Finding AK: Verifies that if writing a discrepancy to the log file fails
        (e.g., disk I/O error), log_write_failures is incremented, treated
        as an invalidating event in get_shadow_telemetry_summary(), and window_active becomes False.
        """
        test_log = Path(self.tmpdir.name) / "write_fail.jsonl"
        with mock.patch.dict(os.environ, {"PAI_SHADOW_LOG": str(test_log)}):
            pai_core_bridge.clear_shadow_log()
            # Seed one clean CLI comparison to start the window
            pai_core_bridge.record_shadow_comparison("ingest_file", source="cli")
            summary_clean = pai_core_bridge.get_shadow_telemetry_summary()
            self.assertTrue(summary_clean["window_started"])
            self.assertTrue(summary_clean["window_active"])

            # Simulate write failure in open()
            with mock.patch("builtins.open", side_effect=OSError("Disk write error [WinError 112]")):
                pai_core_bridge.record_shadow_discrepancy("ingest_file", "Test mismatch during write failure")

            summary_after = pai_core_bridge.get_shadow_telemetry_summary()
            self.assertGreater(summary_after["log_write_failures"], 0)
            self.assertFalse(summary_after["window_active"], "Write failure must disqualify active window (Finding AK)")

    def test_window_complete_conditions(self):
        """
        Finding AK: Verifies that window_complete is strictly computed based on:
        1. window_active is True
        2. cli_comparisons >= 1000
        3. All per-operation quotas satisfied (ingest_file >= 600, ingest_folder >= 150, verify_verdict_frame >= 25)
        4. Elapsed CLI span >= 7 days (604,800 seconds)
        """
        test_log = Path(self.tmpdir.name) / "window_complete_test.jsonl"
        with mock.patch.dict(os.environ, {"PAI_SHADOW_LOG": str(test_log)}):
            pai_core_bridge.clear_shadow_log()

            # Case 1: Incomplete volume (< 1000)
            now = 1700000000.0
            recs_under = []
            for i in range(500):
                recs_under.append({"timestamp": now + i, "type": "comparison", "op": "ingest_file", "source": "cli"})
            with open(test_log, "w", encoding="utf-8") as f:
                for r in recs_under:
                    f.write(json.dumps(r) + "\n")

            s1 = pai_core_bridge.get_shadow_telemetry_summary()
            self.assertTrue(s1["window_active"])
            self.assertFalse(s1["window_complete"], "Window should not be complete with 500 comparisons")

            # Case 2: Complete volume (1000) but short time span (under 7 days)
            recs_span_short = []
            for i in range(600):
                recs_span_short.append({"timestamp": now + i * 10, "type": "comparison", "op": "ingest_file", "source": "cli"})
            for i in range(200):
                recs_span_short.append({"timestamp": now + i * 10, "type": "comparison", "op": "ingest_folder", "source": "cli"})
            for i in range(200):
                recs_span_short.append({"timestamp": now + i * 10, "type": "comparison", "op": "verify_verdict_frame", "source": "cli"})
            with open(test_log, "w", encoding="utf-8") as f:
                for r in recs_span_short:
                    f.write(json.dumps(r) + "\n")

            s2 = pai_core_bridge.get_shadow_telemetry_summary()
            self.assertTrue(s2["quotas_met"])
            self.assertFalse(s2["span_met"], "Span should not be met under 7 days")
            self.assertFalse(s2["window_complete"])

            # Case 3: Complete volume, quotas met, AND span >= 7 days (604,800s)
            span_7d = 7 * 86400.0 + 100.0
            recs_complete = list(recs_span_short)
            recs_complete.append({"timestamp": now + span_7d, "type": "comparison", "op": "ingest_file", "source": "cli"})
            with open(test_log, "w", encoding="utf-8") as f:
                for r in recs_complete:
                    f.write(json.dumps(r) + "\n")

            s3 = pai_core_bridge.get_shadow_telemetry_summary()
            self.assertTrue(s3["quotas_met"])
            self.assertTrue(s3["span_met"])
            self.assertTrue(s3["window_complete"], "All criteria satisfied: window_complete must be True")


if __name__ == "__main__":
    unittest.main()
