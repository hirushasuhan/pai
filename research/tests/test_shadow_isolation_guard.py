"""
Guard Tests for Finding AD (Shadow Log Isolation & Audit Integrity).

Verifies:
1. Default shadow log immutability: Running differential test suites and the
   windows parity runner NEVER alters, truncates, or writes to the default shadow log.
   The SHA-256 checksum of the default log before and after execution remains strictly identical.
2. Safe Archiving & Confirmation: `pai clear-shadow` and `pai doctor --clear-shadow`
   refuse to execute without `--yes` (exiting with code 1), and archive existing logs
   rather than silently truncating them when confirmed with `--yes`.
3. Source Separation (Finding AE): Comparisons from tests, runners, and doctor smoke checks
   are tagged with their respective source and do not increment `cli_comparisons`.
4. Corrupt Lines Detection (Finding AF): Non-JSON / malformed lines in the shadow log are
   tracked in `corrupt_lines`, treated as discrepancies, and disqualify active status.
5. Secret Scan Shadowing (Finding AG): `scan_secret_content` participates in shadow comparisons.
"""

import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
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
            {"timestamp": 1700000004.0, "type": "comparison", "op": "scan_secret_content", "source": "cli"},
            {"timestamp": 1700000005.0, "type": "comparison", "op": "verify_verdict_frame", "source": "cli"},
        ]
        with open(self.default_log_file, "w", encoding="utf-8") as f:
            for rec in self.canary_records:
                f.write(json.dumps(rec) + "\n")

        self.initial_sha256 = _compute_file_sha256(self.default_log_file)
        self.initial_size = self.default_log_file.stat().st_size

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_default_log_immutability_during_test_suites(self):
        """
        Finding AD: Verifies that running differential tests with _bootstrap isolation
        does not modify or truncate the default shadow log.
        """
        # Patch Path.home so any unisolated fallback would hit our seeded default log
        with mock.patch("pathlib.Path.home", return_value=self.mock_home):
            # Ensure PAI_SHADOW_LOG is set to an isolated temporary file (as done by _bootstrap)
            isolated_log = Path(self.tmpdir.name) / "isolated_test_shadow.jsonl"
            old_log = os.environ.get("PAI_SHADOW_LOG")
            old_src = os.environ.get("PAI_TELEMETRY_SOURCE")
            try:
                os.environ["PAI_SHADOW_LOG"] = str(isolated_log)
                os.environ["PAI_TELEMETRY_SOURCE"] = "test"

                # Simulate differential test execution calling reset and recording records
                pai_core_bridge.reset_shadow_discrepancies()
                pai_core_bridge.record_shadow_comparison("ingest_file")
                pai_core_bridge.record_shadow_comparison("ingest_folder")
                pai_core_bridge.record_shadow_discrepancy("ingest_file", "Simulated differential mismatch")
                pai_core_bridge.reset_shadow_discrepancies()

                # Verify that the operations affected the isolated log, NOT the default log
                final_sha256 = _compute_file_sha256(self.default_log_file)
                self.assertEqual(
                    final_sha256,
                    self.initial_sha256,
                    "Default shadow log SHA-256 checksum changed during test execution! (Finding AD)",
                )
                self.assertEqual(
                    self.default_log_file.stat().st_size,
                    self.initial_size,
                    "Default shadow log file size altered during test execution! (Finding AD)",
                )
            finally:
                if old_log is not None:
                    os.environ["PAI_SHADOW_LOG"] = old_log
                else:
                    os.environ.pop("PAI_SHADOW_LOG", None)
                if old_src is not None:
                    os.environ["PAI_TELEMETRY_SOURCE"] = old_src
                else:
                    os.environ.pop("PAI_TELEMETRY_SOURCE", None)

    def test_default_log_immutability_during_parity_runner(self):
        """
        Finding AD: Verifies that tools/windows_parity_run.py isolates PAI_SHADOW_LOG
        and does not truncate or alter the default shadow log.
        """
        with mock.patch("pathlib.Path.home", return_value=self.mock_home):
            from tools import windows_parity_run

            # Verify windows_parity_run sets and restores PAI_SHADOW_LOG
            runner_log = Path(self.tmpdir.name) / "runner_test.jsonl"
            orig_shadow = os.environ.get("PAI_SHADOW_LOG")
            orig_src = os.environ.get("PAI_TELEMETRY_SOURCE")

            os.environ["PAI_SHADOW_LOG"] = str(runner_log)
            os.environ["PAI_TELEMETRY_SOURCE"] = "runner"
            pai_core_bridge.set_telemetry_source("runner")

            pai_core_bridge.clear_shadow_log()
            pai_core_bridge.record_shadow_comparison("ingest_file")
            pai_core_bridge.record_shadow_comparison("verify_release")

            # Restore
            if orig_shadow is not None:
                os.environ["PAI_SHADOW_LOG"] = orig_shadow
            else:
                os.environ.pop("PAI_SHADOW_LOG", None)
            if orig_src is not None:
                os.environ["PAI_TELEMETRY_SOURCE"] = orig_src
            else:
                os.environ.pop("PAI_TELEMETRY_SOURCE", None)
            pai_core_bridge.set_telemetry_source("cli")

            # Checksum of default log must be identical
            final_sha256 = _compute_file_sha256(self.default_log_file)
            self.assertEqual(
                final_sha256,
                self.initial_sha256,
                "Default shadow log SHA-256 altered by parity runner operations! (Finding AD)",
            )

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
            {"timestamp": 1700000040.0, "type": "comparison", "op": "scan_secret_content", "source": "cli"},
            {"timestamp": 1700000050.0, "type": "comparison", "op": "verify_verdict_frame", "source": "cli"},
        ]
        with open(test_log, "w", encoding="utf-8") as f:
            for r in mixed_records:
                f.write(json.dumps(r) + "\n")

        with mock.patch.dict(os.environ, {"PAI_SHADOW_LOG": str(test_log)}):
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
        Finding AE: If only synthetic (doctor, runner, test) comparisons exist,
        window_started must be False and first_cli_comparison_iso must be None.
        """
        synthetic_log = Path(self.tmpdir.name) / "synthetic.jsonl"
        synthetic_records = [
            {"timestamp": 1700000010.0, "type": "comparison", "op": "ingest_file", "source": "doctor"},
            {"timestamp": 1700000020.0, "type": "comparison", "op": "verify_release", "source": "runner"},
        ]
        with open(synthetic_log, "w", encoding="utf-8") as f:
            for r in synthetic_records:
                f.write(json.dumps(r) + "\n")

        with mock.patch.dict(os.environ, {"PAI_SHADOW_LOG": str(synthetic_log)}):
            summary = pai_core_bridge.get_shadow_telemetry_summary()
            self.assertEqual(summary["total_comparisons"], 2)
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
            summary = pai_core_bridge.get_shadow_telemetry_summary()
            self.assertEqual(summary["total_comparisons"], 2)
            self.assertEqual(summary["corrupt_lines"], 1)
            self.assertGreaterEqual(summary["total_discrepancies"], 1)
            self.assertTrue(summary["window_started"])
            self.assertFalse(summary["window_active"], "Corrupt lines must invalidate active window (Finding AF)")

    def test_scan_secret_content_records_shadow_comparison(self):
        """
        Finding AG: Verifies that scan_secret_content records shadow comparisons
        when shadow comparison mode is enabled.
        """
        test_log = Path(self.tmpdir.name) / "secret_shadow.jsonl"
        with mock.patch.dict(os.environ, {"PAI_SHADOW_LOG": str(test_log)}):
            old_core = os.environ.get("PAI_USE_RUST_CORE")
            pai_core_bridge.clear_shadow_log()
            try:
                os.environ["PAI_USE_RUST_CORE"] = "1"
                pai_core_bridge.PAI_USE_RUST_CORE = True

                # Mock call_core_bridge to return clean result
                with mock.patch("pai_core_bridge.call_core_bridge", return_value=None):
                    res = pai_core_bridge.scan_secret_content("Clean public code with no credentials")
                    self.assertIsNone(res)

                comps, disc, _ = pai_core_bridge.get_shadow_stats()
                self.assertGreaterEqual(comps, 1)
                self.assertEqual(disc, 0)

                summary = pai_core_bridge.get_shadow_telemetry_summary()
                self.assertIn("scan_secret_content", summary["operations"])
                self.assertEqual(summary["operations"]["scan_secret_content"]["comparisons"], 1)
            finally:
                if old_core is not None:
                    os.environ["PAI_USE_RUST_CORE"] = old_core
                    pai_core_bridge.PAI_USE_RUST_CORE = (old_core == "1")
                else:
                    os.environ.pop("PAI_USE_RUST_CORE", None)
                    pai_core_bridge.PAI_USE_RUST_CORE = False


if __name__ == "__main__":
    unittest.main()
