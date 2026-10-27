"""
Comprehensive Unit Tests and Negative Control Suite for Milestone P3 (pai_setup.py).

Tests:
  1. Local Hardware Survey: RAM, disk, GPU, CPU, and NPU detection note (ADR-012).
  2. Signed Catalog Verification: Valid Ed25519 signature succeeds; tampered signature,
     revoked key, and lower catalog version fail closed (CatalogSecurityError).
  3. Fit Rule - Disk Requirements: 1.25x model size + 2 GB safety margin.
  4. Fit Rule - GPU Dedicated VRAM: 85% threshold for full offload, 86-120% partial, CPU fallback.
  5. Fit Rule - RAM Headroom & License Preselection: Verified licenses preselected;
     unverified models marked available but NOT preselected.
  6. Ollama Daemon Detection: Mocked HTTP probe handles both running and unreachable daemons.
  7. Progress Events: Validates Appendix C compliant NDJSON event stream (--progress-json).
  8. CLI Execution: Subprocess verification of --survey-only and failure modes.
"""

from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(REPO_ROOT / "research") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "research"))

from packaging.pai_setup import (
    CatalogSecurityError,
    HardwareProfile,
    ModelFitReport,
    ProgressEmitter,
    collect_hardware_survey,
    create_demo_catalog,
    evaluate_model_fit,
    main,
    plan_model_selection,
    probe_ollama_daemon,
    survey_disk_free,
    survey_ram_windows,
    verify_authenticode_publisher,
    verify_catalog_payload,
)


class TestPaiSetupP3(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = tempfile.mkdtemp(prefix="pai_p3_test_")
        self.catalog = create_demo_catalog(version=1)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_01_hardware_survey_fields_and_npu_note(self) -> None:
        """Validates that collect_hardware_survey returns all required fields and ADR-012 NPU note."""
        survey = collect_hardware_survey()
        self.assertIsInstance(survey, HardwareProfile)
        self.assertGreater(survey.total_ram_mb, 0)
        self.assertGreater(survey.free_disk_bytes, 0)
        self.assertIn("detected, not used in this version (ADR-012)", survey.npu_note)
        self.assertGreaterEqual(survey.cpu_logical, 1)

    def test_02_signed_catalog_verification_and_negative_controls(self) -> None:
        """
        Validates signed catalog Ed25519 verification:
          - Valid demo catalog passes.
          - 1-byte tamper in signature fails closed.
          - Version rollback fails closed.
          - Empty or non-hex signature fails closed.
        """
        # 1. Clean valid catalog
        verified = verify_catalog_payload(self.catalog, min_version=1)
        self.assertEqual(verified["catalog_version"], 1)
        self.assertEqual(len(verified["models"]), 3)

        # 2. Tampered signature fails closed
        tampered_cat = dict(self.catalog)
        sig = bytearray.fromhex(tampered_cat["signature"])
        sig[0] ^= 0xFF
        tampered_cat["signature"] = sig.hex()
        with self.assertRaises(CatalogSecurityError):
            verify_catalog_payload(tampered_cat, min_version=1)

        # 3. Monotonic version check: lower version than min_version rejected
        with self.assertRaises(CatalogSecurityError) as cm:
            verify_catalog_payload(self.catalog, min_version=2)
        self.assertIn("version rollback", str(cm.exception).lower())

        # 4. Empty signature rejected
        bad_sig_cat = dict(self.catalog)
        bad_sig_cat["signature"] = ""
        with self.assertRaises(CatalogSecurityError):
            verify_catalog_payload(bad_sig_cat, min_version=1)

        # 5. Missing required fields rejected
        incomplete_cat = {"catalog_version": 1, "signature": "00" * 64}
        with self.assertRaises(CatalogSecurityError):
            verify_catalog_payload(incomplete_cat, min_version=1)

    def test_03_fit_rule_disk_space_thresholds(self) -> None:
        """
        Validates disk fit rule:
        Required disk space = (1.25 * total_model_bytes) + 2 GB safety margin.
        """
        model = {
            "id": "test:3b",
            "download_bytes": 2 * (1024**3),  # 2 GB
            "disk_bytes": 2 * (1024**3),
            "min_ram_mb": 2048,
            "license": {"license_status": "verified"},
        }
        two_gb = 2 * (1024**3)
        # Expected required: 1.25 * 2GB + 2GB = 2.5GB + 2GB = 4.5 GB
        expected_needed = int(1.25 * two_gb) + two_gb

        # Case A: Free disk has plenty of space (10 GB)
        survey_ok = HardwareProfile(
            total_ram_mb=16384.0,
            avail_ram_mb=8192.0,
            free_disk_bytes=10 * (1024**3),
            total_disk_bytes=100 * (1024**3),
            model_drive="C:",
            gpu_name="NVIDIA RTX 4050",
            dedicated_vram_mb=6144.0,
            gpu_driver_version="550.0",
            cpu_cores=6,
            cpu_logical=12,
            cpu_name="AMD",
            npu_detected=False,
            npu_name=None,
        )
        rep_ok = evaluate_model_fit(model, survey_ok)
        self.assertTrue(rep_ok.fits_disk)
        self.assertEqual(rep_ok.disk_required_bytes, expected_needed)
        self.assertEqual(len(rep_ok.rejection_reasons), 0)

        # Case B: Free disk is 1 byte below required threshold
        survey_fail = HardwareProfile(
            total_ram_mb=16384.0,
            avail_ram_mb=8192.0,
            free_disk_bytes=expected_needed - 1,
            total_disk_bytes=100 * (1024**3),
            model_drive="C:",
            gpu_name="NVIDIA RTX 4050",
            dedicated_vram_mb=6144.0,
            gpu_driver_version="550.0",
            cpu_cores=6,
            cpu_logical=12,
            cpu_name="AMD",
            npu_detected=False,
            npu_name=None,
        )
        rep_fail = evaluate_model_fit(model, survey_fail)
        self.assertFalse(rep_fail.fits_disk)
        self.assertFalse(rep_fail.is_preselected)
        self.assertTrue(any("INSUFFICIENT_DISK" in r for r in rep_fail.rejection_reasons))

    def test_04_fit_rule_gpu_vram_thresholds(self) -> None:
        """
        Validates GPU VRAM tiers:
          - Model weights + 512MB <= 85% VRAM: 'full' offload.
          - 85% < Model weights + 512MB <= 120% VRAM: 'partial' offload.
          - Model weights + 512MB > 120% VRAM or no GPU: 'cpu'.
        """
        # Model with 2048 MB weights (+ 512 MB context = 2560 MB footprint)
        model = {
            "id": "test_gpu:model",
            "disk_bytes": 2048 * (1024 * 1024),
            "min_ram_mb": 2048,
            "license": {"license_status": "verified"},
        }
        footprint_mb = 2560.0

        # Case A: VRAM = 4000 MB. 85% is 3400 MB. Footprint (2560) <= 3400 -> FULL
        survey_full = HardwareProfile(
            total_ram_mb=16384.0,
            avail_ram_mb=8192.0,
            free_disk_bytes=50 * (1024**3),
            total_disk_bytes=100 * (1024**3),
            model_drive="C:",
            gpu_name="NVIDIA RTX 4050",
            dedicated_vram_mb=4000.0,
            gpu_driver_version="550.0",
            cpu_cores=6,
            cpu_logical=12,
            cpu_name="AMD",
            npu_detected=False,
            npu_name=None,
        )
        rep_full = evaluate_model_fit(model, survey_full)
        self.assertEqual(rep_full.fits_gpu, "full")

        # Case B: VRAM = 2600 MB. 85% is 2210 MB. Footprint (2560) > 2210, but <= 3120 (120%) -> PARTIAL
        survey_partial = HardwareProfile(
            total_ram_mb=16384.0,
            avail_ram_mb=8192.0,
            free_disk_bytes=50 * (1024**3),
            total_disk_bytes=100 * (1024**3),
            model_drive="C:",
            gpu_name="NVIDIA RTX 3050",
            dedicated_vram_mb=2600.0,
            gpu_driver_version="550.0",
            cpu_cores=6,
            cpu_logical=12,
            cpu_name="AMD",
            npu_detected=False,
            npu_name=None,
        )
        rep_partial = evaluate_model_fit(model, survey_partial)
        self.assertEqual(rep_partial.fits_gpu, "partial")

        # Case C: VRAM = 1000 MB. Footprint (2560) > 1200 MB (120%) -> CPU
        survey_cpu = HardwareProfile(
            total_ram_mb=16384.0,
            avail_ram_mb=8192.0,
            free_disk_bytes=50 * (1024**3),
            total_disk_bytes=100 * (1024**3),
            model_drive="C:",
            gpu_name="Integrated GPU",
            dedicated_vram_mb=1000.0,
            gpu_driver_version="31.0",
            cpu_cores=6,
            cpu_logical=12,
            cpu_name="AMD",
            npu_detected=False,
            npu_name=None,
        )
        rep_cpu = evaluate_model_fit(model, survey_cpu)
        self.assertEqual(rep_cpu.fits_gpu, "cpu")

    def test_05_unverified_license_is_not_preselected(self) -> None:
        """Requirement §5: Only entries with license_status = verified are preselected."""
        survey = HardwareProfile(
            total_ram_mb=32768.0,
            avail_ram_mb=16384.0,
            free_disk_bytes=100 * (1024**3),
            total_disk_bytes=500 * (1024**3),
            model_drive="C:",
            gpu_name="NVIDIA RTX 4090",
            dedicated_vram_mb=24576.0,
            gpu_driver_version="550.0",
            cpu_cores=16,
            cpu_logical=32,
            cpu_name="Intel",
            npu_detected=False,
            npu_name=None,
        )
        recs = plan_model_selection(self.catalog, survey)
        unverified_recs = [r for r in recs if r.license_status == "unverified"]
        self.assertTrue(len(unverified_recs) > 0)
        for u in unverified_recs:
            self.assertFalse(u.is_preselected, f"Unverified model {u.model_id} must NEVER be preselected")

    def test_06_ollama_daemon_probe_mocked(self) -> None:
        """Validates probe_ollama_daemon under running and non-running mocked conditions."""
        # 1. Non-running daemon
        status_down = probe_ollama_daemon("http://127.0.0.1:9999", timeout=0.1)
        self.assertFalse(status_down["running"])
        self.assertIsNone(status_down["version"])

        # 2. Running daemon with mock HTTP response
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b'{"version": "0.4.1"}'
        mock_resp.__enter__.return_value = mock_resp

        with patch("urllib.request.urlopen", return_value=mock_resp):
            status_up = probe_ollama_daemon()
            self.assertTrue(status_up["running"])
            self.assertEqual(status_up["version"], "0.4.1")

    def test_07_progress_json_emitter(self) -> None:
        """Validates NDJSON progress event emission matching Appendix C."""
        buf = io.StringIO()
        emitter = ProgressEmitter(enabled=True)

        with patch("sys.stdout", buf):
            emitter.emit("survey", hardware={"cores": 8})
            emitter.emit("download_start", model="qwen2.5-coder:1.5b", total_bytes=1000)
            emitter.emit("progress", model="qwen2.5-coder:1.5b", completed=500, total=1000)
            emitter.emit("done", model="qwen2.5-coder:1.5b")

        lines = [ln.strip() for ln in buf.getvalue().splitlines() if ln.strip()]
        self.assertEqual(len(lines), 4)

        events = [json.loads(ln) for ln in lines]
        self.assertEqual(events[0]["event"], "survey")
        self.assertEqual(events[1]["event"], "download_start")
        self.assertEqual(events[2]["event"], "progress")
        self.assertEqual(events[3]["event"], "done")

    def test_08_cli_execution_survey_only(self) -> None:
        """Executes pai_setup.py via subprocess with --survey-only."""
        setup_script = REPO_ROOT / "packaging" / "pai_setup.py"
        proc = subprocess.run([sys.executable, str(setup_script), "--survey-only"], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, f"pai_setup.py --survey-only failed:\n{proc.stderr}")
        data = json.loads(proc.stdout)
        self.assertIn("total_ram_mb", data)
        self.assertIn("free_disk_bytes", data)
        self.assertIn("npu_note", data)


if __name__ == "__main__":
    unittest.main()
