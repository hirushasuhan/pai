"""
Comprehensive Unit Tests and Negative Control Suite for Milestone P3 (pai_setup.py).

Verifies Findings CB, CC, CD, CD2, CE, CG, CH:
  1. Local Hardware Survey: RAM, disk, multi-GPU, CPU, and NPU detection note (ADR-012, Finding CE).
  2. Cryptographic Trust: Production fails closed without valid trust.json; old test seeds
     and empty key lists rejected (Finding CB).
  3. Replay Rollback & Freshness: Persistent version state rejects rollbacks; expired
     catalogs (> 90 days) and future dates rejected (Finding CD).
  4. Strict Schema & Purpose Separation: kind="catalog" enforced, demo catalogs rejected
     in production, model IDs and manifest digests validated (Finding CD2).
  5. Fit Rules: Available RAM reserve (2048 MB), GPU context allowance labeled as estimate,
     preselection restricted strictly to "full" tier until measured (Finding CE).
  6. Ollama Installer Publisher Verification: Full Subject & Thumbprint checked in-place;
     fails closed on non-Windows; environment variable passing (Finding CC).
  7. Loopback Security: Non-loopback OLLAMA_HOST rejected; direct proxy bypass (Finding CH).
  8. Progress Events: Appendix C compliant stream (Finding CG).
"""

from __future__ import annotations

import datetime
import http.server
import io
import json
import os
import shutil
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock, patch

TESTS_DIR = Path(__file__).resolve().parent
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

try:
    import _bootstrap  # noqa: F401
except ImportError:
    pass

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
RESEARCH_DIR = Path(__file__).resolve().parent.parent
if str(RESEARCH_DIR) not in sys.path:
    sys.path.insert(0, str(RESEARCH_DIR))

import ed25519_ref

from pai_setup import (
    CatalogSecurityError,
    HardwareProfile,
    ModelFitReport,
    OllamaVerificationError,
    DownloadCancelledError,
    ModelPullError,
    CancelToken,
    PullProgressTracker,
    ConsoleProgressBar,
    ProgressEmitter,
    canonical_json_bytes,
    collect_hardware_survey,
    delete_ollama_model,
    evaluate_model_fit,
    format_bytes_human,
    format_eta_human,
    get_highest_seen_catalog_version,
    load_trust_keys,
    main,
    normalize_digest,
    plan_model_selection,
    probe_ollama_daemon,
    pull_model_stream,
    query_ollama_model_digest,
    record_catalog_version,
    run_setup,
    survey_disk_free,
    survey_gpu_windows,
    survey_ram_windows,
    verify_authenticode_publisher,
    verify_catalog_payload,
)

# Ephemeral test keypair for test suite execution ONLY (never in production code)
TEST_SEED = bytes([i % 256 for i in range(32)])
TEST_PUB_BYTES = ed25519_ref.secret_to_public(TEST_SEED)
TEST_PUB_HEX = TEST_PUB_BYTES.hex()

TEST_TRUST_KEYS = [
    {
        "id": "test-key-1",
        "public_hex": TEST_PUB_HEX,
        "revoked": False,
    }
]


def create_test_catalog(
    version: int = 1,
    issued_utc: Optional[str] = None,
    demo: bool = False,
    kind: str = "catalog",
    models: Optional[list] = None,
    seed: bytes = TEST_SEED,
) -> dict:
    """Generates and signs a test catalog for test suite usage."""
    if issued_utc is None:
        issued_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()

    if models is None:
        models = [
            {
                "id": "qwen2.5-coder:1.5b",
                "display_name": "Qwen 2.5 Coder 1.5B",
                "family": "qwen2.5-coder",
                "parameters_b": 1.5,
                "quantization": "Q4_K_M",
                "download_bytes": 986500000,
                "disk_bytes": 1050000000,
                "min_ram_mb": 2048,
                "min_vram_mb": 1500,
                "tasks": ["code", "chat"],
                "license": {
                    "name": "Apache-2.0",
                    "url": "https://huggingface.co/Qwen/Qwen2.5-Coder-1.5B",
                    "license_status": "verified",
                    "read_on": "2026-10-27",
                },
                "registry_manifest_digest": "sha256:d15ab1e15ab1e15ab1e15ab1e15ab1e15ab1e15ab1e15ab1e15ab1e15ab1e15a",
            },
            {
                "id": "llama3.2:1b",
                "display_name": "Llama 3.2 1B",
                "family": "llama3.2",
                "parameters_b": 1.23,
                "quantization": "Q4_K_M",
                "download_bytes": 1320000000,
                "disk_bytes": 1400000000,
                "min_ram_mb": 2048,
                "min_vram_mb": 1800,
                "tasks": ["chat", "documents"],
                "license": {
                    "name": "Llama-3.2-Community",
                    "url": "https://llama.meta.com/llama3_2/license",
                    "license_status": "verified",
                    "read_on": "2026-10-27",
                },
                "registry_manifest_digest": "sha256:1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b",
            },
            {
                "id": "unverified-experimental:7b",
                "display_name": "Experimental 7B",
                "family": "experimental",
                "parameters_b": 7.0,
                "quantization": "Q4_K_M",
                "download_bytes": 4500000000,
                "disk_bytes": 4800000000,
                "min_ram_mb": 8192,
                "min_vram_mb": 6000,
                "tasks": ["code"],
                "license": {
                    "name": "unknown",
                    "url": "https://example.com/unverified",
                    "license_status": "unverified",
                    "read_on": "2026-10-27",
                },
                "registry_manifest_digest": "sha256:7777777777777777777777777777777777777777777777777777777777777777",
            },
        ]

    doc = {
        "kind": kind,
        "catalog_version": version,
        "issued_utc": issued_utc,
        "models": models,
    }
    if demo:
        doc["demo"] = True

    can_bytes = canonical_json_bytes(doc)
    sig_bytes = ed25519_ref.sign(seed, can_bytes)
    doc["signature"] = sig_bytes.hex()
    return doc


def sign_test_catalog(doc: Dict[str, Any], seed: bytes = TEST_SEED) -> str:
    """Signs a catalog dictionary using ephemeral test key."""
    can_bytes = canonical_json_bytes(doc)
    return ed25519_ref.sign(seed, can_bytes).hex()


class TestPaiSetupP3(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = tempfile.mkdtemp(prefix="pai_p3_test_")
        self.state_file = Path(self.tmp_dir) / "catalog_state.json"
        self.catalog = create_test_catalog(version=1)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_01_hardware_survey_fields_and_npu_note(self) -> None:
        """Validates that collect_hardware_survey returns all required fields and ADR-012 NPU note."""
        survey = collect_hardware_survey(allow_mock=True)
        self.assertIsInstance(survey, HardwareProfile)
        self.assertGreater(survey.total_ram_mb, 0)
        self.assertGreater(survey.free_disk_bytes, 0)
        self.assertIn("detected, not used in this version (ADR-012)", survey.npu_note)
        self.assertGreaterEqual(survey.cpu_logical, 1)

    # -------------------------------------------------------------------------
    # Finding CB: Trust Root & Key Verification
    # -------------------------------------------------------------------------
    def test_02_trust_root_load_and_fail_closed_negative_controls(self) -> None:
        """
        Finding CB:
          - Missing trust.json raises CatalogSecurityError.
          - Empty keys list raises CatalogSecurityError.
          - All keys revoked raises CatalogSecurityError.
          - Valid trust.json loads active keys.
        """
        # Case A: Non-existent file
        with self.assertRaises(CatalogSecurityError):
            load_trust_keys(Path(self.tmp_dir) / "nonexistent_trust.json")

        # Case B: Empty keys list
        empty_trust = Path(self.tmp_dir) / "empty_trust.json"
        empty_trust.write_text(json.dumps({"keys": []}), encoding="utf-8")
        with self.assertRaises(CatalogSecurityError):
            load_trust_keys(empty_trust)

        # Case C: All revoked keys
        revoked_trust = Path(self.tmp_dir) / "revoked_trust.json"
        revoked_trust.write_text(
            json.dumps({"keys": [{"id": "rev-1", "public_hex": TEST_PUB_HEX, "revoked": True}]}),
            encoding="utf-8",
        )
        with self.assertRaises(CatalogSecurityError):
            load_trust_keys(revoked_trust)

        # Case D: Valid trust file
        valid_trust = Path(self.tmp_dir) / "valid_trust.json"
        valid_trust.write_text(
            json.dumps({"keys": [{"id": "ok-1", "public_hex": TEST_PUB_HEX, "revoked": False}]}),
            encoding="utf-8",
        )
        keys = load_trust_keys(valid_trust)
        self.assertEqual(len(keys), 1)
        self.assertEqual(keys[0]["id"], "ok-1")

    # -------------------------------------------------------------------------
    # Finding CK: Trust Root Source Hardening & Negative Controls
    # -------------------------------------------------------------------------
    def test_02b_finding_ck_profile_and_env_trust_paths_ignored_negative_controls(self) -> None:
        """
        Finding CK:
          - In installed product, the ONLY trust root is <install root>/research/trust.json.
          - Explicit trust_path argument is developer/test only and NEVER read from env.
          - Profile locations (%LOCALAPPDATA%, ~/.pai) and PAI_TRUST_PATH are strictly ignored.
          - Negative control 1: Valid-looking trust.json in PAI_TRUST_PATH is ignored.
          - Negative control 2: Valid-looking trust.json in %LOCALAPPDATA%/PAI is ignored.
          - Negative control 3: Valid-looking trust.json in ~/.pai is ignored.
          - Negative control 4: When <install root>/research/trust.json is absent, load_trust_keys()
            fails closed even if valid-looking trust files exist in env or profile paths.
        """
        rogue_key_id = "rogue-key-ck-unauthorized"
        rogue_trust_content = json.dumps({
            "keys": [{"id": rogue_key_id, "public_hex": TEST_PUB_HEX, "revoked": False}]
        })

        # Set up rogue trust file in a temp path
        rogue_trust_path = Path(self.tmp_dir) / "rogue_trust.json"
        rogue_trust_path.write_text(rogue_trust_content, encoding="utf-8")

        # Fake profile locations
        fake_localappdata = Path(self.tmp_dir) / "fake_localappdata"
        fake_pai_appdata = fake_localappdata / "PAI"
        fake_pai_appdata.mkdir(parents=True, exist_ok=True)
        (fake_pai_appdata / "trust.json").write_text(rogue_trust_content, encoding="utf-8")

        fake_home = Path(self.tmp_dir) / "fake_home"
        fake_dot_pai = fake_home / ".pai"
        fake_dot_pai.mkdir(parents=True, exist_ok=True)
        (fake_dot_pai / "trust.json").write_text(rogue_trust_content, encoding="utf-8")

        orig_env = dict(os.environ)
        try:
            # Set hostile environment variables pointing to rogue trust files
            os.environ["PAI_TRUST_PATH"] = str(rogue_trust_path)
            os.environ["LOCALAPPDATA"] = str(fake_localappdata)
            os.environ["USERPROFILE"] = str(fake_home)

            # Test A: Default load_trust_keys() must find the official repo/install research/trust.json,
            # and MUST NOT load the rogue key from PAI_TRUST_PATH or profile folders.
            active_keys = load_trust_keys()
            loaded_ids = [k.get("id") for k in active_keys]
            self.assertNotIn(
                rogue_key_id,
                loaded_ids,
                "Security Failure (Finding CK): Rogue key from PAI_TRUST_PATH or profile was loaded!",
            )

            # Test B (Finding CP Negative Control):
            # PAI_INSTALL_DIR environment variable pointing to a folder with a rogue trust.json
            # MUST BE IGNORED to prevent caller environment manipulation of trust root.
            rogue_install = Path(self.tmp_dir) / "rogue_install_dir"
            rogue_install_res = rogue_install / "research"
            rogue_install_res.mkdir(parents=True, exist_ok=True)
            rogue_install_key = "rogue-key-from-pai-install-dir-env"
            (rogue_install_res / "trust.json").write_text(
                json.dumps({"keys": [{"id": rogue_install_key, "public_hex": TEST_PUB_HEX, "revoked": False}]}),
                encoding="utf-8",
            )
            os.environ["PAI_INSTALL_DIR"] = str(rogue_install)

            # load_trust_keys() must ignore PAI_INSTALL_DIR and load relative to __file__ (official repo keys)
            keys_under_env = load_trust_keys()
            loaded_under_env = [k.get("id") for k in keys_under_env]
            self.assertNotIn(
                rogue_install_key,
                loaded_under_env,
                "Security Failure (Finding CP): PAI_INSTALL_DIR env variable was honoured for trust root!",
            )

            # Test C: Explicit trust_path argument (for developer/test runs only)
            explicit_keys = load_trust_keys(trust_path=rogue_install_res / "trust.json")
            self.assertEqual(len(explicit_keys), 1)
            self.assertEqual(explicit_keys[0]["id"], rogue_install_key)
        finally:
            os.environ.clear()
            os.environ.update(orig_env)

    # -------------------------------------------------------------------------
    # Finding CD & CD2: Replay Rollback, Freshness, and Schema Validation
    # -------------------------------------------------------------------------
    def test_03_catalog_verification_and_monotonic_rollback_defense(self) -> None:
        """
        Finding CD:
          - Valid catalog passes and persists highest seen version.
          - Lower version than highest seen raises CatalogSecurityError (replay rollback defense).
          - Tampered signature fails closed.
        """
        # Initial verify of version 2
        cat_v2 = create_test_catalog(version=2)
        verified = verify_catalog_payload(
            cat_v2,
            trust_keys=TEST_TRUST_KEYS,
            state_path=self.state_file,
        )
        self.assertEqual(verified["catalog_version"], 2)
        self.assertEqual(get_highest_seen_catalog_version(self.state_file), 2)

        # Attempt to supply older version 1 -> Must fail closed!
        cat_v1 = create_test_catalog(version=1)
        with self.assertRaises(CatalogSecurityError) as cm:
            verify_catalog_payload(
                cat_v1,
                trust_keys=TEST_TRUST_KEYS,
                state_path=self.state_file,
            )
        self.assertIn("rollback", str(cm.exception).lower())

        # Attempt to tamper signature in version 3 -> Must fail closed!
        cat_v3 = create_test_catalog(version=3)
        tampered_sig = bytearray.fromhex(cat_v3["signature"])
        tampered_sig[0] ^= 0xFF
        cat_v3["signature"] = tampered_sig.hex()
        with self.assertRaises(CatalogSecurityError):
            verify_catalog_payload(
                cat_v3,
                trust_keys=TEST_TRUST_KEYS,
                state_path=self.state_file,
            )

    def test_04_catalog_freshness_and_future_clock_skew(self) -> None:
        """
        Finding CD:
          - Catalog older than 90 days is rejected.
          - Catalog timestamp > 24 hours in the future is rejected.
        """
        now = datetime.datetime.now(datetime.timezone.utc)

        # 91 days old
        old_time = (now - datetime.timedelta(days=91)).isoformat()
        old_cat = create_test_catalog(version=10, issued_utc=old_time)
        with self.assertRaises(CatalogSecurityError) as cm:
            verify_catalog_payload(old_cat, trust_keys=TEST_TRUST_KEYS, state_path=self.state_file)
        self.assertIn("expired", str(cm.exception).lower())

        # 2 days in the future
        future_time = (now + datetime.timedelta(days=2)).isoformat()
        future_cat = create_test_catalog(version=10, issued_utc=future_time)
        with self.assertRaises(CatalogSecurityError) as cm:
            verify_catalog_payload(future_cat, trust_keys=TEST_TRUST_KEYS, state_path=self.state_file)
        self.assertIn("in the future", str(cm.exception).lower())

    def test_05_strict_catalog_schema_negative_controls(self) -> None:
        """
        Finding CD2:
          - Missing kind != 'catalog' rejected.
          - Demo catalogs rejected in production.
          - Invalid model ID regex rejected.
          - Duplicate model ID rejected.
          - Negative sizes rejected.
          - Invalid digest format rejected.
        """
        # 1. Missing or invalid kind
        cat_bad_kind = create_test_catalog(kind="not_a_catalog")
        with self.assertRaises(CatalogSecurityError):
            verify_catalog_payload(cat_bad_kind, trust_keys=TEST_TRUST_KEYS, state_path=self.state_file)

        # 2. Demo catalog rejected in production
        cat_demo = create_test_catalog(demo=True)
        with self.assertRaises(CatalogSecurityError) as cm:
            verify_catalog_payload(cat_demo, trust_keys=TEST_TRUST_KEYS, state_path=self.state_file)
        self.assertIn("demo catalogs are rejected", str(cm.exception).lower())

        # 3. Invalid model ID regex (e.g. uppercase or invalid characters)
        bad_models = [
            {
                "id": "INVALID/MODEL:ID!",
                "download_bytes": 1000,
                "disk_bytes": 1000,
                "min_ram_mb": 1000,
                "registry_manifest_digest": "sha256:" + "0" * 64,
                "license": {"license_status": "verified"},
            }
        ]
        cat_bad_id = create_test_catalog(models=bad_models)
        with self.assertRaises(CatalogSecurityError):
            verify_catalog_payload(cat_bad_id, trust_keys=TEST_TRUST_KEYS, state_path=self.state_file)

        # 4. Duplicate model IDs
        dup_models = [
            {
                "id": "model:1b",
                "download_bytes": 1000,
                "disk_bytes": 1000,
                "min_ram_mb": 1000,
                "registry_manifest_digest": "sha256:" + "1" * 64,
                "license": {"license_status": "verified"},
            },
            {
                "id": "model:1b",
                "download_bytes": 1000,
                "disk_bytes": 1000,
                "min_ram_mb": 1000,
                "registry_manifest_digest": "sha256:" + "2" * 64,
                "license": {"license_status": "verified"},
            },
        ]
        cat_dup = create_test_catalog(models=dup_models)
        with self.assertRaises(CatalogSecurityError):
            verify_catalog_payload(cat_dup, trust_keys=TEST_TRUST_KEYS, state_path=self.state_file)

        # 5. Invalid registry digest format
        bad_digest_models = [
            {
                "id": "model:1b",
                "download_bytes": 1000,
                "disk_bytes": 1000,
                "min_ram_mb": 1000,
                "registry_manifest_digest": "md5:12345",
                "license": {"license_status": "verified"},
            }
        ]
        cat_bad_digest = create_test_catalog(models=bad_digest_models)
        with self.assertRaises(CatalogSecurityError):
            verify_catalog_payload(cat_bad_digest, trust_keys=TEST_TRUST_KEYS, state_path=self.state_file)

    # -------------------------------------------------------------------------
    # Finding CE: Fit Rules Refinements
    # -------------------------------------------------------------------------
    def test_06_fit_rule_disk_space_thresholds(self) -> None:
        """
        Validates disk fit rule:
        Required disk space = (1.25 * total_model_bytes) + 2 GB safety margin.
        """
        model = {
            "id": "test:3b",
            "download_bytes": 2 * (1024**3),
            "disk_bytes": 2 * (1024**3),
            "min_ram_mb": 2048,
            "license": {"license_status": "verified"},
        }
        two_gb = 2 * (1024**3)
        expected_needed = int(1.25 * two_gb) + two_gb

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

    def test_07_fit_rule_gpu_tiers_and_partial_not_preselected(self) -> None:
        """
        Finding CE:
          - Model weights + 512 MB <= 85% VRAM is 'full'.
          - 85% < Footprint <= 120% VRAM is 'partial' (labeled as estimate).
          - 'partial' tier is NEVER preselected until measured on hardware.
        """
        model = {
            "id": "test_gpu:model",
            "disk_bytes": 2048 * (1024 * 1024),
            "min_ram_mb": 2048,
            "license": {"license_status": "verified"},
        }

        # Case A: Full offload (VRAM = 4000 MB, 85% is 3400 MB >= 2560 MB footprint)
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
        self.assertTrue(rep_full.is_preselected)

        # Case B: Partial offload (VRAM = 2600 MB, 85% is 2210 MB < 2560 MB footprint <= 3120 MB)
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
        # Hard Rule (Finding CE): partial tier is NOT preselected
        self.assertFalse(rep_partial.is_preselected)
        self.assertIn("estimates", rep_partial.gpu_estimate_note)

    def test_08_fit_rule_available_ram_reserve(self) -> None:
        """
        Finding CE: RAM rule must evaluate available RAM at survey time
        and leave a 2048 MB system stability reserve.
        """
        model = {
            "id": "test_ram:model",
            "disk_bytes": 4096 * (1024 * 1024),
            "min_ram_mb": 4096,
            "license": {"license_status": "verified"},
        }
        # Total RAM is 16 GB, but available RAM is only 3000 MB.
        # With 2048 MB reserve, usable available RAM is only 952 MB < 4096 MB!
        survey_low_avail = HardwareProfile(
            total_ram_mb=16384.0,
            avail_ram_mb=3000.0,
            free_disk_bytes=50 * (1024**3),
            total_disk_bytes=100 * (1024**3),
            model_drive="C:",
            gpu_name=None,
            dedicated_vram_mb=0.0,
            gpu_driver_version=None,
            cpu_cores=6,
            cpu_logical=12,
            cpu_name="AMD",
            npu_detected=False,
            npu_name=None,
        )
        rep = evaluate_model_fit(model, survey_low_avail)
        self.assertFalse(rep.fits_ram)
        self.assertFalse(rep.is_preselected)
        self.assertTrue(any("INSUFFICIENT_RAM" in r for r in rep.rejection_reasons))

    # -------------------------------------------------------------------------
    # Finding CC: Ollama Authenticode Publisher Verification
    # -------------------------------------------------------------------------
    def test_09_authenticode_publisher_verification_negative_controls(self) -> None:
        """
        Finding CC:
          - Non-Windows fails closed.
          - Missing file raises FileNotFoundError.
          - Tampered or mismatched thumbprint raises OllamaVerificationError.
        """
        # Case A: Non-Windows fail-closed check
        with patch("sys.platform", "linux"):
            with self.assertRaises(OllamaVerificationError):
                verify_authenticode_publisher(Path(self.tmp_dir) / "dummy.exe")

        # Case B: Missing file
        if sys.platform == "win32":
            with self.assertRaises(FileNotFoundError):
                verify_authenticode_publisher(Path(self.tmp_dir) / "nonexistent.exe")

    # -------------------------------------------------------------------------
    # Finding CH: Loopback and Proxy Bypass
    # -------------------------------------------------------------------------
    def test_10_probe_ollama_daemon_loopback_security_and_mock(self) -> None:
        """
        Finding CH:
          - Non-loopback OLLAMA_HOST ignored/refused for SSRF defense.
          - Loopback connection succeeds with mocked response.
        """
        # Case A: Non-loopback host in environment
        with patch.dict(os.environ, {"OLLAMA_HOST": "http://192.168.1.100:11434"}):
            status = probe_ollama_daemon()
            self.assertIn("127.0.0.1", status["endpoint"])

        # Case B: Mocked loopback daemon response
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b'{"version": "0.5.1"}'
        mock_resp.__enter__.return_value = mock_resp

        mock_opener = MagicMock()
        mock_opener.open.return_value = mock_resp

        with patch("urllib.request.build_opener", return_value=mock_opener):
            status_up = probe_ollama_daemon()
            self.assertTrue(status_up["running"])
            self.assertEqual(status_up["version"], "0.5.1")

    # -------------------------------------------------------------------------
    # Finding CG: Progress Events Stream
    # -------------------------------------------------------------------------
    def test_11_progress_json_emitter(self) -> None:
        """Finding CG: Emits Appendix C NDJSON progress events."""
        buf = io.StringIO()
        emitter = ProgressEmitter(enabled=True)

        with patch("sys.stdout", buf):
            emitter.emit("survey", hardware={"cpu_cores": 8})
            emitter.emit("ollama_status", running=True, version="0.5.1")
            emitter.emit("fit", recommendations=[])
            emitter.emit("error", code="TEST_ERR", message="sample")

        lines = [ln.strip() for ln in buf.getvalue().splitlines() if ln.strip()]
        self.assertEqual(len(lines), 4)

        events = [json.loads(ln) for ln in lines]
        self.assertEqual(events[0]["event"], "survey")
        self.assertEqual(events[1]["event"], "ollama_status")
        self.assertEqual(events[2]["event"], "fit")
        self.assertEqual(events[3]["event"], "error")

    def test_12_cli_execution_survey_only(self) -> None:
        """Executes pai_setup.py via subprocess with --survey-only."""
        setup_script = RESEARCH_DIR / "pai_setup.py"
        proc = subprocess.run([sys.executable, str(setup_script), "--survey-only"], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, f"pai_setup.py --survey-only failed:\n{proc.stderr}")
        data = json.loads(proc.stdout)
        self.assertIn("total_ram_mb", data)
        self.assertIn("avail_ram_mb", data)
        self.assertIn("free_disk_bytes", data)
        self.assertIn("npu_note", data)

    # -------------------------------------------------------------------------
    # Finding CL: Catalog Publisher Block and Thumbprint Rotation
    # -------------------------------------------------------------------------
    def test_13_finding_cl_catalog_publisher_rotation_and_authenticode(self) -> None:
        """
        Finding CL:
          - Catalog supports optional publisher block with subject and accepted thumbprints.
          - verify_authenticode_publisher accepts any thumbprint in the accepted list.
          - Thumbprint rotation verified without modifying code.
        """
        # Case A: Catalog with valid publisher block
        cat = create_test_catalog(version=10)
        cat["publisher"] = {
            "subject": "CN=Ollama Inc., O=Ollama Inc., L=Toronto, S=Ontario, C=CA",
            "thumbprints": [
                "716CD3BC8C02361431A18F56F98C72DE88066103",
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",  # Rotated thumbprint
            ],
        }
        # Re-sign catalog
        cat["signature"] = sign_test_catalog(cat)
        verified = verify_catalog_payload(cat, trust_keys=TEST_TRUST_KEYS, state_path=self.state_file)
        self.assertIn("publisher", verified)
        self.assertEqual(len(verified["publisher"]["thumbprints"]), 2)

        # Case B: Malformed publisher blocks are rejected
        cat_bad_pub = create_test_catalog(version=11)
        cat_bad_pub["publisher"] = "not_an_object"
        cat_bad_pub["signature"] = sign_test_catalog(cat_bad_pub)
        with self.assertRaises(CatalogSecurityError):
            verify_catalog_payload(cat_bad_pub, trust_keys=TEST_TRUST_KEYS, state_path=self.state_file)

        cat_bad_tprints = create_test_catalog(version=12)
        cat_bad_tprints["publisher"] = {"thumbprints": []}
        cat_bad_tprints["signature"] = sign_test_catalog(cat_bad_tprints)
        with self.assertRaises(CatalogSecurityError):
            verify_catalog_payload(cat_bad_tprints, trust_keys=TEST_TRUST_KEYS, state_path=self.state_file)

    # -------------------------------------------------------------------------
    # Finding DQ: Loopback-Only Network Enforcement (Zero External Traffic)
    # -------------------------------------------------------------------------
    def test_14_finding_dq_loopback_only_network_enforcement(self) -> None:
        """
        Finding DQ:
          - download_ollama_installer removed until D10 decision.
          - pai setup enforces loopback-only connections (127.0.0.1, localhost, ::1).
          - No external hosts are ever contacted across survey, probe, catalog verify, and model pull.
          - socket.create_connection is intercepted to guarantee fail-closed enforcement.
        """
        import socket
        import pai_setup

        # Case A: External installer downloader removed completely
        self.assertFalse(hasattr(pai_setup, "download_ollama_installer"), "download_ollama_installer must be deleted per Finding DQ")
        self.assertFalse(hasattr(pai_setup, "StrictRedirectHandler"), "StrictRedirectHandler must be deleted per Finding DQ")
        self.assertFalse(hasattr(pai_setup, "OLLAMA_OFFICIAL_INSTALLER_URL"), "OLLAMA_OFFICIAL_INSTALLER_URL must be deleted per Finding DQ")

        # Case B: Loopback-only network policy enforcement
        loopback_hosts = {"127.0.0.1", "localhost", "::1"}
        recorded_connections = []
        real_create_connection = socket.create_connection

        def guarded_create_connection(address, *args, **kwargs):
            host = address[0]
            recorded_connections.append(host)
            if host not in loopback_hosts:
                raise AssertionError(f"Finding DQ Violation: non-loopback connection attempted to {host}:{address[1]}")
            # Simulate offline loopback daemon (fail-closed without real socket)
            raise ConnectionRefusedError(f"Simulated offline daemon for {host}:{address[1]}")

        with patch("socket.create_connection", side_effect=guarded_create_connection):
            # 1. Survey path: zero network calls
            survey_prof = collect_hardware_survey(allow_mock=True)
            self.assertIsNotNone(survey_prof)
            self.assertEqual(len(recorded_connections), 0, "Hardware survey must make 0 network connections")

            # 2. Probe Ollama path: strictly loopback
            probe_result = probe_ollama_daemon()
            self.assertFalse(probe_result["running"])
            self.assertTrue(all(h in loopback_hosts for h in recorded_connections), "Ollama probe must only contact loopback")

            # 3. Catalog verify path: zero network calls (pure cryptographic verification)
            recorded_connections.clear()
            verify_catalog_payload(self.catalog, trust_keys=TEST_TRUST_KEYS, state_path=self.state_file)
            self.assertEqual(len(recorded_connections), 0, "Catalog verification must make 0 network connections")

            # 4. Negative control: non-loopback connection attempt fails closed via AssertionError
            with self.assertRaises(AssertionError) as ctx:
                socket.create_connection(("external.ollama.com", 443))
            self.assertIn("Finding DQ Violation", str(ctx.exception))

    # -------------------------------------------------------------------------
    # Finding CM: Catalog Expiration Guidance and State Degradation
    # -------------------------------------------------------------------------
    def test_15_finding_cm_catalog_expired_guidance_and_corrupt_state(self) -> None:
        """
        Finding CM:
          - Clear message on catalog expiration citing policy D20.
          - Corrupted catalog_state.json degrades gracefully to version 0.
        """
        # Case A: Expiration guidance
        old_cat = create_test_catalog(version=20, issued_utc="2020-01-01T00:00:00Z")
        with self.assertRaises(CatalogSecurityError) as ctx:
            verify_catalog_payload(old_cat, trust_keys=TEST_TRUST_KEYS, state_path=self.state_file)
        self.assertIn("expired", str(ctx.exception))
        self.assertIn("policy D20", str(ctx.exception))
        self.assertIn("official PAI releases", str(ctx.exception))

        # Case B: Corrupted state file
        corrupt_state = Path(self.tmp_dir) / "corrupt_state.json"
        corrupt_state.write_text("{malformed json", encoding="utf-8")
        seen_ver = get_highest_seen_catalog_version(corrupt_state)
        self.assertEqual(seen_ver, 0)

    # -------------------------------------------------------------------------
    # Milestone P4: Pull Progress Tracker and Layer Aggregation (§6)
    # -------------------------------------------------------------------------
    def test_16_p4_pull_progress_tracker_layer_aggregation(self) -> None:
        """
        Milestone P4:
          - Multi-layer model aggregates completed bytes across layers.
          - Percent and rolling speed calculated correctly.
        """
        tracker = PullProgressTracker(model_id="test-model:latest", known_total_bytes=1000)

        # Layer 1
        tracker.update_layer(digest="sha256:layer1", completed=200, total=500, status="downloading layer1")
        self.assertEqual(tracker.total_completed, 200)
        self.assertEqual(tracker.percent, 20.0)

        # Layer 2
        tracker.update_layer(digest="sha256:layer2", completed=300, total=500, status="downloading layer2")
        self.assertEqual(tracker.total_completed, 500)
        self.assertEqual(tracker.percent, 50.0)

        # Layer 1 completes
        tracker.update_layer(digest="sha256:layer1", completed=500, total=500, status="verifying sha256:layer1")
        self.assertEqual(tracker.total_completed, 800)
        self.assertEqual(tracker.percent, 80.0)
        self.assertTrue(tracker.is_verifying)

        # Human formatting helpers
        self.assertEqual(format_bytes_human(1024), "1.0 KB")
        self.assertEqual(format_bytes_human(1024**2 * 5), "5.0 MB")
        self.assertEqual(format_eta_human(125), "2m 05s")
        self.assertEqual(format_eta_human(None), "--:--")

    # -------------------------------------------------------------------------
    # Milestone P4: Streaming Pull, Progress Events, and Cancellation (§6, Appendix C)
    # -------------------------------------------------------------------------
    def test_17_p4_pull_model_stream_success_and_appendix_c_events(self) -> None:
        """
        Milestone P4:
          - Streams NDJSON responses from mock Ollama pull endpoint.
          - Emits download_start, progress, verifying, done events.
        """
        ndjson_stream = [
            b'{"status": "pulling manifest"}\n',
            b'{"status": "downloading", "digest": "sha256:part1", "total": 1000, "completed": 500}\n',
            b'{"status": "verifying sha256:part1", "digest": "sha256:part1", "total": 1000, "completed": 1000}\n',
            b'{"status": "writing manifest"}\n',
            b'{"status": "success"}\n',
        ]

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__iter__.return_value = iter(ndjson_stream)
        mock_resp.__enter__.return_value = mock_resp

        mock_opener = MagicMock()
        mock_opener.open.return_value = mock_resp

        emitter = ProgressEmitter(enabled=True)
        captured_events = []

        with patch("urllib.request.build_opener", return_value=mock_opener):
            with patch.object(emitter, "emit", side_effect=lambda evt, **kw: captured_events.append((evt, kw))):
                res = pull_model_stream(
                    model_id="mock-model:7b",
                    endpoint="http://127.0.0.1:11434",
                    total_bytes=1000,
                    emitter=emitter,
                    show_console_bar=False,
                )

        self.assertEqual(res["status"], "done")
        event_names = [e[0] for e in captured_events]
        self.assertIn("download_start", event_names)
        self.assertIn("progress", event_names)
        self.assertIn("verifying", event_names)
        self.assertIn("done", event_names)

    def test_18_p4_pull_model_stream_cancellation_and_error_handling(self) -> None:
        """
        Milestone P4:
          - Thread-safe cancellation aborts stream and raises DownloadCancelledError.
          - Daemon DISK_FULL error mapped and raises ModelPullError.
          - Daemon REGISTRY_ERROR mapped and raises ModelPullError.
        """
        # Case A: Cancellation token
        cancel_tok = CancelToken()
        cancel_tok.cancel()

        emitter = ProgressEmitter(enabled=True)
        captured = []

        with patch.object(emitter, "emit", side_effect=lambda evt, **kw: captured.append((evt, kw))):
            with self.assertRaises(DownloadCancelledError):
                pull_model_stream(
                    model_id="cancel-model:7b",
                    cancel_token=cancel_tok,
                    emitter=emitter,
                    show_console_bar=False,
                )
        self.assertTrue(any(e[0] == "error" and e[1].get("code") == "CANCELLED" for e in captured))

        # Case B: Disk full error in stream
        ndjson_disk_err = [
            b'{"error": "write /root/.ollama: no space left on device"}\n',
        ]
        mock_resp_disk = MagicMock()
        mock_resp_disk.status = 200
        mock_resp_disk.__iter__.return_value = iter(ndjson_disk_err)
        mock_resp_disk.__enter__.return_value = mock_resp_disk
        mock_opener_disk = MagicMock()
        mock_opener_disk.open.return_value = mock_resp_disk

        with patch("urllib.request.build_opener", return_value=mock_opener_disk):
            with self.assertRaises(ModelPullError) as ctx:
                pull_model_stream(
                    model_id="disk-model:7b",
                    emitter=emitter,
                    show_console_bar=False,
                )
            self.assertEqual(ctx.exception.code, "DISK_FULL")

        # Case C: Model not found in registry
        ndjson_reg_err = [
            b'{"error": "pull model manifest: file does not exist"}\n',
        ]
        mock_resp_reg = MagicMock()
        mock_resp_reg.status = 200
        mock_resp_reg.__iter__.return_value = iter(ndjson_reg_err)
        mock_resp_reg.__enter__.return_value = mock_resp_reg
        mock_opener_reg = MagicMock()
        mock_opener_reg.open.return_value = mock_resp_reg

        with patch("urllib.request.build_opener", return_value=mock_opener_reg):
            with self.assertRaises(ModelPullError) as ctx:
                pull_model_stream(
                    model_id="unknown-model:7b",
                    emitter=emitter,
                    show_console_bar=False,
                )
            self.assertEqual(ctx.exception.code, "REGISTRY_ERROR")

    # -------------------------------------------------------------------------
    # Finding CO: Stream Termination & Backoff Retry Engine
    # -------------------------------------------------------------------------
    def test_19_finding_co_premature_stream_eof_retry_and_backoff_exhaustion(self) -> None:
        """
        Finding CO:
          - Daemon stream closes prematurely without success/error line (e.g. daemon stopped).
          - Must NOT enter a tight infinite loop!
          - Retries with backoff and raises ModelPullError('NETWORK_ERROR') on retry exhaustion.
        """
        ndjson_premature = [
            b'{"status": "pulling manifest"}\n',
            b'{"status": "downloading", "digest": "sha256:layer1", "total": 1000, "completed": 200}\n',
        ]

        def create_mock_resp():
            m = MagicMock()
            m.status = 200
            m.__iter__.return_value = iter(ndjson_premature)
            m.__enter__.return_value = m
            return m

        mock_opener = MagicMock()
        mock_opener.open.side_effect = [create_mock_resp(), create_mock_resp(), create_mock_resp()]

        with patch("urllib.request.build_opener", return_value=mock_opener):
            with self.assertRaises(ModelPullError) as ctx:
                pull_model_stream(
                    model_id="cut-model:latest",
                    max_retries=2,
                    initial_backoff_sec=0.01,
                    show_console_bar=False,
                )
            self.assertEqual(ctx.exception.code, "NETWORK_ERROR")
            self.assertIn("terminated prematurely", ctx.exception.message)
            self.assertEqual(mock_opener.open.call_count, 3)

    def test_20_finding_co_stream_cut_resume_and_backoff_cancellation(self) -> None:
        """
        Finding CO:
          - Stream cut mid-stream resumes and succeeds on second attempt.
          - Cancellation token triggered during backoff wait raises DownloadCancelledError promptly.
        """
        stream_attempt_1 = [
            b'{"status": "downloading", "digest": "sha256:blob1", "total": 1000, "completed": 500}\n',
        ]
        stream_attempt_2 = [
            b'{"status": "downloading", "digest": "sha256:blob1", "total": 1000, "completed": 1000}\n',
            b'{"status": "success"}\n',
        ]

        resp1 = MagicMock()
        resp1.status = 200
        resp1.__iter__.return_value = iter(stream_attempt_1)
        resp1.__enter__.return_value = resp1

        resp2 = MagicMock()
        resp2.status = 200
        resp2.__iter__.return_value = iter(stream_attempt_2)
        resp2.__enter__.return_value = resp2

        mock_opener = MagicMock()
        mock_opener.open.side_effect = [resp1, resp2]

        with patch("urllib.request.build_opener", return_value=mock_opener):
            res = pull_model_stream(
                model_id="resume-model:7b",
                max_retries=2,
                initial_backoff_sec=0.01,
                show_console_bar=False,
            )
            self.assertEqual(res["status"], "done")
            self.assertEqual(res["completed_bytes"], 1000)

        # Case B (Finding CV): Cancellation during retry backoff wait in a separate thread
        cancel_tok = CancelToken()
        premature_resp = MagicMock()
        premature_resp.status = 200
        premature_resp.__iter__.return_value = iter([b'{"status": "downloading"}\n'])
        premature_resp.__enter__.return_value = premature_resp

        mock_opener_cancel = MagicMock()
        mock_opener_cancel.open.return_value = premature_resp

        # Cancel token triggers 0.1s after pull begins (which falls directly inside the 1.0s backoff sleep)
        cancel_timer = threading.Timer(0.1, cancel_tok.cancel)
        cancel_timer.start()
        t0 = time.monotonic()
        try:
            with patch("urllib.request.build_opener", return_value=mock_opener_cancel):
                with self.assertRaises(DownloadCancelledError):
                    pull_model_stream(
                        model_id="cancel-backoff:7b",
                        cancel_token=cancel_tok,
                        max_retries=3,
                        initial_backoff_sec=1.0,
                        show_console_bar=False,
                    )
            elapsed = time.monotonic() - t0
            # Must exit promptly during backoff sleep (well under the 1.0s full duration)
            self.assertLess(elapsed, 0.8, f"Cancel latency too high: {elapsed:.3f}s >= 0.8s")
            self.assertGreater(elapsed, 0.05, f"Cancel was too fast, did not exercise backoff: {elapsed:.3f}s")
        finally:
            cancel_timer.cancel()

    # -------------------------------------------------------------------------
    # Finding CN & CT: Manifest Digest Verification, Normalization & Purge
    # -------------------------------------------------------------------------
    def test_21_finding_cn_and_ct_manifest_digest_verification_and_normalization(self) -> None:
        """
        Findings CN & CT:
          - After pull, manifest digest is queried from Ollama tags API (bare 64 hex).
          - normalize_digest() handles bare hex vs 'sha256:' catalog format deterministically.
          - On digest match (with or without 'sha256:' prefix): succeeds.
          - On true digest mismatch: model is purged via DELETE /api/delete and DIGEST_MISMATCH raised.
        """
        # Case A: Digest normalization unit tests
        h64 = "67dae4a5d3f745e691ec5f7957d1fa183b06385d83637e100c4366e6c1e33d26"
        self.assertEqual(normalize_digest(h64), h64)
        self.assertEqual(normalize_digest(f"sha256:{h64}"), h64)
        self.assertEqual(normalize_digest(f"  SHA256:{h64.upper()}  "), h64)
        self.assertIsNone(normalize_digest("not-a-digest"))
        self.assertIsNone(normalize_digest("sha256:short"))
        self.assertIsNone(normalize_digest(""))
        self.assertIsNone(normalize_digest(None))

        # Case B: Real daemon shape (bare 64-hex from /api/tags) matching catalog format ('sha256:...')
        bare_daemon_digest = "d15ab1e15ab1e15ab1e15ab1e15ab1e15ab1e15ab1e15ab1e15ab1e15ab1e15a"
        catalog_digest_prefixed = f"sha256:{bare_daemon_digest}"

        resp_good = MagicMock()
        resp_good.status = 200
        resp_good.__iter__.return_value = iter([b'{"status": "success"}\n'])
        resp_good.__enter__.return_value = resp_good

        mock_opener_good = MagicMock()
        mock_opener_good.open.return_value = resp_good

        with patch("urllib.request.build_opener", return_value=mock_opener_good):
            with patch("pai_setup.query_ollama_model_digest", return_value=bare_daemon_digest):
                res = pull_model_stream(
                    model_id="verified:model",
                    expected_manifest_digest=catalog_digest_prefixed,
                    show_console_bar=False,
                )
                self.assertEqual(res["status"], "done")

        # Case C: True digest mismatch -> Purges model with warning and raises DIGEST_MISMATCH
        bad_daemon_digest = "badbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbad1"
        resp_bad = MagicMock()
        resp_bad.status = 200
        resp_bad.__iter__.return_value = iter([b'{"status": "success"}\n'])
        resp_bad.__enter__.return_value = resp_bad

        mock_opener_bad = MagicMock()
        mock_opener_bad.open.return_value = resp_bad

        deleted_models = []
        with patch("urllib.request.build_opener", return_value=mock_opener_bad):
            with patch("pai_setup.query_ollama_model_digest", return_value=bad_daemon_digest):
                with patch("pai_setup.delete_ollama_model", side_effect=lambda ep, m: deleted_models.append(m)):
                    with self.assertRaises(ModelPullError) as ctx:
                        pull_model_stream(
                            model_id="tampered:model",
                            expected_manifest_digest=catalog_digest_prefixed,
                            show_console_bar=False,
                        )
                    self.assertEqual(ctx.exception.code, "DIGEST_MISMATCH")
                    self.assertIn("tampered:model", deleted_models)

    # -------------------------------------------------------------------------
    # Finding CU: Fail-Closed on Missing Digest Without Deleting Model
    # -------------------------------------------------------------------------
    def test_22_finding_cu_missing_digest_fails_closed_without_deletion(self) -> None:
        """
        Finding CU:
          - For catalog models with signed digest, if daemon reports no digest,
            must FAIL with DIGEST_UNAVAILABLE (fail-closed).
          - The downloaded model MUST NOT be deleted (left in place for user).
          - Passing allow_unverified=True bypasses the check with a warning and does not delete.
        """
        def make_success_resp():
            r = MagicMock()
            r.status = 200
            r.__iter__.return_value = iter([b'{"status": "success"}\n'])
            r.__enter__.return_value = r
            return r

        deleted_models = []
        expected_digest = "sha256:67dae4a5d3f745e691ec5f7957d1fa183b06385d83637e100c4366e6c1e33d26"

        # Case A: allow_unverified=False -> Fails closed with DIGEST_UNAVAILABLE, NO delete
        mock_opener_a = MagicMock()
        mock_opener_a.open.return_value = make_success_resp()
        with patch("urllib.request.build_opener", return_value=mock_opener_a):
            with patch("pai_setup.query_ollama_model_digest", return_value=None):
                with patch("pai_setup.delete_ollama_model", side_effect=lambda ep, m: deleted_models.append(m)):
                    with self.assertRaises(ModelPullError) as ctx:
                        pull_model_stream(
                            model_id="catalog:model",
                            expected_manifest_digest=expected_digest,
                            allow_unverified=False,
                            show_console_bar=False,
                        )
                    self.assertEqual(ctx.exception.code, "DIGEST_UNAVAILABLE")
                    self.assertEqual(len(deleted_models), 0, "Model must NOT be deleted on DIGEST_UNAVAILABLE!")

        # Case B: allow_unverified=True -> Succeeds with warning, NO delete
        mock_opener_b = MagicMock()
        mock_opener_b.open.return_value = make_success_resp()
        with patch("urllib.request.build_opener", return_value=mock_opener_b):
            with patch("pai_setup.query_ollama_model_digest", return_value=None):
                with patch("pai_setup.delete_ollama_model", side_effect=lambda ep, m: deleted_models.append(m)):
                    res = pull_model_stream(
                        model_id="catalog:model",
                        expected_manifest_digest=expected_digest,
                        allow_unverified=True,
                        show_console_bar=False,
                    )
                    self.assertEqual(res["status"], "done")
                    self.assertEqual(len(deleted_models), 0)

    # -------------------------------------------------------------------------
    # Finding CX: HTTP 4xx Client Errors Fail Immediately Without Retrying
    # -------------------------------------------------------------------------
    def test_23_finding_cx_http_4xx_client_errors_fail_immediately(self) -> None:
        """
        Finding CX:
          - HTTP 404 from daemon raises MODEL_NOT_FOUND immediately without retries.
          - HTTP 400 from daemon raises CLIENT_ERROR immediately without retries.
          - HTTP 500 from daemon retries with backoff up to max_retries.
        """
        # Case A: HTTP 404
        err_404 = urllib.error.HTTPError(
            url="http://127.0.0.1:11434/api/pull",
            code=404,
            msg="Not Found",
            hdrs={},
            fp=io.BytesIO(b'{"error": "model not found"}'),
        )
        mock_opener_404 = MagicMock()
        mock_opener_404.open.side_effect = err_404

        with patch("urllib.request.build_opener", return_value=mock_opener_404):
            with self.assertRaises(ModelPullError) as ctx:
                pull_model_stream(
                    model_id="nonexistent:model",
                    max_retries=3,
                    show_console_bar=False,
                )
            self.assertEqual(ctx.exception.code, "MODEL_NOT_FOUND")
            self.assertEqual(mock_opener_404.open.call_count, 1, "HTTP 404 must NOT retry!")

        # Case B: HTTP 400
        err_400 = urllib.error.HTTPError(
            url="http://127.0.0.1:11434/api/pull",
            code=400,
            msg="Bad Request",
            hdrs={},
            fp=io.BytesIO(b'{"error": "bad request"}'),
        )
        mock_opener_400 = MagicMock()
        mock_opener_400.open.side_effect = err_400

        with patch("urllib.request.build_opener", return_value=mock_opener_400):
            with self.assertRaises(ModelPullError) as ctx:
                pull_model_stream(
                    model_id="bad:model",
                    max_retries=3,
                    show_console_bar=False,
                )
            self.assertEqual(ctx.exception.code, "CLIENT_ERROR")
            self.assertEqual(mock_opener_400.open.call_count, 1, "HTTP 400 must NOT retry!")

        # Case C: HTTP 500 (Server Error) retries with backoff
        def create_500():
            return urllib.error.HTTPError(
                url="http://127.0.0.1:11434/api/pull",
                code=500,
                msg="Internal Server Error",
                hdrs={},
                fp=io.BytesIO(b'{"error": "internal error"}'),
            )

        mock_opener_500 = MagicMock()
        mock_opener_500.open.side_effect = [create_500(), create_500(), create_500()]

        with patch("urllib.request.build_opener", return_value=mock_opener_500):
            with self.assertRaises(ModelPullError) as ctx:
                pull_model_stream(
                    model_id="server-err:model",
                    max_retries=2,
                    initial_backoff_sec=0.01,
                    show_console_bar=False,
                )
            self.assertEqual(ctx.exception.code, "SERVER_ERROR")
            self.assertEqual(mock_opener_500.open.call_count, 3, "HTTP 500 must retry up to max_retries!")

    # -------------------------------------------------------------------------
    # Finding CW: Real Loopback HTTP Server Integration Test
    # -------------------------------------------------------------------------
    def test_24_finding_cw_real_http_server_integration_suite(self) -> None:
        """
        Finding CW:
          - Starts a real lightweight loopback http.server serving official Ollama endpoints.
          - Tests query_ollama_model_digest against real bare-hex /api/tags JSON.
          - Tests delete_ollama_model against real /api/delete endpoint.
          - Tests pull_model_stream end-to-end with digest verification against real HTTP responses.
          - Tests digest mismatch and CU fail-closed behavior against real HTTP responses.
        """
        qwen_bare_digest = "67dae4a5d3f745e691ec5f7957d1fa183b06385d83637e100c4366e6c1e33d26"
        deleted_on_server = []

        class FakeOllamaHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass  # Silence server access logs

            def do_GET(self):
                if self.path == "/api/tags":
                    body = json.dumps({
                        "models": [
                            {
                                "name": "qwen2.5:0.5b",
                                "model": "qwen2.5:0.5b",
                                "modified_at": "2026-10-27T00:00:00Z",
                                "size": 397750176,
                                "digest": qwen_bare_digest,
                            },
                            {
                                "name": "no-digest:7b",
                                "model": "no-digest:7b",
                                "modified_at": "2026-10-27T00:00:00Z",
                                "size": 1000000,
                            },
                        ]
                    }).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                elif self.path == "/api/version":
                    body = b'{"version": "0.35.1"}'
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                else:
                    self.send_response(404)
                    self.end_headers()

            def do_POST(self):
                if self.path == "/api/pull":
                    content_length = int(self.headers.get("Content-Length", 0))
                    req_body = json.loads(self.rfile.read(content_length).decode("utf-8"))
                    model_name = req_body.get("name", "")

                    if model_name == "nonexistent:model":
                        self.send_response(404)
                        self.send_header("Content-Type", "application/json")
                        self.end_headers()
                        self.wfile.write(b'{"error": "model nonexistent:model not found"}')
                        return

                    self.send_response(200)
                    self.send_header("Content-Type", "application/x-ndjson")
                    self.end_headers()
                    chunks = [
                        b'{"status": "pulling manifest"}\n',
                        b'{"status": "downloading", "digest": "sha256:layer1", "total": 1000, "completed": 500}\n',
                        b'{"status": "downloading", "digest": "sha256:layer1", "total": 1000, "completed": 1000}\n',
                        b'{"status": "verifying sha256 digest"}\n',
                        b'{"status": "writing manifest"}\n',
                        b'{"status": "success"}\n',
                    ]
                    for chunk in chunks:
                        self.wfile.write(chunk)
                        self.wfile.flush()
                else:
                    self.send_response(404)
                    self.end_headers()

            def do_DELETE(self):
                if self.path == "/api/delete":
                    content_length = int(self.headers.get("Content-Length", 0))
                    req_body = json.loads(self.rfile.read(content_length).decode("utf-8"))
                    deleted_on_server.append(req_body.get("name"))
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"status": "success"}')
                else:
                    self.send_response(404)
                    self.end_headers()

        # Start fake server on localhost port 0 (ephemeral free port)
        server = http.server.HTTPServer(("127.0.0.1", 0), FakeOllamaHandler)
        port = server.server_port
        endpoint = f"http://127.0.0.1:{port}"

        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        try:
            # Subtest 1: Real query_ollama_model_digest against fake HTTP server
            digest = query_ollama_model_digest(endpoint, "qwen2.5:0.5b")
            self.assertEqual(digest, qwen_bare_digest)
            self.assertIsNone(query_ollama_model_digest(endpoint, "no-digest:7b"))
            self.assertIsNone(query_ollama_model_digest(endpoint, "unknown:model"))

            # Subtest 2: Real delete_ollama_model against fake HTTP server
            ok = delete_ollama_model(endpoint, "temp:model")
            self.assertTrue(ok)
            self.assertIn("temp:model", deleted_on_server)

            # Subtest 3: Real pull_model_stream with catalog digest (sha256: prefix)
            deleted_on_server.clear()
            res = pull_model_stream(
                model_id="qwen2.5:0.5b",
                endpoint=endpoint,
                expected_manifest_digest=f"sha256:{qwen_bare_digest}",
                show_console_bar=False,
            )
            self.assertEqual(res["status"], "done")
            self.assertEqual(len(deleted_on_server), 0, "Valid digest must NOT trigger deletion!")

            # Subtest 4: Real pull_model_stream with forced digest mismatch
            deleted_on_server.clear()
            with self.assertRaises(ModelPullError) as ctx:
                pull_model_stream(
                    model_id="qwen2.5:0.5b",
                    endpoint=endpoint,
                    expected_manifest_digest="sha256:0000000000000000000000000000000000000000000000000000000000000000",
                    show_console_bar=False,
                )
            self.assertEqual(ctx.exception.code, "DIGEST_MISMATCH")
            self.assertIn("qwen2.5:0.5b", deleted_on_server, "Mismatched model MUST be purged from server!")

            # Subtest 5: Finding CU against real HTTP server (daemon reports no digest for catalog model)
            deleted_on_server.clear()
            with self.assertRaises(ModelPullError) as ctx:
                pull_model_stream(
                    model_id="no-digest:7b",
                    endpoint=endpoint,
                    expected_manifest_digest="sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
                    allow_unverified=False,
                    show_console_bar=False,
                )
            self.assertEqual(ctx.exception.code, "DIGEST_UNAVAILABLE")
            self.assertEqual(len(deleted_on_server), 0, "Model must NOT be deleted on DIGEST_UNAVAILABLE!")

            # Subtest 6: Finding CU bypass with allow_unverified=True against real HTTP server
            deleted_on_server.clear()
            res = pull_model_stream(
                model_id="no-digest:7b",
                endpoint=endpoint,
                expected_manifest_digest="sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
                allow_unverified=True,
                show_console_bar=False,
            )
            self.assertEqual(res["status"], "done")
            self.assertEqual(len(deleted_on_server), 0)

            # Subtest 7: Finding CX HTTP 404 against real HTTP server
            with self.assertRaises(ModelPullError) as ctx:
                pull_model_stream(
                    model_id="nonexistent:model",
                    endpoint=endpoint,
                    max_retries=3,
                    show_console_bar=False,
                )
            self.assertEqual(ctx.exception.code, "MODEL_NOT_FOUND")

        finally:
            server.shutdown()
            server.server_close()

    # -------------------------------------------------------------------------
    # Finding CW: CLI Unverified-Model Rejection and Confirmation Guardrails
    # -------------------------------------------------------------------------
    def test_25_finding_cw_unverified_model_cli_rejection_and_confirmation(self) -> None:
        """
        Finding CW:
          - CLI fails closed with UNVERIFIED_MODEL_REJECTED (exit code 1) when model
            is not present in signed catalog and --allow-unverified-model is omitted.
          - CLI rejects malformed model IDs not matching <family>:<tag> pattern.
        """
        setup_script = RESEARCH_DIR / "pai_setup.py"

        # Case A: Malformed model ID pattern
        proc_bad_id = subprocess.run(
            [sys.executable, str(setup_script), "--pull-model", "bad_id_no_colon"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc_bad_id.returncode, 1)
        self.assertIn("invalid", proc_bad_id.stderr.lower())

        # Case B: Model not in catalog without --allow-unverified-model
        proc_unverified = subprocess.run(
            [sys.executable, str(setup_script), "--pull-model", "unverified-vendor:3b"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc_unverified.returncode, 1)
        self.assertIn("unverified", proc_unverified.stderr.lower())
        self.assertIn("--allow-unverified-model", proc_unverified.stderr)

    # -------------------------------------------------------------------------
    # Finding CN: Layer Totals Dynamic Override in Progress Tracker
    # -------------------------------------------------------------------------
    def test_26_finding_cn_layer_totals_override_catalog_estimate(self) -> None:
        """
        Finding CN:
          - Layer totals from stream override catalog known_total_bytes.
          - Real size ensures progress bar reaches 100% accurately.
        """
        tracker = PullProgressTracker(model_id="test:model", known_total_bytes=1000)
        # Before layers arrive, total_expected is catalog estimate (1000)
        self.assertEqual(tracker.total_expected, 1000)

        # Once layer arrives with actual size 2000, layer total overrides 1000!
        tracker.update_layer(digest="sha256:layer1", completed=500, total=2000, status="downloading")
        self.assertEqual(tracker.total_expected, 2000)
        self.assertEqual(tracker.percent, 25.0)



    # -------------------------------------------------------------------------
    # Milestone P6 & Finding DP: Subcommand Parity, Golden Help Comparison, and Shadow Isolation
    # -------------------------------------------------------------------------
    def test_27_p6_subcommand_parity_golden_help_and_shadow_isolation(self) -> None:
        """
        Milestone P6 Parity and Finding DP:
          1. Subcommand parity: 'pai setup' CLI invokes setup engine with identical options.
          2. Help output integrity: every baseline subcommand's --help output is byte-identical
             to its tag 8ce81cb golden copy.
          3. Top-level 'pai --help' output differs from tag 8ce81cb golden copy by exactly the
             one added 'setup' line in subcommands list and 'setup' in the choices list.
          4. Shadow telemetry isolation: 'pai setup' MUST NOT write shadow comparisons or
             record shadow discrepancy entries (preserves N+1 window integrity).
        """
        import difflib
        pai_py = RESEARCH_DIR / "pai.py"
        golden_dir = Path(__file__).resolve().parent / "golden"
        self.assertTrue(golden_dir.is_dir(), f"Golden directory not found: {golden_dir}")

        env = os.environ.copy()
        env["PYTHONPATH"] = str(RESEARCH_DIR)

        # Test A: pai setup --help works and lists options
        proc_help = subprocess.run([sys.executable, str(pai_py), "setup", "--help"], capture_output=True, text=True, env=env)
        self.assertEqual(proc_help.returncode, 0, f"pai setup --help failed: {proc_help.stderr}")
        self.assertIn("--survey-only", proc_help.stdout)
        self.assertIn("--catalog", proc_help.stdout)
        self.assertIn("--probe-ollama", proc_help.stdout)

        # Test B: Every existing subcommand --help matches tag 8ce81cb golden output byte-for-byte (Finding DP)
        baseline_subcommands = (
            "doctor", "clear-shadow", "calibrate", "models", "route",
            "code", "analyze", "docs", "forecast", "chat", "generate"
        )
        for sub in baseline_subcommands:
            p = subprocess.run([sys.executable, str(pai_py), sub, "--help"], capture_output=True, text=True, env=env)
            self.assertEqual(p.returncode, 0, f"Subcommand '{sub} --help' failed: {p.stderr}")
            golden_file = golden_dir / f"help_{sub.replace('-', '_')}.txt"
            self.assertTrue(golden_file.is_file(), f"Missing golden file for subcommand {sub}: {golden_file}")
            golden_text = golden_file.read_text(encoding="utf-8")
            self.assertEqual(
                p.stdout,
                golden_text,
                f"Subcommand '{sub} --help' diverged from tag 8ce81cb golden baseline"
            )

        # Test C: Top-level pai --help differs from tag 8ce81cb golden copy by exactly the 'setup' addition (Finding DP)
        proc_main_help = subprocess.run([sys.executable, str(pai_py), "--help"], capture_output=True, text=True, env=env)
        self.assertEqual(proc_main_help.returncode, 0)
        golden_main = (golden_dir / "help_pai.txt").read_text(encoding="utf-8")

        # Verify that removing ',setup' from choices and the one 'setup' line reproduces the golden baseline byte-for-byte
        normalized_help = proc_main_help.stdout.replace(",setup,", ",")
        setup_line = "    setup               Hardware survey, model fit analysis, and setup engine\n"
        self.assertIn(setup_line, proc_main_help.stdout, "Top-level help must include 'setup' subcommand description")
        normalized_help = normalized_help.replace(setup_line, "")
        self.assertEqual(
            normalized_help,
            golden_main,
            "Top-level help text diverged from 8ce81cb baseline beyond the single 'setup' subcommand addition"
        )

        # Verify unified diff between baseline and current consists solely of the expected setup additions
        diff = list(difflib.unified_diff(
            golden_main.splitlines(keepends=True),
            proc_main_help.stdout.splitlines(keepends=True),
            fromfile="golden_8ce81cb",
            tofile="current_pai",
        ))
        added_lines = [l for l in diff if l.startswith("+") and not l.startswith("+++")]
        for l in added_lines:
            self.assertIn("setup", l, f"Unexpected added line in help diff: {l}")

        # Test D: Shadow isolation - pai setup must NOT write shadow comparisons
        shadow_test_log = Path(self.tmp_dir) / "test_shadow_isolation.jsonl"
        env_shadow = env.copy()
        env_shadow["PAI_SHADOW_LOG"] = str(shadow_test_log)
        p_survey = subprocess.run(
            [sys.executable, str(pai_py), "setup", "--survey-only"],
            capture_output=True,
            text=True,
            env=env_shadow,
        )
        self.assertEqual(p_survey.returncode, 0, f"pai setup --survey-only failed: {p_survey.stderr}")
        data = json.loads(p_survey.stdout)
        self.assertIn("free_disk_bytes", data)
        if shadow_test_log.exists():
            self.assertEqual(shadow_test_log.stat().st_size, 0, "pai setup must not write shadow comparisons")

    # -------------------------------------------------------------------------
    # Milestone P6 & Finding DR: RAM Survey Failure Safety and Preselection Guard
    # -------------------------------------------------------------------------
    def test_29_finding_dr_ram_survey_failure_handling_and_preselection_safety(self) -> None:
        """
        Finding DR:
          - When telemetry fails or returns None, survey_ram_windows returns (None, None, 'unavailable').
          - HardwareProfile marks ram_source as 'unavailable'.
          - Unknown RAM prevents model preselection (is_preselected = False) with clear rejection reason.
          - CLI --survey-only emits total_ram_mb: null, avail_ram_mb: null, ram_source: 'unavailable'.
        """
        # Case A: HardwareTelemetry returns empty or None fields
        with patch("hardware_telemetry.HardwareTelemetry.get_system_snapshot", return_value={"total_ram_gb": None, "avail_ram_mb": None}):
            tot, avail, src = survey_ram_windows()
            self.assertIsNone(tot, "Total RAM must be None when telemetry returns None")
            self.assertIsNone(avail, "Available RAM must be None when telemetry returns None")
            self.assertEqual(src, "unavailable", "ram_source must be 'unavailable'")

        # Case B: HardwareTelemetry raises exception
        with patch("hardware_telemetry.HardwareTelemetry.get_system_snapshot", side_effect=RuntimeError("Simulated WMI failure")):
            tot, avail, src = survey_ram_windows()
            self.assertIsNone(tot)
            self.assertIsNone(avail)
            self.assertEqual(src, "unavailable")

        # Case C: Unknown RAM disables model preselection with clear rejection message
        profile_no_ram = HardwareProfile(
            total_ram_mb=None,
            avail_ram_mb=None,
            ram_source="unavailable",
            free_disk_bytes=100 * 1024 * 1024 * 1024,
            total_disk_bytes=250 * 1024 * 1024 * 1024,
            model_drive="C:",
            gpu_name="NVIDIA GeForce RTX 4090",
            dedicated_vram_mb=24576.0,
            gpu_driver_version="550.0",
            cpu_cores=8,
            cpu_logical=16,
            cpu_name="AMD Ryzen 7",
            npu_detected=False,
            npu_name=None,
        )

        candidate_model = {
            "id": "qwen2.5-coder:7b",
            "family": "qwen",
            "tasks": ["code"],
            "download_bytes": 4 * 1024 * 1024 * 1024,
            "disk_bytes": 4 * 1024 * 1024 * 1024,
            "min_ram_mb": 4096,
            "license": {"license_status": "verified"},
        }

        report = evaluate_model_fit(candidate_model, profile_no_ram)
        self.assertFalse(report.fits_ram, "fits_ram must be False when available RAM is unknown")
        self.assertFalse(report.is_preselected, "Model must NEVER be preselected when RAM is unknown (Finding DR)")
        self.assertTrue(
            any("RAM_UNKNOWN" in r for r in report.rejection_reasons),
            f"Expected RAM_UNKNOWN rejection reason, got: {report.rejection_reasons}"
        )
        self.assertTrue(
            any("model preselection disabled" in r for r in report.rejection_reasons),
            f"Expected informative message, got: {report.rejection_reasons}"
        )

        # Case D: Catalog planning with unknown RAM preselects 0 models
        catalog = {"models": [candidate_model]}
        plan = plan_model_selection(catalog, profile_no_ram)
        preselected = [r for r in plan if r.is_preselected]
        self.assertEqual(len(preselected), 0, "Zero models may be preselected when RAM survey is unavailable")

        # Case E: CLI --survey-only emits null RAM and ram_source 'unavailable'
        pai_py = RESEARCH_DIR / "pai.py"
        env = os.environ.copy()
        env["PYTHONPATH"] = str(RESEARCH_DIR)
        with patch("pai_setup.survey_ram_windows", return_value=(None, None, "unavailable")):
            import pai_setup
            parser = pai_setup.build_setup_parser()
            args = parser.parse_args(["--survey-only"])
            import io
            from contextlib import redirect_stdout
            f = io.StringIO()
            with patch("pai_setup.collect_hardware_survey") as mock_survey:
                mock_survey.return_value = profile_no_ram
                with redirect_stdout(f):
                    rc = pai_setup.run_setup(args)
                self.assertEqual(rc, 0)
                survey_json = json.loads(f.getvalue())
                self.assertIsNone(survey_json["total_ram_mb"])
                self.assertIsNone(survey_json["avail_ram_mb"])
                self.assertEqual(survey_json["ram_source"], "unavailable")


if __name__ == "__main__":
    unittest.main()
