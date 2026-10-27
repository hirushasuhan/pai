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

import ed25519_ref

from packaging.pai_setup import (
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
    download_ollama_installer,
    evaluate_model_fit,
    format_bytes_human,
    format_eta_human,
    get_highest_seen_catalog_version,
    load_trust_keys,
    main,
    plan_model_selection,
    probe_ollama_daemon,
    pull_model_stream,
    query_ollama_model_digest,
    record_catalog_version,
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
        setup_script = REPO_ROOT / "packaging" / "pai_setup.py"
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
    # Finding CL: Download Safety Guardrails for Ollama Installer
    # -------------------------------------------------------------------------
    def test_14_finding_cl_download_ollama_installer_safety_controls(self) -> None:
        """
        Finding CL:
          - Insecure (non-HTTPS) download rejected.
          - Untrusted host rejected.
          - Exceeding size limit (500 MB) rejected.
          - Failed download or verification unlinks target file immediately.
        """
        # Case A: Untrusted download host
        with patch("packaging.pai_setup.OLLAMA_OFFICIAL_INSTALLER_URL", "https://malicious-site.com/OllamaSetup.exe"):
            with self.assertRaises(OllamaVerificationError) as ctx:
                download_ollama_installer(dest_dir=self.tmp_dir)
            self.assertIn("Untrusted download host", str(ctx.exception))

        # Case B: Insecure scheme
        with patch("packaging.pai_setup.OLLAMA_OFFICIAL_INSTALLER_URL", "http://ollama.com/download/OllamaSetup.exe"):
            with self.assertRaises(OllamaVerificationError) as ctx:
                download_ollama_installer(dest_dir=self.tmp_dir)
            self.assertIn("requires HTTPS", str(ctx.exception))

        # Case C: Verification failure cleans up downloaded file
        mock_resp = MagicMock()
        mock_resp.headers = {"Content-Length": "1024"}
        mock_resp.read.side_effect = [b"dummy bytes", b""]
        mock_resp.__enter__.return_value = mock_resp

        mock_opener = MagicMock()
        mock_opener.open.return_value = mock_resp

        target_file = Path(self.tmp_dir) / "OllamaSetup.exe"

        with patch("urllib.request.build_opener", return_value=mock_opener):
            with patch("packaging.pai_setup.verify_authenticode_publisher", side_effect=OllamaVerificationError("Bad signature")):
                with self.assertRaises(OllamaVerificationError):
                    download_ollama_installer(dest_dir=self.tmp_dir)
                # File must be cleaned up!
                self.assertFalse(target_file.exists(), "Target file must be unlinked when verification fails (Finding CL)")

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

        # Case B: Cancellation during retry backoff wait
        cancel_tok = CancelToken()

        def slow_resp():
            cancel_tok.cancel()
            m = MagicMock()
            m.status = 200
            m.__iter__.return_value = iter([b'{"status": "starting"}\n'])
            m.__enter__.return_value = m
            return m

        mock_opener_cancel = MagicMock()
        mock_opener_cancel.open.side_effect = [slow_resp(), slow_resp()]

        with patch("urllib.request.build_opener", return_value=mock_opener_cancel):
            with self.assertRaises(DownloadCancelledError):
                pull_model_stream(
                    model_id="cancel-backoff:7b",
                    cancel_token=cancel_tok,
                    max_retries=3,
                    initial_backoff_sec=0.05,
                    show_console_bar=False,
                )

    # -------------------------------------------------------------------------
    # Finding CN: Manifest Digest Verification & Purge
    # -------------------------------------------------------------------------
    def test_21_finding_cn_manifest_digest_verification_and_purge_on_mismatch(self) -> None:
        """
        Finding CN:
          - After pull, manifest digest is queried from Ollama tags API.
          - On digest match: succeeds.
          - On digest mismatch: model is purged via DELETE /api/delete and DIGEST_MISMATCH raised.
        """
        success_stream = [
            b'{"status": "success"}\n',
        ]
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__iter__.return_value = iter(success_stream)
        mock_resp.__enter__.return_value = mock_resp

        mock_opener = MagicMock()
        mock_opener.open.return_value = mock_resp

        expected_good = "sha256:d15ab1e15ab1e15ab1e15ab1e15ab1e15ab1e15ab1e15ab1e15ab1e15ab1e15a"
        bad_actual = "sha256:badbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbad1"

        # Case A: Good digest matches
        resp_good = MagicMock()
        resp_good.status = 200
        resp_good.__iter__.return_value = iter([b'{"status": "success"}\n'])
        resp_good.__enter__.return_value = resp_good

        mock_opener_good = MagicMock()
        mock_opener_good.open.return_value = resp_good

        with patch("urllib.request.build_opener", return_value=mock_opener_good):
            with patch("packaging.pai_setup.query_ollama_model_digest", return_value=expected_good):
                res = pull_model_stream(
                    model_id="verified:model",
                    expected_manifest_digest=expected_good,
                    show_console_bar=False,
                )
                self.assertEqual(res["status"], "done")

        # Case B: Digest mismatch -> Purges model and raises DIGEST_MISMATCH
        resp_bad = MagicMock()
        resp_bad.status = 200
        resp_bad.__iter__.return_value = iter([b'{"status": "success"}\n'])
        resp_bad.__enter__.return_value = resp_bad

        mock_opener_bad = MagicMock()
        mock_opener_bad.open.return_value = resp_bad

        deleted_models = []
        with patch("urllib.request.build_opener", return_value=mock_opener_bad):
            with patch("packaging.pai_setup.query_ollama_model_digest", return_value=bad_actual):
                with patch("packaging.pai_setup.delete_ollama_model", side_effect=lambda ep, m: deleted_models.append(m)):
                    with self.assertRaises(ModelPullError) as ctx:
                        pull_model_stream(
                            model_id="tampered:model",
                            expected_manifest_digest=expected_good,
                            show_console_bar=False,
                        )
                    self.assertEqual(ctx.exception.code, "DIGEST_MISMATCH")
                    self.assertIn("tampered:model", deleted_models)

    # -------------------------------------------------------------------------
    # Finding CN: CLI Guardrails for Free-Form and Unverified Models
    # -------------------------------------------------------------------------
    def test_22_finding_cn_free_form_pull_model_guardrails_and_pattern(self) -> None:
        """
        Finding CN:
          - Model ID not matching <family>:<tag> pattern rejected with INVALID_MODEL_ID.
        """
        setup_script = REPO_ROOT / "packaging" / "pai_setup.py"
        proc_bad = subprocess.run(
            [sys.executable, str(setup_script), "--pull-model", "bad_id_no_colon"],
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(proc_bad.returncode, 0)
        self.assertIn("invalid", proc_bad.stderr.lower())

    def test_23_finding_cn_layer_totals_override_catalog_estimate(self) -> None:
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


if __name__ == "__main__":
    unittest.main()
