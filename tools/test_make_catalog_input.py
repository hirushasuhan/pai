#!/usr/bin/env python3
"""
Unit Tests for tools/make_catalog_input.py (Milestone C1 & C1b).

Strict Invariants Enforced:
1. Purely offline: Uses FAKE registry responses only. Zero real network requests.
2. Covers:
   - Sum of layer sizes for download_bytes and disk_bytes (excludes config blob).
   - Exact manifest digest calculation and recording.
   - Unverified license status default across all models.
   - Grounded license detection (Apache-2.0, fallback to 'see licence text') and file export.
   - Config blob parsing (quantization from file_type, parameters_b from model_type).
   - Failure on missing config fields (file_type, model_type).
   - Measured fields handling (real measured values when present, conservative formula when unmeasured).
   - Single uniform rule for min_vram_mb (weights size in MB, observed VRAM in measured).
   - Atomic failure: Network error leaves no file behind.
   - HTTP 404 failure handling.
   - Malformed JSON handling.
   - Empty layers list rejection.
   - Digest header mismatch validation.
   - Schema conformance against research/pai_setup.py:verify_catalog_payload (fails if cryptography missing).
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = REPO_ROOT / "tools"
RESEARCH_DIR = REPO_ROOT / "research"

for p in (str(TOOLS_DIR), str(RESEARCH_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

from make_catalog_input import (
    build_model_entry,
    detect_license_name,
    fetch_registry_blob,
    fetch_registry_manifest,
    generate_catalog_input_payload,
    load_cold_ram_measurements,
    main as cli_main,
    parse_config_parameters_b,
    parse_config_quantization,
    parse_model_tag,
    safe_filename_for_tag,
    write_catalog_input_atomically,
)
from pai_setup import verify_catalog_payload

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
except ImportError:
    ed25519 = None


def make_fake_config(file_type: str = "Q4_K_M", model_type: str = "1.5B") -> bytes:
    """Generates synthetic OCI config blob bytes."""
    cfg = {
        "model_format": "gguf",
        "model_family": "qwen2",
        "model_type": model_type,
        "file_type": file_type,
    }
    return json.dumps(cfg).encode("utf-8")


def make_fake_manifest(
    layer_sizes: List[int],
    config_digest: Optional[str] = None,
    license_digest: Optional[str] = None,
) -> bytes:
    """Generates synthetic OCI manifest bytes with specified layer sizes and digests."""
    cfg_dig = config_digest or f"sha256:{hashlib.sha256(b'default_cfg').hexdigest()}"
    layers = []
    if license_digest:
        layers.append({
            "mediaType": "application/vnd.ollama.image.license",
            "size": 100,
            "digest": license_digest,
        })
    for idx, sz in enumerate(layer_sizes):
        layers.append({
            "mediaType": "application/vnd.ollama.image.model",
            "size": sz,
            "digest": f"sha256:{hashlib.sha256(f'layer_{idx}'.encode()).hexdigest()}",
        })
    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": 400,
            "digest": cfg_dig,
        },
        "layers": layers,
    }
    return json.dumps(manifest).encode("utf-8")


class TestMakeCatalogInput(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory(prefix="pai_cat_test_")
        self.tmp_path = Path(self.tmp_dir.name)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def test_01_sum_of_layer_sizes(self) -> None:
        """Requirement: download_bytes and disk_bytes are computed as the sum of layer sizes (excluding config)."""
        raw_manifest_bytes = make_fake_manifest([1000, 2500, 6500])
        manifest = json.loads(raw_manifest_bytes.decode("utf-8"))
        digest = f"sha256:{hashlib.sha256(raw_manifest_bytes).hexdigest()}"
        config = {"file_type": "Q4_K_M", "model_type": "0.5B"}

        entry = build_model_entry(
            tag="qwen2.5:0.5b",
            manifest=manifest,
            manifest_digest=digest,
            config=config,
            license_text=None,
            license_digest=None,
            measurements={},
        )

        expected_sum = 1000 + 2500 + 6500  # 10,000 bytes
        self.assertEqual(entry["download_bytes"], expected_sum)
        self.assertEqual(entry["disk_bytes"], expected_sum)

    def test_02_digest_recorded(self) -> None:
        """Requirement: Exact SHA-256 digest of registry manifest is calculated and recorded."""
        raw_bytes = make_fake_manifest([500, 1500])
        expected_sha256 = f"sha256:{hashlib.sha256(raw_bytes).hexdigest()}"

        mock_resp = MagicMock()
        mock_resp.read.return_value = raw_bytes
        mock_resp.headers = {}
        mock_resp.__enter__.return_value = mock_resp

        with patch("urllib.request.urlopen", return_value=mock_resp):
            digest, manifest = fetch_registry_manifest("qwen2.5:0.5b")

        self.assertEqual(digest, expected_sha256)
        config = {"file_type": "Q4_K_M", "model_type": "0.5B"}
        entry = build_model_entry("qwen2.5:0.5b", manifest, digest, config, None, None, {})
        self.assertEqual(entry["registry_manifest_digest"], expected_sha256)

    def test_03_unverified_license_default(self) -> None:
        """Requirement: license_status must be 'unverified' and URL must point to ollama library."""
        lic_bytes = b"Some random license terms without known header"
        lic_sha = f"sha256:{hashlib.sha256(lic_bytes).hexdigest()}"
        raw_bytes = make_fake_manifest([1000], license_digest=lic_sha)
        manifest = json.loads(raw_bytes.decode("utf-8"))
        digest = f"sha256:{hashlib.sha256(raw_bytes).hexdigest()}"
        config = {"file_type": "Q4_K_M", "model_type": "0.5B"}

        entry = build_model_entry(
            tag="qwen2.5:0.5b",
            manifest=manifest,
            manifest_digest=digest,
            config=config,
            license_text=lic_bytes.decode("utf-8"),
            license_digest=lic_sha,
            measurements={},
        )
        lic = entry.get("license", {})
        self.assertEqual(lic.get("license_status"), "unverified")
        self.assertIsNone(lic.get("read_on"))
        self.assertEqual(lic.get("url"), "https://ollama.com/library/qwen2.5:0.5b")
        self.assertEqual(lic.get("sha256"), lic_sha)
        self.assertEqual(lic.get("name"), "see licence text")

    def test_04_measured_fields_handling(self) -> None:
        """
        Requirement:
          - Models with real measurements record real values from cold_ram_measurements.json.
          - min_vram_mb follows single uniform rule (weights size in MB), observed VRAM in measured.
          - Unmeasured models have measured=None and conservative footprint formula.
        """
        fake_measurements = {
            "qwen2.5-coder:1.5b": {
                "model_footprint_mb": 1112.2,
                "model_vram_mb": 1112.2,
                "host_delta_mb_max": 628.3,
            }
        }
        raw_bytes = make_fake_manifest([1024 * 1024 * 500])  # ~500 MB
        manifest = json.loads(raw_bytes.decode("utf-8"))
        digest = f"sha256:{hashlib.sha256(raw_bytes).hexdigest()}"
        config = {"file_type": "Q4_K_M", "model_type": "1.5B"}

        # 1. Measured model
        entry_measured = build_model_entry(
            "qwen2.5-coder:1.5b", manifest, digest, config, None, None, fake_measurements
        )
        self.assertEqual(entry_measured["min_ram_mb"], 1112.2)
        self.assertEqual(entry_measured["min_vram_mb"], 500.0)  # Weights size
        self.assertIsNotNone(entry_measured["measured"])
        self.assertEqual(entry_measured["measured"]["host_delta_mb"], 628.3)
        self.assertEqual(entry_measured["measured"]["observed_vram_mb"], 1112.2)
        self.assertIsNone(entry_measured["measured"]["tokens_per_sec"])
        self.assertEqual(entry_measured["measured"]["machine"], "RTX 4050 6GB / 16GB RAM")

        # 2. Unmeasured model (must have measured=None, conservative formula)
        config_05 = {"file_type": "Q4_K_M", "model_type": "0.5B"}
        entry_unmeasured = build_model_entry(
            "qwen2.5:0.5b", manifest, digest, config_05, None, None, fake_measurements
        )
        self.assertIsNone(entry_unmeasured["measured"])
        # Conservative formula: 500 MB + 512 MB = 1012.0 MB
        self.assertEqual(entry_unmeasured["min_ram_mb"], 1012.0)
        self.assertEqual(entry_unmeasured["min_vram_mb"], 500.0)

    def test_05_network_error_leaves_no_file_atomic(self) -> None:
        """Requirement: Network failure for one tag fails visibly and leaves no partial output file."""
        out_target = self.tmp_path / "catalog_input_test.json"
        self.assertFalse(out_target.exists())

        # Simulate network error on fetch
        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Network connection failed")):
            with patch("sys.argv", ["make_catalog_input.py", "--out", str(out_target)]):
                exit_code = cli_main()

        self.assertNotEqual(exit_code, 0, "CLI must exit with non-zero on network failure")
        self.assertFalse(out_target.exists(), "No partial or failed output file must remain")
        # Ensure no stray temporary files in target directory
        stray_tmps = list(self.tmp_path.glob("tmp_cat_input_*.json"))
        self.assertEqual(stray_tmps, [], "No stray temp files should remain after failure")

    def test_06_output_passes_verifier_schema_checks(self) -> None:
        """
        Requirement: Generated catalog output passes all schema and security checks
        that research/pai_setup.py:verify_catalog_payload enforces (except signature).
        Fails (not skips) if cryptography is missing.
        """
        if ed25519 is None:
            self.fail("cryptography library required for test_06")

        config_bytes = make_fake_config("Q4_K_M", "0.5B")
        cfg_dig = f"sha256:{hashlib.sha256(config_bytes).hexdigest()}"
        lic_bytes = b"Apache License\nVersion 2.0, January 2004\nhttp://www.apache.org/licenses/"
        lic_dig = f"sha256:{hashlib.sha256(lic_bytes).hexdigest()}"
        manifest_bytes = make_fake_manifest([300_000_000], config_digest=cfg_dig, license_digest=lic_dig)

        def mock_urlopen(req, timeout=15.0):
            url = req.full_url if hasattr(req, "full_url") else str(req)
            resp = MagicMock()
            resp.headers = {}
            resp.__enter__.return_value = resp
            if "/manifests/" in url:
                resp.read.return_value = manifest_bytes
            elif cfg_dig in url:
                resp.read.return_value = config_bytes
            elif lic_dig in url:
                resp.read.return_value = lic_bytes
            else:
                resp.read.return_value = b"{}"
            return resp

        with patch("urllib.request.urlopen", side_effect=mock_urlopen):
            catalog_payload = generate_catalog_input_payload(
                model_tags=["qwen2.5:0.5b"],
                measurements_path=self.tmp_path / "nonexistent_measurements.json",
                licence_texts_dir=self.tmp_path / "licences",
            )

        self.assertEqual(catalog_payload["kind"], "catalog")
        self.assertEqual(catalog_payload["catalog_version"], 1)
        self.assertEqual(len(catalog_payload["models"]), 1)

        # Sign with a throwaway test key to test complete verify_catalog_payload execution
        priv_key = ed25519.Ed25519PrivateKey.generate()
        pub_hex = priv_key.public_key().public_bytes_raw().hex()

        # Canonical bytes without signature
        d = {k: v for k, v in catalog_payload.items() if k != "signature"}
        canonical_bytes = json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        sig_hex = priv_key.sign(canonical_bytes).hex()

        test_catalog = dict(catalog_payload)
        test_catalog["signature"] = sig_hex

        trust_keys = [{"id": "test_key", "public_hex": pub_hex, "revoked": False}]
        verified = verify_catalog_payload(
            test_catalog,
            trust_keys=trust_keys,
            state_path=self.tmp_path / "test_state.json",
            enforce_freshness=True,
        )
        self.assertEqual(verified["kind"], "catalog")
        self.assertEqual(len(verified["models"]), 1)

    def test_07_license_detection_apache(self) -> None:
        """Requirement: Apache 2.0 license text derives Apache-2.0 and writes license file."""
        lic_text = (
            "\n                                 Apache License\n"
            "                           Version 2.0, January 2004\n"
            "                        http://www.apache.org/licenses/\n"
        )
        self.assertEqual(detect_license_name(lic_text), "Apache-2.0")

        # Test writing file during generate_catalog_input_payload
        cfg_bytes = make_fake_config("Q4_K_M", "1.5B")
        cfg_dig = f"sha256:{hashlib.sha256(cfg_bytes).hexdigest()}"
        lic_bytes = lic_text.encode("utf-8")
        lic_dig = f"sha256:{hashlib.sha256(lic_bytes).hexdigest()}"
        man_bytes = make_fake_manifest([100_000_000], config_digest=cfg_dig, license_digest=lic_dig)

        def mock_urlopen(req, timeout=15.0):
            url = req.full_url if hasattr(req, "full_url") else str(req)
            resp = MagicMock()
            resp.headers = {}
            resp.__enter__.return_value = resp
            if "/manifests/" in url:
                resp.read.return_value = man_bytes
            elif cfg_dig in url:
                resp.read.return_value = cfg_bytes
            elif lic_dig in url:
                resp.read.return_value = lic_bytes
            return resp

        lic_dir = self.tmp_path / "licence_texts"
        with patch("urllib.request.urlopen", side_effect=mock_urlopen):
            cat = generate_catalog_input_payload(
                model_tags=["qwen2.5-coder:1.5b"],
                measurements_path=self.tmp_path / "empty.json",
                licence_texts_dir=lic_dir,
            )

        saved_file = lic_dir / "qwen2.5-coder_1.5b.txt"
        self.assertTrue(saved_file.is_file(), "License file must be saved with safe filename")
        self.assertEqual(saved_file.read_bytes(), lic_bytes, "Saved file must be byte-exact to downloaded blob (Finding FW)")
        self.assertEqual(cat["models"][0]["license"]["name"], "Apache-2.0")

    def test_08_license_fallback_unknown(self) -> None:
        """Requirement: Unrecognized license text falls back to 'see licence text'."""
        unknown_text = "Custom terms and proprietary conditions apply."
        self.assertEqual(detect_license_name(unknown_text), "see licence text")
        self.assertEqual(detect_license_name(""), "see licence text")

    def test_09_config_blob_parsing(self) -> None:
        """Requirement: quantization taken from file_type, parameters_b taken from model_type."""
        cfg_05 = {"file_type": "Q4_K_M", "model_type": "494.03M"}
        self.assertEqual(parse_config_quantization(cfg_05, "qwen2.5:0.5b"), "Q4_K_M")
        self.assertEqual(parse_config_parameters_b(cfg_05, "qwen2.5:0.5b"), 0.5)

        cfg_15 = {"file_type": "Q5_K_M", "model_type": "1.5B"}
        self.assertEqual(parse_config_quantization(cfg_15, "qwen2.5-coder:1.5b"), "Q5_K_M")
        self.assertEqual(parse_config_parameters_b(cfg_15, "qwen2.5-coder:1.5b"), 1.5)

        cfg_7b = {"file_type": "Q4_K_M", "model_type": "7.6B"}
        self.assertEqual(parse_config_quantization(cfg_7b, "qwen2.5-coder:7b"), "Q4_K_M")
        self.assertEqual(parse_config_parameters_b(cfg_7b, "qwen2.5-coder:7b"), 7.6)

    def test_10_config_blob_missing_fields_fails(self) -> None:
        """Requirement: Missing file_type or model_type in config fails visibly with ValueError."""
        with self.assertRaises(ValueError):
            parse_config_quantization({}, "test:tag")

        with self.assertRaises(ValueError):
            parse_config_parameters_b({}, "test:tag")

        with self.assertRaises(ValueError):
            parse_config_parameters_b({"model_type": "invalid_format"}, "test:tag")

    def test_11_http_404_failure(self) -> None:
        """Requirement: HTTP 404 on manifest or blob raises RuntimeError and CLI exits non-zero."""
        err_404 = urllib.error.HTTPError(
            url="http://fake", code=404, msg="Not Found", hdrs=MagicMock(), fp=io.BytesIO(b"Not Found")
        )
        with patch("urllib.request.urlopen", side_effect=err_404):
            with self.assertRaises(RuntimeError):
                fetch_registry_manifest("qwen2.5:0.5b")

        out_target = self.tmp_path / "catalog_404.json"
        with patch("urllib.request.urlopen", side_effect=err_404):
            with patch("sys.argv", ["make_catalog_input.py", "--out", str(out_target)]):
                exit_code = cli_main()
        self.assertNotEqual(exit_code, 0)
        self.assertFalse(out_target.exists())

    def test_12_malformed_json_failure(self) -> None:
        """Requirement: Malformed JSON from registry raises RuntimeError and CLI exits non-zero."""
        mock_resp = MagicMock()
        mock_resp.read.return_value = b"{malformed json here..."
        mock_resp.headers = {}
        mock_resp.__enter__.return_value = mock_resp

        with patch("urllib.request.urlopen", return_value=mock_resp):
            with self.assertRaises(RuntimeError):
                fetch_registry_manifest("qwen2.5:0.5b")

    def test_13_empty_layers_failure(self) -> None:
        """Requirement: Manifest with empty layers raises ValueError."""
        manifest = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "config": {"digest": "sha256:1234"},
            "layers": [],
        }
        with self.assertRaises(ValueError):
            build_model_entry("qwen2.5:0.5b", manifest, "sha256:dummy", {}, None, None, {})

    def test_14_digest_header_mismatch_fails(self) -> None:
        """Requirement: Docker-Content-Digest header mismatch raises ValueError / RuntimeError."""
        raw_bytes = make_fake_manifest([1000])
        computed_sha = f"sha256:{hashlib.sha256(raw_bytes).hexdigest()}"
        mismatched_sha = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

        mock_resp = MagicMock()
        mock_resp.read.return_value = raw_bytes
        mock_resp.headers = {"Docker-Content-Digest": mismatched_sha}
        mock_resp.__enter__.return_value = mock_resp

        with patch("urllib.request.urlopen", return_value=mock_resp):
            with self.assertRaises(RuntimeError) as ctx:
                fetch_registry_manifest("qwen2.5:0.5b")
            self.assertIn("mismatch", str(ctx.exception).lower())

    def test_15_license_mentioning_apache_in_body_not_named_apache(self) -> None:
        """Requirement (Finding FX): License text mentioning Apache License in its body must NOT be detected as Apache-2.0."""
        custom_text = (
            "My Custom Proprietary License\n"
            "Copyright (c) 2026 Author\n"
            "All rights reserved.\n\n"
            "Portions of this software are based on dependencies licensed under\n"
            "the Apache License Version 2.0.\n"
        )
        self.assertEqual(detect_license_name(custom_text), "see licence text")

    def test_16_saved_license_file_sha256_equals_digest(self) -> None:
        """Requirement (Finding FW): Saved license file bytes must have SHA-256 equal to recorded license digest."""
        lic_bytes = b"Apache License\nVersion 2.0, January 2004\nhttp://www.apache.org/licenses/\n"
        lic_sha = f"sha256:{hashlib.sha256(lic_bytes).hexdigest()}"
        cfg_bytes = make_fake_config("Q4_K_M", "0.5B")
        cfg_dig = f"sha256:{hashlib.sha256(cfg_bytes).hexdigest()}"
        man_bytes = make_fake_manifest([50_000_000], config_digest=cfg_dig, license_digest=lic_sha)

        def mock_urlopen(req, timeout=15.0):
            url = req.full_url if hasattr(req, "full_url") else str(req)
            resp = MagicMock()
            resp.headers = {}
            resp.__enter__.return_value = resp
            if "/manifests/" in url:
                resp.read.return_value = man_bytes
            elif cfg_dig in url:
                resp.read.return_value = cfg_bytes
            elif lic_sha in url:
                resp.read.return_value = lic_bytes
            return resp

        lic_dir = self.tmp_path / "test_lic_exact"
        with patch("urllib.request.urlopen", side_effect=mock_urlopen):
            cat = generate_catalog_input_payload(
                model_tags=["qwen2.5:0.5b"],
                measurements_path=self.tmp_path / "empty.json",
                licence_texts_dir=lic_dir,
            )

        saved_file = lic_dir / "qwen2.5_0.5b.txt"
        self.assertTrue(saved_file.is_file())
        file_bytes = saved_file.read_bytes()
        file_sha = f"sha256:{hashlib.sha256(file_bytes).hexdigest()}"
        recorded_sha = cat["models"][0]["license"]["sha256"]
        self.assertEqual(file_sha, recorded_sha)
        self.assertEqual(file_bytes, lic_bytes)


if __name__ == "__main__":
    unittest.main()
