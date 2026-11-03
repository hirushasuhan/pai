#!/usr/bin/env python3
"""
Unit Tests for tools/make_catalog_input.py (Milestone C1).

Strict Invariants Enforced:
1. Purely offline: Uses FAKE registry responses only. Zero real network requests.
2. Covers:
   - Sum of layer sizes for download_bytes and disk_bytes.
   - Exact manifest digest calculation and recording.
   - Unverified license status default across all models.
   - Measured fields handling (real measured values when present, null when unmeasured).
   - Atomic failure: Network error leaves no file behind.
   - Schema conformance against research/pai_setup.py:verify_catalog_payload.
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
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = REPO_ROOT / "tools"
RESEARCH_DIR = REPO_ROOT / "research"

for p in (str(TOOLS_DIR), str(RESEARCH_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

from make_catalog_input import (
    build_model_entry,
    fetch_registry_manifest,
    generate_catalog_input_payload,
    load_cold_ram_measurements,
    main as cli_main,
    parse_model_tag,
    parse_parameters_b,
    write_catalog_input_atomically,
)
from pai_setup import verify_catalog_payload

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
except ImportError:
    ed25519 = None


def make_fake_manifest(layer_sizes: list[int]) -> bytes:
    """Generates synthetic OCI manifest bytes with specified layer sizes."""
    layers = [
        {
            "mediaType": "application/vnd.ollama.image.model",
            "size": sz,
            "digest": f"sha256:{hashlib.sha256(f'layer_{idx}'.encode()).hexdigest()}",
        }
        for idx, sz in enumerate(layer_sizes)
    ]
    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": 400,
            "digest": f"sha256:{hashlib.sha256(b'config').hexdigest()}",
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
        """Requirement: download_bytes and disk_bytes are computed as the sum of layer sizes."""
        raw_manifest_bytes = make_fake_manifest([1000, 2500, 6500])
        manifest = json.loads(raw_manifest_bytes.decode("utf-8"))
        digest = f"sha256:{hashlib.sha256(raw_manifest_bytes).hexdigest()}"

        entry = build_model_entry(
            tag="qwen2.5:0.5b",
            manifest=manifest,
            manifest_digest=digest,
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
        mock_resp.__enter__.return_value = mock_resp

        with patch("urllib.request.urlopen", return_value=mock_resp):
            digest, manifest = fetch_registry_manifest("qwen2.5:0.5b")

        self.assertEqual(digest, expected_sha256)
        entry = build_model_entry("qwen2.5:0.5b", manifest, digest, {})
        self.assertEqual(entry["registry_manifest_digest"], expected_sha256)

    def test_03_unverified_license_default(self) -> None:
        """Requirement: license_status must be 'unverified' for every entry."""
        raw_bytes = make_fake_manifest([1000])
        manifest = json.loads(raw_bytes.decode("utf-8"))
        digest = f"sha256:{hashlib.sha256(raw_bytes).hexdigest()}"

        test_tags = ["qwen2.5:0.5b", "qwen2.5-coder:1.5b", "qwen2.5-coder:7b"]
        for tag in test_tags:
            entry = build_model_entry(tag, manifest, digest, {})
            lic = entry.get("license", {})
            self.assertEqual(lic.get("license_status"), "unverified")
            self.assertIsNone(lic.get("read_on"))
            self.assertTrue(bool(lic.get("name")))
            self.assertTrue(bool(lic.get("url")))

    def test_04_measured_fields_handling(self) -> None:
        """
        Requirement:
          - Models with real measurements record real values from cold_ram_measurements.json.
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

        # 1. Measured model
        entry_measured = build_model_entry("qwen2.5-coder:1.5b", manifest, digest, fake_measurements)
        self.assertEqual(entry_measured["min_ram_mb"], 1112.2)
        self.assertEqual(entry_measured["min_vram_mb"], 1112.2)
        self.assertIsNotNone(entry_measured["measured"])
        self.assertEqual(entry_measured["measured"]["host_delta_mb"], 628.3)
        self.assertIsNone(entry_measured["measured"]["tokens_per_sec"])
        self.assertEqual(entry_measured["measured"]["machine"], "RTX 4050 6GB / 16GB RAM")

        # 2. Unmeasured model (must have measured=None, conservative formula)
        entry_unmeasured = build_model_entry("qwen2.5:0.5b", manifest, digest, fake_measurements)
        self.assertIsNone(entry_unmeasured["measured"])
        # Conservative formula: 500 MB + 512 MB = 1012.0 MB
        self.assertEqual(entry_unmeasured["min_ram_mb"], 1012.0)
        self.assertEqual(entry_unmeasured["min_vram_mb"], 500.0)

    def test_05_network_error_leaves_no_file_atomic(self) -> None:
        """Requirement: Network failure for one tag fails visibly and leaves no partial output file."""
        out_target = self.tmp_path / "catalog_input.json"
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
        """
        fake_manifest_bytes = make_fake_manifest([300_000_000])

        mock_resp = MagicMock()
        mock_resp.read.return_value = fake_manifest_bytes
        mock_resp.__enter__.return_value = mock_resp

        with patch("urllib.request.urlopen", return_value=mock_resp):
            catalog_payload = generate_catalog_input_payload(
                model_tags=["qwen2.5:0.5b", "qwen2.5-coder:1.5b"],
                measurements_path=self.tmp_path / "nonexistent_measurements.json",
            )

        self.assertEqual(catalog_payload["kind"], "catalog")
        self.assertEqual(catalog_payload["catalog_version"], 1)
        self.assertEqual(len(catalog_payload["models"]), 2)

        if ed25519 is not None:
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
            self.assertEqual(len(verified["models"]), 2)


if __name__ == "__main__":
    unittest.main()
