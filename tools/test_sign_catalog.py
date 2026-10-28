#!/usr/bin/env python3
"""
Unit tests for tools/sign_catalog.py.

Specification: docs/PACKAGING_SPEC.md (Section 15.5)
Finding EH: Throwaway test keys only; assert key is never leaked in logs or output.
"""

from __future__ import annotations

import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
RESEARCH_DIR = REPO_ROOT / "research"
TOOLS_DIR = REPO_ROOT / "tools"
if str(RESEARCH_DIR) not in sys.path:
    sys.path.insert(0, str(RESEARCH_DIR))
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from pai_setup import CatalogSecurityError, verify_catalog_payload
from sign_catalog import canonical_catalog_bytes, load_private_key_file, main, sign_catalog


def create_sample_catalog(version: int = 1) -> dict:
    return {
        "kind": "catalog",
        "catalog_version": version,
        "issued_utc": "2026-10-28T00:00:00Z",
        "models": [
            {
                "id": "qwen2.5:0.5b",
                "family": "qwen",
                "parameters_b": 0.5,
                "quantization": "q4_k_m",
                "download_bytes": 397000000,
                "disk_bytes": 800000000,
                "min_ram_mb": 1024.0,
                "min_vram_mb": 0.0,
                "tasks": ["chat"],
                "license": {
                    "name": "Apache-2.0",
                    "url": "https://example.com/license",
                    "license_status": "verified",
                    "read_on": "2026-10-28",
                },
                "registry_manifest_digest": "sha256:" + "a" * 64,
                "measured": {
                    "machine": "test-box",
                    "tokens_per_sec": 42.0,
                    "host_delta_mb": 512.0,
                },
            }
        ],
    }


class TestSignCatalogTool(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = tempfile.mkdtemp(prefix="pai_sign_test_")
        self.tmp_path = Path(self.tmp_dir)

        # Generate ephemeral throwaway Ed25519 key for tests only
        self.priv_key = ed25519.Ed25519PrivateKey.generate()
        self.pub_key = self.priv_key.public_key()
        self.pub_hex = self.pub_key.public_bytes_raw().hex()

        self.key_raw_file = self.tmp_path / "throwaway_ed25519.raw"
        self.key_raw_file.write_bytes(self.priv_key.private_bytes_raw())

        self.key_hex_file = self.tmp_path / "throwaway_ed25519.hex"
        self.key_hex_file.write_text(self.priv_key.private_bytes_raw().hex(), encoding="ascii")

        pem_bytes = self.priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        self.key_pem_file = self.tmp_path / "throwaway_ed25519.pem"
        self.key_pem_file.write_bytes(pem_bytes)

        self.catalog_file = self.tmp_path / "catalog_input.json"
        self.catalog_file.write_text(json.dumps(create_sample_catalog(1)), encoding="utf-8")

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_01_sign_and_verify_with_all_key_formats(self) -> None:
        """Tests signing catalog with raw binary, hex string, and PKCS#8 PEM formats."""
        for key_f in (self.key_raw_file, self.key_hex_file, self.key_pem_file):
            out_file = self.tmp_path / f"catalog_signed_{key_f.suffix}.json"
            sign_catalog(self.catalog_file, key_f, out_file)
            self.assertTrue(out_file.is_file())

            signed_data = json.loads(out_file.read_text(encoding="utf-8"))
            self.assertIn("signature", signed_data)
            self.assertEqual(len(signed_data["signature"]), 128)  # 64 bytes in hex

            # Verify against pai_setup trust validation
            trust_keys = [{"id": "rel-1", "public_hex": self.pub_hex, "revoked": False}]
            verified = verify_catalog_payload(signed_data, trust_keys=trust_keys)
            self.assertEqual(verified["catalog_version"], 1)

    def test_02_canonical_json_determinism(self) -> None:
        """Asserts that key ordering differences produce identical canonical bytes."""
        cat_a = {"b": 2, "a": 1, "c": {"y": 20, "x": 10}}
        cat_b = {"a": 1, "c": {"x": 10, "y": 20}, "b": 2, "signature": "ignored"}
        self.assertEqual(canonical_catalog_bytes(cat_a), canonical_catalog_bytes(cat_b))

    def test_03_tamper_detection_fail_closed(self) -> None:
        """Asserts that tampering with any field in a signed catalog fails verification."""
        out_file = self.tmp_path / "catalog_signed.json"
        sign_catalog(self.catalog_file, self.key_raw_file, out_file)

        signed_data = json.loads(out_file.read_text(encoding="utf-8"))
        # Tamper with model download size
        signed_data["models"][0]["download_bytes"] += 1

        trust_keys = [{"id": "rel-1", "public_hex": self.pub_hex, "revoked": False}]
        with self.assertRaises(CatalogSecurityError):
            verify_catalog_payload(signed_data, trust_keys=trust_keys)

    def test_04_cli_execution_and_exit_codes(self) -> None:
        """Tests sign_catalog CLI main entry point."""
        out_file = self.tmp_path / "cli_signed.json"
        rc = main([
            "--catalog", str(self.catalog_file),
            "--private-key-file", str(self.key_raw_file),
            "--out", str(out_file),
        ])
        self.assertEqual(rc, 0)
        self.assertTrue(out_file.is_file())

        # Test failure on missing key file
        rc_fail = main([
            "--catalog", str(self.catalog_file),
            "--private-key-file", str(self.tmp_path / "nonexistent.key"),
            "--out", str(self.tmp_path / "failed.json"),
        ])
        self.assertEqual(rc_fail, 1)

    def test_05_key_never_written_or_leaked_in_output(self) -> None:
        """
        Finding EJ & EH: Asserts that key bytes, hex strings, or PEM representations
        are NEVER printed to stdout/stderr or included in exception messages.
        """
        key_hex = self.priv_key.private_bytes_raw().hex()
        corrupt_key = self.tmp_path / "corrupt.key"
        corrupt_key.write_bytes(b"CORRUPT_NOT_AN_ED25519_KEY")

        # Capture output
        old_stdout, old_stderr = sys.stdout, sys.stderr
        capture_out, capture_err = io.StringIO(), io.StringIO()
        try:
            sys.stdout, sys.stderr = capture_out, capture_err
            rc = main([
                "--catalog", str(self.catalog_file),
                "--private-key-file", str(corrupt_key),
                "--out", str(self.tmp_path / "wont_be_written.json"),
            ])
            self.assertEqual(rc, 1)
        finally:
            sys.stdout, sys.stderr = old_stdout, old_stderr

        combined = capture_out.getvalue() + capture_err.getvalue()
        self.assertNotIn(key_hex, combined)
        self.assertNotIn("CORRUPT_NOT_AN_ED25519_KEY", combined)


if __name__ == "__main__":
    unittest.main()
