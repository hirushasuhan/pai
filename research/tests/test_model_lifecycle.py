"""Unit tests for PAI Studio Model Lifecycle and Uninstall / Purge Engine."""

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from desktop.bridge_server import (
    delete_local_model,
    get_current_model,
    set_current_model,
    get_installed_image_models,
    set_installed_image_model,
)


class TestModelLifecycle(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.models_root = Path(self.temp_dir) / "models"
        self.manifests_dir = self.models_root / "manifests" / "registry.ollama.ai" / "library"
        self.blobs_dir = self.models_root / "blobs"
        self.manifests_dir.mkdir(parents=True, exist_ok=True)
        self.blobs_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_delete_empty_name(self):
        ok, msg = delete_local_model("")
        self.assertFalse(ok)
        self.assertIn("empty", msg.lower())

    def test_delete_model_manifest_and_unreferenced_blobs(self):
        # Create testmodel:1b manifest and blobs
        m1_dir = self.manifests_dir / "testmodel"
        m1_dir.mkdir(parents=True, exist_ok=True)
        m1_file = m1_dir / "1b"
        
        # Two layers: blob_unique and blob_shared
        d_unique = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
        d_shared = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
        
        m1_file.write_text(json.dumps({
            "schemaVersion": 2,
            "config": {"digest": "sha256:cfg111"},
            "layers": [
                {"digest": d_unique, "size": 1048576}, # 1MB
                {"digest": d_shared, "size": 2097152}, # 2MB
            ]
        }), encoding="utf-8")

        # Create another model (othermodel:2b) that shares d_shared
        m2_dir = self.manifests_dir / "othermodel"
        m2_dir.mkdir(parents=True, exist_ok=True)
        m2_file = m2_dir / "2b"
        m2_file.write_text(json.dumps({
            "schemaVersion": 2,
            "layers": [
                {"digest": d_shared, "size": 2097152},
            ]
        }), encoding="utf-8")

        # Create the blob files on disk
        b_unique = self.blobs_dir / d_unique.replace(":", "-")
        b_shared = self.blobs_dir / d_shared.replace(":", "-")
        b_cfg = self.blobs_dir / "sha256-cfg111"

        b_unique.write_bytes(b"U" * 1048576)
        b_shared.write_bytes(b"S" * 2097152)
        b_cfg.write_bytes(b"C" * 256)

        self.assertTrue(m1_file.is_file())
        self.assertTrue(b_unique.is_file())
        self.assertTrue(b_shared.is_file())

        with patch("desktop.bridge_server.get_model_storage_path", return_value=str(self.models_root)):
            with patch("desktop.bridge_server.ensure_ollama_server"):
                ok, msg = delete_local_model("testmodel:1b")

        self.assertTrue(ok)
        self.assertIn("successfully uninstalled", msg)

        # 1. m1_file should be deleted
        self.assertFalse(m1_file.is_file())
        # 2. b_unique and b_cfg should be deleted because no other manifest uses them
        self.assertFalse(b_unique.is_file())
        self.assertFalse(b_cfg.is_file())
        # 3. b_shared should still exist because othermodel:2b still uses it!
        self.assertTrue(b_shared.is_file())

    def test_active_model_fallback(self):
        set_current_model("deleteme:latest")
        self.assertEqual(get_current_model(), "deleteme:latest")

        with patch("desktop.bridge_server.get_model_storage_path", return_value=str(self.models_root)):
            with patch("desktop.bridge_server.ensure_ollama_server"):
                with patch("desktop.bridge_server.get_all_installed_local_models", return_value=([{"name": "fallback:3b"}], True)):
                    ok, msg = delete_local_model("deleteme:latest")

        self.assertTrue(ok)
        self.assertEqual(get_current_model(), "fallback:3b")


if __name__ == "__main__":
    unittest.main()
