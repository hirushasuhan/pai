"""
Unit tests for tools/check_n_plus_1.py (installed copy verification and release pins).
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.check_n_plus_1 import (
    PINNED_BINARY_SHA256,
    PINNED_CORE_TREE,
    PINNED_RESEARCH_TREE,
    verify_installed_copy,
)


class TestCheckNPlus1(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = tempfile.mkdtemp(prefix="pai_check_n1_")

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _create_mock_installed_dir(
        self,
        core_tree: str = PINNED_CORE_TREE,
        research_tree: str = PINNED_RESEARCH_TREE,
        binary_bytes: Optional[bytes] = None,
    ) -> Path:
        p = Path(self.tmp_dir) / "mock_install"
        p.mkdir(parents=True, exist_ok=True)
        bin_dir = p / "bin"
        bin_dir.mkdir(parents=True, exist_ok=True)

        manifest = {
            "format": 1,
            "version": "1.1.0-rc2",
            "tag": "v1.1.0-rc2",
            "trees": {
                "core": core_tree,
                "research": research_tree,
            },
        }
        (p / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

        core_exe = bin_dir / ("pai-core.exe" if sys.platform == "win32" else "pai-core")
        if binary_bytes is None:
            # Create a file whose SHA-256 matches PINNED_BINARY_SHA256 if possible,
            # or copy from real core binary
            real_bin = REPO_ROOT / "core" / "target" / "release" / ("pai-core.exe" if sys.platform == "win32" else "pai-core")
            if real_bin.exists():
                shutil.copy2(real_bin, core_exe)
            else:
                core_exe.write_bytes(b"dummy")
        else:
            core_exe.write_bytes(binary_bytes)

        # Create dummy launcher
        launcher = bin_dir / ("pai.exe" if sys.platform == "win32" else "pai")
        launcher.write_bytes(b"launcher_stub")

        return p

    def test_verify_installed_copy_clean(self) -> None:
        """Asserts that a valid installed directory matching pins is accepted."""
        install_dir = self._create_mock_installed_dir()
        ok, res = verify_installed_copy(install_dir)
        self.assertTrue(res["manifest_found"])
        self.assertTrue(res["core_tree_match"])
        self.assertTrue(res["research_tree_match"])
        self.assertTrue(res["binary_found"])
        self.assertTrue(res["binary_match"])
        self.assertTrue(ok)

    def test_verify_installed_copy_tampered_core_tree(self) -> None:
        """Asserts that a tampered core tree hash is detected and rejected."""
        install_dir = self._create_mock_installed_dir(core_tree="0000000000000000000000000000000000000000")
        ok, res = verify_installed_copy(install_dir)
        self.assertFalse(ok)
        self.assertFalse(res["core_tree_match"])
        self.assertIn("does not match pin", res["errors"][0])

    def test_verify_installed_copy_tampered_research_tree(self) -> None:
        """Asserts that a tampered research tree hash is detected and rejected."""
        install_dir = self._create_mock_installed_dir(research_tree="ffffffffffffffffffffffffffffffffffffffff")
        ok, res = verify_installed_copy(install_dir)
        self.assertFalse(ok)
        self.assertFalse(res["research_tree_match"])

    def test_verify_installed_copy_tampered_binary(self) -> None:
        """Asserts that an unpinned or tampered core binary hash is rejected."""
        install_dir = self._create_mock_installed_dir(binary_bytes=b"tampered_binary_bytes")
        ok, res = verify_installed_copy(install_dir)
        self.assertFalse(ok)
        self.assertFalse(res["binary_match"])

    def test_verify_installed_copy_missing_manifest(self) -> None:
        """Asserts that a directory missing manifest.json fails closed."""
        p = Path(self.tmp_dir) / "empty_dir"
        p.mkdir(parents=True, exist_ok=True)
        ok, res = verify_installed_copy(p)
        self.assertFalse(ok)
        self.assertFalse(res["manifest_found"])

    def test_cli_installed_dir_invocation(self) -> None:
        """Asserts running tools/check_n_plus_1.py with --installed-dir inspects the target directory."""
        install_dir = self._create_mock_installed_dir()
        script = REPO_ROOT / "tools" / "check_n_plus_1.py"
        cmd = [sys.executable, str(script), "--installed-dir", str(install_dir)]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        self.assertIn("[INSTALLED COPY]", proc.stdout)
        self.assertIn("Installed Manifest      : FOUND", proc.stdout)
        self.assertIn("Installed Core Binary   : MATCH", proc.stdout)


if __name__ == "__main__":
    unittest.main()
