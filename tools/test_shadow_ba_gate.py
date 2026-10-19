"""
Unit and integration tests for Finding BA & BB: Gate verification and evaluation manifest tree ID tracking.
Strictly confined to tools/ directory.
Uses tempfile.TemporaryDirectory for full environment and filesystem isolation.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))
sys.path.insert(0, str(REPO_ROOT / "research"))

import run_shadow_workload


class TestFindingBAGate(unittest.TestCase):

    def test_manifest_tree_ids_persisted_and_verified(self):
        """Finding BA & BB: Manifest creation, verification, and mismatch checks using tempdir."""
        with tempfile.TemporaryDirectory() as tmp_dir_str:
            manifest_dir = Path(tmp_dir_str)
            commit = "9ac1bc5b056f53fb88c1206fec896df9ffc85c1f"
            bin_hash = "6f13d49463c757f2f3e43506f9743c37f602196544ce8fa85d5c5ce9332e3efe"
            r_tree = "6e0fb90123f282caa68ea51d54ee3816a96fb4fd"
            c_tree = "14c60746ca9a41d91aafd88cc0c7d98719cfe3a9"

            # 1. First run creates manifest with tree IDs
            m_path = run_shadow_workload.check_or_update_evaluation_manifest(
                manifest_dir, commit, bin_hash, r_tree, c_tree
            )
            self.assertTrue(m_path.exists())
            with open(m_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.assertEqual(data.get("research_tree_id"), r_tree)
            self.assertEqual(data.get("core_tree_id"), c_tree)

            # 2. Subsequent matching run passes
            m_path2 = run_shadow_workload.check_or_update_evaluation_manifest(
                manifest_dir, commit, bin_hash, r_tree, c_tree
            )
            self.assertEqual(m_path, m_path2)

            # 3. research/ tree ID mismatch fails closed
            with self.assertRaises(RuntimeError) as ctx_r:
                run_shadow_workload.check_or_update_evaluation_manifest(
                    manifest_dir, commit, bin_hash, "ffffffffffffffffffffffffffffffffffffffff", c_tree
                )
            self.assertIn("research/ tree ID", str(ctx_r.exception))
            self.assertIn("Finding BA Gate Failed", str(ctx_r.exception))

            # 4. core/ tree ID mismatch fails closed
            with self.assertRaises(RuntimeError) as ctx_c:
                run_shadow_workload.check_or_update_evaluation_manifest(
                    manifest_dir, commit, bin_hash, r_tree, "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
                )
            self.assertIn("core/ tree ID", str(ctx_c.exception))
            self.assertIn("Finding BA Gate Failed", str(ctx_c.exception))

    def test_gate_fails_closed_on_uncommitted_working_tree_change(self):
        """Finding BA & BB: Gate refuses execution when working tree has uncommitted edits."""
        real_run = subprocess.run

        def side_effect(cmd, **kwargs):
            if isinstance(cmd, (list, tuple)) and len(cmd) > 0 and cmd[0] == "git":
                if "status" in cmd:
                    mock_res = mock.MagicMock()
                    mock_res.stdout = " M research/pai.py\n"
                    mock_res.returncode = 0
                    return mock_res
                return real_run(cmd, **kwargs)
            return real_run(cmd, **kwargs)

        with mock.patch("subprocess.run", side_effect=side_effect):
            with self.assertRaises(RuntimeError) as ctx:
                run_shadow_workload.verify_shadow_evaluation_gate(REPO_ROOT)
            self.assertIn("Working tree contains uncommitted changes", str(ctx.exception))

    def test_gate_fails_closed_on_git_diff_mismatch(self):
        """Finding BA & BB: Gate refuses execution when working tree differs from pinned commit."""
        real_run = subprocess.run

        def side_effect(cmd, **kwargs):
            if isinstance(cmd, (list, tuple)) and len(cmd) > 0 and cmd[0] == "git":
                if "diff" in cmd:
                    mock_res = mock.MagicMock()
                    mock_res.returncode = 1
                    return mock_res
                return real_run(cmd, **kwargs)
            return real_run(cmd, **kwargs)

        with mock.patch("subprocess.run", side_effect=side_effect):
            with self.assertRaises(RuntimeError) as ctx:
                run_shadow_workload.verify_shadow_evaluation_gate(REPO_ROOT)
            self.assertIn("Working tree differs from pinned evaluated commit", str(ctx.exception))

    def test_real_git_clone_adversarial_modification_halts_gate(self):
        """
        Finding BB Integration Test: Clones repository into a temporary directory,
        modifies a tracked file in research/, and verifies verify_shadow_evaluation_gate
        fails closed without needing any mocks.
        """
        with tempfile.TemporaryDirectory() as tmp_clone_dir:
            clone_path = Path(tmp_clone_dir) / "clone"
            # Fast local shared clone
            subprocess.run(
                ["git", "clone", "-s", str(REPO_ROOT), str(clone_path)],
                check=True,
                capture_output=True,
                text=True,
            )

            test_file = clone_path / "research" / "pai.py"
            self.assertTrue(test_file.exists(), "research/pai.py must exist in temporary clone")

            # 1. Dirty working tree test: modify research/pai.py
            with open(test_file, "a", encoding="utf-8") as f:
                f.write("\n# Adversarial uncommitted change for Finding BB test\n")

            with self.assertRaises(RuntimeError) as ctx_dirty:
                run_shadow_workload.verify_shadow_evaluation_gate(clone_path)
            self.assertIn("Working tree contains uncommitted changes", str(ctx_dirty.exception))

            # 2. Committed drift test: commit the change in clone
            subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=str(clone_path), check=True)
            subprocess.run(["git", "config", "user.name", "Test Runner"], cwd=str(clone_path), check=True)
            subprocess.run(["git", "add", "research/pai.py"], cwd=str(clone_path), check=True)
            subprocess.run(["git", "commit", "-m", "adversarial drift commit"], cwd=str(clone_path), check=True)

            with self.assertRaises(RuntimeError) as ctx_drift:
                run_shadow_workload.verify_shadow_evaluation_gate(clone_path)
            self.assertIn("Working tree differs from pinned evaluated commit", str(ctx_drift.exception))


if __name__ == "__main__":
    unittest.main()
