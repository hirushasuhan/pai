"""
Unit tests for Finding BA: Gate verification and evaluation manifest tree ID tracking.
Strictly confined to tools/ directory.
"""
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

# Ensure tools/ is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))
sys.path.insert(0, str(REPO_ROOT / "research"))

import run_shadow_workload


class TestFindingBAGate(unittest.TestCase):

    def setUp(self):
        self.repo_root = REPO_ROOT
        self.test_manifest_dir = REPO_ROOT / "tools" / "corpus" / "_test_manifest_ba"
        self.test_manifest_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        import shutil
        if self.test_manifest_dir.exists():
            shutil.rmtree(self.test_manifest_dir, ignore_errors=True)

    def test_manifest_tree_ids_persisted_and_verified(self):
        commit = "9ac1bc5b056f53fb88c1206fec896df9ffc85c1f"
        bin_hash = "6f13d49463c757f2f3e43506f9743c37f602196544ce8fa85d5c5ce9332e3efe"
        r_tree = "6e0fb90123f282caa68ea51d54ee3816a96fb4fd"
        c_tree = "14c60746ca9a41d91aafd88cc0c7d98719cfe3a9"

        # 1. First run creates manifest with tree IDs
        m_path = run_shadow_workload.check_or_update_evaluation_manifest(
            self.test_manifest_dir, commit, bin_hash, r_tree, c_tree
        )
        self.assertTrue(m_path.exists())
        with open(m_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data.get("research_tree_id"), r_tree)
        self.assertEqual(data.get("core_tree_id"), c_tree)

        # 2. Subsequent matching run passes
        m_path2 = run_shadow_workload.check_or_update_evaluation_manifest(
            self.test_manifest_dir, commit, bin_hash, r_tree, c_tree
        )
        self.assertEqual(m_path, m_path2)

        # 3. research/ tree ID mismatch fails closed
        with self.assertRaises(RuntimeError) as ctx_r:
            run_shadow_workload.check_or_update_evaluation_manifest(
                self.test_manifest_dir, commit, bin_hash, "ffffffffffffffffffffffffffffffffffffffff", c_tree
            )
        self.assertIn("research/ tree ID", str(ctx_r.exception))
        self.assertIn("Finding BA Gate Failed", str(ctx_r.exception))

        # 4. core/ tree ID mismatch fails closed
        with self.assertRaises(RuntimeError) as ctx_c:
            run_shadow_workload.check_or_update_evaluation_manifest(
                self.test_manifest_dir, commit, bin_hash, r_tree, "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
            )
        self.assertIn("core/ tree ID", str(ctx_c.exception))
        self.assertIn("Finding BA Gate Failed", str(ctx_c.exception))

    def test_gate_fails_closed_on_uncommitted_working_tree_change(self):
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
                run_shadow_workload.verify_shadow_evaluation_gate(self.repo_root)
            self.assertIn("Working tree contains uncommitted changes", str(ctx.exception))

    def test_gate_fails_closed_on_git_diff_mismatch(self):
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
                run_shadow_workload.verify_shadow_evaluation_gate(self.repo_root)
            self.assertIn("Working tree differs from pinned evaluated commit", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
