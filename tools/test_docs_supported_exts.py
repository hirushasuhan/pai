#!/usr/bin/env python3
"""
tools/test_docs_supported_exts.py - Unit test asserting driver docs extensions match research/pai.py.

Condition 1: Ensures no drift between `tools/run_shadow_workload.py` valid extensions
and `cmd_docs` in `research/pai.py` without modifying research/ or core/.
"""

import unittest
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))
import run_shadow_workload as rsw


class TestDocsSupportedExtensions(unittest.TestCase):
    def test_extensions_match_cmd_docs(self):
        exts = rsw.get_pai_docs_supported_extensions(REPO_ROOT)
        expected = {".txt", ".md", ".csv", ".text", ".markdown"}
        self.assertEqual(
            exts,
            expected,
            f"Driver docs extensions ({exts}) drift from expected cmd_docs supported formats ({expected})",
        )
        # Ensure code extensions are rejected by the docs target filter
        for invalid in [".py", ".rs", ".json", ".toml", ".yml", ".yaml", ".properties", ".docx"]:
            self.assertNotIn(invalid, exts)


if __name__ == "__main__":
    unittest.main()
