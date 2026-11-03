#!/usr/bin/env python3
"""
Unit tests for tools/check_pins.py (Milestone D2a, Finding GB).
Tests:
  - HEAD pin consistency passes with binary present.
  - Absence of pai-core binary emits NOTE and passes when --require-binary is False.
  - Absence of pai-core binary emits FAIL and exits 1 when --require-binary is True.
  - Historic ref v1.0.0-rc1 detects research tree mismatch and fails.
  - CLI parser handling of --require-binary.
"""

from __future__ import annotations

import io
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "tools"))

from check_pins import check_pin_consistency, main as check_pins_main


class TestCheckPins(unittest.TestCase):
    def test_01_pins_pass_on_head(self) -> None:
        """HEAD verification passes all three invariants."""
        passed, lines = check_pin_consistency(ref="HEAD", require_binary=False)
        report = "\n".join(lines)
        self.assertTrue(passed, f"Expected PASS on HEAD, got report:\n{report}")
        self.assertIn("1. CORE TREE INVARIANT: PASS", report)
        self.assertIn("2. RESEARCH TREE INVARIANT: PASS", report)
        self.assertIn("3. CORE BINARY SHA-256 INVARIANT: PASS", report)
        self.assertIn("OVERALL PIN AUDIT VERDICT: PASS", report)

    def test_02_research_tree_mismatch_on_rc1_ref(self) -> None:
        """Historical tag v1.0.0-rc1 research tree differs from pinned tree, causing FAIL."""
        passed, lines = check_pin_consistency(ref="v1.0.0-rc1", require_binary=False)
        report = "\n".join(lines)
        self.assertFalse(passed, f"Expected FAIL on rc1 ref, got report:\n{report}")
        self.assertIn("2. RESEARCH TREE INVARIANT: FAIL", report)
        self.assertIn("OVERALL PIN AUDIT VERDICT: FAIL", report)

    def test_03_missing_binary_without_require_binary_notes_and_passes(self) -> None:
        """When pai-core binary is absent, notes omission and passes based on recorded pins (Finding GB)."""
        orig_is_file = Path.is_file

        def fake_is_file(p_self: Path) -> bool:
            if "pai-core" in p_self.name:
                return False
            return orig_is_file(p_self)

        with patch.object(Path, "is_file", fake_is_file):
            passed, lines = check_pin_consistency(ref="HEAD", require_binary=False)
            report = "\n".join(lines)
            self.assertTrue(passed, f"Expected PASS with NOTE when binary missing without --require-binary:\n{report}")
            self.assertIn("binary file not found, file hash not checked", report)
            self.assertIn("[NOTE    ]", report)
            self.assertIn("3. CORE BINARY SHA-256 INVARIANT: PASS", report)
            self.assertIn("OVERALL PIN AUDIT VERDICT: PASS", report)

    def test_04_missing_binary_with_require_binary_fails(self) -> None:
        """When pai-core binary is absent and --require-binary is True, audit FAILS (Finding GB)."""
        orig_is_file = Path.is_file

        def fake_is_file(p_self: Path) -> bool:
            if "pai-core" in p_self.name:
                return False
            return orig_is_file(p_self)

        with patch.object(Path, "is_file", fake_is_file):
            passed, lines = check_pin_consistency(ref="HEAD", require_binary=True)
            report = "\n".join(lines)
            self.assertFalse(passed, f"Expected FAIL when binary missing with --require-binary:\n{report}")
            self.assertIn("binary file not found, file hash not checked", report)
            self.assertIn("[FAIL    ]", report)
            self.assertIn("3. CORE BINARY SHA-256 INVARIANT: FAIL", report)
            self.assertIn("OVERALL PIN AUDIT VERDICT: FAIL", report)

    def test_05a_cli_main_require_binary_absent_fails(self) -> None:
        """CLI main with --require-binary returns 1 when binary is absent (Finding GD)."""
        orig_is_file = Path.is_file

        def fake_is_file(p_self: Path) -> bool:
            if "pai-core" in p_self.name:
                return False
            return orig_is_file(p_self)

        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            with patch.object(Path, "is_file", fake_is_file):
                rc = check_pins_main(["--require-binary"])
        finally:
            sys.stdout = old_stdout
        self.assertEqual(rc, 1)

    def test_05b_cli_main_require_binary_present_passes(self) -> None:
        """CLI main with --require-binary returns 0 when binary is present with matching SHA-256 (Finding GD)."""
        orig_is_file = Path.is_file
        from packaging.build_payload import EXPECTED_BINARY_SHA256

        def fake_is_file(p_self: Path) -> bool:
            if "pai-core" in p_self.name:
                return True
            return orig_is_file(p_self)

        def fake_sha256(p_self: Path) -> str:
            if "pai-core" in p_self.name:
                return EXPECTED_BINARY_SHA256.lower()
            import hashlib
            return hashlib.sha256(p_self.read_bytes()).hexdigest()

        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            with patch.object(Path, "is_file", fake_is_file), patch("check_pins.sha256_file", fake_sha256):
                rc = check_pins_main(["--require-binary"])
        finally:
            sys.stdout = old_stdout
        self.assertEqual(rc, 0)

    def test_05c_cli_main_default_without_require_binary(self) -> None:
        """CLI main without --require-binary returns 0 even when binary is absent (Finding GD)."""
        orig_is_file = Path.is_file

        def fake_is_file(p_self: Path) -> bool:
            if "pai-core" in p_self.name:
                return False
            return orig_is_file(p_self)

        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            with patch.object(Path, "is_file", fake_is_file):
                rc = check_pins_main([])
        finally:
            sys.stdout = old_stdout
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
