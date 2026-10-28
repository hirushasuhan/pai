"""
Unit tests for ADR-014 Commit 1: Managed Local Ollama Service Lifecycle.
Tests service detection, hostile PATH rejection, Authenticode gating, consent modes,
lifecycle process cleanup, and raw WinError 10061 suppression.
"""

from __future__ import annotations

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

RESEARCH_DIR = Path(__file__).resolve().parent.parent
if str(RESEARCH_DIR) not in sys.path:
    sys.path.insert(0, str(RESEARCH_DIR))

from service_manager import (
    DEFAULT_CONSENT_MODE,
    SERVICE_OFFLINE_GUIDANCE,
    OllamaServiceManager,
    get_official_ollama_path,
    get_ollama_consent_mode,
    set_ollama_consent_mode,
)
from pai_setup import OllamaVerificationError


class TestServiceManagerADR014(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = tempfile.mkdtemp(prefix="pai_sm_test_")
        self.config_dir = Path(self.tmp_dir) / "config"
        self.config_dir.mkdir(parents=True, exist_ok=True)
        # Reset singleton if needed
        OllamaServiceManager._global_instance = None

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp_dir, ignore_errors=True)
        OllamaServiceManager._global_instance = None

    # -------------------------------------------------------------------------
    # 1. State Discovery Order (ADR-014 §2)
    # -------------------------------------------------------------------------
    def test_service_detection_states(self) -> None:
        """
        Tests discovery states:
          A. Online -> immediately available (is_running = True)
          B. Offline & missing executable -> fails with guidance
          C. Offline & present executable -> proceeds to start
        """
        # State A: Online
        mgr = OllamaServiceManager(config_dir=self.config_dir)
        with patch.object(mgr, "is_running", return_value=True):
            ok, msg = mgr.ensure_service_running()
            self.assertTrue(ok)
            self.assertIn("running", msg)

        # State B: Offline & missing executable
        mgr_missing = OllamaServiceManager(config_dir=self.config_dir)
        with patch.object(mgr_missing, "is_running", return_value=False):
            with patch.object(mgr_missing, "get_target_executable", return_value=None):
                ok, msg = mgr_missing.ensure_service_running()
                self.assertFalse(ok)
                self.assertEqual(msg, SERVICE_OFFLINE_GUIDANCE)

        # State C: Offline & executable present with consent
        fake_bin = Path(self.tmp_dir) / "ollama.exe"
        fake_bin.write_bytes(b"MZ_MOCK_BINARY")
        mgr_present = OllamaServiceManager(
            config_dir=self.config_dir,
            executable_path=fake_bin,
            verify_authenticode=False,
        )
        set_ollama_consent_mode("always", self.config_dir)
        with patch.object(mgr_present, "is_running", side_effect=[False, False, True]):
            with patch("subprocess.Popen") as mock_popen:
                mock_proc = MagicMock()
                mock_proc.pid = 9999
                mock_proc.poll.return_value = None
                mock_popen.return_value = mock_proc
                ok, msg = mgr_present.ensure_service_running()
                self.assertTrue(ok)
                self.assertEqual(mgr_present.child_pid, 9999)

    # -------------------------------------------------------------------------
    # 2. Hostile PATH Hijacking Rejected (ADR-014 §2)
    # -------------------------------------------------------------------------
    def test_hostile_path_hijack_rejected(self) -> None:
        """
        Places a rogue 'ollama.exe' earlier on PATH.
        Asserts that get_target_executable NEVER searches PATH and only inspects
        the pinned official path (%LOCALAPPDATA%\\Programs\\Ollama\\ollama.exe).
        """
        rogue_dir = Path(self.tmp_dir) / "rogue_path"
        rogue_dir.mkdir(parents=True, exist_ok=True)
        rogue_exe = rogue_dir / "ollama.exe"
        rogue_exe.write_bytes(b"MALICIOUS_ROGUE_BINARY")

        env = os.environ.copy()
        env["PATH"] = f"{rogue_dir}{os.pathsep}{env.get('PATH', '')}"

        with patch.dict(os.environ, env):
            # Assert shutil.which would find the rogue binary
            found_which = shutil.which("ollama", path=env["PATH"])
            self.assertIsNotNone(found_which)
            self.assertEqual(Path(found_which).resolve(), rogue_exe.resolve())

            # ServiceManager must NOT find the rogue binary when official path is missing
            with patch.dict(os.environ, {"LOCALAPPDATA": str(Path(self.tmp_dir) / "empty_localappdata")}):
                mgr = OllamaServiceManager(config_dir=self.config_dir)
                target = mgr.get_target_executable()
                self.assertIsNone(target, "Service manager MUST NOT resolve ollama.exe from PATH (Finding T21 / ADR-014)")

    # -------------------------------------------------------------------------
    # 3. Authenticode Verification Gate (ADR-014 §2)
    # -------------------------------------------------------------------------
    def test_authenticode_validation_fail_closed(self) -> None:
        """
        Asserts that if the target binary fails Authenticode verification,
        execution fails closed with OllamaVerificationError and subprocess is never called.
        """
        fake_bin = Path(self.tmp_dir) / "ollama.exe"
        fake_bin.write_bytes(b"UNSIGNED_BINARY")

        mgr = OllamaServiceManager(
            config_dir=self.config_dir,
            executable_path=fake_bin,
            verify_authenticode=True,
        )
        set_ollama_consent_mode("always", self.config_dir)

        with patch.object(mgr, "is_running", return_value=False):
            with patch("pai_setup.verify_authenticode_publisher", side_effect=OllamaVerificationError("Invalid digital signature")):
                with patch("subprocess.Popen") as mock_popen:
                    with self.assertRaises(OllamaVerificationError):
                        mgr.start_service()
                    mock_popen.assert_not_called()

    # -------------------------------------------------------------------------
    # 4. Process Lifecycle and Cleanup (ADR-014 §2)
    # -------------------------------------------------------------------------
    def test_lifecycle_cleanup_started_vs_external(self) -> None:
        """
        Case A: Process started by PAI -> terminated on stop_service().
        Case B: Process was already running externally -> stop_service() touches nothing.
        """
        # Case A: Started by PAI
        mgr = OllamaServiceManager(config_dir=self.config_dir)
        mock_proc = MagicMock()
        mock_proc.pid = 12345
        mgr.child_process = mock_proc
        mgr.child_pid = 12345

        mgr.stop_service()
        mock_proc.terminate.assert_called_once()
        self.assertIsNone(mgr.child_process)
        self.assertIsNone(mgr.child_pid)

        # Case B: External process (was already running)
        mgr_ext = OllamaServiceManager(config_dir=self.config_dir)
        with patch.object(mgr_ext, "is_running", return_value=True):
            ok = mgr_ext.start_service()
            self.assertTrue(ok)
            self.assertIsNone(mgr_ext.child_process)
            self.assertIsNone(mgr_ext.child_pid)

            # Stopping must NOT terminate any external process
            mgr_ext.stop_service()
            self.assertIsNone(mgr_ext.child_process)

    # -------------------------------------------------------------------------
    # 5. User Consent Modes and Persistence (ADR-014 D17)
    # -------------------------------------------------------------------------
    def test_consent_modes_and_persistence(self) -> None:
        """
        Tests:
          - Default mode is 'ask'
          - 'always' proceeds without prompt
          - 'never' aborts without prompt
          - 'ask' prompts interactively and persists 'always' or 'never'
          - 'ask' non-interactive returns False fail-closed
        """
        # Default is 'ask'
        self.assertEqual(get_ollama_consent_mode(self.config_dir), DEFAULT_CONSENT_MODE)

        # Mode 'always'
        set_ollama_consent_mode("always", self.config_dir)
        mgr_always = OllamaServiceManager(config_dir=self.config_dir)
        self.assertTrue(mgr_always.prompt_user_consent())

        # Mode 'never'
        set_ollama_consent_mode("never", self.config_dir)
        mgr_never = OllamaServiceManager(config_dir=self.config_dir)
        self.assertFalse(mgr_never.prompt_user_consent())

        # Mode 'ask' with non-interactive session
        set_ollama_consent_mode("ask", self.config_dir)
        mgr_ask = OllamaServiceManager(config_dir=self.config_dir)
        with patch("sys.stdin.isatty", return_value=False):
            self.assertFalse(mgr_ask.prompt_user_consent(), "Non-interactive 'ask' mode must fail closed")

        # Mode 'ask' with interactive session choosing 'always'
        with patch("sys.stdin.isatty", return_value=True):
            with patch("sys.stdout.isatty", return_value=True):
                with patch("builtins.input", return_value="always"):
                    self.assertTrue(mgr_ask.prompt_user_consent())
                    self.assertEqual(get_ollama_consent_mode(self.config_dir), "always")

    # -------------------------------------------------------------------------
    # 6. Raw WinError 10061 Suppressed in Call Model Generate (ADR-014 §2)
    # -------------------------------------------------------------------------
    def test_raw_winerror_10061_suppressed(self) -> None:
        """
        Asserts call_model_generate replaces raw WinError 10061 socket failures
        with the clean, single-sentence guidance without socket trace.
        """
        from pai import call_model_generate
        import urllib.error

        # Simulate raw WinError 10061
        mock_err = urllib.error.URLError("[WinError 10061] No connection could be made because the target machine actively refused it")

        with patch("urllib.request.urlopen", side_effect=mock_err):
            with patch("service_manager.OllamaServiceManager.ensure_service_running", return_value=(False, SERVICE_OFFLINE_GUIDANCE)):
                with self.assertRaises(RuntimeError) as ctx:
                    call_model_generate("test-model", "hello", timeout=1.0)

                err_msg = str(ctx.exception)
                self.assertNotIn("WinError 10061", err_msg, "Raw socket error code must be suppressed")
                self.assertIn("Local AI service (Ollama) is not running on 127.0.0.1:11434", err_msg)


if __name__ == "__main__":
    unittest.main()
