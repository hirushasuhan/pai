"""
Personal Agentic AI (PAI) - Managed Local Ollama Service Lifecycle.
Part of ADR-014 (Commit 1: Managed Ollama Start).

Invariants Enforced:
1. Pinned executable location: Only %LOCALAPPDATA%\\Programs\\Ollama\\ollama.exe is checked.
   PATH lookup is strictly prohibited (test_hostile_path_hijack_rejected).
2. Authenticode verification: Exact target binary is verified via WinVerifyTrust before execution.
3. Loopback-only binding: Only 127.0.0.1:11434 is contacted; external hosts rejected.
4. User consent & persistence: Mode in ~/.pai/config.json with values ("ask", "always", "never").
   Default is "ask" (D17 provisional default). When "ask" is set in non-interactive environment,
   refuses to start fail-closed.
5. Process lifecycle management: Spawns 'ollama.exe serve' with CREATE_NO_WINDOW; tracks child PID.
   Terminates ONLY the specific child PID started by PAI; pre-existing external servers are never touched.
6. Plain language errors: Low-level socket errors ([WinError 10061]) are replaced with informative guidance.
"""

from __future__ import annotations

import atexit
import json
import logging
import os
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("pai.service_manager")

OLLAMA_LOOPBACK_ENDPOINT = "http://127.0.0.1:11434"
DEFAULT_CONSENT_MODE = "ask"
ALLOWED_CONSENT_MODES = ("ask", "always", "never")

SERVICE_OFFLINE_GUIDANCE = (
    "Local AI service (Ollama) is not running on 127.0.0.1:11434. "
    "Run 'pai setup' or start Ollama from the Start Menu."
)


def get_official_ollama_path() -> Path:
    """
    Returns the official per-user Ollama server executable path on Windows.
    PATH lookup is strictly prohibited (ADR-014).
    """
    local_app_data = os.environ.get("LOCALAPPDATA")
    if not local_app_data:
        local_app_data = str(Path.home() / "AppData" / "Local")
    return Path(local_app_data) / "Programs" / "Ollama" / "ollama.exe"


def get_ollama_consent_mode(config_dir: Optional[str | Path] = None) -> str:
    """
    Returns user consent mode from ~/.pai/config.json.
    Allowed values: 'ask', 'always', 'never'. Default: 'ask' (D17 provisional default).
    """
    from config import load_user_config, get_user_config_path
    try:
        cfg_path = get_user_config_path(str(config_dir) if config_dir else None)
        cfg = load_user_config(cfg_path)
        mode = cfg.get("ollama_start_consent", DEFAULT_CONSENT_MODE)
        if mode in ALLOWED_CONSENT_MODES:
            return mode
    except Exception:
        pass
    return DEFAULT_CONSENT_MODE


def set_ollama_consent_mode(mode: str, config_dir: Optional[str | Path] = None) -> None:
    """
    Persists user consent mode to ~/.pai/config.json.
    """
    if mode not in ALLOWED_CONSENT_MODES:
        raise ValueError(f"Invalid consent mode: {mode!r}; must be one of {ALLOWED_CONSENT_MODES}")
    from config import load_user_config, save_user_config, get_user_config_path
    cfg_path = get_user_config_path(str(config_dir) if config_dir else None)
    cfg = load_user_config(cfg_path)
    cfg["ollama_start_consent"] = mode
    save_user_config(cfg, cfg_path)


class OllamaServiceManager:
    """
    Manages local Ollama background service lifecycle per ADR-014.
    Tracks child PID so that ONLY instances spawned by PAI are terminated on exit.
    """

    _global_instance: Optional["OllamaServiceManager"] = None

    def __init__(
        self,
        endpoint: str = OLLAMA_LOOPBACK_ENDPOINT,
        config_dir: Optional[str | Path] = None,
        executable_path: Optional[str | Path] = None,
        verify_authenticode: bool = True,
    ) -> None:
        self.endpoint = self._validate_loopback_endpoint(endpoint)
        self.config_dir = config_dir
        self.executable_path = Path(executable_path) if executable_path else None
        self.verify_authenticode = verify_authenticode
        self.child_process: Optional[subprocess.Popen] = None
        self.child_pid: Optional[int] = None
        self._atexit_registered = False

    @classmethod
    def get_instance(cls, **kwargs) -> "OllamaServiceManager":
        if cls._global_instance is None:
            cls._global_instance = cls(**kwargs)
        return cls._global_instance

    @staticmethod
    def _validate_loopback_endpoint(endpoint: str) -> str:
        """Enforces that the service endpoint strictly binds to local loopback (ADR-014)."""
        parsed = urllib.parse.urlsplit(endpoint)
        host = (parsed.hostname or "").lower()
        if host not in ("127.0.0.1", "localhost", "::1", "[::1]"):
            raise ValueError(f"Ollama service endpoint must be local loopback, got {endpoint!r}")
        return endpoint.rstrip("/")

    def is_running(self, timeout: float = 1.0) -> bool:
        """
        Probes local Ollama daemon over loopback via /api/tags or /api/version.
        Returns True if reachable and HTTP 200, False otherwise.
        """
        url = f"{self.endpoint}/api/tags"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "PAI-ServiceManager/1.0"})
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(req, timeout=timeout) as resp:
                return resp.status == 200
        except Exception:
            return False

    def get_target_executable(self) -> Optional[Path]:
        """
        Resolves the target Ollama executable path.
        CRITICAL: Never consults PATH (prevents PATH hijacking per ADR-014).
        """
        if self.executable_path is not None:
            return self.executable_path if self.executable_path.is_file() else None

        official = get_official_ollama_path()
        if official.is_file():
            return official
        return None

    def prompt_user_consent(self) -> bool:
        """
        Evaluates user consent mode ('ask', 'always', 'never').
        If 'ask', prompts in interactive terminal and allows persisting choice.
        If non-interactive and mode is 'ask', returns False fail-closed.
        """
        mode = get_ollama_consent_mode(self.config_dir)
        if mode == "always":
            return True
        if mode == "never":
            return False

        # Mode is 'ask'
        is_interactive = sys.stdin.isatty() and sys.stdout.isatty()
        if not is_interactive:
            return False

        try:
            prompt_text = (
                "\nLocal AI service (Ollama) is not running on 127.0.0.1:11434.\n"
                "Start local Ollama service now? [y/N/always/never]: "
            )
            ans = input(prompt_text).strip().lower()
            if ans == "always":
                set_ollama_consent_mode("always", self.config_dir)
                return True
            elif ans == "never":
                set_ollama_consent_mode("never", self.config_dir)
                return False
            elif ans in ("y", "yes"):
                return True
            else:
                return False
        except (EOFError, KeyboardInterrupt):
            return False

    def start_service(self, readiness_timeout: float = 10.0) -> bool:
        """
        Starts local Ollama daemon ('ollama.exe serve') after verifying Authenticode.
        Tracks child process and PID. Waits until loopback endpoint is ready.
        """
        # Step 1: If already running, leave it running; do NOT track PID (external service)
        if self.is_running(timeout=1.0):
            self.child_process = None
            self.child_pid = None
            return True

        # Step 2: Locate executable without searching PATH
        target_exe = self.get_target_executable()
        if not target_exe or not target_exe.is_file():
            logger.warning("Ollama executable not found at official path (%s)", target_exe)
            return False

        # Step 3: Authenticode verification on the exact target binary
        if self.verify_authenticode:
            from pai_setup import verify_authenticode_publisher
            verify_authenticode_publisher(target_exe)

        # Step 4: Launch 'ollama.exe serve' as child process
        cmd = [str(target_exe), "serve"]
        flags = 0
        if sys.platform == "win32":
            flags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)

        try:
            proc = subprocess.Popen(
                cmd,
                creationflags=flags,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self.child_process = proc
            self.child_pid = proc.pid

            # Register lifecycle cleanup handlers
            if not self._atexit_registered:
                atexit.register(self.stop_service)
                self._atexit_registered = True
        except Exception as e:
            logger.error("Failed to spawn Ollama daemon: %s", e)
            self.child_process = None
            self.child_pid = None
            return False

        # Step 5: Wait for loopback readiness
        start_time = time.monotonic()
        while time.monotonic() - start_time < readiness_timeout:
            if self.is_running(timeout=0.5):
                return True
            if proc.poll() is not None:
                # Process exited prematurely
                logger.error("Ollama process %d exited prematurely with code %s", proc.pid, proc.returncode)
                self.child_process = None
                self.child_pid = None
                return False
            time.sleep(0.25)

        # Timed out waiting for readiness
        logger.error("Timed out waiting for Ollama service readiness (%ss)", readiness_timeout)
        self.stop_service()
        return False

    def stop_service(self) -> None:
        """
        Terminates ONLY the background service started by PAI (matching child_pid).
        Never touches pre-existing external services (Finding / ADR-014 invariant).
        """
        proc = self.child_process
        pid = self.child_pid
        if proc is not None:
            try:
                proc.terminate()
                proc.wait(timeout=3.0)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        self.child_process = None
        self.child_pid = None

    def ensure_service_running(self) -> Tuple[bool, str]:
        """
        High-level lifecycle check for callers (e.g. pai chat or shell).
        If offline, evaluates consent and starts if approved.
        Returns (success: bool, status_message: str).
        """
        if self.is_running(timeout=1.0):
            return True, "Ollama service is running"

        target_exe = self.get_target_executable()
        if not target_exe:
            return False, SERVICE_OFFLINE_GUIDANCE

        consent = self.prompt_user_consent()
        if not consent:
            return False, SERVICE_OFFLINE_GUIDANCE

        try:
            started = self.start_service()
            if started:
                return True, "Ollama service started successfully"
            return False, SERVICE_OFFLINE_GUIDANCE
        except Exception as e:
            logger.error("Failed to start Ollama service: %s", e)
            return False, f"Failed to start Ollama service: {e}"
