"""PAI Studio Desktop Application Native Launcher.

Ensures the local loopback bridge server (127.0.0.1:8765) is running,
and launches PAI Studio in a native frameless app window via Microsoft Edge
or Chrome App Mode, falling back seamlessly to default browser.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import threading
import time
import urllib.request
import webbrowser
from pathlib import Path
from typing import Optional, Tuple

BRIDGE_URL = "http://127.0.0.1:8765"


def is_bridge_server_running(timeout: float = 0.5) -> bool:
    """Check if PAI desktop bridge server is responding on 127.0.0.1:8765."""
    try:
        req = urllib.request.Request(
            f"{BRIDGE_URL}/api/status",
            headers={"User-Agent": "PAI-Launcher/1.1"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status == 200
    except Exception:
        return False


def start_bridge_server() -> bool:
    """Start bridge server if not already active."""
    if is_bridge_server_running():
        return True

    # 1. Try starting as in-process daemon thread
    try:
        from research.desktop.bridge_server import run_bridge_server
    except ImportError:
        try:
            from desktop.bridge_server import run_bridge_server
        except ImportError:
            run_bridge_server = None

    if run_bridge_server is not None:
        t = threading.Thread(target=run_bridge_server, daemon=True)
        t.start()
        # Wait up to 3 seconds for server to be responsive
        for _ in range(30):
            time.sleep(0.1)
            if is_bridge_server_running():
                return True

    # 2. Fallback to background subprocess
    curr_dir = Path(__file__).resolve().parent
    server_script = curr_dir / "desktop" / "bridge_server.py"
    if not server_script.is_file():
        server_script = curr_dir.parent / "desktop" / "bridge_server.py"

    if server_script.is_file():
        py_exe = sys.executable or "python"
        flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        subprocess.Popen(
            [py_exe, str(server_script)],
            creationflags=flags,
        )
        for _ in range(30):
            time.sleep(0.1)
            if is_bridge_server_running():
                return True

    return is_bridge_server_running()


def find_browser_app_executable() -> Optional[str]:
    """Find Microsoft Edge or Chrome executable for standalone App Mode."""
    # Check PATH
    for candidate in ("msedge", "msedge.exe", "chrome", "chrome.exe"):
        found = shutil.which(candidate)
        if found:
            return found

    # Check standard Windows directories
    std_paths = [
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Edge\Application\msedge.exe"),
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
    ]
    for p in std_paths:
        if os.path.isfile(p):
            return p

    return None


def launch_desktop_app() -> Tuple[bool, str]:
    """Launch PAI Studio in native desktop window."""
    ok_server = start_bridge_server()
    if not ok_server:
        return False, "Could not start local desktop bridge server on 127.0.0.1:8765."

    browser_exe = find_browser_app_executable()
    if browser_exe:
        try:
            subprocess.Popen([
                browser_exe,
                f"--app={BRIDGE_URL}",
                "--window-size=1280,840",
            ])
            return True, f"PAI Studio Desktop opened in native app mode ({os.path.basename(browser_exe)})."
        except Exception:
            pass

    # Fallback to system default browser
    try:
        webbrowser.open(BRIDGE_URL)
        return True, "PAI Studio Desktop opened in default web browser."
    except Exception as exc:
        return False, f"Failed to open browser: {exc}"
