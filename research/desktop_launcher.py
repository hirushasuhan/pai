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
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Optional, Tuple

# Ensure search paths include research and repo/install root
_CURR_DIR = Path(__file__).resolve().parent
_INSTALL_ROOT = _CURR_DIR.parent
if str(_CURR_DIR) not in sys.path:
    sys.path.insert(0, str(_CURR_DIR))
if str(_INSTALL_ROOT) not in sys.path:
    sys.path.insert(0, str(_INSTALL_ROOT))

# Guard against None stdio when running under pythonw.exe on Windows
if sys.stdout is None:
    try:
        sys.stdout = open(os.devnull, "w", encoding="utf-8")
    except Exception:
        pass
if sys.stderr is None:
    try:
        sys.stderr = open(os.devnull, "w", encoding="utf-8")
    except Exception:
        pass

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


def start_bridge_server() -> Tuple[bool, Optional[ThreadingHTTPServer]]:
    """Start bridge server if not already active. Returns (ok, server_instance)."""
    if is_bridge_server_running():
        return True, None

    try:
        try:
            from research.desktop.bridge_server import HOST, PORT, PAIBridgeHandler
        except ImportError:
            from desktop.bridge_server import HOST, PORT, PAIBridgeHandler

        server = ThreadingHTTPServer((HOST, PORT), PAIBridgeHandler)
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()

        for _ in range(30):
            time.sleep(0.1)
            if is_bridge_server_running():
                return True, server
    except Exception:
        pass

    return is_bridge_server_running(), None


def find_browser_app_executable() -> Optional[str]:
    """Find Microsoft Edge, Chrome, or Brave executable for standalone App Mode."""
    # Check PATH
    for candidate in ("msedge", "msedge.exe", "chrome", "chrome.exe", "brave", "brave.exe"):
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
        r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe",
    ]
    for p in std_paths:
        if os.path.isfile(p):
            return p

    return None


def launch_desktop_app(wait_for_exit: bool = False) -> Tuple[bool, str]:
    """Launch PAI Studio in native desktop window."""
    ok_server, server_instance = start_bridge_server()
    if not ok_server:
        return False, "Could not start local desktop bridge server on 127.0.0.1:8765."

    browser_exe = find_browser_app_executable()
    proc = None
    if browser_exe:
        try:
            profile_dir = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "PAI" / "desktop_profile"
            profile_dir.mkdir(parents=True, exist_ok=True)
            flags = 0
            if sys.platform == "win32":
                flags = 0x00000200  # CREATE_NEW_PROCESS_GROUP
            proc = subprocess.Popen(
                [
                    browser_exe,
                    f"--app={BRIDGE_URL}",
                    f"--user-data-dir={profile_dir}",
                    "--window-size=1280,840",
                ],
                creationflags=flags,
            )
            msg = f"PAI Studio Desktop opened in native app mode ({os.path.basename(browser_exe)})."
        except Exception:
            proc = None

    if proc is None:
        try:
            webbrowser.open(BRIDGE_URL)
            msg = "PAI Studio Desktop opened in default web browser."
        except Exception as exc:
            return False, f"Failed to open browser: {exc}"

    if wait_for_exit and server_instance is not None:
        if proc is not None:
            try:
                proc.wait()
            except KeyboardInterrupt:
                pass
            finally:
                server_instance.shutdown()
                server_instance.server_close()
        else:
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                server_instance.shutdown()
                server_instance.server_close()

    return True, msg


if __name__ == "__main__":
    ok, msg = launch_desktop_app(wait_for_exit=True)
    if not ok:
        print(f"Error: {msg}", file=sys.stderr)
        sys.exit(1)
