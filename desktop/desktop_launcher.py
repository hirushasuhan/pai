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

# Apply pending update if staged before launching app
try:
    try:
        from desktop.apply_pending_update import check_and_apply_pending
    except ImportError:
        try:
            from apply_pending_update import check_and_apply_pending
        except ImportError:
            from research.apply_pending_update import check_and_apply_pending
    check_and_apply_pending()
except Exception:
    pass

BRIDGE_URL = "http://127.0.0.1:8765"


def kill_stale_port_8765() -> None:
    """Terminates any process holding port 8765 so new bridge server can bind cleanly (100% silent, no terminal)."""
    if sys.platform == "win32":
        try:
            flags = 0x08000000  # CREATE_NO_WINDOW
            out = subprocess.check_output(["netstat", "-ano", "-p", "tcp"], creationflags=flags, text=True)
            pids = set()
            for line in out.splitlines():
                parts = line.strip().split()
                if len(parts) >= 5 and ":8765" in parts[1] and parts[3] == "LISTENING":
                    try:
                        pid = int(parts[4])
                        if pid > 0 and pid != os.getpid():
                            pids.add(pid)
                    except ValueError:
                        pass
            for pid in pids:
                subprocess.run(["taskkill", "/F", "/PID", str(pid)], creationflags=flags, capture_output=True)
            time.sleep(0.3)
        except Exception:
            pass


def is_bridge_server_running(timeout: float = 0.8) -> bool:
    """Check if PAI desktop bridge server is responding on 127.0.0.1:8765 and running >= 1.3.0."""
    try:
        req = urllib.request.Request(
            f"{BRIDGE_URL}/api/status",
            headers={"User-Agent": "PAI-Launcher/1.3"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status != 200:
                return False
            import json
            data = json.loads(resp.read().decode("utf-8"))
            if data.get("version", "1.0.0") < "1.3.0":
                return False

        # Verify update endpoints are alive
        req_up = urllib.request.Request(
            f"{BRIDGE_URL}/api/update/status",
            headers={"User-Agent": "PAI-Launcher/1.3"},
        )
        with urllib.request.urlopen(req_up, timeout=timeout) as resp_up:
            return resp_up.status == 200
    except Exception:
        return False


def start_bridge_server() -> Tuple[bool, Optional[ThreadingHTTPServer], int, str]:
    """Start bridge server if not already active. Returns (ok, server_instance, port, token)."""
    try:
        try:
            from desktop.bridge_server import HOST, PAIBridgeHandler, PAI_BRIDGE_TOKEN
        except ImportError:
            from bridge_server import HOST, PAIBridgeHandler, PAI_BRIDGE_TOKEN

        # Bind ephemeral port on loopback
        server = ThreadingHTTPServer((HOST, 0), PAIBridgeHandler)
        bound_port = server.server_address[1]
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        time.sleep(0.2)
        return True, server, bound_port, PAI_BRIDGE_TOKEN
    except Exception as exc:
        print(f"[WARN] Failed to start ephemeral bridge: {exc}", file=sys.stderr)

    return False, None, 8765, ""


def find_native_desktop_executable() -> Optional[str]:
    """Find native PAI Studio Tauri release binary."""
    cand_paths = [
        _CURR_DIR / "src-tauri" / "target" / "release" / "pai-desktop.exe",
        _INSTALL_ROOT / "desktop" / "src-tauri" / "target" / "release" / "pai-desktop.exe",
        _CURR_DIR / "pai-desktop.exe",
        _INSTALL_ROOT / "pai-desktop.exe",
        Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "PAI" / "pai-desktop.exe",
    ]
    for p in cand_paths:
        if p.is_file() and p.stat().st_size > 0:
            return str(p.resolve())
    return None


def find_browser_app_executable() -> Optional[str]:
    """Find Google Chrome, Microsoft Edge, or Brave executable for standalone App Mode."""
    # Check standard Windows directories (Chrome preferred for standalone PWA isolation)
    std_paths = [
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Edge\Application\msedge.exe"),
        r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe",
    ]
    for p in std_paths:
        if os.path.isfile(p):
            return p

    for candidate in ("chrome", "chrome.exe", "msedge", "msedge.exe", "brave", "brave.exe"):
        found = shutil.which(candidate)
        if found:
            return found

    return None


def launch_desktop_app(wait_for_exit: bool = False) -> Tuple[bool, str]:
    """Launch PAI Studio exclusively in native desktop application mode."""
    ok_server, server_instance, actual_port, token = start_bridge_server()
    if not ok_server:
        return False, "Could not start local desktop bridge server."

    bridge_url = f"http://127.0.0.1:{actual_port}"
    app_url = f"{bridge_url}/#token={token}" if token else bridge_url

    flags = 0
    if sys.platform == "win32":
        flags = 0x00000200  # CREATE_NEW_PROCESS_GROUP

    # 1. Prefer True Native Tauri Desktop Executable
    native_exe = find_native_desktop_executable()
    if native_exe:
        try:
            proc = subprocess.Popen([native_exe], creationflags=flags)
            msg = f"PAI Studio Desktop opened in native application mode ({os.path.basename(native_exe)})."
            if wait_for_exit:
                if proc is not None and proc.poll() is None:
                    try:
                        proc.wait()
                    except Exception:
                        pass
                    if server_instance is not None:
                        try:
                            server_instance.shutdown()
                            server_instance.server_close()
                        except Exception:
                            pass
                elif server_instance is not None:
                    try:
                        while True:
                            time.sleep(1)
                    except KeyboardInterrupt:
                        server_instance.shutdown()
                        server_instance.server_close()
            return True, msg
        except Exception:
            pass

    # 2. Fallback to Browser App Mode (Edge or Chrome)
    browser_exe = find_browser_app_executable()
    if not browser_exe:
        return False, "Neither Google Chrome nor Microsoft Edge was found to launch PAI Studio in App Mode."

    bname = os.path.basename(browser_exe).lower()
    profile_name = "chrome_app_profile" if "chrome" in bname else "edge_app_profile"
    profile_dir = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "PAI" / profile_name
    profile_dir.mkdir(parents=True, exist_ok=True)

    # Standalone Application Window arguments (No browser tabs, no URL bar, no browser controls)
    app_args = [
        browser_exe,
        f"--app={app_url}",
        f"--user-data-dir={profile_dir}",
        "--window-size=1280,840",
        "--window-position=center",
        "--app-id=PAI_Studio_Desktop",
        "--class=PAIStudio",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-extensions",
        "--disable-default-apps",
        "--disable-background-mode",
        "--enable-features=OverlayScrollbar",
        "--disable-features=Translate,OptimizationHints",
        "--disable-save-password-bubble",
        "--disable-blink-features=AutomationControlled",
    ]

    flags = 0
    if sys.platform == "win32":
        flags = 0x00000200  # CREATE_NEW_PROCESS_GROUP

    try:
        proc = subprocess.Popen(app_args, creationflags=flags)
        msg = f"PAI Studio Desktop opened in native standalone app mode ({os.path.basename(browser_exe)})."
    except Exception as exc:
        return False, f"Failed to launch standalone app: {exc}"

    if wait_for_exit:
        if proc is not None and proc.poll() is None:
            try:
                proc.wait()
            except Exception:
                pass
            if server_instance is not None:
                try:
                    server_instance.shutdown()
                    server_instance.server_close()
                except Exception:
                    pass
        elif server_instance is not None:
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
