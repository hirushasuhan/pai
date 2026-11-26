"""Compatibility forwarding shim for ``desktop.desktop_launcher``."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_SELF_PATH = Path(__file__).resolve()
_REPO_ROOT = _SELF_PATH.parent.parent
_REPO_ROOT_STR = str(_REPO_ROOT)
if not sys.path or sys.path[0] != _REPO_ROOT_STR:
    sys.path.insert(0, _REPO_ROOT_STR)

try:
    import desktop.desktop_launcher as _impl
except ImportError:
    _flat_path = _REPO_ROOT / "desktop_launcher.py"
    if not _flat_path.is_file():
        raise
    _spec = importlib.util.spec_from_file_location("_pai_desktop_launcher_impl", _flat_path)
    if _spec is None or _spec.loader is None or not _spec.origin or Path(_spec.origin).resolve() == _SELF_PATH:
        raise
    _impl = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_impl)

BRIDGE_URL = _impl.BRIDGE_URL
kill_stale_port_8765 = _impl.kill_stale_port_8765
is_bridge_server_running = _impl.is_bridge_server_running
start_bridge_server = _impl.start_bridge_server
find_native_desktop_executable = _impl.find_native_desktop_executable
find_browser_app_executable = _impl.find_browser_app_executable
launch_desktop_app = _impl.launch_desktop_app

__all__ = [
    "BRIDGE_URL",
    "kill_stale_port_8765",
    "is_bridge_server_running",
    "start_bridge_server",
    "find_native_desktop_executable",
    "find_browser_app_executable",
    "launch_desktop_app",
]

if __name__ == "__main__":
    _ok, _msg = launch_desktop_app(wait_for_exit=True)
    if not _ok:
        print(f"Error: {_msg}", file=sys.stderr)
        sys.exit(1)
