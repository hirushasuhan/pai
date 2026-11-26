"""Compatibility forwarding shim for ``desktop.apply_pending_update``."""

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
    import desktop.apply_pending_update as _impl
except ImportError:
    _flat_path = _REPO_ROOT / "apply_pending_update.py"
    if not _flat_path.is_file():
        raise
    _spec = importlib.util.spec_from_file_location("_pai_apply_pending_update_impl", _flat_path)
    if _spec is None or _spec.loader is None or not _spec.origin or Path(_spec.origin).resolve() == _SELF_PATH:
        raise
    _impl = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_impl)

get_pai_install_dir = _impl.get_pai_install_dir
check_and_apply_pending = _impl.check_and_apply_pending
apply_and_restart = _impl.apply_and_restart

__all__ = [
    "get_pai_install_dir",
    "check_and_apply_pending",
    "apply_and_restart",
]

if __name__ == "__main__":
    if "--restart" in sys.argv:
        apply_and_restart()
    else:
        check_and_apply_pending()
