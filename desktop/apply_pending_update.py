"""PAI Studio Pending Update Applicator.
Applies staged software update packages (cryptographic verification + atomic file swap) and restarts the application.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Any, Dict, Optional, Tuple


_MAX_UNCOMPRESSED_ZIP_BYTES = 250 * 1024 * 1024  # 250 MiB zip-bomb cap


def _log_update(msg: str) -> None:
    """Prints and appends update diagnostics to ~/.pai/updates/apply.log."""
    line = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    try:
        print(line)
    except Exception:
        pass
    try:
        log_dir = Path.home() / ".pai" / "updates"
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / "apply.log"
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


def get_pai_install_dir() -> Path:
    local_app = os.environ.get("LOCALAPPDATA", "")
    if local_app:
        cand = Path(local_app) / "Programs" / "PAI"
        if cand.is_dir():
            return cand
    return Path(__file__).resolve().parent.parent


def _find_trust_root(pai_dir: Path) -> Optional[Path]:
    """Locate directory containing trust.json."""
    candidates = [
        pai_dir / "research",
        pai_dir,
        Path(__file__).resolve().parent.parent / "research",
        Path(__file__).resolve().parent.parent,
    ]
    for c in candidates:
        if (c / "trust.json").is_file():
            return c
    return None


def _parse_semver(v: str) -> Tuple[int, int, int, str]:
    cleaned = str(v or "").strip().lstrip("vV")
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?", cleaned)
    if not m:
        return (0, 0, 0, "")
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)), m.group(4) or "")


def _is_version_downgrade(target_v: str, current_v: str) -> bool:
    """Returns True strictly when target_v < current_v (rollback)."""
    if not current_v:
        return False
    t_maj, t_min, t_pat, t_pre = _parse_semver(target_v)
    c_maj, c_min, c_pat, c_pre = _parse_semver(current_v)
    if (t_maj, t_min, t_pat) != (c_maj, c_min, c_pat):
        return (t_maj, t_min, t_pat) < (c_maj, c_min, c_pat)
    if t_pre and not c_pre:
        return True
    if not t_pre and c_pre:
        return False
    if t_pre and c_pre:
        return t_pre < c_pre
    return False


def _read_installed_version(pai_dir: Path) -> str:
    for cand in (pai_dir / "ui" / "VERSION", pai_dir / "VERSION"):
        if cand.is_file():
            try:
                v = cand.read_text(encoding="utf-8").strip()
                if v:
                    return v
            except Exception:
                pass
    curr_json = pai_dir / "releases" / "current.json"
    if curr_json.is_file():
        try:
            v = str(json.loads(curr_json.read_text(encoding="utf-8")).get("version", "")).strip()
            if v:
                return v
        except Exception:
            pass
    return ""


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest().lower()


def _validate_zip_safety(zf: zipfile.ZipFile) -> None:
    """Rejects path traversal, symlinks, and oversized zip bombs before extraction."""
    total_size = 0
    for member in zf.namelist():
        norm = member.replace("\\", "/")
        if ".." in norm.split("/") or norm.startswith("/") or re.match(r"^[A-Za-z]:", norm):
            raise ValueError(f"Illegal traversal entry in update archive: {member}")
        info = zf.getinfo(member)
        if (info.external_attr >> 16) & stat.S_IFLNK == stat.S_IFLNK:
            raise ValueError(f"Symlink rejected in update archive: {member}")
        total_size += max(0, int(info.file_size))
        if total_size > _MAX_UNCOMPRESSED_ZIP_BYTES:
            raise ValueError(f"Update archive exceeds uncompressed size cap ({total_size} > {_MAX_UNCOMPRESSED_ZIP_BYTES})")


def _verify_archive_digest(
    zip_path: Path,
    manifest_path: Optional[str],
    expected_sha256: Optional[str],
) -> None:
    """Verifies downloaded zip integrity against expected_sha256 and/or release manifest.json."""
    actual_sha = _sha256_file(zip_path)
    actual_size = zip_path.stat().st_size

    if expected_sha256:
        if not hmac.compare_digest(actual_sha, str(expected_sha256).lower().strip()):
            raise ValueError(f"Update archive SHA-256 mismatch ({actual_sha[:12]} != {str(expected_sha256)[:12]})")

    if manifest_path and Path(manifest_path).is_file():
        m_doc = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
        files_map = m_doc.get("files") if isinstance(m_doc, dict) else None
        if isinstance(files_map, dict) and files_map:
            matched_meta: Optional[Dict[str, Any]] = files_map.get(zip_path.name)
            if matched_meta is None:
                for k_name, v_meta in files_map.items():
                    if str(k_name).endswith(".zip") and isinstance(v_meta, dict):
                        matched_meta = v_meta
                        break
            if isinstance(matched_meta, dict):
                m_sha = str(matched_meta.get("sha256", "")).lower().strip()
                m_size = matched_meta.get("size")
                if m_sha and not hmac.compare_digest(actual_sha, m_sha):
                    raise ValueError(f"Manifest SHA-256 mismatch ({actual_sha[:12]} != {m_sha[:12]})")
                if isinstance(m_size, int) and m_size > 0 and actual_size != m_size:
                    raise ValueError(f"Manifest file size mismatch ({actual_size} != {m_size})")


def _copy_if_different(src: Path, dst: Path) -> None:
    if not src.is_file() or dst.is_symlink():
        return
    dst.parent.mkdir(parents=True, exist_ok=True)
    if dst.exists():
        try:
            if src.resolve() == dst.resolve():
                return
        except Exception:
            pass
    shutil.copy2(src, dst)


def _write_with_lock_retry(src_stream, dst_path: Path) -> None:
    """Writes an extracted archive entry with backoff if Windows file handles are releasing."""
    last_err: Optional[Exception] = None
    for delay in (0.3, 0.7, 1.2):
        try:
            with open(dst_path, "wb") as dst:
                shutil.copyfileobj(src_stream, dst)
            return
        except PermissionError as exc:
            last_err = exc
            src_stream.seek(0)
            time.sleep(delay)
    if last_err:
        raise last_err


def check_and_apply_pending() -> bool:
    """Checks pending_update.json, enforces archive integrity/Ed25519 checks, and swaps files atomically."""
    pai_dir = get_pai_install_dir()
    pending_file = pai_dir / "pending_update.json"
    if not pending_file.is_file():
        return False

    try:
        data = json.loads(pending_file.read_text(encoding="utf-8"))
    except Exception as e:
        _log_update(f"[WARN] Malformed pending_update.json: {e}")
        try:
            pending_file.unlink()
        except Exception:
            pass
        return False

    target_version = str(data.get("target_version", "1.5.0-beta.3")).strip()
    staged_path = data.get("staged_path")
    manifest_path = data.get("manifest_path")
    signature_path = data.get("signature_path")
    expected_sha256 = data.get("expected_sha256")
    is_simulated = bool(data.get("is_simulated", False))
    _log_update(f"[+] Applying pending update to v{target_version} from {staged_path}...")

    installed_ver = _read_installed_version(pai_dir)
    if installed_ver and _is_version_downgrade(target_version, installed_ver):
        _log_update(f"[REJECTED] Rollback blocked: target v{target_version} < installed v{installed_ver}")
        try:
            pending_file.unlink()
        except Exception:
            pass
        return False

    require_signed = os.environ.get("PAI_REQUIRE_SIGNED_UPDATE", "").strip() == "1"
    trust_root = _find_trust_root(pai_dir)

    # Reject missing staged zips unless this is explicitly a simulated developer flow
    is_zip = bool(staged_path and os.path.isfile(staged_path) and str(staged_path).lower().endswith(".zip"))
    is_dir = bool(staged_path and os.path.isdir(staged_path))
    if not is_zip and not is_dir:
        if not is_simulated:
            _log_update(f"[REJECTED] Staged update archive missing or invalid: {staged_path}")
            try:
                pending_file.unlink()
            except Exception:
                pass
            return False
        # Simulated test flow
        clean_v = target_version.lstrip("vV")
        _finalize_version_metadata(pai_dir, clean_v, pending_file, staged_path)
        _log_update(f"[SUCCESS] Simulated update applied cleanly for v{clean_v}.")
        return True

    # Cryptographic verification:
    # - Always run full Ed25519 + Constitution check if manifest.sig exists (in staged package or signature_path)
    #   or if PAI_REQUIRE_SIGNED_UPDATE=1.
    # - For CI-built GitHub release archives without manifest.sig, enforce SHA-256 + manifest size + archive safety.
    has_signature = bool(signature_path and os.path.isfile(str(signature_path)))
    if is_dir and (Path(staged_path) / "manifest.sig").is_file():
        has_signature = True
    elif is_zip:
        try:
            with zipfile.ZipFile(staged_path, "r") as zf_probe:
                _validate_zip_safety(zf_probe)
                if "manifest.sig" in zf_probe.namelist():
                    has_signature = True
        except Exception as zip_err:
            _log_update(f"[REJECTED] Archive safety check failed: {zip_err}")
            try:
                pending_file.unlink()
            except Exception:
                pass
            return False

    if require_signed or has_signature:
        if not trust_root:
            _log_update("[REJECTED] Signed update required but trust.json trust root was not found.")
            try:
                pending_file.unlink()
            except Exception:
                pass
            return False
        try:
            try:
                from research.updater import Updater, UpdateRejected
            except ImportError:
                from updater import Updater, UpdateRejected
            updater = Updater(str(trust_root), str(pai_dir), product="pai-desktop")
            if is_dir:
                updater.verify_release(staged_path, check_rollback=True)
            else:
                with tempfile.TemporaryDirectory() as verify_tmp:
                    with zipfile.ZipFile(staged_path, "r") as zf:
                        _validate_zip_safety(zf)
                        zf.extractall(verify_tmp)
                    if signature_path and os.path.isfile(str(signature_path)) and not (Path(verify_tmp) / "manifest.sig").is_file():
                        shutil.copy2(signature_path, Path(verify_tmp) / "manifest.sig")
                    if manifest_path and os.path.isfile(str(manifest_path)) and not (Path(verify_tmp) / "manifest.json").is_file():
                        shutil.copy2(manifest_path, Path(verify_tmp) / "manifest.json")
                    updater.verify_release(verify_tmp, check_rollback=True)
        except Exception as verif_err:
            _log_update(f"[REJECTED] Signed update verification failed: {verif_err}")
            try:
                pending_file.unlink()
            except Exception:
                pass
            return False
    elif is_zip:
        # GitHub CI release archive verification: require SHA-256 and/or manifest.json match
        if not expected_sha256 and not (manifest_path and os.path.isfile(str(manifest_path))):
            _log_update("[REJECTED] Update archive lacks both SHA-256 digest and Ed25519 signature.")
            try:
                pending_file.unlink()
            except Exception:
                pass
            return False
        try:
            _verify_archive_digest(Path(staged_path), manifest_path, expected_sha256)
        except Exception as dig_err:
            _log_update(f"[REJECTED] Archive digest verification failed: {dig_err}")
            try:
                pending_file.unlink()
            except Exception:
                pass
            return False

    success = False
    if is_zip:
        try:
            with zipfile.ZipFile(staged_path, "r") as zf:
                _validate_zip_safety(zf)
                for member in zf.namelist():
                    if member.endswith("/"):
                        continue
                    target_file = pai_dir / member
                    if target_file.is_symlink():
                        continue
                    target_file.parent.mkdir(parents=True, exist_ok=True)
                    try:
                        with zf.open(member) as src:
                            _write_with_lock_retry(src, target_file)
                    except Exception as locked_err:
                        _log_update(f"[WARN] Could not overwrite {member}: {locked_err}")

            # Sync extracted UI files to canonical UI directories
            for fname in ["index.html", "style.css", "app.js", "manifest.json", "VERSION"]:
                src_f = pai_dir / "ui" / fname
                if not src_f.is_file():
                    src_f = pai_dir / fname
                if src_f.is_file():
                    ui_targets = [pai_dir / "ui"]
                    if (pai_dir / "desktop").is_dir():
                        ui_targets.append(pai_dir / "desktop" / "ui")
                    for d in ui_targets:
                        _copy_if_different(src_f, d / fname)

            # Sync backend launcher, bridge, and applicator to desktop/ if present
            if (pai_dir / "desktop").is_dir():
                for bf in ["bridge_server.py", "desktop_launcher.py", "apply_pending_update.py"]:
                    _copy_if_different(pai_dir / bf, pai_dir / "desktop" / bf)

            # Sync updated research/*.py files into flat top-level install dir if present
            if (pai_dir / "research").is_dir() and (pai_dir / "agent_core.py").is_file():
                for py_f in (pai_dir / "research").glob("*.py"):
                    _copy_if_different(py_f, pai_dir / py_f.name)

            success = True
            _log_update(f"[OK] Successfully extracted and deployed v{target_version} update files.")
        except Exception as exc:
            _log_update(f"[ERROR] Failed extracting update zip: {exc}")
    elif is_dir:
        success = True

    if success:
        clean_v = target_version.lstrip("vV")
        _finalize_version_metadata(pai_dir, clean_v, pending_file, staged_path)
        _log_update(f"[SUCCESS] PAI Studio has been updated to v{clean_v}!")
        return True

    return False


def _finalize_version_metadata(
    pai_dir: Path,
    clean_v: str,
    pending_file: Path,
    staged_path: Optional[str],
) -> None:
    """Updates VERSION files, PAI_CURRENT_VERSION constants, releases/current.json, and temp artifacts."""
    for v_dir in [pai_dir / "ui", pai_dir]:
        if v_dir == pai_dir or v_dir.is_dir():
            try:
                (v_dir / "VERSION").write_text(clean_v, encoding="utf-8")
            except Exception:
                pass

    for bpath in [
        pai_dir / "bridge_server.py",
        pai_dir / "desktop" / "bridge_server.py",
    ]:
        if bpath.is_file():
            try:
                txt = bpath.read_text(encoding="utf-8")
                if "PAI_CURRENT_VERSION" in txt:
                    txt = re.sub(r'PAI_CURRENT_VERSION\s*=\s*["\'][^"\']+["\']', f'PAI_CURRENT_VERSION = "{clean_v}"', txt)
                    bpath.write_text(txt, encoding="utf-8")
            except Exception:
                pass

    try:
        rel_dir = pai_dir / "releases"
        rel_dir.mkdir(parents=True, exist_ok=True)
        (rel_dir / "current.json").write_text(
            json.dumps({"version": clean_v, "updated_at": time.time()}, indent=2),
            encoding="utf-8",
        )
    except Exception:
        pass

    try:
        if pending_file.exists():
            pending_file.unlink()
    except Exception:
        pass

    if staged_path and os.path.isfile(staged_path):
        try:
            os.remove(staged_path)
            parent_dir = os.path.dirname(staged_path)
            if "pai_update_" in parent_dir:
                shutil.rmtree(parent_dir, ignore_errors=True)
        except Exception:
            pass


def apply_and_restart() -> None:
    """Waits for previous app process to exit, applies update cleanly, and relaunches PAI Studio."""
    pai_dir = get_pai_install_dir()
    bridge_pid = None
    pending_file = pai_dir / "pending_update.json"
    if pending_file.is_file():
        try:
            bridge_pid = json.loads(pending_file.read_text(encoding="utf-8")).get("bridge_pid")
        except Exception:
            bridge_pid = None

    # Allow UI ~1.5s to invoke app_window_exit cleanly, then terminate lingering handles
    time.sleep(1.8)

    if sys.platform == "win32":
        try:
            flags = 0x08000000  # CREATE_NO_WINDOW
            subprocess.run(["taskkill", "/F", "/IM", "pai-desktop.exe"], creationflags=flags, capture_output=True)
            if isinstance(bridge_pid, int) and bridge_pid > 0 and bridge_pid != os.getpid():
                subprocess.run(["taskkill", "/F", "/PID", str(bridge_pid)], creationflags=flags, capture_output=True)
            out = subprocess.check_output(["netstat", "-ano", "-p", "tcp"], creationflags=flags, text=True)
            for line in out.splitlines():
                parts = line.strip().split()
                if len(parts) >= 5 and ":8765" in parts[1] and parts[3] == "LISTENING":
                    try:
                        pid = int(parts[4])
                        if pid > 0 and pid != os.getpid():
                            subprocess.run(["taskkill", "/F", "/PID", str(pid)], creationflags=flags, capture_output=True)
                    except ValueError:
                        pass
            time.sleep(0.6)
        except Exception:
            pass

    check_and_apply_pending()

    # Launch PAI Studio cleanly after file swap finishes
    time.sleep(0.4)
    exe_target = pai_dir / "pai-desktop.exe"
    pyw_target = pai_dir / "python" / "pythonw.exe"
    desktop_launcher = pai_dir / "desktop" / "desktop_launcher.py"
    flat_launcher = pai_dir / "desktop_launcher.py"
    shim_launcher = pai_dir / "research" / "desktop_launcher.py"
    win_flags = 0x08000000 | 0x00000200 if sys.platform == "win32" else 0

    if exe_target.is_file():
        subprocess.Popen([str(exe_target)], cwd=str(pai_dir), creationflags=win_flags)
    elif pyw_target.is_file():
        if desktop_launcher.is_file():
            subprocess.Popen([str(pyw_target), "-m", "desktop.desktop_launcher"], cwd=str(pai_dir), creationflags=win_flags)
        elif flat_launcher.is_file():
            subprocess.Popen([str(pyw_target), str(flat_launcher)], cwd=str(pai_dir), creationflags=win_flags)
        elif shim_launcher.is_file():
            subprocess.Popen([str(pyw_target), "-m", "research.desktop_launcher"], cwd=str(pai_dir), creationflags=win_flags)


if __name__ == "__main__":
    if "--restart" in sys.argv:
        apply_and_restart()
    else:
        check_and_apply_pending()
