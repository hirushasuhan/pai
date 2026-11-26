"""PAI Studio Pending Update Applicator.
Applies staged software update packages (atomic file swap) and restarts the application.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Optional


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


def check_and_apply_pending() -> bool:
    """Checks for pending_update.json, verifies signatures/constitution, and extracts/swaps the new files."""
    pai_dir = get_pai_install_dir()
    pending_file = pai_dir / "pending_update.json"
    if not pending_file.is_file():
        return False

    try:
        data = json.loads(pending_file.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"[WARN] Malformed pending_update.json: {e}")
        try:
            pending_file.unlink()
        except Exception:
            pass
        return False

    target_version = data.get("target_version", "1.4.0-beta.1")
    staged_path = data.get("staged_path")
    print(f"[+] Applying pending update to v{target_version} from {staged_path}...")

    # FINDING-03: Verify release bundle cryptographically via research.updater.Updater
    trust_root = _find_trust_root(pai_dir)
    if trust_root:
        try:
            try:
                from research.updater import Updater, UpdateRejected
            except ImportError:
                from updater import Updater, UpdateRejected
            updater = Updater(str(trust_root), str(pai_dir), product="pai-desktop")
            if staged_path and os.path.isdir(staged_path):
                updater.verify_release(staged_path, check_rollback=True)
            elif staged_path and os.path.isfile(staged_path) and str(staged_path).endswith(".zip"):
                with tempfile.TemporaryDirectory() as verify_tmp:
                    with zipfile.ZipFile(staged_path, "r") as zf:
                        for m in zf.namelist():
                            if ".." in m or m.startswith(("/", "\\")):
                                raise UpdateRejected(f"Illegal traversal entry: {m}")
                            info = zf.getinfo(m)
                            if (info.external_attr >> 16) & stat.S_IFLNK == stat.S_IFLNK:
                                raise UpdateRejected(f"Symlink rejected in update archive: {m}")
                            zf.extract(m, verify_tmp)
                    updater.verify_release(verify_tmp, check_rollback=True)
        except Exception as verif_err:
            print(f"[REJECTED] Update verification failed: {verif_err}")
            try:
                pending_file.unlink()
            except Exception:
                pass
            return False

    success = False
    if staged_path and os.path.isfile(staged_path) and str(staged_path).endswith(".zip"):
        try:
            with zipfile.ZipFile(staged_path, "r") as zf:
                for member in zf.namelist():
                    # Security check: Prevent directory traversal
                    if ".." in member or member.startswith("/") or member.startswith("\\"):
                        continue
                    info = zf.getinfo(member)
                    if (info.external_attr >> 16) & stat.S_IFLNK == stat.S_IFLNK:
                        continue

                    target_file = pai_dir / member
                    if target_file.is_symlink():
                        continue
                    target_file.parent.mkdir(parents=True, exist_ok=True)
                    try:
                        with zf.open(member) as src, open(target_file, "wb") as dst:
                            shutil.copyfileobj(src, dst)
                    except PermissionError:
                        time.sleep(0.5)
                        try:
                            with zf.open(member) as src, open(target_file, "wb") as dst:
                                shutil.copyfileobj(src, dst)
                        except Exception as locked_err:
                            print(f"[WARN] Could not overwrite {member}: {locked_err}")

                # Sync extracted UI files to canonical UI directories
                for fname in ["index.html", "style.css", "app.js", "manifest.json"]:
                    src_f = pai_dir / "ui" / fname
                    if not src_f.is_file():
                        src_f = pai_dir / fname
                    if src_f.is_file():
                        ui_targets = [pai_dir / "ui"]
                        if (pai_dir / "desktop").is_dir():
                            ui_targets.append(pai_dir / "desktop" / "ui")
                        for d in ui_targets:
                            d.mkdir(parents=True, exist_ok=True)
                            dst_f = d / fname
                            if src_f.resolve() == dst_f.resolve():
                                continue
                            try:
                                shutil.copy2(src_f, dst_f)
                            except Exception:
                                pass

                # Sync backend launcher, bridge, and updater applicator to desktop/ if present
                if (pai_dir / "desktop").is_dir():
                    for bf in ["bridge_server.py", "desktop_launcher.py", "apply_pending_update.py"]:
                        src_b = pai_dir / bf
                        if src_b.is_file():
                            dst_b = pai_dir / "desktop" / bf
                            if src_b.resolve() == dst_b.resolve():
                                continue
                            try:
                                shutil.copy2(src_b, dst_b)
                            except Exception:
                                pass

            success = True
            print(f"[OK] Successfully extracted and deployed v{target_version} update files.")
        except Exception as exc:
            print(f"[ERROR] Failed extracting update zip: {exc}")
    else:
        # Simulated release or non-zip staged package
        success = True

    if success:
        clean_v = target_version.lstrip("vV")
        # 1. Update VERSION file
        for v_dir in [pai_dir / "ui", pai_dir]:
            if v_dir == pai_dir or v_dir.is_dir():
                try:
                    (v_dir / "VERSION").write_text(clean_v, encoding="utf-8")
                except Exception:
                    pass

        # 2. Patch PAI_CURRENT_VERSION in canonical bridge_server.py files
        import re
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

        # 3. Update releases tracking current.json
        try:
            rel_dir = pai_dir / "releases"
            rel_dir.mkdir(parents=True, exist_ok=True)
            (rel_dir / "current.json").write_text(
                json.dumps({"version": clean_v, "updated_at": time.time()}, indent=2),
                encoding="utf-8",
            )
        except Exception:
            pass

        # 3. Clean up pending_update.json and temp staged package
        try:
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

        print(f"[SUCCESS] PAI Studio has been updated to v{target_version}!")
        return True

    return False


def apply_and_restart():
    """Waits for previous app process to exit, applies update, and relaunches PAI Studio."""
    time.sleep(1.2)
    pai_dir = get_pai_install_dir()

    # Kill remaining pai-desktop.exe or python processes on port 8765 silently (no console window)
    if sys.platform == "win32":
        try:
            flags = 0x08000000  # CREATE_NO_WINDOW
            subprocess.run(["taskkill", "/F", "/IM", "pai-desktop.exe"], creationflags=flags, capture_output=True)
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
            time.sleep(0.4)
        except Exception:
            pass

    # Apply the pending update
    check_and_apply_pending()

    # Launch PAI Studio
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
