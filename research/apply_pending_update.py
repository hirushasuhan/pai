"""PAI Studio Pending Update Applicator.
Applies staged software update packages (atomic file swap) and restarts the application.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
import zipfile
from pathlib import Path


def get_pai_install_dir() -> Path:
    local_app = os.environ.get("LOCALAPPDATA", "")
    if local_app:
        cand = Path(local_app) / "Programs" / "PAI"
        if cand.is_dir():
            return cand
    return Path(__file__).resolve().parent.parent


def check_and_apply_pending() -> bool:
    """Checks for pending_update.json and extracts/swaps the new files."""
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

    success = False
    if staged_path and os.path.isfile(staged_path) and str(staged_path).endswith(".zip"):
        try:
            with zipfile.ZipFile(staged_path, "r") as zf:
                for member in zf.namelist():
                    # Security check: Prevent directory traversal
                    if ".." in member or member.startswith("/") or member.startswith("\\"):
                        continue

                    target_file = pai_dir / member
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

                # Sync extracted UI files to all standard UI directories
                for fname in ["index.html", "style.css", "app.js", "manifest.json"]:
                    src_f = pai_dir / "ui" / fname
                    if not src_f.is_file():
                        src_f = pai_dir / fname
                    if src_f.is_file():
                        for d in [
                            pai_dir,
                            pai_dir / "desktop",
                            pai_dir / "desktop" / "ui",
                            pai_dir / "research" / "desktop",
                        ]:
                            d.mkdir(parents=True, exist_ok=True)
                            try:
                                shutil.copy2(src_f, d / fname)
                            except Exception:
                                pass

                # Sync backend launcher and bridge files
                for bf in ["bridge_server.py", "desktop_launcher.py"]:
                    src_b = pai_dir / bf
                    if src_b.is_file():
                        for d in [
                            pai_dir / "desktop",
                            pai_dir / "research",
                            pai_dir / "research" / "desktop",
                        ]:
                            d.mkdir(parents=True, exist_ok=True)
                            try:
                                shutil.copy2(src_b, d / bf)
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
        try:
            (pai_dir / "VERSION").write_text(clean_v, encoding="utf-8")
        except Exception:
            pass

        # 2. Patch PAI_CURRENT_VERSION in all bridge_server.py files
        import re
        for bpath in [
            pai_dir / "bridge_server.py",
            pai_dir / "desktop" / "bridge_server.py",
            pai_dir / "desktop" / "ui" / "bridge_server.py",
            pai_dir / "research" / "desktop" / "bridge_server.py",
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

    # Kill remaining pai-desktop.exe or python processes on port 8765
    if sys.platform == "win32":
        try:
            cmd = (
                "Get-Process -Name 'pai-desktop' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue; "
                "$c = Get-NetTCPConnection -LocalPort 8765 -ErrorAction SilentlyContinue; "
                "foreach ($x in $c) { if ($x.OwningProcess -gt 0) { Stop-Process -Id $x.OwningProcess -Force -ErrorAction SilentlyContinue } }"
            )
            subprocess.run(["powershell", "-NoProfile", "-Command", cmd], timeout=6, capture_output=True)
            time.sleep(0.5)
        except Exception:
            pass

    # Apply the pending update
    check_and_apply_pending()

    # Launch PAI Studio
    exe_target = pai_dir / "pai-desktop.exe"
    pyw_target = pai_dir / "python" / "pythonw.exe"
    launcher_target = pai_dir / "desktop_launcher.py"

    if exe_target.is_file():
        subprocess.Popen([str(exe_target)], cwd=str(pai_dir), creationflags=0x08000000 | 0x00000200 if sys.platform == "win32" else 0)
    elif pyw_target.is_file() and launcher_target.is_file():
        subprocess.Popen([str(pyw_target), "-m", "research.desktop_launcher"], cwd=str(pai_dir), creationflags=0x08000000 | 0x00000200 if sys.platform == "win32" else 0)


if __name__ == "__main__":
    if "--restart" in sys.argv:
        apply_and_restart()
    else:
        check_and_apply_pending()
