"""Update the Desktop-installed PAI Studio installation with latest code and UI."""
import os
import shutil
import sys
from pathlib import Path

def update_pai_installation():
    repo_root = Path(__file__).resolve().parent.parent
    local_app_data = Path(os.environ.get("LOCALAPPDATA", ""))
    target_pai = local_app_data / "Programs" / "PAI"
    
    if not target_pai.is_dir():
        print(f"[ERROR] Target directory not found: {target_pai}")
        return False

    print(f"[+] Found installed PAI at: {target_pai}")
    
    # 0. Terminate running PAI desktop and bridge server processes so files can be replaced
    print("[+] Ensuring old PAI Studio and bridge server processes are stopped...")
    if sys.platform == "win32":
        try:
            import subprocess
            import time
            cmd = (
                "Get-Process -Name 'pai-desktop' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue; "
                "$c = Get-NetTCPConnection -LocalPort 8765 -ErrorAction SilentlyContinue; "
                "foreach ($x in $c) { if ($x.OwningProcess -gt 0) { Stop-Process -Id $x.OwningProcess -Force -ErrorAction SilentlyContinue } }"
            )
            subprocess.run(["powershell", "-NoProfile", "-Command", cmd], timeout=8, capture_output=True)
            time.sleep(0.5)
        except Exception as e:
            print(f"[WARN] Could not stop running PAI processes: {e}")

    # 1. Update native binary
    release_exe = repo_root / "desktop" / "src-tauri" / "target" / "release" / "pai-desktop.exe"
    if release_exe.is_file():
        dest_exe = target_pai / "pai-desktop.exe"
        try:
            shutil.copy2(release_exe, dest_exe)
            print(f"[OK] Updated native binary: {dest_exe} ({release_exe.stat().st_size} bytes)")
        except Exception as e:
            print(f"[WARN] Could not copy {dest_exe}: {e}")
            
        repo_desktop_exe = repo_root / "desktop" / "pai-desktop.exe"
        try:
            shutil.copy2(release_exe, repo_desktop_exe)
            print(f"[OK] Updated repo desktop binary: {repo_desktop_exe}")
        except Exception as e:
            print(f"[WARN] Could not copy {repo_desktop_exe}: {e}")

    # 2. Update UI files across all required locations
    ui_src = repo_root / "desktop" / "ui"
    ui_destinations = [
        target_pai,                                    # root
        target_pai / "desktop",                        # desktop/
        target_pai / "desktop" / "ui",                 # desktop/ui/
        target_pai / "research" / "desktop",           # research/desktop/
    ]

    for dest in ui_destinations:
        dest.mkdir(parents=True, exist_ok=True)
        for fname in ["index.html", "style.css", "app.js", "manifest.json"]:
            src_f = ui_src / fname
            if src_f.is_file():
                dest_f = dest / fname
                shutil.copy2(src_f, dest_f)
                print(f"[OK] Synced UI {fname} -> {dest_f}")

    # 3. Update backend python files across all possible import locations
    backend_files = [
        ("desktop/bridge_server.py", target_pai / "bridge_server.py"),
        ("desktop/bridge_server.py", target_pai / "desktop" / "bridge_server.py"),
        ("desktop/bridge_server.py", target_pai / "desktop" / "ui" / "bridge_server.py"),
        ("desktop/bridge_server.py", target_pai / "research" / "bridge_server.py"),
        ("desktop/bridge_server.py", target_pai / "research" / "desktop" / "bridge_server.py"),
        ("desktop/desktop_launcher.py", target_pai / "desktop_launcher.py"),
        ("desktop/desktop_launcher.py", target_pai / "desktop" / "desktop_launcher.py"),
        ("desktop/desktop_launcher.py", target_pai / "research" / "desktop_launcher.py"),
        ("desktop/desktop_launcher.py", target_pai / "research" / "desktop" / "desktop_launcher.py"),
        ("research/apply_pending_update.py", target_pai / "apply_pending_update.py"),
        ("research/apply_pending_update.py", target_pai / "desktop" / "apply_pending_update.py"),
        ("research/apply_pending_update.py", target_pai / "research" / "apply_pending_update.py"),
        ("research/apply_pending_update.py", target_pai / "research" / "desktop" / "apply_pending_update.py"),
    ]

    # Also sync core research modules
    for py_file in (repo_root / "research").glob("*.py"):
        backend_files.append((f"research/{py_file.name}", target_pai / py_file.name))
        backend_files.append((f"research/{py_file.name}", target_pai / "research" / py_file.name))

    for src_rel, dest_path in backend_files:
        src_path = repo_root / src_rel
        if src_path.is_file():
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            try:
                shutil.copy2(src_path, dest_path)
                print(f"[OK] Updated python module: {src_rel} -> {dest_path}")
            except Exception as e:
                print(f"[WARN] Could not copy {dest_path}: {e}")

    # 4. Refresh Desktop shortcut
    desktop = Path.home() / "Desktop"
    shortcut_path = desktop / "PAI Studio.lnk"
    print(f"[+] Verifying Desktop shortcut at: {shortcut_path}")
    
    # Run shortcut creator
    sys.path.insert(0, str(repo_root / "tools"))
    try:
        import create_desktop_shortcut
        create_desktop_shortcut.create_shortcuts()
    except Exception as e:
        print(f"[WARN] Could not refresh shortcut: {e}")

    print("\n[SUCCESS] Desktop PAI Studio software successfully updated!")
    return True

if __name__ == "__main__":
    success = update_pai_installation()
    sys.exit(0 if success else 1)
