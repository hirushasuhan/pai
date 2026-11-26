"""Update the Desktop-installed PAI Studio installation with latest code and UI."""
import os
import shutil
import sys
from pathlib import Path

def update_pai_installation():
    repo_root = Path(__file__).resolve().parent.parent
    local_app_raw = os.environ.get("LOCALAPPDATA", "").strip()
    if not local_app_raw:
        print("[ERROR] LOCALAPPDATA is not set.")
        return False
    target_pai = Path(local_app_raw) / "Programs" / "PAI"
    
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
            flags = 0x08000000  # CREATE_NO_WINDOW
            subprocess.run("taskkill /F /IM pai-desktop.exe", shell=True, creationflags=flags, capture_output=True)
            out = subprocess.check_output("netstat -ano -p tcp", shell=True, creationflags=flags, text=True)
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
                subprocess.run(f"taskkill /F /PID {pid}", shell=True, creationflags=flags, capture_output=True)
            time.sleep(0.4)
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

    # 2. Update UI files across canonical locations
    ui_src = repo_root / "desktop" / "ui"
    ui_destinations = [
        target_pai / "ui",                             # flat ui/
        target_pai / "desktop" / "ui",                 # canonical desktop/ui/
    ]

    for dest in ui_destinations:
        dest.mkdir(parents=True, exist_ok=True)
        for fname in ["index.html", "style.css", "app.js", "manifest.json"]:
            src_f = ui_src / fname
            if src_f.is_file():
                dest_f = dest / fname
                shutil.copy2(src_f, dest_f)
                print(f"[OK] Synced UI {fname} -> {dest_f}")
        ui_assets = ui_src / "assets"
        if ui_assets.is_dir():
            shutil.copytree(ui_assets, dest / "assets", dirs_exist_ok=True)
            shutil.copytree(ui_assets, target_pai / "assets", dirs_exist_ok=True)

    # 2.1 Sync VERSION file across targets
    v_src = ui_src / "VERSION"
    if v_src.is_file():
        for dest in [target_pai, target_pai / "ui", target_pai / "desktop" / "ui"]:
            dest.mkdir(parents=True, exist_ok=True)
            shutil.copy2(v_src, dest / "VERSION")
            print(f"[OK] Synced VERSION -> {dest / 'VERSION'}")

    # 3. Update backend python files across canonical locations
    backend_files = [
        ("desktop/bridge_server.py", target_pai / "bridge_server.py"),
        ("desktop/bridge_server.py", target_pai / "desktop" / "bridge_server.py"),
        ("desktop/desktop_launcher.py", target_pai / "desktop_launcher.py"),
        ("desktop/desktop_launcher.py", target_pai / "desktop" / "desktop_launcher.py"),
        ("desktop/apply_pending_update.py", target_pai / "apply_pending_update.py"),
        ("desktop/apply_pending_update.py", target_pai / "desktop" / "apply_pending_update.py"),
        ("desktop/bin/pai_folder_picker.exe", target_pai / "bin" / "pai_folder_picker.exe"),
        ("desktop/bin/pai_folder_picker.exe", target_pai / "desktop" / "bin" / "pai_folder_picker.exe"),
    ]

    # Also sync core research modules (do not let research/ shims overwrite canonical root files)
    for py_file in (repo_root / "research").glob("*.py"):
        if py_file.name not in {"desktop_launcher.py", "apply_pending_update.py"}:
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
