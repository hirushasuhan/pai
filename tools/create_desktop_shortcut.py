"""Create Desktop and Start Menu Shortcuts for PAI Studio."""
import os
import shutil
import subprocess
import sys
from pathlib import Path

def create_shortcuts() -> bool:
    desktop = Path.home() / "Desktop"
    shortcut_path = desktop / "PAI Studio.lnk"
    
    # Check if installed or in repo
    installed_dir = Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "PAI"
    if (installed_dir / "assets" / "pai.ico").is_file():
        app_dir = installed_dir
        ico_path = installed_dir / "assets" / "pai.ico"
        pythonw = installed_dir / "python" / "pythonw.exe"
        if not pythonw.is_file():
            pythonw = Path(sys.executable).parent / "pythonw.exe"
    else:
        app_dir = Path(__file__).resolve().parent.parent
        ico_path = app_dir / "packaging" / "assets" / "pai.ico"
        pythonw = Path(sys.executable).parent / "pythonw.exe"
        if not pythonw.is_file():
            pythonw = Path(sys.executable)

    vbs_code = f'''
Set oWS = WScript.CreateObject("WScript.Shell")
sLinkFile = "{shortcut_path}"
Set oLink = oWS.CreateShortcut(sLinkFile)
oLink.TargetPath = "{pythonw}"
oLink.Arguments = "-m research.desktop_launcher"
oLink.WorkingDirectory = "{app_dir}"
oLink.IconLocation = "{ico_path}, 0"
oLink.Description = "Personal Agentic AI (PAI) Studio"
oLink.Save
'''
    vbs_path = app_dir / "_temp_shortcut.vbs"
    try:
        vbs_path.write_text(vbs_code, encoding="utf-8")
        subprocess.run(["cscript", "//nologo", str(vbs_path)], check=True)
        print(f"[OK] Desktop shortcut created at: {shortcut_path}")
        return True
    except Exception as exc:
        print(f"[ERROR] Failed to create shortcut: {exc}")
        return False
    finally:
        if vbs_path.is_file():
            vbs_path.unlink()

if __name__ == "__main__":
    create_shortcuts()
