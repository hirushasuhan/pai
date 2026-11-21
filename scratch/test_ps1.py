import subprocess
import tempfile
import os
from pathlib import Path

temp_dir = tempfile.gettempdir()
ps1_path = os.path.join(temp_dir, "test_picker.ps1")
out_txt = os.path.join(temp_dir, "test_ps1_out.txt")

ps_content = """
param([string]$title, [string]$outPath, [string]$initialPath)
Add-Type -AssemblyName System.Windows.Forms
$f = New-Object System.Windows.Forms.FolderBrowserDialog
$f.Description = if ($title) { $title } else { "Select Folder" }
$f.ShowNewFolderButton = $true
if ($initialPath -and [System.IO.Directory]::Exists($initialPath)) {
    $f.SelectedPath = $initialPath
}
Write-Output "PS1 script parsed successfully, arguments: $title | $outPath | $initialPath"
"""

with open(ps1_path, "w", encoding="utf-8") as f:
    f.write(ps_content)

p = subprocess.run(
    ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", ps1_path, "My Title", out_txt, "D:\\ai"],
    capture_output=True,
    text=True,
)
print("PS1 stdout:", p.stdout.strip())
print("PS1 stderr:", p.stderr.strip())
