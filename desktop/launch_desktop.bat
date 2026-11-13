@echo off
setlocal
set SCRIPT_DIR=%~dp0
if exist "%SCRIPT_DIR%..\..\python\pythonw.exe" (
    start "" "%SCRIPT_DIR%..\..\python\pythonw.exe" "%SCRIPT_DIR%..\desktop_launcher.py"
) else if exist "%SCRIPT_DIR%..\python\pythonw.exe" (
    start "" "%SCRIPT_DIR%..\python\pythonw.exe" "%SCRIPT_DIR%desktop_launcher.py"
) else (
    start "" pythonw "%SCRIPT_DIR%..\desktop_launcher.py"
)
exit /b 0
