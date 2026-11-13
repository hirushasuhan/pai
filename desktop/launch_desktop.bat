@echo off
setlocal
set SCRIPT_DIR=%~dp0

set LAUNCHER=
if exist "%SCRIPT_DIR%desktop_launcher.py" set "LAUNCHER=%SCRIPT_DIR%desktop_launcher.py"
if not defined LAUNCHER if exist "%SCRIPT_DIR%..\research\desktop_launcher.py" set "LAUNCHER=%SCRIPT_DIR%..\research\desktop_launcher.py"
if not defined LAUNCHER if exist "%SCRIPT_DIR%..\desktop_launcher.py" set "LAUNCHER=%SCRIPT_DIR%..\desktop_launcher.py"
if not defined LAUNCHER if exist "%SCRIPT_DIR%..\..\research\desktop_launcher.py" set "LAUNCHER=%SCRIPT_DIR%..\..\research\desktop_launcher.py"

set PY_EXE=pythonw
if exist "%SCRIPT_DIR%..\..\python\pythonw.exe" (
    set "PY_EXE=%SCRIPT_DIR%..\..\python\pythonw.exe"
) else if exist "%SCRIPT_DIR%..\python\pythonw.exe" (
    set "PY_EXE=%SCRIPT_DIR%..\python\pythonw.exe"
)

if defined LAUNCHER (
    start "" "%PY_EXE%" "%LAUNCHER%"
) else (
    echo Error: desktop_launcher.py not found.
    pause
)
exit /b 0
