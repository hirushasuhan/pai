@echo off
setlocal enabledelayedexpansion
title PAI Studio Desktop Launcher

echo ========================================================================
echo                 PAI STUDIO - PERSONAL AGENTIC AI DESKTOP
echo ========================================================================
echo Starting local API bridge daemon on http://127.0.0.1:8765...

:: Start background bridge daemon if not already listening
netstat -ano | findstr "8765" >nul
if errorlevel 1 (
    start "" /B python "%~dp0bridge_server.py"
    timeout /t 2 /nobreak >nul
) else (
    echo Bridge server is already active on port 8765.
)

:: Launch standalone native desktop window
echo Opening PAI Studio in native desktop app window...
where msedge.exe >nul 2>&1
if not errorlevel 1 (
    start "" msedge.exe --app="http://127.0.0.1:8765" --window-size=1280,840
    goto :done
)

where chrome.exe >nul 2>&1
if not errorlevel 1 (
    start "" chrome.exe --app="http://127.0.0.1:8765" --window-size=1280,840
    goto :done
)

:: Fallback default browser
start "" "http://127.0.0.1:8765"

:done
echo PAI Studio launched successfully.
