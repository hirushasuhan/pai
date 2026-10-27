@echo off
setlocal enabledelayedexpansion

echo ===================================================================
echo              Personal Agentic AI (PAI) - One-Click Setup           
echo ===================================================================
echo.

set "INSTALL_DIR=%~dp0"
set "INSTALL_DIR=%INSTALL_DIR:~0,-1%"

echo Target Directory: %INSTALL_DIR%
echo.

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "$dir = '%INSTALL_DIR%';" ^
    "$userPath = [Environment]::GetEnvironmentVariable('Path', 'User');" ^
    "$paths = if ($userPath) { $userPath -split ';' } else { @() };" ^
    "if ($paths -notcontains $dir) {" ^
    "    $newPath = if ($userPath) { $userPath + ';' + $dir } else { $dir };" ^
    "    [Environment]::SetEnvironmentVariable('Path', $newPath, 'User');" ^
    "    Write-Host '[SUCCESS] PAI added to User PATH environment variable successfully!' -ForegroundColor Green;" ^
    "} else {" ^
    "    Write-Host '[INFO] PAI directory is already present in your User PATH.' -ForegroundColor Cyan;" ^
    "}"

echo.
echo ===================================================================
echo Setup Complete!
echo You can now open a new Command Prompt or PowerShell window and run:
echo.
echo    pai --help
echo    pai progress
echo    pai docs README.md
echo ===================================================================
echo.
pause
