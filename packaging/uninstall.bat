@echo off
setlocal enabledelayedexpansion

echo ===================================================================
echo       Personal Agentic AI (PAI) - Portable Uninstallation
echo ===================================================================
echo.

if "%PAI_INSTALL_DIR%"=="" (
    set "TARGET_DIR=%LOCALAPPDATA%\Programs\PAI"
) else (
    set "TARGET_DIR=%PAI_INSTALL_DIR%"
)

set "BIN_DIR=%TARGET_DIR%\bin"
echo Removing %BIN_DIR% from User PATH...

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "$dir = '%BIN_DIR%';" ^
    "$cur = [Environment]::GetEnvironmentVariable('Path', 'User');" ^
    "$parts = if ($cur) { $cur -split ';' | Where-Object { $_ } } else { @() };" ^
    "$new_parts = $parts | Where-Object { $_.TrimEnd('\') -ine $dir };" ^
    "[Environment]::SetEnvironmentVariable('Path', ($new_parts -join ';'), 'User');" ^
    "Write-Host '[SUCCESS] Removed ' $dir ' from User PATH.' -ForegroundColor Green;"

echo.
echo Note: Installed program files in %TARGET_DIR% can now be deleted.
echo User configuration and local models (~/.pai, Ollama models) are preserved.
echo ===================================================================
echo.
