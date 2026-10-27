@echo off
setlocal enabledelayedexpansion

echo ===================================================================
echo        Personal Agentic AI (PAI) - Portable Installation Setup
echo ===================================================================
echo.

:: 1. Source and target paths
set "SOURCE_DIR=%~dp0"
if "%SOURCE_DIR:~-1%"=="\" set "SOURCE_DIR=%SOURCE_DIR:~0,-1%"

:: Target defaults to %LOCALAPPDATA%\Programs\PAI unless PAI_INSTALL_DIR is set
if "%PAI_INSTALL_DIR%"=="" (
    set "TARGET_DIR=%LOCALAPPDATA%\Programs\PAI"
) else (
    set "TARGET_DIR=%PAI_INSTALL_DIR%"
)

echo Source Directory: %SOURCE_DIR%
echo Target Directory: %TARGET_DIR%
echo.

:: 2. Copy payload to target if source and target differ
if /I not "%SOURCE_DIR%"=="%TARGET_DIR%" (
    echo Copying files to %TARGET_DIR%...
    if not exist "%TARGET_DIR%" mkdir "%TARGET_DIR%"
    xcopy /E /I /Y /Q "%SOURCE_DIR%\*" "%TARGET_DIR%\" >nul
    if errorlevel 1 (
        echo [ERROR] Failed to copy files to %TARGET_DIR%.
        exit /b 1
    )
    echo [OK] Files copied successfully.
)

:: 3. Configure User PATH using the Appendix D pattern (registry User scope, case-insensitive, empty PATH handling)
set "BIN_DIR=%TARGET_DIR%\bin"
echo Configuring User PATH for %BIN_DIR%...

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "$dir = '%BIN_DIR%';" ^
    "$cur = [Environment]::GetEnvironmentVariable('Path', 'User');" ^
    "$parts = if ($cur) { $cur -split ';' | Where-Object { $_ } } else { @() };" ^
    "if (-not ($parts | Where-Object { $_.TrimEnd('\') -ieq $dir })) {" ^
    "    [Environment]::SetEnvironmentVariable('Path', (($parts + $dir) -join ';'), 'User');" ^
    "    Write-Host '[SUCCESS] Added ' $dir ' to User PATH.' -ForegroundColor Green;" ^
    "} else {" ^
    "    Write-Host '[INFO] ' $dir ' is already in User PATH.' -ForegroundColor Cyan;" ^
    "}"

:: 4. Run setup wizard if present (Milestone P3+)
if exist "%TARGET_DIR%\packaging\pai_setup.py" (
    echo.
    echo Running setup checks...
    "%BIN_DIR%\pai.exe" setup
)

echo.
echo ===================================================================
echo Installation Complete!
echo.
echo To start using PAI, open a NEW Command Prompt or PowerShell window:
echo.
echo    where pai
echo    pai --version
echo    pai --help
echo.
echo To uninstall at any time, run:
echo    "%TARGET_DIR%\uninstall.bat"
echo ===================================================================
echo.
