@echo off
setlocal disabledelayedexpansion

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
set "PAI_BIN_DIR=%BIN_DIR%"
if "%PAI_REG_SUBKEY%"=="" set "PAI_REG_SUBKEY=Environment"

echo Removing %BIN_DIR% from User PATH...

set "UPDATE_PATH_SCRIPT=%TARGET_DIR%\tools\update_path.ps1"
if not exist "%UPDATE_PATH_SCRIPT%" set "UPDATE_PATH_SCRIPT=%~dp0tools\update_path.ps1"
if not exist "%UPDATE_PATH_SCRIPT%" set "UPDATE_PATH_SCRIPT=%~dp0packaging\update_path.ps1"
if not exist "%UPDATE_PATH_SCRIPT%" (
    echo [ERROR] PATH update helper script tools\update_path.ps1 was not found!
    exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%UPDATE_PATH_SCRIPT%" -Action Remove -TargetDir "%BIN_DIR%" -RegSubKey "%PAI_REG_SUBKEY%"
if errorlevel 1 exit /b 1

echo.
echo Note: Installed program files in %TARGET_DIR% can now be safely deleted.
echo User configuration and local models (~/.pai, Ollama models) are preserved.
echo ===================================================================
echo.
