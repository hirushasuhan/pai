@echo off
setlocal disabledelayedexpansion

echo ===================================================================
echo        Personal Agentic AI (PAI) - Portable Installation Setup
echo ===================================================================
echo.

:: 1. Source and target paths
set "SOURCE_DIR=%~dp0"
if "%SOURCE_DIR:~-1%"=="\" set "SOURCE_DIR=%SOURCE_DIR:~0,-1%"

if not "%PAI_INSTALL_DIR%"=="" goto use_custom_target
set "TARGET_DIR=%LOCALAPPDATA%\Programs\PAI"
goto after_target_select

:use_custom_target
set "TARGET_DIR=%PAI_INSTALL_DIR%"
echo [NOTICE] Using custom installation directory from PAI_INSTALL_DIR:
echo          %TARGET_DIR%
echo.

:after_target_select
set "BIN_DIR=%TARGET_DIR%\bin"

echo Source Directory: %SOURCE_DIR%
echo Target Directory: %TARGET_DIR%
echo.

:: 2. Staged copy and manifest verification (Finding BP)
if /I "%SOURCE_DIR%"=="%TARGET_DIR%" goto after_copy

echo Staging files for installation...
set "STAGING_DIR=%TARGET_DIR%_staging"

if exist "%STAGING_DIR%" rmdir /S /Q "%STAGING_DIR%"
mkdir "%STAGING_DIR%"

xcopy /E /I /Y /Q "%SOURCE_DIR%\*" "%STAGING_DIR%\" >nul
if errorlevel 1 goto copy_failed

:: 2. Verify staging files against manifest and perform safe atomic swap with rollback (Finding BV)
:: Note: PAI_TEST_FAIL_SWAP_MOVE is strictly an internal test hook for rollback negative control tests (Finding BZ).
echo Verifying staged files against manifest.json...
set "PAI_STAGING_DIR=%STAGING_DIR%"
set "PAI_TARGET_DIR=%TARGET_DIR%"

powershell -NoProfile -Command ^
    "$ErrorActionPreference = 'Stop';" ^
    "$stage = $env:PAI_STAGING_DIR;" ^
    "$target = $env:PAI_TARGET_DIR;" ^
    "$manifestPath = Join-Path $stage 'manifest.json';" ^
    "if (-not (Test-Path -LiteralPath $manifestPath)) { Write-Error 'manifest.json missing in staging.'; exit 1 }" ^
    "$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json;" ^
    "$files = $manifest.files;" ^
    "if (-not $files) { Write-Error 'manifest.json has empty files entry.'; exit 1 }" ^
    "$manifestSet = @{};" ^
    "foreach ($prop in $files.psobject.Properties) {" ^
    "    $rel = $prop.Name.Replace('/', [IO.Path]::DirectorySeparatorChar);" ^
    "    $manifestSet[$rel.ToLowerInvariant()] = $true;" ^
    "    $targetFile = Join-Path $stage $rel;" ^
    "    if (-not (Test-Path -LiteralPath $targetFile)) { Write-Error ('Missing staged file: ' + $rel); exit 1 }" ^
    "    $actualSize = (Get-Item -LiteralPath $targetFile).Length;" ^
    "    if ($actualSize -ne $prop.Value.size) { Write-Error ('Size mismatch for: ' + $rel); exit 1 }" ^
    "    $actualHash = (Get-FileHash -LiteralPath $targetFile -Algorithm SHA256).Hash.ToLower();" ^
    "    if ($actualHash -ne $prop.Value.sha256.ToLower()) { Write-Error ('SHA-256 mismatch for: ' + $rel); exit 1 }" ^
    "}" ^
    "$stagedItems = Get-ChildItem -LiteralPath $stage -Recurse -File;" ^
    "foreach ($item in $stagedItems) {" ^
    "    $relPath = $item.FullName.Substring($stage.Length).TrimStart([IO.Path]::DirectorySeparatorChar);" ^
    "    if ($relPath -ieq 'manifest.json' -or $relPath -ieq 'manifest.sig') { continue }" ^
    "    if ($relPath -match '__pycache__' -or $relPath.EndsWith('.pyc')) { continue }" ^
    "    if (-not $manifestSet.ContainsKey($relPath.ToLowerInvariant())) {" ^
    "        Write-Error ('Unlisted file in payload staging directory: ' + $relPath);" ^
    "        exit 1" ^
    "    }" ^
    "}" ^
    "$hasSig = Test-Path -LiteralPath (Join-Path $stage 'manifest.sig');" ^
    "if ($hasSig) {" ^
    "    Write-Host '[OK] All staged files verified against manifest checksums (signature file present).' -ForegroundColor Green;" ^
    "} else {" ^
    "    Write-Host '[OK] All staged files verified against manifest.json checksums.' -ForegroundColor Green;" ^
    "}" ^
    "$backup = $target + '_backup';" ^
    "if (Test-Path -LiteralPath $backup) { Remove-Item -LiteralPath $backup -Recurse -Force };" ^
    "$hadTarget = Test-Path -LiteralPath $target;" ^
    "if ($hadTarget) { Move-Item -LiteralPath $target -Destination $backup -Force };" ^
    "try {" ^
    "    <# Note: PAI_TEST_FAIL_SWAP_MOVE is strictly an internal test hook for rollback negative control tests. #>" ^
    "    if ($env:PAI_TEST_FAIL_SWAP_MOVE -eq '1') { throw 'Simulated swap move failure for negative control' }" ^
    "    Move-Item -LiteralPath $stage -Destination $target -Force;" ^
    "} catch {" ^
    "    $moveErr = $_.Exception.Message;" ^
    "    if ($hadTarget -and (Test-Path -LiteralPath $backup)) {" ^
    "        Write-Host '[ROLLBACK] Restoring previous installation from backup...' -ForegroundColor Yellow;" ^
    "        if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Recurse -Force };" ^
    "        Move-Item -LiteralPath $backup -Destination $target -Force;" ^
    "    };" ^
    "    Write-Error ('Failed to move staged directory into target: ' + $moveErr);" ^
    "    exit 1" ^
    "}" ^
    "if (Test-Path -LiteralPath $backup) { Remove-Item -LiteralPath $backup -Recurse -Force };" ^
    "exit 0"

if errorlevel 1 goto verify_failed

echo [OK] Files installed successfully to %TARGET_DIR%.
goto after_copy

:copy_failed
echo [ERROR] Failed to stage files into %STAGING_DIR%.
if exist "%STAGING_DIR%" rmdir /S /Q "%STAGING_DIR%"
exit /b 1

:verify_failed
echo.
echo [ERROR] Staged payload failed manifest checksum verification!
echo Aborting installation without touching target directory or PATH.
if exist "%STAGING_DIR%" rmdir /S /Q "%STAGING_DIR%"
exit /b 1

:after_copy

:: 3. Configure User PATH using update_path.ps1 (Findings BO, BQ, DD)
set "PAI_BIN_DIR=%BIN_DIR%"
if "%PAI_REG_SUBKEY%"=="" set "PAI_REG_SUBKEY=Environment"
echo Configuring User PATH for %BIN_DIR%...

set "UPDATE_PATH_SCRIPT=%TARGET_DIR%\tools\update_path.ps1"
if not exist "%UPDATE_PATH_SCRIPT%" set "UPDATE_PATH_SCRIPT=%SOURCE_DIR%\tools\update_path.ps1"
if not exist "%UPDATE_PATH_SCRIPT%" set "UPDATE_PATH_SCRIPT=%SOURCE_DIR%\packaging\update_path.ps1"
if not exist "%UPDATE_PATH_SCRIPT%" (
    echo [ERROR] PATH update helper script tools\update_path.ps1 was not found!
    goto path_failed
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%UPDATE_PATH_SCRIPT%" -Action Add -TargetDir "%BIN_DIR%" -RegSubKey "%PAI_REG_SUBKEY%"
if errorlevel 1 goto path_failed

:: 4. Run setup wizard if present (Milestone P3+)
if exist "%TARGET_DIR%\research\pai_setup.py" (
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
exit /b 0

:path_failed
echo.
echo [ERROR] Failed to configure User PATH in registry!
exit /b 1
