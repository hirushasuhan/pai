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

powershell -NoProfile -Command ^
    "$targetDir = $env:PAI_BIN_DIR;" ^
    "$rawSub = if ($env:PAI_REG_SUBKEY) { $env:PAI_REG_SUBKEY.Trim() } else { 'Environment' };" ^
    "if (-not $rawSub -or $rawSub -ieq 'Environment') { $subKey = 'Environment' } " ^
    "elseif ($rawSub.StartsWith('Test_', [System.StringComparison]::OrdinalIgnoreCase) -or $rawSub.StartsWith('PAI_TEST_', [System.StringComparison]::OrdinalIgnoreCase)) { $subKey = $rawSub } " ^
    "else { Write-Error ('Rejected non-test PAI_REG_SUBKEY: ' + $rawSub + '. Custom subkeys must start with Test_ or PAI_TEST_ prefix.'); exit 1 };" ^
    "$key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($subKey, $true);" ^
    "if (-not $key) { Write-Error ('Cannot open HKCU:\' + $subKey); exit 1 }" ^
    "$raw = $key.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames);" ^
    "$kind = try { $key.GetValueKind('Path') } catch { [Microsoft.Win32.RegistryValueKind]::ExpandString };" ^
    "if (-not $kind -or $kind -eq [Microsoft.Win32.RegistryValueKind]::None) { $kind = [Microsoft.Win32.RegistryValueKind]::ExpandString };" ^
    "$parts = if ($raw) { @($raw -split ';' | Where-Object { $_ }) } else { @() };" ^
    "$newParts = @($parts | Where-Object {" ^
    "    $_.TrimEnd('\') -ine $targetDir.TrimEnd('\') -and " ^
    "    [Environment]::ExpandEnvironmentVariables($_).TrimEnd('\') -ine $targetDir.TrimEnd('\')" ^
    "});" ^
    "$newVal = ($newParts -join ';');" ^
    "$key.SetValue('Path', $newVal, $kind);" ^
    "$key.Close();" ^
    "Write-Host ('[SUCCESS] Removed ' + $targetDir + ' from User PATH.') -ForegroundColor Green;" ^
    "Add-Type -Namespace Win32 -Name Native -MemberDefinition '[DllImport(\"user32.dll\", SetLastError=true, CharSet=CharSet.Auto)] public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam, uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);' -ErrorAction SilentlyContinue;" ^
    "[Win32.Native]::SendMessageTimeout([IntPtr]0xffff, 0x001A, [UIntPtr]::Zero, 'Environment', 2, 5000, [ref][UIntPtr]::Zero) | Out-Null"

if errorlevel 1 exit /b 1

echo.
echo Note: Installed program files in %TARGET_DIR% can now be safely deleted.
echo User configuration and local models (~/.pai, Ollama models) are preserved.
echo ===================================================================
echo.
