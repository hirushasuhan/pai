<#
.SYNOPSIS
    Personal Agentic AI (PAI) - User PATH Registry Manager.
    Implements Appendix D of docs/PACKAGING_SPEC.md.

.DESCRIPTION
    Safely adds or removes a directory to/from User PATH in HKCU\Environment.
    Preserves REG_EXPAND_SZ unexpanded variables (e.g. %USERPROFILE%),
    never calls setx (avoiding truncation), handles empty or case-variant PATHs,
    and broadcasts WM_SETTINGCHANGE to notify running shells.
#>

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("Add", "Remove")]
    [string]$Action,

    [Parameter(Mandatory=$true)]
    [string]$TargetDir,

    [string]$RegSubKey = ""
)

$ErrorActionPreference = "Stop"

$rawSub = if ($RegSubKey) { $RegSubKey.Trim().Trim('"').Trim("'") } elseif ($env:PAI_REG_SUBKEY) { $env:PAI_REG_SUBKEY.Trim().Trim('"').Trim("'") } else { "Environment" }
if (-not $rawSub -or $rawSub -ieq "Environment") {
    $subKey = "Environment"
} elseif ($rawSub.StartsWith("Test_", [System.StringComparison]::OrdinalIgnoreCase) -or $rawSub.StartsWith("PAI_TEST_", [System.StringComparison]::OrdinalIgnoreCase)) {
    $subKey = $rawSub
} else {
    Write-Error ("Rejected non-test RegSubKey: " + $rawSub + ". Custom subkeys must start with Test_ or PAI_TEST_ prefix.")
    exit 1
}

$key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($subKey, $true)
if (-not $key) {
    Write-Error ("Cannot open HKCU:\" + $subKey)
    exit 1
}

$raw = $key.GetValue("Path", "", [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
$kind = try { $key.GetValueKind("Path") } catch { [Microsoft.Win32.RegistryValueKind]::ExpandString }
if (-not $kind -or $kind -eq [Microsoft.Win32.RegistryValueKind]::None) {
    $kind = [Microsoft.Win32.RegistryValueKind]::ExpandString
}

$parts = if ($raw) { @($raw -split ";" | Where-Object { $_ }) } else { @() }
$targetNorm = $TargetDir.TrimEnd("\")

if ($Action -ieq "Add") {
    $matched = $parts | Where-Object {
        $_.TrimEnd("\") -ieq $targetNorm -or
        [Environment]::ExpandEnvironmentVariables($_).TrimEnd("\") -ieq $targetNorm
    }
    if (-not $matched) {
        $newParts = @($parts) + $TargetDir
        $newVal = ($newParts -join ";")
        $key.SetValue("Path", $newVal, $kind)
        Write-Host ("[SUCCESS] Added " + $TargetDir + " to User PATH.") -ForegroundColor Green
    } else {
        Write-Host ("[INFO] " + $TargetDir + " is already in User PATH.") -ForegroundColor Cyan
    }
} elseif ($Action -ieq "Remove") {
    $newParts = @($parts | Where-Object {
        $_.TrimEnd("\") -ine $targetNorm -and
        [Environment]::ExpandEnvironmentVariables($_).TrimEnd("\") -ine $targetNorm
    })
    $newVal = ($newParts -join ";")
    $key.SetValue("Path", $newVal, $kind)
    Write-Host ("[SUCCESS] Removed " + $TargetDir + " from User PATH.") -ForegroundColor Green
}

$key.Close()

# Broadcast WM_SETTINGCHANGE ("Environment") so new terminal windows observe the change
Add-Type -Namespace Win32 -Name Native -MemberDefinition '[DllImport("user32.dll", SetLastError=true, CharSet=CharSet.Auto)] public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam, uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);' -ErrorAction SilentlyContinue
[Win32.Native]::SendMessageTimeout([IntPtr]0xffff, 0x001A, [UIntPtr]::Zero, "Environment", 2, 5000, [ref][UIntPtr]::Zero) | Out-Null
exit 0
