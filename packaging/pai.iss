; Personal Agentic AI (PAI) - Inno Setup Script
; Part of Milestone P5 for the v1.1.0 Packaging and Installer Subsystem
; Specification: docs/PACKAGING_SPEC.md (§2, §3, §4, §5, §6, §7, Appendix A, Appendix D)

#ifndef AppVersion
  #define AppVersion "1.0.0"
#endif

#ifndef OutputDir
  #define OutputDir "..\dist"
#endif

#ifndef OutputBaseFilename
  #define OutputBaseFilename "PAI-Setup-" + AppVersion + "-win-x64"
#endif

#ifndef PayloadDir
  #define PayloadDir "..\dist\payload"
#endif

#ifndef AgreementPath
  #define AgreementPath "agreement.txt"
#endif

#ifndef AgreementSha256
  #define AgreementSha256 "unknown"
#endif

[Setup]
AppId={{8B7B61CA-C450-4E87-9F1B-4198A82711C9}
AppName=Personal Agentic AI (PAI)
AppVersion={#AppVersion}
AppPublisher=PAI Project
DefaultDirName={localappdata}\Programs\PAI
DefaultGroupName=Personal Agentic AI
DisableProgramGroupPage=yes
DisableDirPage=no
PrivilegesRequired=lowest
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
LicenseFile={#AgreementPath}
OutputDir={#OutputDir}
OutputBaseFilename={#OutputBaseFilename}
Compression=lzma2/max
SolidCompression=yes
UninstallDisplayIcon={app}\bin\pai.exe
UninstallDisplayName=Personal Agentic AI (PAI)
WizardStyle=modern

[Files]
Source: "{#PayloadDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#AgreementPath}"; DestDir: "{app}"; DestName: "AGREEMENT.txt"; Flags: ignoreversion

[Run]
Filename: "{app}\bin\pai.exe"; Parameters: "setup"; Description: "Run First-Run Setup (Hardware Survey & Model Setup)"; Flags: postinstall skipifsilent nowait unchecked
Filename: "{app}\bin\pai.exe"; Parameters: "doctor --skip-smoke"; Description: "Run Diagnostic Doctor Check"; Flags: postinstall skipifsilent nowait unchecked

[UninstallDelete]
Type: files; Name: "{app}\agreement_acceptance.json"
Type: filesandordirs; Name: "{app}"

[Code]
function ExecPowerShell(Args: string; var ResultCode: Integer): Boolean;
var
  PSExe: string;
begin
  PSExe := ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe');
  if not FileExists(PSExe) then
  begin
    PSExe := 'powershell.exe';
  end;
  Result := Exec(PSExe, '-NoProfile -NonInteractive -ExecutionPolicy Bypass ' + Args, '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

function GetTargetRegSubKey(): string;
var
  Sub: string;
begin
  Sub := ExpandConstant('{param:REG_SUBKEY}');
  if Sub = '' then
  begin
    Sub := GetEnv('PAI_REG_SUBKEY');
  end;
  Sub := Trim(Sub);
  if (Length(Sub) >= 2) and (Sub[1] = '"') and (Sub[Length(Sub)] = '"') then
  begin
    Sub := Copy(Sub, 2, Length(Sub) - 2);
  end;
  Result := Trim(Sub);
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  AcceptanceJson: string;
  AppDir: string;
  BinDir: string;
  ScriptPath: string;
  ResultCode: Integer;
  PaiDir: string;
  SubKey: string;
  ExtraArgs: string;
begin
  if CurStep = ssPostInstall then
  begin
    AppDir := ExpandConstant('{app}');
    BinDir := AppDir + '\bin';

    // 1. Record Agreement Acceptance locally (Specification §3)
    AcceptanceJson := '{' + #13#10 +
      '  "installed_version": "' + '{#AppVersion}' + '",' + #13#10 +
      '  "agreement_text_sha256": "' + '{#AgreementSha256}' + '",' + #13#10 +
      '  "accepted_utc": "' + GetDateTimeString('yyyy/mm/dd hh:nn:ss', '-', ':') + '",' + #13#10 +
      '  "accepted": true' + #13#10 +
      '}';
    SaveStringToFile(AppDir + '\agreement_acceptance.json', AcceptanceJson, False);

    // Also record into ~/.pai/agreement_acceptance.json if ~/.pai directory exists
    PaiDir := GetEnv('USERPROFILE') + '\.pai';
    if (PaiDir <> '\.pai') and DirExists(PaiDir) then
    begin
      SaveStringToFile(PaiDir + '\agreement_acceptance.json', AcceptanceJson, False);
    end;

    // 2. Add bin directory to User PATH using Appendix D PowerShell script
    if (BinDir <> '') and (BinDir <> '\bin') and (BinDir <> '\\bin') then
    begin
      ScriptPath := AppDir + '\tools\update_path.ps1';
      if not FileExists(ScriptPath) then
      begin
        ScriptPath := AppDir + '\packaging\update_path.ps1';
      end;

      SubKey := GetTargetRegSubKey();
      if SubKey <> '' then
        ExtraArgs := ' -RegSubKey "' + SubKey + '"'
      else
        ExtraArgs := '';

      if FileExists(ScriptPath) then
      begin
        ExecPowerShell('-File "' + ScriptPath + '" -Action Add -TargetDir "' + BinDir + '"' + ExtraArgs, ResultCode);
      end
      else
      begin
        // Fallback inline PowerShell Appendix D execution
        ExecPowerShell('-Command "$dir = ''' + BinDir + '''; $rawSub = ''' + SubKey + '''; if (-not $rawSub) { $rawSub = if ($env:PAI_REG_SUBKEY) { $env:PAI_REG_SUBKEY.Trim() } else { ''Environment'' } }; $subKey = if ($rawSub -and ($rawSub -ieq ''Environment'' -or $rawSub.StartsWith(''Test_'') -or $rawSub.StartsWith(''PAI_TEST_''))) { $rawSub } else { ''Environment'' }; $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($subKey, $true); if ($key) { $raw = $key.GetValue(''Path'', '''', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames); $kind = try { $key.GetValueKind(''Path'') } catch { [Microsoft.Win32.RegistryValueKind]::ExpandString }; if (-not $kind -or $kind -eq [Microsoft.Win32.RegistryValueKind]::None) { $kind = [Microsoft.Win32.RegistryValueKind]::ExpandString }; $parts = if ($raw) { @($raw -split '';'' | Where-Object { $_ }) } else { @() }; $have = $parts | Where-Object { $_.TrimEnd(''\'') -ieq $dir.TrimEnd(''\'') -or [Environment]::ExpandEnvironmentVariables($_).TrimEnd(''\'') -ieq $dir.TrimEnd(''\'') }; if (-not $have) { $key.SetValue(''Path'', ((@($parts) + $dir) -join '';''), $kind) }; $key.Close(); Add-Type -Namespace Win32 -Name Native -MemberDefinition ''[DllImport(\"\"user32.dll\"\", SetLastError=true, CharSet=CharSet.Auto)] public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam, uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);'' -ErrorAction SilentlyContinue; [Win32.Native]::SendMessageTimeout([IntPtr]0xffff, 0x001A, [UIntPtr]::Zero, ''Environment'', 2, 5000, [ref][UIntPtr]::Zero) | Out-Null }"', ResultCode);
      end;
    end;
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  AppDir: string;
  BinDir: string;
  ScriptPath: string;
  ResultCode: Integer;
  PaiDir: string;
  KeepData: Integer;
  SubKey: string;
  ExtraArgs: string;
begin
  if CurUninstallStep = usUninstall then
  begin
    AppDir := ExpandConstant('{app}');
    BinDir := AppDir + '\bin';

    // 1. Remove bin directory from User PATH (Appendix D)
    if (BinDir <> '') and (BinDir <> '\bin') and (BinDir <> '\\bin') then
    begin
      ScriptPath := AppDir + '\tools\update_path.ps1';
      if not FileExists(ScriptPath) then
      begin
        ScriptPath := AppDir + '\packaging\update_path.ps1';
      end;

      SubKey := GetTargetRegSubKey();
      if SubKey <> '' then
        ExtraArgs := ' -RegSubKey "' + SubKey + '"'
      else
        ExtraArgs := '';

      if FileExists(ScriptPath) then
      begin
        ExecPowerShell('-File "' + ScriptPath + '" -Action Remove -TargetDir "' + BinDir + '"' + ExtraArgs, ResultCode);
      end
      else
      begin
        // Fallback inline PowerShell Appendix D execution
        ExecPowerShell('-Command "$dir = ''' + BinDir + '''; $rawSub = ''' + SubKey + '''; if (-not $rawSub) { $rawSub = if ($env:PAI_REG_SUBKEY) { $env:PAI_REG_SUBKEY.Trim() } else { ''Environment'' } }; $subKey = if ($rawSub -and ($rawSub -ieq ''Environment'' -or $rawSub.StartsWith(''Test_'') -or $rawSub.StartsWith(''PAI_TEST_''))) { $rawSub } else { ''Environment'' }; $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($subKey, $true); if ($key) { $raw = $key.GetValue(''Path'', '''', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames); $kind = try { $key.GetValueKind(''Path'') } catch { [Microsoft.Win32.RegistryValueKind]::ExpandString }; if (-not $kind -or $kind -eq [Microsoft.Win32.RegistryValueKind]::None) { $kind = [Microsoft.Win32.RegistryValueKind]::ExpandString }; $parts = if ($raw) { @($raw -split '';'' | Where-Object { $_ }) } else { @() }; $newParts = @($parts | Where-Object { $_.TrimEnd(''\'') -ine $dir.TrimEnd(''\'') -and [Environment]::ExpandEnvironmentVariables($_).TrimEnd(''\'') -ine $dir.TrimEnd(''\'') }); $key.SetValue(''Path'', ($newParts -join '';''), $kind); $key.Close(); Add-Type -Namespace Win32 -Name Native -MemberDefinition ''[DllImport(\"\"user32.dll\"\", SetLastError=true, CharSet=CharSet.Auto)] public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam, uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);'' -ErrorAction SilentlyContinue; [Win32.Native]::SendMessageTimeout([IntPtr]0xffff, 0x001A, [UIntPtr]::Zero, ''Environment'', 2, 5000, [ref][UIntPtr]::Zero) | Out-Null }"', ResultCode);
      end;
    end;

    // 2. Ask user whether to keep downloaded models and local ~/.pai configuration (§4, §9.5)
    PaiDir := GetEnv('USERPROFILE') + '\.pai';
    if (PaiDir <> '\.pai') and DirExists(PaiDir) and (not UninstallSilent) then
    begin
      KeepData := MsgBox('Do you want to keep your downloaded local AI models and settings in ~/.pai?' + #13#10#13#10 +
        'Click Yes to keep models and data (recommended).' + #13#10 +
        'Click No to delete all local models and ~/.pai configuration.', mbConfirmation, MB_YESNO);
      if KeepData = IDNO then
      begin
        DelTree(PaiDir, True, True, True);
      end;
    end;
  end;
end;
