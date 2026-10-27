; Personal Agentic AI (PAI) - Inno Setup Script
; Part of Milestone P5 for the v1.1.0 Packaging and Installer Subsystem
; Specification: docs/PACKAGING_SPEC.md (§2, §3, §4, §5, §6, §7, Appendix A, Appendix D)

#ifndef AppVersion
  #error "AppVersion must be defined when compiling pai.iss (e.g. via /DAppVersion=1.1.0-rc1)"
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
type
  TSystemTime = record
    wYear: Word;
    wMonth: Word;
    wDayOfWeek: Word;
    wDay: Word;
    wHour: Word;
    wMinute: Word;
    wSecond: Word;
    wMilliseconds: Word;
  end;

procedure ExitProcess(uExitCode: UINT); external 'ExitProcess@kernel32.dll stdcall';
procedure GetSystemTime(var lpSystemTime: TSystemTime); external 'GetSystemTime@kernel32.dll stdcall';

function GetUtcIsoTimestamp(): string;
var
  st: TSystemTime;
begin
  GetSystemTime(st);
  Result := Format('%.4d-%.2d-%.2dT%.2d:%.2d:%.2dZ', [st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond]);
end;

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

    // 1. Record Agreement Acceptance locally (Specification §3, Finding DE)
    AcceptanceJson := '{' + #13#10 +
      '  "installed_version": "' + '{#AppVersion}' + '",' + #13#10 +
      '  "agreement_text_sha256": "' + '{#AgreementSha256}' + '",' + #13#10 +
      '  "accepted_utc": "' + GetUtcIsoTimestamp() + '",' + #13#10 +
      '  "accepted": true' + #13#10 +
      '}';

    // Abort installation if agreement record cannot be written (Finding DC)
    if not SaveStringToFile(AppDir + '\agreement_acceptance.json', AcceptanceJson, False) then
    begin
      Log('CRITICAL: Failed to write agreement_acceptance.json to ' + AppDir);
      if not WizardSilent() then
      begin
        MsgBox('Fatal Error: Failed to write agreement acceptance record to ' + AppDir + '\agreement_acceptance.json.' + #13#10 +
               'Installation has been aborted.', mbCriticalError, MB_OK);
      end;
      ExitProcess(2);
    end;

    // Also record into ~/.pai/agreement_acceptance.json if ~/.pai directory exists
    PaiDir := GetEnv('USERPROFILE') + '\.pai';
    if (PaiDir <> '\.pai') and DirExists(PaiDir) then
    begin
      SaveStringToFile(PaiDir + '\agreement_acceptance.json', AcceptanceJson, False);
    end;

    // 2. Add bin directory to User PATH using Appendix D PowerShell script (Findings DC, DD)
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

      if not FileExists(ScriptPath) then
      begin
        Log('CRITICAL: tools\update_path.ps1 not found in application directory: ' + ScriptPath);
        if not WizardSilent() then
        begin
          MsgBox('Personal Agentic AI (PAI) was installed, but the PATH update helper script is missing.' + #13#10#13#10 +
                 'Please manually add the following directory to your User PATH:' + #13#10 +
                 BinDir + #13#10#13#10 +
                 'You can do this by searching "Environment Variables" in Windows Settings.', mbError, MB_OK);
        end
        else
        begin
          ExitProcess(3);
        end;
      end
      else
      begin
        ResultCode := -1;
        if (not ExecPowerShell('-File "' + ScriptPath + '" -Action Add -TargetDir "' + BinDir + '"' + ExtraArgs, ResultCode)) or (ResultCode <> 0) then
        begin
          Log('ERROR: Failed to update User PATH via update_path.ps1 (ResultCode: ' + IntToStr(ResultCode) + ').');
          if not WizardSilent() then
          begin
            MsgBox('Personal Agentic AI (PAI) was installed, but updating the User PATH environment variable failed (exit code ' + IntToStr(ResultCode) + ').' + #13#10#13#10 +
                   'Please manually add the following directory to your User PATH:' + #13#10 +
                   BinDir + #13#10#13#10 +
                   'You can do this by searching "Environment Variables" in Windows Settings.', mbError, MB_OK);
          end
          else
          begin
            ExitProcess(3);
          end;
        end
        else
        begin
          Log('SUCCESS: User PATH updated successfully with ' + BinDir);
        end;
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

    // 1. Remove bin directory from User PATH (Appendix D, Finding DD)
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
        ResultCode := -1;
        if (not ExecPowerShell('-File "' + ScriptPath + '" -Action Remove -TargetDir "' + BinDir + '"' + ExtraArgs, ResultCode)) or (ResultCode <> 0) then
        begin
          Log('WARNING: Failed to remove bin from User PATH during uninstall (ResultCode: ' + IntToStr(ResultCode) + ').');
        end;
      end
      else
      begin
        Log('WARNING: tools\update_path.ps1 not found during uninstall: ' + ScriptPath);
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
