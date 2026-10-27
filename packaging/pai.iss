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
Type: files; Name: "{app}\.pai-install"
Type: files; Name: "{app}\manifest.files"
Type: filesandordirs; Name: "{app}\research\__pycache__"

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

function IsDirEmpty(const Dir: string): Boolean;
var
  FindRec: TFindRec;
begin
  Result := True;
  if FindFirst(Dir + '\*', FindRec) then
  begin
    try
      repeat
        if (FindRec.Name <> '.') and (FindRec.Name <> '..') then
        begin
          Result := False;
          Break;
        end;
      until not FindNext(FindRec);
    finally
      FindClose(FindRec);
    end;
  end;
end;

function HasValidPaiMarker(const Dir: string): Boolean;
var
  CleanDir: string;
  MarkerPath: string;
  Lines: TArrayOfString;
  I: Integer;
begin
  Result := False;
  CleanDir := RemoveQuotes(Trim(Dir));
  if (Length(CleanDir) > 0) and (CleanDir[Length(CleanDir)] = '\') then
    CleanDir := Copy(CleanDir, 1, Length(CleanDir) - 1);
  MarkerPath := CleanDir + '\.pai-install';
  if FileExists(MarkerPath) then
  begin
    if LoadStringsFromFile(MarkerPath, Lines) then
    begin
      for I := 0 to GetArrayLength(Lines) - 1 do
      begin
        if Pos('{8B7B61CA-C450-4E87-9F1B-4198A82711C9}', Lines[I]) > 0 then
        begin
          Result := True;
          Break;
        end;
      end;
    end;
  end;
end;

function IsSafeRelativePath(const PathStr: string): Boolean;
var
  FirstChar: string;
begin
  Result := True;
  if Length(PathStr) = 0 then
  begin
    Result := False;
    Exit;
  end;
  FirstChar := Copy(PathStr, 1, 1);
  if FirstChar = '/' then
    Log('MATCHED SLASH: ' + FirstChar);
  if FirstChar = '\' then
    Log('MATCHED BACKSLASH: ' + FirstChar);
  if Pos(FirstChar, '/\') > 0 then
    Log('MATCHED POS');
  if (FirstChar = '/') or (FirstChar = '\') then
  begin
    Log('REJECT 2: starts with slash: [' + PathStr + ']');
    Result := False;
    Exit;
  end;
  // Reject drive letters / colon
  if Pos(':', PathStr) > 0 then
  begin
    Log('REJECT 3: colon: ' + PathStr);
    Result := False;
    Exit;
  end;
  // Reject directory traversal (..)
  if Pos('..', PathStr) > 0 then
  begin
    Log('REJECT 4: ..: ' + PathStr);
    Result := False;
    Exit;
  end;
end;

function IsValidInstallDir(const TargetDir: string): Boolean;
begin
  // A directory is valid if:
  // 1. It does not exist yet (will be created by installer)
  // 2. It exists and is completely empty
  // 3. It exists and contains a valid .pai-install marker with AppId GUID (existing PAI installation / upgrade)
  Result := True;
  if DirExists(TargetDir) then
  begin
    if (not IsDirEmpty(TargetDir)) and (not HasValidPaiMarker(TargetDir)) then
    begin
      Result := False;
    end;
  end;
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  TargetDir: string;
begin
  Result := True;
  if CurPageID = wpSelectDir then
  begin
    TargetDir := ExpandConstant('{app}');
    if not IsValidInstallDir(TargetDir) then
    begin
      if WizardSilent() then
      begin
        Log('CRITICAL: Non-empty target directory rejected in silent mode: ' + TargetDir);
        ExitProcess(1);
      end
      else
      begin
        MsgBox('The selected installation directory already exists and contains files:' + #13#10#13#10 +
               TargetDir + #13#10#13#10 +
               'PAI requires a new directory, an empty directory, or an existing PAI installation.' + #13#10#13#10 +
               'Please select a different folder.', mbError, MB_OK);
        Result := False;
        Exit;
      end;
    end;
  end;
end;

procedure RemoveEmptySubdirs(const Dir: string);
var
  FindRec: TFindRec;
  SubDir: string;
begin
  if FindFirst(Dir + '\*', FindRec) then
  begin
    try
      repeat
        if (FindRec.Name <> '.') and (FindRec.Name <> '..') then
        begin
          SubDir := Dir + '\' + FindRec.Name;
          if (FindRec.Attributes and 16) <> 0 then
          begin
            RemoveEmptySubdirs(SubDir);
            RemoveDir(SubDir);
          end;
        end;
      until not FindNext(FindRec);
    finally
      FindClose(FindRec);
    end;
  end;
  RemoveDir(Dir);
end;

procedure DeleteManifestAndGeneratedFiles(const AppDir: string);
var
  FilesListPath: string;
  Lines: TArrayOfString;
  I: Integer;
  Line: string;
  RelPath: string;
  FullFilePath: string;
  FindRec: TFindRec;
  HasMarker: Boolean;
begin
  HasMarker := HasValidPaiMarker(AppDir);

  // 1. Delete files listed in manifest.files (Finding DM)
  FilesListPath := AppDir + '\manifest.files';
  if FileExists(FilesListPath) then
  begin
    if LoadStringsFromFile(FilesListPath, Lines) then
    begin
      for I := 0 to GetArrayLength(Lines) - 1 do
      begin
        Line := Trim(Lines[I]);
        if Line = '' then
          Continue;

        if not IsSafeRelativePath(Line) then
        begin
          Log('WARNING: Unsafe path in manifest.files rejected: ' + Line);
          Continue;
        end;

        RelPath := Line;
        StringChangeEx(RelPath, '/', '\', True);
        FullFilePath := AppDir + '\' + RelPath;
        if FileExists(FullFilePath) then
        begin
          DeleteFile(FullFilePath);
        end;
      end;
    end;
  end;

  // 2. Delete generated and installer files placed during installation ONLY if marker exists (Finding DL)
  if HasMarker then
  begin
    DeleteFile(AppDir + '\agreement_acceptance.json');
    DeleteFile(AppDir + '\AGREEMENT.txt');
    DeleteFile(AppDir + '\manifest.sig');
    DeleteFile(AppDir + '\manifest.json');
    DeleteFile(AppDir + '\manifest.files');
    DeleteFile(AppDir + '\.pai-install');

    // Delete unins000.* files placed by Inno Setup
    if FindFirst(AppDir + '\unins*.*', FindRec) then
    begin
      try
        repeat
          if (FindRec.Attributes and 16) = 0 then
          begin
            DeleteFile(AppDir + '\' + FindRec.Name);
          end;
        until not FindNext(FindRec);
      finally
        FindClose(FindRec);
      end;
    end;
  end;
end;

procedure ExecuteRollback(const AppDir: string; const BinDir: string; const ScriptPath: string; const SubKey: string);
var
  ResultCode: Integer;
  ExtraArgs: string;
  AppIdSubKey: string;
begin
  Log('INFO: Executing manifest-scoped rollback for ' + AppDir);

  // 1. Revert any PATH entry added
  if SubKey <> '' then
    ExtraArgs := ' -RegSubKey "' + SubKey + '"'
  else
    ExtraArgs := '';

  if FileExists(ScriptPath) and (BinDir <> '') then
  begin
    ExecPowerShell('-File "' + ScriptPath + '" -Action Remove -TargetDir "' + BinDir + '"' + ExtraArgs, ResultCode);
  end;

  // 2. Remove Inno Setup uninstaller registry key from HKCU (Finding DK)
  AppIdSubKey := 'Software\Microsoft\Windows\CurrentVersion\Uninstall\{8B7B61CA-C450-4E87-9F1B-4198A82711C9}_is1';
  if RegKeyExists(HKCU, AppIdSubKey) then
  begin
    Log('INFO: Removing uninstaller registry key: HKCU\' + AppIdSubKey);
    RegDeleteKeyIncludingSubkeys(HKCU, AppIdSubKey);
  end;

  // 3. Delete only manifest-tracked and PAI-generated files (Finding DK)
  DeleteManifestAndGeneratedFiles(AppDir);

  // 4. Remove empty subdirectories and remove AppDir only if left completely empty (Finding DK)
  RemoveEmptySubdirs(AppDir);
  RemoveDir(AppDir);

  if DirExists(AppDir) then
  begin
    Log('INFO: Target directory preserved because it contains unrelated user files: ' + AppDir);
  end
  else
  begin
    Log('INFO: Target directory was empty and was cleanly removed: ' + AppDir);
  end;
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
  if CurStep = ssInstall then
  begin
    AppDir := ExpandConstant('{app}');
    if not IsValidInstallDir(AppDir) then
    begin
      Log('CRITICAL: Target directory is non-empty and not an existing PAI installation: ' + AppDir);
      if not WizardSilent() then
      begin
        MsgBox('The selected installation directory already exists and contains files:' + #13#10#13#10 +
               AppDir + #13#10#13#10 +
               'PAI requires a new directory, an empty directory, or an existing PAI installation.' + #13#10 +
               'Installation aborted.', mbError, MB_OK);
      end;
      ExitProcess(1);
    end;
    // Write or ensure .pai-install marker immediately once directory is approved (Finding DL)
    ForceDirectories(AppDir);
    SaveStringToFile(AppDir + '\.pai-install', '{8B7B61CA-C450-4E87-9F1B-4198A82711C9}' + #13#10, False);
  end
  else if CurStep = ssPostInstall then
  begin
    AppDir := ExpandConstant('{app}');
    BinDir := AppDir + '\bin';
    ScriptPath := AppDir + '\tools\update_path.ps1';
    if not FileExists(ScriptPath) then
    begin
      ScriptPath := AppDir + '\packaging\update_path.ps1';
    end;
    SubKey := GetTargetRegSubKey();

    // 1. Record Agreement Acceptance locally (Specification §3, Finding DE)
    AcceptanceJson := '{' + #13#10 +
      '  "installed_version": "' + '{#AppVersion}' + '",' + #13#10 +
      '  "agreement_text_sha256": "' + '{#AgreementSha256}' + '",' + #13#10 +
      '  "accepted_utc": "' + GetUtcIsoTimestamp() + '",' + #13#10 +
      '  "accepted": true' + #13#10 +
      '}';

    // Abort installation and rollback if agreement record cannot be written (Findings DC, DI, DK)
    if not SaveStringToFile(AppDir + '\agreement_acceptance.json', AcceptanceJson, False) then
    begin
      Log('CRITICAL: Failed to write agreement_acceptance.json to ' + AppDir + '. Executing rollback.');
      ExecuteRollback(AppDir, BinDir, ScriptPath, SubKey);
      if not WizardSilent() then
      begin
        MsgBox('Fatal Error: Failed to write agreement acceptance record to ' + AppDir + '\agreement_acceptance.json.' + #13#10#13#10 +
               'Installation has been rolled back and aborted. If this was an upgrade over an existing version, the previous installation has been removed; please re-run setup.', mbCriticalError, MB_OK);
      end;
      ExitProcess(2);
    end;

    // Also record into ~/.pai/agreement_acceptance.json if ~/.pai directory exists
    PaiDir := GetEnv('USERPROFILE') + '\.pai';
    if (PaiDir <> '\.pai') and DirExists(PaiDir) then
    begin
      SaveStringToFile(PaiDir + '\agreement_acceptance.json', AcceptanceJson, False);
    end;

    // 2. Add bin directory to User PATH using Appendix D PowerShell script (Findings DC, DD, DI, DK)
    if (BinDir <> '') and (BinDir <> '\bin') and (BinDir <> '\\bin') then
    begin
      if SubKey <> '' then
        ExtraArgs := ' -RegSubKey "' + SubKey + '"'
      else
        ExtraArgs := '';

      if not FileExists(ScriptPath) then
      begin
        Log('CRITICAL: tools\update_path.ps1 not found in application directory: ' + ScriptPath + '. Executing rollback.');
        ExecuteRollback(AppDir, BinDir, ScriptPath, SubKey);
        if not WizardSilent() then
        begin
          MsgBox('Personal Agentic AI (PAI) installation failed: PATH update helper script is missing.' + #13#10#13#10 +
                 'Installation has been rolled back. If this was an upgrade over an existing version, the previous installation has been removed; please re-run setup.', mbError, MB_OK);
        end;
        ExitProcess(3);
      end
      else
      begin
        ResultCode := -1;
        if (not ExecPowerShell('-File "' + ScriptPath + '" -Action Add -TargetDir "' + BinDir + '"' + ExtraArgs, ResultCode)) or (ResultCode <> 0) then
        begin
          Log('ERROR: Failed to update User PATH via update_path.ps1 (ResultCode: ' + IntToStr(ResultCode) + '). Executing rollback.');
          ExecuteRollback(AppDir, BinDir, ScriptPath, SubKey);
          if not WizardSilent() then
          begin
            MsgBox('Personal Agentic AI (PAI) installation failed: unable to update User PATH environment variable (exit code ' + IntToStr(ResultCode) + ').' + #13#10#13#10 +
                   'Installation has been rolled back. If this was an upgrade over an existing version, the previous installation has been removed; please re-run setup.', mbError, MB_OK);
          end;
          ExitProcess(3);
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
  end
  else if CurUninstallStep = usPostUninstall then
  begin
    AppDir := ExpandConstant('{app}');
    // Clean up empty subdirectories and remove AppDir ONLY if left completely empty (Finding DK)
    RemoveEmptySubdirs(AppDir);
    RemoveDir(AppDir);
  end;
end;
