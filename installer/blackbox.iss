; BlackBox setup. Build with scripts\build-installer.ps1, which compiles the
; release binaries and passes AppVersion from Cargo.toml.
;
; Unattended install (e.g. for Intune or a deployment script):
;   BlackBox-Setup-x.y.z.exe /VERYSILENT /RECIPIENT=age1...
; Add /MERGETASKS="!evidence" to leave Windows logging settings alone, or
; /TYPE=technician /MERGETASKS="assoc" for the viewer tools only (no
; recording) with double-click to open bundles.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#define BinDir "..\target\release"

[Setup]
AppId={{6E3B1F0A-5C2D-4B8E-9A41-B1ACB0C5E7D2}
AppName=BlackBox
AppVersion={#AppVersion}
AppVerName=BlackBox {#AppVersion}
AppPublisher=BlackBox
; bbx install expects %ProgramFiles%\BlackBox; keep the folder fixed.
DefaultDirName={autopf}\BlackBox
DisableDirPage=yes
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir=..\dist
OutputBaseFilename=BlackBox-Setup-{#AppVersion}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
SetupIconFile=..\assets\blackbox.ico
UninstallDisplayName=BlackBox
UninstallDisplayIcon={app}\bbx.exe
ChangesEnvironment=yes
ChangesAssociations=yes
; The service and tray agent are stopped in PrepareToInstall instead.
CloseApplications=no

[Types]
Name: "recorder";   Description: "Record this PC (service, tray icon and tools)"
Name: "technician"; Description: "Technician tools only (open and analyze bundles, no recording)"

[Components]
Name: "tools";    Description: "bbx command-line tools and viewer"; Types: recorder technician; Flags: fixed
Name: "recorder"; Description: "Recording service and tray icon";  Types: recorder

[Tasks]
Name: "evidence"; Description: "Configure Windows to keep more evidence (larger event logs, crash dumps, Right Ctrl + Scroll Lock crash for total freezes)"; Components: recorder
; Off by default; ticked automatically for "Technician tools only" (CurPageChanged).
; Unattended: /MERGETASKS="assoc".
Name: "assoc"; Description: "Open encrypted BlackBox bundles (.zip.age) by double-clicking them"; Components: tools; Flags: unchecked

[Files]
Source: "{#BinDir}\bbx.exe";       DestDir: "{app}"; Flags: ignoreversion
Source: "{#BinDir}\bbx-agent.exe"; DestDir: "{app}"; Flags: ignoreversion; Components: recorder

[Registry]
; Put bbx on the system PATH so it works from any prompt.
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; \
  ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; Check: NeedsAddPath(ExpandConstant('{app}'))
; Double-click a .zip.age bundle to open it in the viewer (technician PCs).
Root: HKA; Subkey: "Software\Classes\.age"; ValueType: string; ValueName: ""; ValueData: "BlackBox.Bundle"; Flags: uninsdeletevalue; Tasks: assoc
Root: HKA; Subkey: "Software\Classes\.age\OpenWithProgids"; ValueType: string; ValueName: "BlackBox.Bundle"; ValueData: ""; Flags: uninsdeletevalue; Tasks: assoc
Root: HKA; Subkey: "Software\Classes\BlackBox.Bundle"; ValueType: string; ValueName: ""; ValueData: "BlackBox bundle"; Flags: uninsdeletekey; Tasks: assoc
Root: HKA; Subkey: "Software\Classes\BlackBox.Bundle\DefaultIcon"; ValueType: string; ValueName: ""; ValueData: "{app}\bbx.exe,0"; Tasks: assoc
Root: HKA; Subkey: "Software\Classes\BlackBox.Bundle\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\bbx.exe"" view ""%1"" --idle-exit 600"; Tasks: assoc

[Icons]
; Starts recording again (UAC prompt if it was stopped) and shows the tray icon.
Name: "{autoprograms}\BlackBox"; Filename: "{app}\bbx-agent.exe"; Parameters: "--start"; \
  Comment: "Start recording and show the BlackBox tray icon"; Components: recorder
; Asks for a bundle from a client and opens it in the viewer.
Name: "{autoprograms}\BlackBox Viewer"; Filename: "{app}\bbx.exe"; Parameters: "view --idle-exit 600"; \
  Comment: "Open a BlackBox bundle from a client"; Components: tools

[UninstallDelete]
Type: files; Name: "{app}\install.log"

[Code]
var
  KeyPage: TInputQueryWizardPage;
  // An installed BlackBox service existed before this run (upgrade).
  WasRecording: Boolean;
  // The files were replaced and bbx install ran.
  InstallFinished: Boolean;

function NeedsAddPath(Dir: String): Boolean;
var
  Paths: String;
begin
  if not RegQueryStringValue(HKLM, 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment', 'Path', Paths) then
  begin
    Result := True;
    exit;
  end;
  Result := Pos(';' + Uppercase(Dir) + ';', ';' + Uppercase(Paths) + ';') = 0;
end;

procedure RemovePath(Dir: String);
var
  Paths: String;
  P: Integer;
begin
  if not RegQueryStringValue(HKLM, 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment', 'Path', Paths) then
    exit;
  P := Pos(';' + Uppercase(Dir) + ';', ';' + Uppercase(Paths) + ';');
  if P = 0 then
    exit;
  if P = 1 then
    Delete(Paths, 1, Length(Dir) + 1)
  else
    Delete(Paths, P - 1, Length(Dir) + 1);
  RegWriteExpandStringValue(HKLM, 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment', 'Path', Paths);
end;

procedure InitializeWizard;
begin
  KeyPage := CreateInputQueryPage(wpSelectTasks,
    'Technician key',
    'Who should be able to open exported evidence?',
    'Paste the technician''s public key (it starts with age1). Bundles exported from this PC ' +
    'will then always be encrypted so only that technician can open them.' + #13#10#13#10 +
    'Create a key on the technician''s computer with:  bbx keygen' + #13#10 +
    'Leave this blank to keep the current setting, or to export without encryption.');
  KeyPage.Add('Public key:', False);
  KeyPage.Values[0] := ExpandConstant('{param:RECIPIENT|}');
end;

var
  AssocDefaulted: Boolean;

procedure CurPageChanged(CurPageID: Integer);
begin
  // A technician-only install is for opening bundles: tick the double-click
  // option the first time the tasks page shows (never untick a choice).
  if (CurPageID = wpSelectTasks) and not AssocDefaulted then
  begin
    AssocDefaulted := True;
    if not WizardIsComponentSelected('recorder') then
      WizardSelectTasks('assoc');
  end;
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := (PageID = KeyPage.ID) and not WizardIsComponentSelected('recorder');
end;

function ValidKey(Key: String): Boolean;
begin
  Result := (Key = '') or ((Copy(Key, 1, 4) = 'age1') and (Length(Key) = 62));
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if CurPageID = KeyPage.ID then
  begin
    KeyPage.Values[0] := Trim(KeyPage.Values[0]);
    if not ValidKey(KeyPage.Values[0]) then
    begin
      MsgBox('That doesn''t look like a technician public key. It should be 62 characters and start with age1.', mbError, MB_OK);
      Result := False;
    end;
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Rc: Integer;
begin
  Result := '';
  if WizardSilent and not ValidKey(Trim(KeyPage.Values[0])) then
  begin
    Result := 'The /RECIPIENT value is not a valid technician public key (62 characters, starting with age1).';
    exit;
  end;
  // An upgrade: stop the service, both ETW sessions, the tray agent and any
  // open viewer (bbx view) so their files can be replaced. bbx install
  // starts recording again; DeinitializeSetup does if setup stops early.
  if FileExists(ExpandConstant('{app}\bbx.exe')) then
  begin
    WasRecording := Exec(ExpandConstant('{sys}\sc.exe'), 'query BlackBox', '', SW_HIDE, ewWaitUntilTerminated, Rc) and (Rc = 0);
    Exec(ExpandConstant('{app}\bbx.exe'), 'stop', '', SW_HIDE, ewWaitUntilTerminated, Rc);
  end;
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/IM bbx-agent.exe /F', '', SW_HIDE, ewWaitUntilTerminated, Rc);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/IM bbx.exe /F', '', SW_HIDE, ewWaitUntilTerminated, Rc);
end;

// Setup stopped after PrepareToInstall (cancelled, or a file couldn't be
// replaced): don't leave the PC unrecorded. Start the old copy again.
procedure DeinitializeSetup();
var
  Rc: Integer;
begin
  if WasRecording and not InstallFinished and FileExists(ExpandConstant('{app}\bbx.exe')) then
  begin
    Exec(ExpandConstant('{app}\bbx.exe'), 'start', '', SW_HIDE, ewWaitUntilTerminated, Rc);
    if FileExists(ExpandConstant('{app}\bbx-agent.exe')) then
      ExecAsOriginalUser(ExpandConstant('{app}\bbx-agent.exe'), '', '', SW_SHOWNORMAL, ewNoWait, Rc);
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  Args, Log: String;
  Rc: Integer;
begin
  if CurStep <> ssPostInstall then
    exit;
  InstallFinished := True;
  if not WizardIsComponentSelected('recorder') then
    exit;
  Args := 'install';
  if not WizardIsTaskSelected('evidence') then
    Args := Args + ' --no-system-changes';
  if Trim(KeyPage.Values[0]) <> '' then
    Args := Args + ' --recipient ' + Trim(KeyPage.Values[0]);
  Log := ExpandConstant('{app}\install.log');
  WizardForm.StatusLabel.Caption := 'Registering the BlackBox service and starting recording...';
  if not Exec(ExpandConstant('{cmd}'),
      '/c ""' + ExpandConstant('{app}\bbx.exe') + '" ' + Args + ' > "' + Log + '" 2>&1"',
      ExpandConstant('{app}'), SW_HIDE, ewWaitUntilTerminated, Rc) or (Rc <> 0) then
    SuppressibleMsgBox('BlackBox was copied, but setting up the service failed (code ' + IntToStr(Rc) + ').' + #13#10#13#10 +
      'Details are in ' + Log, mbError, MB_OK, IDOK);
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Args: String;
  Rc: Integer;
begin
  if CurUninstallStep = usUninstall then
  begin
    Args := 'uninstall';
    if DirExists(ExpandConstant('{commonappdata}\BlackBox')) and
       (SuppressibleMsgBox('Also delete everything BlackBox has recorded on this PC?' + #13#10#13#10 +
          'Choose No to keep the recordings in ' + ExpandConstant('{commonappdata}\BlackBox') + '.',
          mbConfirmation, MB_YESNO or MB_DEFBUTTON2, IDNO) = IDYES) then
      Args := Args + ' --purge';
    // Removes the service, ETW sessions and tray agent before the files go.
    Exec(ExpandConstant('{app}\bbx.exe'), Args, '', SW_HIDE, ewWaitUntilTerminated, Rc);
  end
  else if CurUninstallStep = usPostUninstall then
    RemovePath(ExpandConstant('{app}'));
end;
