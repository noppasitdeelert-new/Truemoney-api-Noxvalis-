; ngm-panel — Inno Setup 6 script
; Build:  iscc packaging\installer\ngm-panel.iss
; Installer adds the install folder to the *user* PATH and broadcasts the change,
; so `ngm-panel` works in cmd / PowerShell / Windows Terminal right after install.

#define MyAppName "ngm-panel"
#define MyAppVersion "1.1.0"
#define MyAppPublisher "NGM"
#define MyAppExeName "ngm-panel.exe"
#define MyAppUrl "https://github.com/NGM/ngm-panel"

[Setup]
AppId={{8F3C2B7A-5D14-4E6B-9C2F-A1D4E7B39C50}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppUrl}
AppSupportURL={#MyAppUrl}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
OutputDir=..\..\dist
OutputBaseFilename=ngm-panel-{#MyAppVersion}-setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesInstallIn64BitMode=x64compatible
ArchitecturesAllowed=x64compatible
ChangesEnvironment=yes
UninstallDisplayName={#MyAppName}
LicenseFile=..\..\LICENSE
; ถ้าต้องการไอคอน ให้วางไฟล์ packaging\ngm-panel.ico แล้วเปิดบรรทัดล่างนี้
; SetupIconFile=..\ngm-panel.ico

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "addtopath"; Description: "เพิ่ม ngm-panel ลง PATH ของผู้ใช้ (แนะนำ)"; GroupDescription: "Integration:"
Name: "desktopicon"; Description: "สร้างไอคอนบน Desktop"; GroupDescription: "Icons:"; Flags: unchecked

[Files]
Source: "..\..\dist\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\README.md"; DestDir: "{app}"; Flags: ignoreversion isreadme
Source: "..\..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Parameters: "run"
Name: "{group}\ngm-panel doctor"; Filename: "{app}\{#MyAppExeName}"; Parameters: "doctor"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Parameters: "run"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Parameters: "doctor"; Description: "ตรวจสอบการติดตั้ง (doctor)"; Flags: postinstall nowait skipifsilent

[Code]
const
  EnvironmentKey = 'Environment';

function UserPathContains(Path: string): Boolean;
var
  Paths: string;
begin
  Result := False;
  if RegQueryStringValue(HKCU, EnvironmentKey, 'Path', Paths) then
    Result := Pos(';' + Uppercase(Path) + ';', ';' + Uppercase(Paths) + ';') > 0;
end;

procedure EnvAddPath(Path: string);
var
  Paths: string;
begin
  if UserPathContains(Path) then
    Exit;
  if not RegQueryStringValue(HKCU, EnvironmentKey, 'Path', Paths) then
    Paths := '';
  if Paths <> '' then
    Paths := Paths + ';';
  Paths := Paths + Path;
  RegWriteExpandStringValue(HKCU, EnvironmentKey, 'Path', Paths);
  Log('Added to user PATH: ' + Path);
end;

procedure EnvRemovePath(Path: string);
var
  Paths: string;
  P: Integer;
begin
  if not RegQueryStringValue(HKCU, EnvironmentKey, 'Path', Paths) then
    Exit;
  P := Pos(';' + Uppercase(Path) + ';', ';' + Uppercase(Paths) + ';');
  if P = 0 then
    Exit;
  Delete(Paths, P, Length(Path) + 1);
  if (Length(Paths) > 0) and (Paths[1] = ';') then
    Delete(Paths, 1, 1);
  RegWriteExpandStringValue(HKCU, EnvironmentKey, 'Path', Paths);
  Log('Removed from user PATH: ' + Path);
end;

procedure BroadcastEnvironmentChange();
begin
  SendMessageTimeout(HWND_BROADCAST, WM_SETTINGCHANGE, 0, LParam(PChar('Environment')),
    SMTO_ABORTIFHUNG, 5000, 0);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    if WizardIsTaskSelected('addtopath') then
      EnvAddPath(ExpandConstant('{app}'));
    BroadcastEnvironmentChange();
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
  begin
    EnvRemovePath(ExpandConstant('{app}'));
    BroadcastEnvironmentChange();
  end;
end;
