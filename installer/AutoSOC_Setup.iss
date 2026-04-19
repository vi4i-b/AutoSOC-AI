[Setup]
AppId={{A98D5D84-697D-47B7-BD8E-7F092AF8A1F7}
AppName=AutoSOC
AppVersion=3.0
AppPublisher=AutoSOC
DefaultDirName={autopf}\AutoSOC
DefaultGroupName=AutoSOC
OutputDir=.
OutputBaseFilename=AutoSOC_Setup
Compression=lzma
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
SetupIconFile=..\assets\app_icon.ico
UninstallDisplayIcon={app}\AutoSOC.exe

[Files]
Source: "..\dist\AutoSOC.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\dist\Launch AutoSOC.bat"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\dist\ai_memory.json"; DestDir: "{app}"; Flags: onlyifdoesntexist
Source: "..\dist\soc_audit.db"; DestDir: "{app}"; Flags: onlyifdoesntexist
Source: "..\dist\.env.example"; DestDir: "{app}"; Flags: onlyifdoesntexist

[Icons]
Name: "{group}\AutoSOC"; Filename: "{app}\Launch AutoSOC.bat"; WorkingDir: "{app}"
Name: "{autodesktop}\AutoSOC"; Filename: "{app}\Launch AutoSOC.bat"; WorkingDir: "{app}"

[Run]
Filename: "{app}\Launch AutoSOC.bat"; Description: "Launch AutoSOC"; Flags: nowait postinstall skipifsilent

[Code]
function NmapInstalled: Boolean;
begin
  Result :=
    FileExists(ExpandConstant('{pf32}\Nmap\nmap.exe')) or
    FileExists(ExpandConstant('{pf}\Nmap\nmap.exe'));
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    if not NmapInstalled then
    begin
      MsgBox(
        'AutoSOC installed successfully, but Nmap was not found.' + #13#10 + #13#10 +
        'Network scan features require Nmap to be installed separately.',
        mbInformation,
        MB_OK
      );
    end;
  end;
end;
