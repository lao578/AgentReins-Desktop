; AgentReins Windows installer (Inno Setup 6+).
; Build with: powershell -ExecutionPolicy Bypass -File build-installer.ps1

#define ProductName "AgentReins"
#ifndef AGENTREINS_VERSION
  #define AGENTREINS_VERSION "0.1.0"
#endif
#define ProductVersion AGENTREINS_VERSION
#define Publisher "AgentReins"
#define ExecutableName "AgentReins.exe"

[Setup]
AppId={{B9D7D48B-9B51-4C17-A5A5-4BB3F2D0A2A1}
AppName={#ProductName}
AppVersion={#ProductVersion}
AppPublisher={#Publisher}
DefaultDirName={localappdata}\Programs\AgentReins
DefaultGroupName=AgentReins
DisableProgramGroupPage=yes
OutputDir=..\..\dist\installer
OutputBaseFilename=AgentReins-{#ProductVersion}-Windows-x64-Setup
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=lowest
UninstallDisplayIcon={app}\{#ExecutableName}
ChangesAssociations=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked
Name: "autostart"; Description: "Start AgentReins when I sign in to Windows"; GroupDescription: "Startup options:"; Flags: unchecked

[Files]
Source: "..\..\dist\AgentReins.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\BrowserExtension\manifest.json"; DestDir: "{app}\BrowserExtension"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\..\BrowserExtension\service-worker.js"; DestDir: "{app}\BrowserExtension"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\..\BrowserExtension\web-agent-content.js"; DestDir: "{app}\BrowserExtension"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\..\BrowserExtension\install-native-host.ps1"; DestDir: "{app}\BrowserExtension"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\..\BrowserExtension\uninstall-native-host.ps1"; DestDir: "{app}\BrowserExtension"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\..\dist\AgentReinsNativeHost.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\Assets\agentreins-logo.png"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist

[Icons]
Name: "{autodesktop}\AgentReins"; Filename: "{app}\{#ExecutableName}"; WorkingDir: "{app}"; Tasks: desktopicon
Name: "{group}\AgentReins"; Filename: "{app}\{#ExecutableName}"; WorkingDir: "{app}"

[Registry]
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "AgentReins"; ValueData: "{app}\{#ExecutableName}"; Flags: uninsdeletevalue; Tasks: autostart

[Run]
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\BrowserExtension\install-native-host.ps1"" -HostBinary ""{app}\AgentReinsNativeHost.exe"""; WorkingDir: "{app}"; Flags: runhidden waituntilterminated; StatusMsg: "Registering browser integration..."; Check: NativeHostAvailable
Filename: "{app}\{#ExecutableName}"; Description: "Launch AgentReins"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\BrowserExtension\uninstall-native-host.ps1"""; RunOnceId: "RemoveAgentReinsNativeHost"; Flags: runhidden waituntilterminated; Check: NativeHostCleanupAvailable

[Code]
function NativeHostAvailable(): Boolean;
begin
  Result := FileExists(ExpandConstant('{app}\AgentReinsNativeHost.exe')) and
    FileExists(ExpandConstant('{app}\BrowserExtension\install-native-host.ps1'));
end;

function NativeHostCleanupAvailable(): Boolean;
begin
  Result := FileExists(ExpandConstant('{app}\BrowserExtension\uninstall-native-host.ps1'));
end;
