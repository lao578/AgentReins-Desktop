; AgentReins Windows installer (Inno Setup 6+).
; Build with: powershell -ExecutionPolicy Bypass -File build-installer.ps1

#define ProductName "AgentReins"
#ifndef AGENTREINS_VERSION
  #define AGENTREINS_VERSION "0.1.1"
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
Name: "chinesesimplified"; MessagesFile: "compiler:Languages\ChineseSimplified.isl"

[CustomMessages]
english.CreateDesktopIcon=Create a desktop shortcut
chinesesimplified.CreateDesktopIcon=创建桌面快捷方式
english.AdditionalShortcuts=Additional shortcuts:
chinesesimplified.AdditionalShortcuts=其他快捷方式：
english.StartAtLogin=Start AgentReins when I sign in to Windows
chinesesimplified.StartAtLogin=登录 Windows 时启动 AgentReins
english.StartupOptions=Startup options:
chinesesimplified.StartupOptions=启动选项：
english.RegisterBrowserIntegration=Registering browser integration...
chinesesimplified.RegisterBrowserIntegration=正在注册浏览器集成…
english.LaunchAgentReins=Launch AgentReins
chinesesimplified.LaunchAgentReins=启动 AgentReins

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalShortcuts}"; Flags: unchecked
Name: "autostart"; Description: "{cm:StartAtLogin}"; GroupDescription: "{cm:StartupOptions}"; Flags: unchecked

[Files]
Source: "..\..\dist\AgentReins.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\BrowserExtension\manifest.json"; DestDir: "{app}\BrowserExtension"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\..\BrowserExtension\service-worker.js"; DestDir: "{app}\BrowserExtension"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\..\BrowserExtension\web-agent-content.js"; DestDir: "{app}\BrowserExtension"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\..\BrowserExtension\install-native-host.ps1"; DestDir: "{app}\BrowserExtension"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\..\BrowserExtension\uninstall-native-host.ps1"; DestDir: "{app}\BrowserExtension"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\..\dist\AgentReinsNativeHost.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\dist\etw-helper\AgentReinsEtwHelper.exe"; DestDir: "{app}\ETW"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\..\Assets\agentreins-logo.png"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist

[Icons]
Name: "{autodesktop}\AgentReins"; Filename: "{app}\{#ExecutableName}"; WorkingDir: "{app}"; Tasks: desktopicon
Name: "{group}\AgentReins"; Filename: "{app}\{#ExecutableName}"; WorkingDir: "{app}"
Name: "{userstartup}\AgentReins"; Filename: "{app}\{#ExecutableName}"; Parameters: "--background --start-watch"; WorkingDir: "{app}"; Tasks: autostart

[Run]
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\BrowserExtension\install-native-host.ps1"" -HostBinary ""{app}\AgentReinsNativeHost.exe"""; WorkingDir: "{app}"; Flags: runhidden waituntilterminated; StatusMsg: "{cm:RegisterBrowserIntegration}"; Check: NativeHostAvailable
Filename: "{app}\{#ExecutableName}"; Description: "{cm:LaunchAgentReins}"; Parameters: "--start-watch"; Flags: nowait postinstall skipifsilent

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
