; Inno Setup 6 script — builds TVIntelligenceScanner-Setup-<version>.exe
; Build (from the repository root, after PyInstaller):
;   iscc /DMyAppVersion=1.0.1 installer\tvis_setup.iss
; User data (%LOCALAPPDATA%\TVIntelligenceScanner: database, firmware library, reports) is NOT removed on
; uninstall, so firmware originals and evidence are never deleted by the installer.

#ifndef MyAppVersion
  #define MyAppVersion "1.0.1"
#endif
#define MyAppName "TV Intelligence Scanner"
#define MyAppExe "TVIntelligenceScanner.exe"

[Setup]
AppId={{6C1F0B6E-5D7A-4B3E-9C51-2E8A7D4F9B10}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher=TV Intelligence Scanner project
DefaultDirName={autopf}\TV Intelligence Scanner
DefaultGroupName=TV Intelligence Scanner
DisableProgramGroupPage=yes
OutputDir=..\dist\installer
OutputBaseFilename=TVIntelligenceScanner-Setup-{#MyAppVersion}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
MinVersion=10.0
UninstallDisplayName={#MyAppName} {#MyAppVersion}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "..\dist\TVIntelligenceScanner\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\docs\USER_GUIDE.md"; DestDir: "{app}\docs"; Flags: ignoreversion
Source: "..\docs\INSTALL_WINDOWS.md"; DestDir: "{app}\docs"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExe}"
Name: "{group}\User guide"; Filename: "{app}\docs\USER_GUIDE.md"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExe}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExe}"; Description: "{cm:LaunchProgram,{#MyAppName}}"; Flags: nowait postinstall skipifsilent
