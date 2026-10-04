; Inno Setup script for SanctumSetup.exe.
;
;   iscc /DAppVersion=0.0.0 /DSourceDir=build\windows\dist\Sanctum packaging\windows\sanctum.iss
;
; scripts\build-windows.ps1 runs this after PyInstaller. Decisions worth
; knowing before changing anything here:
;
; * Per-user install by default, no administrator needed. Nothing the app
;   does on Windows requires elevation, so the installer does not ask for it
;   either. An administrator may still choose an all-users install in the
;   dialog (PrivilegesRequiredOverridesAllowed).
; * AppId is fixed. It is what makes a newer SanctumSetup.exe upgrade an
;   existing install in place instead of installing a second copy. Never
;   change it.
; * Uninstall removes the program files only. The ledger, reports and
;   recovered objects in %LOCALAPPDATA%\Sanctum are an audit trail, and an
;   uninstaller that silently deleted one would destroy evidence; the final
;   page says where they are.
; * No bundled Python or Node is required on the target: the app is the
;   PyInstaller onedir, a self-contained runtime.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef SourceDir
  #define SourceDir "..\..\build\windows\dist\Sanctum"
#endif
#ifndef IconFile
  #define IconFile "..\..\build\icons\sanctum.ico"
#endif

[Setup]
AppId={{6A4C2F0E-5B7D-4E3A-9C1B-7F2D8E5A1C43}
AppName=Sanctum
AppVersion={#AppVersion}
AppPublisher=Sanctum Forensics
DefaultDirName={autopf}\Sanctum
DefaultGroupName=Sanctum
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\..\dist
OutputBaseFilename=SanctumSetup
SetupIconFile={#IconFile}
UninstallDisplayIcon={app}\Sanctum.exe
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes
MinVersion=10.0.17763

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[InstallDelete]
; An upgrade replaces the runtime wholesale, so a module removed in the new
; version cannot linger and be imported by it.
Type: filesandordirs; Name: "{app}\_internal"

[Icons]
Name: "{group}\Sanctum"; Filename: "{app}\Sanctum.exe"
Name: "{group}\Uninstall Sanctum"; Filename: "{uninstallexe}"
Name: "{autodesktop}\Sanctum"; Filename: "{app}\Sanctum.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\Sanctum.exe"; Description: "{cm:LaunchProgram,Sanctum}"; Flags: nowait postinstall skipifsilent

[Messages]
FinishedLabel=Sanctum is installed.%n%nYour ledger and reports are kept in %LOCALAPPDATA%\Sanctum and are not removed by uninstalling.
