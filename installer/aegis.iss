; AEGIS Windows installer (Inno Setup 6).
;
;   "%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe" installer\aegis.iss
;   ISCC /DSourceDir=E:\aegis-dist\AEGIS /DOutputDir=D:\AEGIS-installer installer\aegis.iss
;
; Packages the staged, hash-verified folder produced by tools\stage-aegis-package.ps1. Installs
; machine-wide to Program Files by default (administrator), or for the current user only.
; User data (%APPDATA%\AEGIS: profile and the report-signing key) and case folders are never
; removed by the uninstaller.

#ifndef SourceDir
  #define SourceDir "E:\aegis-dist\AEGIS"
#endif
#ifndef OutputDir
  #define OutputDir "D:\AEGIS-installer"
#endif
#define AppName "AEGIS"
#define AppVersion "1.0.0"
#define AppPublisher "knightspan"
#define AppURL "https://github.com/knightspan/Aegis"

[Setup]
AppId={{D5CB75F1-4BF1-44CE-AEFE-F49F5FA0F67E}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}/issues
AppUpdatesURL={#AppURL}/releases
AppCopyright=Copyright (c) 2026 {#AppPublisher}. All rights reserved.
AppComments=Digital Forensics & Secure Data Sanitization
VersionInfoVersion={#AppVersion}.0
VersionInfoDescription={#AppName} {#AppVersion} Setup
VersionInfoProductName={#AppName}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
LicenseFile=..\external\aegis variant\LICENSE
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=dialog commandline
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir={#OutputDir}
OutputBaseFilename=AEGIS-{#AppVersion}-Setup
SetupIconFile=aegis.ico
UninstallDisplayIcon={app}\AEGIS.exe
UninstallDisplayName={#AppName} {#AppVersion}
WizardStyle=modern
WizardImageFile=wizard.bmp,wizard-125.bmp,wizard-150.bmp,wizard-200.bmp
WizardSmallImageFile=wizard-small.bmp,wizard-small-125.bmp,wizard-small-150.bmp,wizard-small-200.bmp
Compression=lzma2/max
SolidCompression=yes
LZMAUseSeparateProcess=yes
LZMANumBlockThreads=4
DiskSpanning=no
CloseApplications=yes
RestartApplications=no
ChangesAssociations=no
SetupLogging=yes
; Installed size is about 2.6 GB.
ExtraDiskSpaceRequired=104857600

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Messages]
WelcomeLabel2=This will install [name/ver] on your computer.%n%nAEGIS acquires, recovers, analyses and securely sanitizes digital evidence, with every step hashed, ledgered and signed.%n%nIt is recommended that you close all other applications before continuing.
FinishedLabel=Setup has finished installing [name] on your computer.%n%nUse "AEGIS (Administrator)" for physical USB/SD acquisition and device sanitization; everything else runs as a standard user.

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Excludes: "*.pyc,__pycache__,AEGIS_BUILD_MANIFEST.txt"; Flags: recursesubdirs createallsubdirs ignoreversion
Source: "{#SourceDir}\AEGIS_BUILD_MANIFEST.txt"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\AEGIS"; Filename: "{app}\AEGIS.exe"; WorkingDir: "{app}"; Comment: "Digital Forensics & Secure Data Sanitization"
Name: "{group}\AEGIS (Administrator)"; Filename: "{app}\AEGIS.exe"; WorkingDir: "{app}"; Comment: "AEGIS with raw device access (USB/SD acquisition and sanitization)"
Name: "{group}\Third-party notices"; Filename: "{app}\THIRD_PARTY_NOTICES.md"
Name: "{group}\Read me"; Filename: "{app}\README.txt"
Name: "{group}\Uninstall AEGIS"; Filename: "{uninstallexe}"
Name: "{autodesktop}\AEGIS"; Filename: "{app}\AEGIS.exe"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
; Program Files is read-only for standard users, so the engine's bytecode is compiled at install
; time instead of on first use.
Filename: "{app}\aegis-engine\runtime\python311\python.exe"; Parameters: "-X utf8 -m compileall -q -j 0 ""{app}\aegis-engine\engine"""; StatusMsg: "Optimizing the AEGIS engine..."; Flags: runhidden waituntilterminated
Filename: "{app}\AEGIS.exe"; Description: "{cm:LaunchProgram,AEGIS}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
; Bytecode compiled at install time; user data in %APPDATA%\AEGIS and case folders are kept.
Type: filesandordirs; Name: "{app}\aegis-engine"
Type: dirifempty; Name: "{app}"

[Code]
{ Marks a shortcut "Run as administrator" (SLDF_RUNAS_USER, bit 0x20 of byte 0x15 of the .lnk). }
procedure SetRunAsAdministrator(const Shortcut: string);
var
  Buffer: AnsiString;
  Stream: TStream;
begin
  if not FileExists(Shortcut) then
    Exit;
  Stream := TFileStream.Create(Shortcut, fmOpenReadWrite);
  try
    Stream.Seek($15, soFromBeginning);
    SetLength(Buffer, 1);
    Stream.ReadBuffer(Buffer, 1);
    Buffer[1] := Chr(Ord(Buffer[1]) or $20);
    Stream.Seek(-1, soFromCurrent);
    Stream.WriteBuffer(Buffer, 1);
  finally
    Stream.Free;
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
    SetRunAsAdministrator(ExpandConstant('{group}\AEGIS (Administrator).lnk'));
end;
