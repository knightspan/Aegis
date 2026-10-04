<#
.SYNOPSIS
  Build SanctumSetup.exe (Windows 10 1809+ / Windows 11, x64) into dist\.

.DESCRIPTION
  Prerequisites on the build machine (not on the target):
    * Python 3.11 x64 (the `py -3.11` launcher)
    * Node.js 20+ with npm
    * Inno Setup 6 (iscc.exe on PATH, or at the default install path)
  The target machine needs none of these: the installer carries the
  PyInstaller onedir, a self-contained runtime.

  Unsigned: Authenticode signing needs a code-signing certificate, which this
  script does not have. Pass -SignCommand to sign both the app and the
  installer; without it SmartScreen will warn on first run.
#>
param(
  [string]$Python = "py",
  [string]$PythonArgs = "-3.11",
  [string]$SignCommand = ""
)
$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $Root
$Build = Join-Path $Root "build\windows"
$Venv = Join-Path $Build "venv"
New-Item -ItemType Directory -Force -Path $Build, (Join-Path $Root "dist") | Out-Null

Write-Host "==> UI bundle"
Push-Location ui
npm ci --no-audit --no-fund; if ($LASTEXITCODE) { throw "npm ci failed" }
npm run build; if ($LASTEXITCODE) { throw "UI build failed" }
Pop-Location

Write-Host "==> Build environment"
# `py -3.11` needs its selector argument; a direct interpreter path must not
# be handed an empty string, which it would read as a script name.
$pyArgs = @()
if ($Python -eq "py" -and $PythonArgs) { $pyArgs = @($PythonArgs) }
& $Python @pyArgs -m venv $Venv
$Py = Join-Path $Venv "Scripts\python.exe"
& $Py -m pip install --quiet --upgrade pip
& $Py -m pip install --quiet --constraint constraints.txt ".[build,desktop]"
if ($LASTEXITCODE) { throw "pip install failed" }
$Version = & $Py -c "import importlib.metadata as m; print(m.version('sanctum-forensics'))"

Write-Host "==> Build metadata"
& $Py packaging\build_info.py

Write-Host "==> Icons"
& $Py packaging\make_icons.py build\icons

Write-Host "==> Freeze (PyInstaller onedir)"
& $Py -m PyInstaller --noconfirm --clean --distpath (Join-Path $Build "dist") --workpath (Join-Path $Build "work") packaging\sanctum.spec
if ($LASTEXITCODE) { throw "PyInstaller failed" }

if ($SignCommand) {
  Write-Host "==> Sign app"
  & cmd /c "$SignCommand `"$Build\dist\Sanctum\Sanctum.exe`""
}

Write-Host "==> Installer"
$Iscc = (Get-Command iscc.exe -ErrorAction SilentlyContinue).Source
if (-not $Iscc) { $Iscc = "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe" }
& $Iscc "/DAppVersion=$Version" "/DSourceDir=$Build\dist\Sanctum" "/DIconFile=$Root\build\icons\sanctum.ico" packaging\windows\sanctum.iss
if ($LASTEXITCODE) { throw "Inno Setup failed" }

if ($SignCommand) {
  Write-Host "==> Sign installer"
  & cmd /c "$SignCommand `"$Root\dist\SanctumSetup.exe`""
}

Get-FileHash dist\SanctumSetup.exe -Algorithm SHA256 | Format-List
