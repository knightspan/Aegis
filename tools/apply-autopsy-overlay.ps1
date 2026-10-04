# Turns a clean Autopsy 4.23.1 source checkout into the AEGIS desktop suite.
#
#   git clone --branch autopsy-4.23.1 --depth 1 https://github.com/sleuthkit/autopsy.git ..\autopsy
#   powershell -NoProfile -ExecutionPolicy Bypass -File tools\apply-autopsy-overlay.ps1 -Autopsy ..\autopsy
#
# Copies, from this repository:
#   desktop\autopsy-overlay\*  over the checkout (the files AEGIS adds or modifies; see OVERLAY_FILES.txt)
#   desktop\aegis-module       to <Autopsy>\AegisSanitization (the AEGIS NetBeans module)
#   desktop\branding           to <Autopsy>\branding
#   desktop\launcher           to <Autopsy>\launcher
# Then build as described in docs\building.md.
param([Parameter(Mandatory = $true)][string]$Autopsy)
$ErrorActionPreference = "Stop"
$Repo = Split-Path -Parent $PSScriptRoot
if (-not (Test-Path (Join-Path $Autopsy "Core\src\org\sleuthkit\autopsy\casemodule\Case.java"))) {
    throw "$Autopsy is not an Autopsy source checkout"
}
$version = Select-String -LiteralPath (Join-Path $Autopsy "nbproject\project.properties") -Pattern "^app.version=(.*)$" |
    ForEach-Object { $_.Matches[0].Groups[1].Value } | Select-Object -First 1
if ($version -and $version -ne "4.23.1") { Write-Warning "Expected Autopsy 4.23.1, found $version; the overlay was made against 4.23.1." }

function CopyTree($from, $to) {
    & robocopy $from $to /E /NFL /NDL /NJH /NJS /NP | Out-Null
    if ($LASTEXITCODE -ge 8) { throw "robocopy failed ($LASTEXITCODE): $from -> $to" }
}
CopyTree (Join-Path $Repo "desktop\autopsy-overlay") $Autopsy
Remove-Item -Force (Join-Path $Autopsy "OVERLAY_FILES.txt") -ErrorAction SilentlyContinue
CopyTree (Join-Path $Repo "desktop\aegis-module") (Join-Path $Autopsy "AegisSanitization")
CopyTree (Join-Path $Repo "desktop\branding") (Join-Path $Autopsy "branding")
CopyTree (Join-Path $Repo "desktop\launcher") (Join-Path $Autopsy "launcher")
"AEGIS overlay applied to $Autopsy"
