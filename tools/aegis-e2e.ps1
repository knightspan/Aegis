# Runs the AEGIS end-to-end rehearsal driver inside the staged package and waits for it to exit.
# Usage: powershell -File aegis-e2e.ps1 -Out <dir> -Source <evidence image> [-EngineHome <dir>] [-App <install dir>]
#        [-CaseName "Demo Case"] [-CaseNumber 2026-001] [-Examiner "Demo Examiner"]   (showcase screenshots)
param([Parameter(Mandatory=$true)][string]$Out, [Parameter(Mandatory=$true)][string]$Source,
      [string]$App = "E:\aegis-dist\AEGIS", [string]$EngineHome = "",
      [string]$CaseName = "", [string]$CaseNumber = "", [string]$Examiner = "", [double]$TimeoutScale = 1, [string]$CaseBase = "",
      [string]$UserDir = "")
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $UserDir) { $UserDir = Join-Path (Split-Path -Parent $here) "working\aegis-test-home\ud-e2e" }
$jdk = Join-Path $here "jdk-17.0.20.1+1"
if (Test-Path "$App\jre\bin\java.exe") { $jdk = "$App\jre" }
if (-not $CaseBase) { $CaseBase = Join-Path $Out "cases" }
New-Item -ItemType Directory -Force $Out, $UserDir, "$UserDir-cache", $CaseBase | Out-Null
$a = @('--jdkhome', "`"$jdk`"", '--userdir', "`"$UserDir`"", '--cachedir', "`"$UserDir-cache`"",
  "-J-Daegis.uidriver.out=`"$Out`"", "-J-Daegis.uidriver.source=`"$Source`"", "-J-Daegis.uidriver.casebase=`"$CaseBase`"", '-J-Daegis.uidriver.exit=true')
if ($EngineHome) { $a += "-J-Daegis.engine.home=`"$EngineHome`"" }
if ($CaseName) { $a += "-J-Daegis.uidriver.casename=`"$CaseName`"" }
if ($CaseNumber) { $a += "-J-Daegis.uidriver.casenumber=`"$CaseNumber`"" }
if ($TimeoutScale -gt 1) { $a += "-J-Daegis.uidriver.timeoutscale=$TimeoutScale" }
if ($Examiner) { $a += "-J-Daegis.uidriver.examiner=`"$Examiner`"" }
$p = Start-Process -FilePath "$App\bin\aegis64.exe" -ArgumentList $a -PassThru
$p.WaitForExit([int](5400000 * [Math]::Max(1, $TimeoutScale))) | Out-Null
Get-Content "$Out\driver-log.txt" -ErrorAction SilentlyContinue
