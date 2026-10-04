# Launches the staged AEGIS package with the UI probe and waits for it to exit.
# Usage: powershell -File aegis-probe.ps1 -Out <dir> [-Pages HOME,DISK_IMAGER] [-Delay 9000] [-Extra "-J-Dx=y"]
param([Parameter(Mandatory=$true)][string]$Out, [string]$Pages = "HOME,DISK_IMAGER,RECOVERY,SANITIZATION,REPORTS,ORACLE",
      [int]$Delay = 9000, [string]$Extra = "", [string]$App = "E:\aegis-dist\AEGIS",
      [string]$EngineHome = "", [switch]$NoJdk, [string]$UserDir = "")
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $UserDir) { $UserDir = Join-Path (Split-Path -Parent $here) "working\aegis-test-home\ud-probe" }
$jdk = Join-Path $here "jdk-17.0.20.1+1"
if (Test-Path "$App\jre\bin\java.exe") { $jdk = "$App\jre" }
New-Item -ItemType Directory -Force $Out, $UserDir, "$UserDir-cache" | Out-Null
$args = @('--userdir', "`"$UserDir`"", '--cachedir', "`"$UserDir-cache`"",
  "-J-Daegis.uiprobe.dir=`"$Out`"", "-J-Daegis.uiprobe.pages=$Pages", "-J-Daegis.uiprobe.delay=$Delay", '-J-Daegis.uiprobe.exit=true')
if (-not $NoJdk) { $args = @('--jdkhome', "`"$jdk`"") + $args }
if ($EngineHome) { $args += "-J-Daegis.engine.home=`"$EngineHome`"" }
if ($Extra) { $args += $Extra.Split(' ') }
$p = Start-Process -FilePath "$App\bin\aegis64.exe" -ArgumentList $args -PassThru
$p.WaitForExit(900000) | Out-Null
Get-ChildItem $Out -Filter *.png | Select-Object Name, Length | Format-Table -AutoSize | Out-String
