# AEGIS disposable-USB hardware test (acquire -> verify -> recover -> sanitize -> verify -> report -> ledger).
#
# DESTRUCTIVE in phase 2: the selected USB stick is overwritten. Use ONLY a disposable USB stick or SD card.
# Run from an elevated PowerShell (Run as administrator):
#   powershell -NoProfile -ExecutionPolicy Bypass -File tools\usb-demo-test.ps1
#
# Internal drives (SSD, NVMe, SATA, HDD) are never offered and are refused by the engine.
# The script stops before phase 2 unless the operator types the device serial and SANITIZE.
param([string]$App = "E:\aegis-dist\AEGIS", [string]$Work = "D:\AEGIS-USB-TEST",
      [ValidateSet("raw","e01")][string]$Format = "e01", [ValidateSet("SINGLE_PASS_OVERWRITE","DOD_5220_22_M_3PASS")][string]$Profile = "SINGLE_PASS_OVERWRITE")
$ErrorActionPreference = "Stop"
$Py = "$App\aegis-engine\runtime\python311\python.exe"
$Cli = "$App\aegis-engine\engine\aegis_engine_cli.py"
$env:AEGIS_LIBEWF_DIR = "$App\aegis-engine\runtime\libewf"
$State = Join-Path $Work "state"
New-Item -ItemType Directory -Force $Work, $State | Out-Null
$Log = Join-Path $Work ("usb-test-" + (Get-Date -Format "yyyyMMdd-HHmmss") + ".log")
function Log($m) { $line = "$(Get-Date -Format o)  $m"; $line | Tee-Object -FilePath $Log -Append }
function B64($s) { "b64:" + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($s)) }
function Engine([string[]]$a) {
    $out = & $Py -X utf8 -u $Cli @a --state $State --case-id "USB-HW-TEST" 2>> (Join-Path $Work "engine-stderr.log")
    $result = $null
    foreach ($l in $out) {
        if ($l -match '^\{') {
            $e = $l | ConvertFrom-Json
            if ($e.AEGIS_EVENT -eq "PROGRESS") { Write-Host -NoNewline ("`r  {0,-10} {1,6:N1}%  {2}" -f $e.phase, $e.pct, $e.message) }
            if ($e.AEGIS_EVENT -eq "RESULT") { $result = $e }
        }
    }
    Write-Host ""
    return $result
}

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Log "AEGIS USB hardware test. Elevated: $admin. Log: $Log"
if (-not $admin) { Log "STOP: run this script from an elevated PowerShell (Run as administrator)."; exit 2 }

$d = Engine @("devices")
$usb = @($d.result.devices | Where-Object { $_.sanitization.eligible -eq $true })
foreach ($x in $d.result.devices) { Log ("device {0} {1} serial={2} bus={3} system={4} sanitize={5}" -f $x.id, $x.model, $x.serial, $x.bus_type, $x.system_device, $x.sanitization.status) }
if ($usb.Count -eq 0) { Log "STOP: no removable USB/SD device is eligible. Attach a disposable USB stick and rerun."; exit 3 }
for ($i = 0; $i -lt $usb.Count; $i++) { Write-Host ("[{0}] {1}  {2}  serial {3}  {4:N1} GB  mounted: {5}" -f $i, $usb[$i].id, $usb[$i].model, $usb[$i].serial, ($usb[$i].capacity_bytes / 1e9), ($usb[$i].mount_points -join ",")) }
$pick = $usb[[int](Read-Host "Select the DISPOSABLE USB device number")]
$serial = "$($pick.serial)".Trim()
Log "Selected $($pick.id) $($pick.model) serial $serial size $($pick.capacity_bytes)"

# Phase 1: read-only acquisition, verification, recovery, signed reports
$ext = if ($Format -eq "e01") { "E01" } else { "raw" }
$dest = Join-Path $Work ("usb-" + (Get-Date -Format "yyyyMMdd-HHmmss") + "." + $ext)
$a = Engine @("acquire", "--source", $pick.path, "--dest", $dest, "--format", $Format, "--expected-serial", (B64 $serial),
    "--expected-size", "$($pick.capacity_bytes)", "--sector-size", "$([Math]::Max(512, [int]$pick.logical_sector_size))", "--device-model", (B64 $pick.model))
Log "ACQUIRE: $($a.status) $($a.error.type) $($a.error.message) job=$($a.operation_id) sha256=$($a.result.record.sha256) blake3=$($a.result.record.blake3) verified=$($a.result.verification.passed) bad_sectors=$($a.result.bad_sector_count)"
if ($a.status -notlike "SUCCESS*") { Log "STOP: acquisition did not succeed."; exit 4 }
$acqJob = $a.operation_id
$r = Engine @("recover", "--image", $dest, "--source-job", $acqJob)
Log "RECOVER: $($r.status) candidates=$($r.result.candidates) written=$($r.result.written) buckets=$($r.result.by_bucket | ConvertTo-Json -Compress)"
foreach ($job in @($acqJob, $r.operation_id)) {
    $rep = Engine @("report", "--job-id", $job); Log "REPORT $job : $($rep.status) $($rep.result.json)"
    if ($rep.result.json) { $v = Engine @("verify-report", "--report", $rep.result.json); Log "VERIFY-REPORT: $($v.status) verdict=$($v.result.verdict)" }
}

# Phase 2: destructive sanitization (typed serial + SANITIZE)
Write-Host ""; Write-Host "PHASE 2 OVERWRITES EVERY BYTE OF $($pick.model) ($serial)." -ForegroundColor Red
$typed = Read-Host "Type the device serial exactly to continue (anything else stops)"
if ($typed.Trim() -ne $serial) { Log "STOP: typed serial does not match; nothing was written."; exit 0 }
if ((Read-Host "Type SANITIZE to confirm") -ne "SANITIZE") { Log "STOP: not confirmed; nothing was written."; exit 0 }
if ($pick.mounted) {
    $p = Engine @("prepare-device", "--device", $pick.id, "--typed-serial", (B64 $typed))
    Log "PREPARE (offline): $($p.status) $($p.error.type) $($p.error.message)"
    if ($p.status -notlike "SUCCESS*") { Log "STOP: could not take the disk offline."; exit 5 }
}
$s = Engine @("sanitize-device", "--device", $pick.id, "--typed-serial", (B64 $typed), "--expected-serial", (B64 $serial),
    "--expected-size", "$($pick.capacity_bytes)", "--level", "CLEAR", "--overwrite-method", $Profile, "--backup-job", $acqJob, "--confirm-destructive")
Log "SANITIZE: $($s.status) $($s.error.type) $($s.error.message) job=$($s.operation_id) achieved=$($s.result.achieved_level) verification=$($s.result.verification | ConvertTo-Json -Compress -Depth 3)"
if ($s.status -like "SUCCESS*") {
    if ($pick.mount_points.Count -gt 0) {
        $t = Engine (@("traces", "--directory", "--source-job", $s.operation_id) + ($pick.mount_points | ForEach-Object { @("--erased", $_) }))
        Log "TRACE SWEEP: $($t.status) traces=$(@($t.result.sweep.traces).Count)"
    }
    $rep = Engine @("report", "--job-id", $s.operation_id); Log "SANITIZATION REPORT: $($rep.status) $($rep.result.json)"
    if ($rep.result.json) { $v = Engine @("verify-report", "--report", $rep.result.json); Log "VERIFY-REPORT: $($v.status) verdict=$($v.result.verdict)" }
}
$l = Engine @("ledger-verify"); Log "LEDGER: $($l.status) $($l.result.status) entries=$($l.result.entry_count) $($l.result.explanation)"
Log "Done. Replug the USB stick to bring it back online (the offline state is not persistent)."
