$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$cli = Join-Path $root "aegis_cli.exe"
if (-not (Test-Path $cli)) { throw "aegis_cli.exe is missing. Build it first." }

$work = Join-Path $env:TEMP ("aegis-cli-tests-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $work | Out-Null
$failures = 0

function Assert-Exit($code, $expected, $label) {
    if ($code -ne $expected) {
        Write-Host "FAIL: $label exit $code expected $expected"
        $script:failures++
    } else {
        Write-Host "PASS: $label"
    }
}

function Invoke-Cli([string[]]$cliArgs) {
    $ErrorActionPreference = "Continue"
    $stdoutFile = Join-Path $work ("out-" + [guid]::NewGuid().ToString("N") + ".txt")
    $stderrFile = Join-Path $work ("err-" + [guid]::NewGuid().ToString("N") + ".txt")
    & $cli @cliArgs 1> $stdoutFile 2> $stderrFile
    $code = $LASTEXITCODE
    $stdout = ""
    $stderr = ""
    if (Test-Path $stdoutFile) { $stdout = [System.IO.File]::ReadAllText($stdoutFile) }
    if (Test-Path $stderrFile) { $stderr = [System.IO.File]::ReadAllText($stderrFile) }
    return @{ Code = $code; Out = $stdout; Err = $stderr }
}

$missing = Invoke-Cli @("shred", (Join-Path $work "missing.bin"), "--method", "zero")
Assert-Exit $missing.Code 1 "missing path"

$wipe = Invoke-Cli @("wipe-disk", "\\.\PhysicalDrive99", "--force")
# Missing/invalid physical drive must fail closed without writing.
if ($wipe.Code -eq 0) {
    Write-Host "FAIL: wipe-disk on missing drive returned success"
    $failures++
} elseif ($wipe.Out -match '"status":"(FAILED|UNSUPPORTED)"') {
    Write-Host "PASS: wipe-disk refuses missing PhysicalDrive99"
} else {
    Write-Host "FAIL: wipe-disk unexpected output"
    Write-Host $wipe.Out
    $failures++
}

$wipeNoForce = Invoke-Cli @("wipe-disk", "\\.\PhysicalDrive99")
Assert-Exit $wipeNoForce.Code 1 "wipe-disk requires --force"


$volume = Invoke-Cli @("shred", "C:\", "--recursive", "--method", "zero")
Assert-Exit $volume.Code 4 "volume root refused"

$file = Join-Path $work "File With Spaces.txt"
[System.IO.File]::WriteAllText($file, "secret payload")
$audit = Join-Path $work "audit.json"
$report = Join-Path $work "report.txt"
$zero = Invoke-Cli @("shred", $file, "--method", "zero", "--audit", $audit, "--report", $report)
if ($zero.Code -ne 0) {
    Write-Host "FAIL: zero file exit $($zero.Code)"
    Write-Host $zero.Err
    $failures++
} else {
    Write-Host "PASS: zero file exit 0"
}
if (-not (Test-Path $audit)) {
    Write-Host "FAIL: audit missing"
    $failures++
} else {
    try {
        Get-Content -Raw -Encoding UTF8 $audit | ConvertFrom-Json | Out-Null
        Write-Host "PASS: audit JSON parses"
    } catch {
        Write-Host "FAIL: audit is not valid JSON"
        $failures++
    }
}
if (-not (Test-Path $report)) { Write-Host "FAIL: report missing"; $failures++ } else { Write-Host "PASS: report written" }

$uniDir = Join-Path $work "unicode-dir"
New-Item -ItemType Directory -Path $uniDir | Out-Null
$uni = Join-Path $uniDir ([string]([char]0x0444) + [char]0x0430 + [char]0x0439 + [char]0x043B + ".txt")
[System.IO.File]::WriteAllText($uni, "unicode")
$uniRun = Invoke-Cli @("shred", $uni, "--method", "zero", "--audit", (Join-Path $work "unicode-audit.json"), "--report", (Join-Path $work "unicode-report.txt"))
Assert-Exit $uniRun.Code 0 "unicode path"

$dir = Join-Path $work "folder"
New-Item -ItemType Directory -Path (Join-Path $dir "nested") | Out-Null
[System.IO.File]::WriteAllText((Join-Path $dir "a.txt"), "a")
[System.IO.File]::WriteAllText((Join-Path $dir "nested\b.txt"), "b")
$dirRun = Invoke-Cli @("shred", $dir, "--recursive", "--method", "zero", "--audit", (Join-Path $work "dir-audit.json"), "--report", (Join-Path $work "dir-report.txt"))
Assert-Exit $dirRun.Code 0 "directory"

$cancelFile = Join-Path $work "big.bin"
$stream = [System.IO.File]::Create($cancelFile)
$stream.SetLength(8MB)
$stream.Close()
$flag = Join-Path $work "cancel.flag"
Set-Content -Path $flag -Value "cancel"
$cancel = Invoke-Cli @("shred", $cancelFile, "--method", "zero", "--cancel-file", $flag, "--audit", (Join-Path $work "cancel-audit.json"), "--report", (Join-Path $work "cancel-report.txt"))
Assert-Exit $cancel.Code 3 "pre-cancelled file"

if ($failures -ne 0) {
    Write-Host "$failures CLI test(s) failed"
    exit 1
}
Write-Host "all CLI tests passed"
exit 0
