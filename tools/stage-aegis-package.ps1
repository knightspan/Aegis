# Stages the final AEGIS Windows package from the current build outputs and verifies it.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File tools\stage-aegis-package.ps1 [-Dist E:\aegis-dist] [-Zip]
#
# Inputs (all from this source bundle, never from an older package):
#   working\autopsy\build\cluster\modules\org-sleuthkit-autopsy-aegis.jar   (clean module build)
#   working\sanitizer\aegis_cli.exe + MinGW runtime DLLs                     (C++ file/folder sanitizer)
#   external\aegis variant                                                    (AEGIS Variant engine source + models)
#   working\engine-runtime\python311, working\engine-runtime\libewf           (engine runtime)
#   tools\jdk-17.0.20.1+1                                                     (bundled Java 17 runtime)
#   working\autopsy\launcher\AEGIS.exe, aegis.ico                             (AEGIS launcher)
#   working\autopsy\branding + tools\build-aegis-branding.py                  (splash, title, UI strings)
# Output: <Dist>\AEGIS updated in place (an older <Dist>\autopsy-4.23.1 is renamed to it), started
# with <Dist>\AEGIS\AEGIS.exe; AEGIS_BUILD_MANIFEST.txt with SHA-256 of every staged binary; and
# (with -Zip) <Dist>\AEGIS-final.zip. The script fails if any staged file's hash differs from its
# build output. AEGIS must not be running.
param([string]$Dist = "E:\aegis-dist", [switch]$Zip)
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$App = Join-Path $Dist "AEGIS"
$Legacy = Join-Path $Dist "autopsy-4.23.1"
$Py = "$Root\working\engine-runtime\python311\python.exe"
$running = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path -and ($_.Path -like "$App\*" -or $_.Path -like "$Legacy\*") }
if ($running) { throw "AEGIS is running from the package ($(($running.Name | Sort-Object -Unique) -join ', ')); close it before staging." }
if (-not (Test-Path $App) -and (Test-Path $Legacy)) { Rename-Item -LiteralPath $Legacy -NewName "AEGIS" }
if (-not (Test-Path "$App\bin\aegis64.exe") -and -not (Test-Path "$App\bin\autopsy64.exe")) { throw "No extracted AEGIS package at $App" }

function Hash($p) { (Get-FileHash -Algorithm SHA256 -LiteralPath $p).Hash.ToLower() }
function Mirror($from, $to, [string[]]$excludeDirs = @(), [string[]]$excludeFiles = @()) {
    $args = @($from, $to, "/MIR", "/NFL", "/NDL", "/NJH", "/NJS", "/NP", "/R:2", "/W:1")
    if ($excludeDirs.Count) { $args += "/XD"; $args += $excludeDirs }
    if ($excludeFiles.Count) { $args += "/XF"; $args += $excludeFiles }
    & robocopy @args | Out-Null
    if ($LASTEXITCODE -ge 8) { throw "robocopy failed ($LASTEXITCODE): $from -> $to" }
}

$staged = [ordered]@{}

# 1. AEGIS NetBeans module (clean build output)
$jar = "$Root\working\autopsy\build\cluster\modules\org-sleuthkit-autopsy-aegis.jar"
Copy-Item -LiteralPath $jar "$App\autopsy\modules\org-sleuthkit-autopsy-aegis.jar" -Force
$staged["autopsy\modules\org-sleuthkit-autopsy-aegis.jar"] = $jar

# 2. C++ sanitizer and its runtime DLLs (module bin and cluster bin)
foreach ($dest in @("$App\autopsy\bin", "$App\autopsy\modules\bin")) {
    New-Item -ItemType Directory -Force $dest | Out-Null
    Copy-Item "$Root\working\sanitizer\aegis_cli.exe" $dest -Force
}
$staged["autopsy\bin\aegis_cli.exe"] = "$Root\working\sanitizer\aegis_cli.exe"
$staged["autopsy\modules\bin\aegis_cli.exe"] = "$Root\working\sanitizer\aegis_cli.exe"
foreach ($dll in @("libgcc_s_seh-1.dll", "libstdc++-6.dll", "libwinpthread-1.dll")) {
    $src = "$Root\working\autopsy\AegisSanitization\release\bin\$dll"
    if (Test-Path $src) { Copy-Item $src "$App\autopsy\bin\" -Force; Copy-Item $src "$App\autopsy\modules\bin\" -Force }
}

# 3. AEGIS engine: Variant source (full source ships with the binary runtime), runtime, writer
$Engine = "$App\aegis-engine"
Mirror "$Root\external\aegis variant" "$Engine\engine" @("__pycache__", ".pytest_cache", ".mypy_cache", "node_modules", ".m2-scratch*", ".git") @("*.pyc")
Mirror "$Root\working\engine-runtime\python311" "$Engine\runtime\python311" @("__pycache__") @("*.pyc")
Mirror "$Root\working\engine-runtime\libewf" "$Engine\runtime\libewf"
foreach ($f in @("aegis_engine_cli.py", "core\carve\ewf_ctypes.py", "core\carve\acquire.py", "core\platform\windows.py",
                 "core\ledger\store.py", "core\carve\signature.py", "core\carve\structure.py")) {
    $staged["aegis-engine\engine\$f"] = "$Root\external\aegis variant\$f"
}
$staged["aegis-engine\runtime\python311\python.exe"] = "$Root\working\engine-runtime\python311\python.exe"
$staged["aegis-engine\runtime\libewf\libewf.dll"] = "$Root\working\engine-runtime\libewf\libewf.dll"
foreach ($m in Get-ChildItem "$Root\external\aegis variant\models\*.pb") { $staged["aegis-engine\engine\models\$($m.Name)"] = $m.FullName }
# The legacy loose engine folder beside the package is replaced by aegis-engine inside it.
if (Test-Path "$Dist\aegis-engine") { Remove-Item -Recurse -Force "$Dist\aegis-engine" }

# 4. Bundled Java 17 runtime and launchers. The NetBeans platform launcher reads etc\<its name>.conf,
#    so bin\aegis64.exe (the platform launcher, with the AEGIS icon) runs from etc\aegis.conf and
#    etc\aegis.clusters. AEGIS.exe at the top starts it with the bundled jre and the AEGIS profile.
Mirror "$Root\tools\jdk-17.0.20.1+1" "$App\jre"
$staged["jre\bin\java.exe"] = "$Root\tools\jdk-17.0.20.1+1\bin\java.exe"
foreach ($n in @("conf", "clusters")) {
    if (-not (Test-Path "$App\etc\aegis.$n")) { Copy-Item "$App\etc\autopsy.$n" "$App\etc\aegis.$n" }
}
$conf = "$App\etc\aegis.conf"
$text = Get-Content -Raw $conf
if ($text -notmatch '(?m)^jdkhome=') { $text = $text.TrimEnd() + "`r`njdkhome=`"jre`"`r`n" }
Set-Content -LiteralPath $conf -Value $text -Encoding ascii
if (-not (Test-Path "$App\bin\aegis64.exe")) {
    Copy-Item "$App\bin\autopsy64.exe" "$App\bin\aegis64.exe.tmp"
    & $Py "$Root\tools\set-exe-icon.py" "$App\bin\aegis64.exe.tmp" "$Root\working\autopsy\launcher\aegis.ico"
    if ($LASTEXITCODE -ne 0) { throw "could not set the launcher icon" }
    Move-Item "$App\bin\aegis64.exe.tmp" "$App\bin\aegis64.exe"
}
foreach ($old in @("bin\autopsy64.exe", "etc\autopsy.conf", "etc\autopsy.clusters")) {
    if (Test-Path "$App\$old") { Remove-Item -Force "$App\$old" }
}
Copy-Item "$Root\working\autopsy\launcher\AEGIS.exe" "$App\AEGIS.exe" -Force
Copy-Item "$Root\working\autopsy\launcher\aegis.ico" "$App\icon.ico" -Force
$staged["AEGIS.exe"] = "$Root\working\autopsy\launcher\AEGIS.exe"

# 4b. Branding: splash, window title and every UI string that named Autopsy (NetBeans locale jars;
#     no Autopsy jar is modified).
& $Py "$Root\tools\build-aegis-branding.py" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "branding build failed" }
foreach ($kind in @("core", "modules")) {
    foreach ($j in Get-ChildItem "$Root\working\autopsy\build\aegis-branding\$kind\locale\*.jar") {
        Copy-Item $j.FullName "$App\autopsy\$kind\locale\$($j.Name)" -Force
        $staged["autopsy\$kind\locale\$($j.Name)"] = $j.FullName
    }
}

# 4c. Upstream Autopsy top-level files move under third-party\autopsy; every licence file stays.
$tp = "$App\third-party\autopsy"
New-Item -ItemType Directory -Force $tp | Out-Null
foreach ($f in @("README.txt", "NEWS.txt", "Running_Linux_OSX.md", "unix_setup.sh", "linux_macos_install_scripts")) {
    if ((Test-Path "$App\$f") -and -not ($f -eq "README.txt" -and (Select-String -Quiet -LiteralPath "$App\$f" -Pattern "^AEGIS"))) {
        Move-Item -Force "$App\$f" "$tp\"
    }
}
Copy-Item -Force "$App\LICENSE-2.0.txt" "$tp\LICENSE-2.0.txt"
Copy-Item -Force "$Root\docs\package\README.txt" "$App\README.txt"
Copy-Item -Force "$Root\docs\package\THIRD_PARTY_NOTICES.md" "$App\THIRD_PARTY_NOTICES.md"

# 5. NetBeans caches class bytes per cluster keyed on <cluster>\.lastModified: touch it so an
#    existing user profile never runs classes from a previous jar.
(Get-Item "$App\autopsy\.lastModified").LastWriteTime = Get-Date

# 6. Verify every staged file against its build output and write the manifest
$lines = @("AEGIS build manifest", "Staged: $(Get-Date -Format o)", "Source bundle: $Root", "")
$bad = 0
foreach ($k in $staged.Keys) {
    $d = Join-Path $App $k
    $hs = Hash $staged[$k]; $hd = Hash $d
    $ok = $hs -eq $hd
    if (-not $ok) { $bad++ }
    $lines += ("{0}  {1}  {2}" -f $hd, ($(if ($ok) { "MATCH" } else { "MISMATCH" })), $k)
}
# Other Autopsy module jars must equal the working cluster build (no stale mix).
$cluster = "$Root\working\autopsy\build\cluster\modules"
$checked = 0; $diff = @()
foreach ($j in Get-ChildItem "$App\autopsy\modules\*.jar") {
    $w = Join-Path $cluster $j.Name
    if (Test-Path $w) { $checked++; if ((Hash $w) -ne (Hash $j.FullName)) { $diff += $j.Name } }
}
$lines += ""; $lines += "Autopsy cluster jars compared with working build: $checked; differing: $($diff.Count) $($diff -join ', ')"
$lines | Set-Content -LiteralPath "$App\AEGIS_BUILD_MANIFEST.txt" -Encoding utf8
$lines | ForEach-Object { $_ }
if ($bad -gt 0) { throw "$bad staged file(s) do not match their build output" }

if ($Zip) {
    $zipPath = Join-Path $Dist "AEGIS-final.zip"
    if (Test-Path $zipPath) { Remove-Item -Force $zipPath }
    Push-Location $Dist
    & tar.exe -a -c -f $zipPath "AEGIS"
    Pop-Location
    if ($LASTEXITCODE -ne 0) { throw "zip failed" }
    "ZIP $zipPath $((Get-Item $zipPath).Length) bytes sha256 $(Hash $zipPath)"
}
