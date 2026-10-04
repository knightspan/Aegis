$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$cxx = $env:AEGIS_CXX
if (-not $cxx) {
    foreach ($candidate in @(
        "D:\aegis-mingw\bin\g++.exe",
        "C:\mingw64\bin\g++.exe",
        (Join-Path $root "..\..\tools\mingw64\bin\g++.exe")
    )) {
        if (Get-Command $candidate -ErrorAction SilentlyContinue) { $cxx = $candidate; break }
        if (Test-Path $candidate) { $cxx = $candidate; break }
    }
}
if (-not $cxx) { throw "No C++20 compiler found. Set AEGIS_CXX." }
Write-Host "Using $cxx"
$out = Join-Path $root "aegis_cli.exe"
$test = Join-Path $root "engine_tests.exe"
$sources = @(
    (Join-Path $root "src\sanitizer\file_shredder.cpp"),
    (Join-Path $root "src\sanitizer\platform_fs_win32.cpp"),
    (Join-Path $root "src\sanitizer\win_device_ops.cpp"),
    (Join-Path $root "src\main_cli.cpp")
)
& $cxx -std=c++20 -O2 -I (Join-Path $root "include") @sources -o $out -lshell32 -lbcrypt
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$testSources = @(
    (Join-Path $root "src\sanitizer\file_shredder.cpp"),
    (Join-Path $root "src\sanitizer\platform_fs_win32.cpp"),
    (Join-Path $root "src\sanitizer\win_device_ops.cpp"),
    (Join-Path $root "tests\engine_tests.cpp")
)
& $cxx -std=c++20 -O2 -I (Join-Path $root "include") @testSources -o $test -lshell32 -lbcrypt
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& $test
exit $LASTEXITCODE
