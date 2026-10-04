# Downloads the EDSR super-resolution models used by AEGIS AI enhancement and verifies them.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File tools\fetch-models.ps1 [-Dest engine\models]
#
# Source: github.com/Saafke/EDSR_Tensorflow (Apache-2.0). A file whose SHA-256 differs from the pin
# below is deleted and the script fails; AEGIS records the model hash in every enhancement entry.
param([string]$Dest = "")
$ErrorActionPreference = "Stop"
if (-not $Dest) { $Dest = Join-Path (Split-Path -Parent $PSScriptRoot) "engine\models" }
$pins = [ordered]@{
    "EDSR_x2.pb" = "585623221baa070279a0d1e7e113a4c3faba0f318ca7fdd9a65d9afc0763d9b4"
    "EDSR_x3.pb" = "3baa3740fdb8ee9c52f1a41d69fa74cb9feef0fa9bfeec24f0ee58b928068e9a"
    "EDSR_x4.pb" = "dd35ce3cae53ecee2d16045e08a932c3e7242d641bb65cb971d123e06904347f"
}
New-Item -ItemType Directory -Force $Dest | Out-Null
foreach ($name in $pins.Keys) {
    $file = Join-Path $Dest $name
    if ((Test-Path $file) -and (Get-FileHash -Algorithm SHA256 $file).Hash.ToLower() -eq $pins[$name]) {
        "$name already present and verified"; continue
    }
    Invoke-WebRequest -UseBasicParsing "https://github.com/Saafke/EDSR_Tensorflow/raw/master/models/$name" -OutFile $file
    $hash = (Get-FileHash -Algorithm SHA256 $file).Hash.ToLower()
    if ($hash -ne $pins[$name]) { Remove-Item -Force $file; throw "$name SHA-256 $hash does not match the pin $($pins[$name])" }
    "$name downloaded and verified"
}
