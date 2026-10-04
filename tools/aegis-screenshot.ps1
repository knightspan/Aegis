# Captures the AEGIS main window (or the full primary screen) to a PNG.
# Usage: powershell -File aegis-screenshot.ps1 -Out C:\path\shot.png [-Title AEGIS]
param([Parameter(Mandatory=$true)][string]$Out, [string]$Title = "AEGIS")
Add-Type -AssemblyName System.Windows.Forms, System.Drawing
Add-Type @"
using System; using System.Runtime.InteropServices;
public static class AegisWin {
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int cmd);
  [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr h, IntPtr hdc, uint flags);
  [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
  public struct RECT { public int Left, Top, Right, Bottom; }
}
"@
[AegisWin]::SetProcessDPIAware() | Out-Null
$p = Get-Process | Where-Object { $_.MainWindowHandle -ne 0 -and $_.MainWindowTitle -like "*$Title*" } | Select-Object -First 1
if ($p) {
  $h = $p.MainWindowHandle
  [AegisWin]::ShowWindow($h, 3) | Out-Null
  Start-Sleep -Milliseconds 600
  $r = New-Object AegisWin+RECT
  [AegisWin]::GetWindowRect($h, [ref]$r) | Out-Null
  $w = $r.Right - $r.Left; $hgt = $r.Bottom - $r.Top
  $bmp = New-Object System.Drawing.Bitmap $w, $hgt
  $g = [System.Drawing.Graphics]::FromImage($bmp)
  $hdc = $g.GetHdc(); [AegisWin]::PrintWindow($h, $hdc, 2) | Out-Null; $g.ReleaseHdc($hdc)
  "window: $($p.MainWindowTitle) ${w}x${hgt}"
} else {
  $b = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
  $bmp = New-Object System.Drawing.Bitmap $b.Width, $b.Height
  $g = [System.Drawing.Graphics]::FromImage($bmp)
  $g.CopyFromScreen($b.Location, [System.Drawing.Point]::Empty, $b.Size)
  "screen: no window titled *$Title*"
}
$bmp.Save($Out, [System.Drawing.Imaging.ImageFormat]::Png)
$g.Dispose(); $bmp.Dispose()
