package org.sleuthkit.autopsy.aegis.device;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.sleuthkit.autopsy.aegis.sanitization.DeviceEligibilityService;

/**
 * Enumerates storage devices and exposes capability/eligibility facts for AEGIS.
 * Destructive planning must still pass DeviceEligibilityService.mayExecute.
 */
public final class DeviceCapabilityEngine {

    private static final Logger LOG = Logger.getLogger(DeviceCapabilityEngine.class.getName());
    private volatile String lastEnumerationError = "";

    public static final class DeviceInfo {
        public int diskNumber = -1;
        public String model = "—";
        public String serial = "—";
        public String busType = "—";
        public String mediaType = "—";
        public String fileSystem = "—";
        public String driveLetters = "";
        public String physicalPath = "";
        public long sizeBytes = -1;
        public int sectorSize = -1;
        public boolean removable;
        public boolean usb;
        public boolean systemDisk;
        public boolean bootDisk;
        public boolean mounted;
        public String status = "UNKNOWN";

        public boolean eligibleForDestructiveWipe() {
            return removable && usb && !systemDisk && !bootDisk && diskNumber >= 0;
        }

        public boolean eligibleForReadOnlyAcquire() {
            return diskNumber >= 0 && !systemDisk;
        }

        public Path physicalDevicePath() {
            if (physicalPath == null || physicalPath.isBlank()) {
                return null;
            }
            return Path.of(physicalPath);
        }
    }

    private final DeviceEligibilityService eligibility = new DeviceEligibilityService();

    public DeviceEligibilityService eligibility() {
        return eligibility;
    }

    public List<DeviceInfo> listDevices() {
        lastEnumerationError = "";
        String script = ""
                + "$ErrorActionPreference='Stop'; "
                + "try { "
                + "  Get-Disk | ForEach-Object { "
                + "    $d = $_; "
                + "    $parts = Get-Partition -DiskNumber $d.Number -ErrorAction SilentlyContinue; "
                + "    $letters = @(); $fs=''; $mounted=$false; "
                + "    foreach ($p in $parts) { "
                + "      if ($p.DriveLetter) { $letters += ($p.DriveLetter.ToString() + ':'); $mounted=$true; "
                + "        $vol = Get-Volume -DriveLetter $p.DriveLetter -ErrorAction SilentlyContinue; "
                + "        if ($vol -and $vol.FileSystem) { $fs = [string]$vol.FileSystem } "
                + "      } "
                + "    }; "
                + "    $letterStr = ($letters -join ','); "
                + "    $serial = [string]$d.SerialNumber; "
                + "    $bus = [string]$d.BusType; "
                + "    $rem = if ($bus -match 'USB|SD|Multi-Media') { '1' } else { '0' }; "
                + "    Write-Output ('NUM=' + $d.Number + ';MODEL=' + $d.FriendlyName + ';SERIAL=' + $serial + ';BUS=' + $bus + ';MEDIA=' + $d.MediaType + ';SIZE=' + $d.Size + ';SS=' + $d.LogicalSectorSize + ';SYS=' + $d.IsSystem + ';BOOT=' + $d.IsBoot + ';REM=' + $rem + ';FS=' + $fs + ';LETTERS=' + $letterStr + ';MOUNTED=' + $mounted) "
                + "  } "
                + "} catch { Write-Output ('ERROR=' + $_.Exception.Message) }";
        List<String> lines = runPowerShellLines(script);
        List<DeviceInfo> out = new ArrayList<>();
        for (String line : lines) {
            if (line == null || line.isBlank()) {
                continue;
            }
            if (line.startsWith("ERROR=")) {
                lastEnumerationError = line.substring("ERROR=".length());
                continue;
            }
            DeviceInfo info = parse(line);
            if (info.diskNumber >= 0) {
                out.add(info);
            }
        }
        return out;
    }

    public String lastEnumerationError() {
        return lastEnumerationError;
    }

    public List<DeviceInfo> listRemovableEligible() {
        List<DeviceInfo> all = listDevices();
        List<DeviceInfo> out = new ArrayList<>();
        for (DeviceInfo d : all) {
            if (d.eligibleForDestructiveWipe()) {
                d.status = "READY";
                out.add(d);
            }
        }
        return out;
    }

    private static DeviceInfo parse(String line) {
        DeviceInfo d = new DeviceInfo();
        d.diskNumber = (int) longVal(line, "NUM", -1);
        d.model = str(line, "MODEL");
        d.serial = str(line, "SERIAL");
        d.busType = str(line, "BUS");
        d.mediaType = str(line, "MEDIA");
        d.sizeBytes = longVal(line, "SIZE", -1);
        d.sectorSize = (int) longVal(line, "SS", -1);
        d.systemDisk = bool(line, "SYS");
        d.bootDisk = bool(line, "BOOT");
        d.removable = "1".equals(str(line, "REM"));
        d.usb = d.busType != null && (d.busType.equalsIgnoreCase("USB")
                || d.busType.equalsIgnoreCase("SD")
                || d.busType.toLowerCase(Locale.ROOT).contains("multi-media"));
        d.fileSystem = str(line, "FS");
        if (d.fileSystem.isBlank()) {
            d.fileSystem = "—";
        }
        d.driveLetters = str(line, "LETTERS");
        d.mounted = bool(line, "MOUNTED");
        d.physicalPath = "\\\\.\\PhysicalDrive" + d.diskNumber;
        if (d.systemDisk || d.bootDisk) {
            d.status = "PROTECTED";
        } else if (d.eligibleForDestructiveWipe()) {
            d.status = "READY";
        } else if (d.eligibleForReadOnlyAcquire()) {
            d.status = "ACQUIRE_OK";
        } else {
            d.status = "UNSUPPORTED";
        }
        return d;
    }

    private static List<String> runPowerShellLines(String script) {
        ProcessBuilder builder = new ProcessBuilder(
                "powershell.exe", "-NoProfile", "-NonInteractive",
                "-ExecutionPolicy", "Bypass", "-Command", script);
        builder.redirectErrorStream(true);
        try {
            Process process = builder.start();
            List<String> lines = new ArrayList<>();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (!line.isBlank()) {
                        lines.add(line.trim());
                    }
                }
            }
            if (!process.waitFor(20, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                LOG.warning("Device enumeration timed out.");
                return Collections.emptyList();
            }
            if (process.exitValue() != 0) {
                LOG.warning("Device enumeration command exited with code " + process.exitValue());
            }
            return lines;
        } catch (Exception ex) {
            LOG.log(Level.WARNING, "Device enumeration failed", ex);
            return List.of("ERROR=" + ex.getMessage());
        }
    }

    private static String str(String line, String key) {
        String token = key + "=";
        int i = line.indexOf(token);
        if (i < 0) {
            return "";
        }
        int start = i + token.length();
        int end = line.indexOf(';', start);
        if (end < 0) {
            end = line.length();
        }
        return line.substring(start, end).trim();
    }

    private static long longVal(String line, String key, long def) {
        try {
            String v = str(line, key);
            if (v.isBlank()) {
                return def;
            }
            return Long.parseLong(v);
        } catch (NumberFormatException ex) {
            return def;
        }
    }

    private static boolean bool(String line, String key) {
        String v = str(line, key);
        return "True".equalsIgnoreCase(v) || "1".equals(v) || "true".equalsIgnoreCase(v);
    }
}
