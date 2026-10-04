package org.sleuthkit.autopsy.aegis.sanitization;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Determines whether a target may be sanitized.
 * <p>
 * File and folder logical overwrite is allowed on internal drives and on
 * removable USB/pendrive media. Volume and physical-disk sanitization are
 * allowed only when the device is independently confirmed as removable USB
 * and the wipe-disk engine path is available.
 */
public final class DeviceEligibilityService {

    private static final Logger LOG = Logger.getLogger(DeviceEligibilityService.class.getName());
    private static final String USB_ONLY_MESSAGE
            = "Volume and Physical Disk sanitization are available only for USB drives and memory cards (e.g., pendrive). "
            + "This option is disabled for internal SSDs and hard drives to prevent accidental data loss.";

    /**
     * Volume/physical wipe is enabled only for devices that DeviceEligibilityService
     * independently confirms as removable USB/SD. Internal disks remain rejected.
     */
    public static final boolean ENGINE_SUPPORTS_VOLUME_OR_DISK = true;

    private final DeviceProbe probe;
    private final ConcurrentHashMap<String, DeviceClassification> cache = new ConcurrentHashMap<>();

    public DeviceEligibilityService() {
        this(new WindowsDeviceProbe());
    }

    public DeviceEligibilityService(DeviceProbe probe) {
        this.probe = Objects.requireNonNull(probe);
    }

    public static String usbOnlyMessage() {
        return USB_ONLY_MESSAGE;
    }

    public DeviceClassification classify(Path path, TargetType requested) {
        if (path == null) {
            return DeviceClassification.builder(DeviceClassification.Kind.MISSING)
                    .eligibility(DeviceEligibility.UNSUPPORTED)
                    .reason("No target selected.")
                    .build();
        }
        Path normalized = path.toAbsolutePath().normalize();
        String key = requested.name() + "|" + normalized;
        DeviceClassification cached = cache.get(key);
        if (cached != null) {
            return cached;
        }
        DeviceClassification result = classifyUncached(normalized, requested);
        cache.put(key, result);
        return result;
    }

    public void invalidate(Path path) {
        if (path == null) {
            return;
        }
        String suffix = "|" + path.toAbsolutePath().normalize();
        cache.keySet().removeIf(key -> key.endsWith(suffix));
    }

    public void clearCache() {
        cache.clear();
    }

    /**
     * Final gate before any destructive call. UI state is never trusted.
     * Volume/physical-disk execution requires confirmed removable USB/SD media.
     * File/folder execution is allowed on internal disks and USB media after classification passes.
     */
    public boolean mayExecute(Path path, TargetType type) {
        if (type == null || path == null) {
            return false;
        }
        if (type == TargetType.VOLUME || type == TargetType.PHYSICAL_DISK) {
            if (!ENGINE_SUPPORTS_VOLUME_OR_DISK) {
                return false;
            }
            DeviceClassification classification = classify(path, type);
            return classification.eligibility() == DeviceEligibility.SUPPORTED
                    && classification.removable()
                    && classification.usb()
                    && !classification.systemDisk()
                    && !classification.bootDisk();
        }
        if (type != TargetType.FILE && type != TargetType.FOLDER) {
            return false;
        }
        DeviceClassification classification = classify(path, type);
        return classification.eligibility() == DeviceEligibility.SUPPORTED
                && !classification.systemDisk()
                && Files.exists(path);
    }

    public boolean volumeAndDiskUiEnabled(Path selectedVolumeOrDisk) {
        if (!ENGINE_SUPPORTS_VOLUME_OR_DISK) {
            return false;
        }
        if (selectedVolumeOrDisk == null) {
            return false;
        }
        DeviceClassification classification = classify(selectedVolumeOrDisk, TargetType.VOLUME);
        return classification.eligibility().isAllowed();
    }

    private DeviceClassification classifyUncached(Path path, TargetType requested) {
        if (requested == TargetType.FILE) {
            return classifyFile(path);
        }
        if (requested == TargetType.FOLDER) {
            return classifyFolder(path);
        }
        if (requested == TargetType.VOLUME) {
            return classifyVolume(path);
        }
        if (requested == TargetType.PHYSICAL_DISK) {
            return classifyPhysicalDisk(path);
        }
        return DeviceClassification.builder(DeviceClassification.Kind.INVALID)
                .eligibility(DeviceEligibility.UNSUPPORTED)
                .reason("Unsupported target type.")
                .build();
    }

    private DeviceClassification classifyFile(Path path) {
        if (!Files.exists(path)) {
            return DeviceClassification.builder(DeviceClassification.Kind.MISSING)
                    .eligibility(DeviceEligibility.UNSUPPORTED)
                    .reason("Target does not exist.")
                    .build();
        }
        if (!Files.isRegularFile(path)) {
            return DeviceClassification.builder(DeviceClassification.Kind.INVALID)
                    .eligibility(DeviceEligibility.UNSUPPORTED)
                    .reason("Path is not a regular file.")
                    .build();
        }
        long size = -1;
        String fs = "—";
        String device = "—";
        boolean removable = false;
        boolean usb = false;
        boolean fixedInternal = false;
        try {
            size = Files.size(path);
            fs = Files.getFileStore(path).type();
        } catch (IOException ex) {
            LOG.log(Level.FINE, "Metadata read failed for " + path, ex);
        }
        Path root = volumeRoot(path);
        if (root != null) {
            device = root.toString();
            ProbeResult probeResult = probe.probeVolume(root);
            if (probeResult != null && !probeResult.unknown) {
                removable = probeResult.removable && probeResult.usb;
                usb = probeResult.usb;
                fixedInternal = probeResult.fixedInternal || (!probeResult.removable);
                if (probeResult.identity != null && !probeResult.identity.isBlank()) {
                    device = probeResult.identity;
                }
            }
        }
        return DeviceClassification.builder(DeviceClassification.Kind.FILE)
                .eligibility(DeviceEligibility.SUPPORTED)
                .removable(removable)
                .usb(usb)
                .fixedInternal(fixedInternal)
                .fileSystem(fs)
                .sizeBytes(size)
                .deviceIdentity(device)
                .reason("Logical file overwrite is supported.")
                .build();
    }

    private DeviceClassification classifyFolder(Path path) {
        if (!Files.exists(path)) {
            return DeviceClassification.builder(DeviceClassification.Kind.MISSING)
                    .eligibility(DeviceEligibility.UNSUPPORTED)
                    .reason("Target does not exist.")
                    .build();
        }
        if (!Files.isDirectory(path)) {
            return DeviceClassification.builder(DeviceClassification.Kind.INVALID)
                    .eligibility(DeviceEligibility.UNSUPPORTED)
                    .reason("Path is not a folder.")
                    .build();
        }
        if (isBlockedDirectory(path)) {
            return DeviceClassification.builder(DeviceClassification.Kind.FOLDER)
                    .eligibility(DeviceEligibility.UNSUPPORTED)
                    .systemDisk(true)
                    .reason("Volume roots and the Windows directory cannot be sanitized.")
                    .build();
        }
        String fs = "—";
        String device = "—";
        boolean removable = false;
        boolean usb = false;
        boolean fixedInternal = false;
        try {
            fs = Files.getFileStore(path).type();
        } catch (IOException ex) {
            LOG.log(Level.FINE, "Filesystem probe failed for " + path, ex);
        }
        Path root = volumeRoot(path);
        if (root != null) {
            device = root.toString();
            ProbeResult probeResult = probe.probeVolume(root);
            if (probeResult != null && !probeResult.unknown) {
                removable = probeResult.removable && probeResult.usb;
                usb = probeResult.usb;
                fixedInternal = probeResult.fixedInternal || (!probeResult.removable);
                if (probeResult.identity != null && !probeResult.identity.isBlank()) {
                    device = probeResult.identity;
                }
            }
        }
        return DeviceClassification.builder(DeviceClassification.Kind.FOLDER)
                .eligibility(DeviceEligibility.SUPPORTED)
                .removable(removable)
                .usb(usb)
                .fixedInternal(fixedInternal)
                .fileSystem(fs)
                .deviceIdentity(device)
                .reason("Logical folder overwrite is supported.")
                .build();
    }

    private DeviceClassification classifyVolume(Path path) {
        Path root = volumeRoot(path);
        if (root == null) {
            return DeviceClassification.builder(DeviceClassification.Kind.VOLUME)
                    .eligibility(DeviceEligibility.UNKNOWN)
                    .reason("Could not resolve a volume root. Volume sanitization stays disabled.")
                    .build();
        }
        ProbeResult probeResult = probe.probeVolume(root);
        return toVolumeOrDiskResult(DeviceClassification.Kind.VOLUME, probeResult);
    }

    private DeviceClassification classifyPhysicalDisk(Path path) {
        ProbeResult probeResult = probe.probePhysicalDisk(path);
        return toVolumeOrDiskResult(DeviceClassification.Kind.PHYSICAL_DISK, probeResult);
    }

    private static DeviceClassification toVolumeOrDiskResult(DeviceClassification.Kind kind, ProbeResult probeResult) {
        if (probeResult == null) {
            return DeviceClassification.builder(kind)
                    .eligibility(DeviceEligibility.UNKNOWN)
                    .reason("Device classification unavailable. Safety fails closed.")
                    .build();
        }
        if (probeResult.unknown) {
            return DeviceClassification.builder(kind)
                    .eligibility(DeviceEligibility.UNKNOWN)
                    .fileSystem(probeResult.fileSystem)
                    .deviceIdentity(probeResult.identity)
                    .reason("Device type could not be confirmed. Safety fails closed.")
                    .build();
        }
        if (probeResult.systemDisk || probeResult.bootDisk) {
            return DeviceClassification.builder(kind)
                    .eligibility(DeviceEligibility.UNSUPPORTED)
                    .systemDisk(probeResult.systemDisk)
                    .bootDisk(probeResult.bootDisk)
                    .fixedInternal(true)
                    .fileSystem(probeResult.fileSystem)
                    .deviceIdentity(probeResult.identity)
                    .reason("System and boot disks are not eligible.")
                    .build();
        }
        if (probeResult.fixedInternal || !probeResult.removable || !probeResult.usb) {
            return DeviceClassification.builder(kind)
                    .eligibility(DeviceEligibility.UNSUPPORTED)
                    .fixedInternal(probeResult.fixedInternal || !probeResult.removable)
                    .removable(probeResult.removable)
                    .usb(probeResult.usb)
                    .fileSystem(probeResult.fileSystem)
                    .deviceIdentity(probeResult.identity)
                    .sizeBytes(probeResult.sizeBytes)
                    .reason(USB_ONLY_MESSAGE)
                    .build();
        }
        return DeviceClassification.builder(kind)
                .eligibility(DeviceEligibility.SUPPORTED)
                .removable(true)
                .usb(true)
                .fileSystem(probeResult.fileSystem)
                .deviceIdentity(probeResult.identity)
                .sizeBytes(probeResult.sizeBytes)
                .reason("Confirmed removable USB storage.")
                .build();
    }

    static boolean isBlockedDirectory(Path path) {
        Path windows = Path.of(System.getenv().getOrDefault("SystemRoot", "C:\\Windows"));
        Path normalized = path.toAbsolutePath().normalize();
        return normalized.getNameCount() == 0
                || normalized.equals(normalized.getRoot())
                || normalized.equals(windows.toAbsolutePath().normalize());
    }

    static Path volumeRoot(Path path) {
        if (path == null) {
            return null;
        }
        Path absolute = path.toAbsolutePath().normalize();
        Path root = absolute.getRoot();
        if (root != null) {
            return root;
        }
        String text = absolute.toString();
        if (text.length() >= 2 && text.charAt(1) == ':') {
            return Path.of(text.substring(0, 2) + "\\");
        }
        return null;
    }

    static boolean isSystemDriveLetter(Path root) {
        String system = System.getenv("SystemDrive");
        if (system == null || system.isBlank() || root == null) {
            return false;
        }
        String letter = root.toString().replace("\\", "");
        return letter.equalsIgnoreCase(system) || letter.equalsIgnoreCase(system + "\\");
    }

    /**
     * Probe results used by {@link DeviceEligibilityService}. Tests inject fakes.
     */
    public interface DeviceProbe {
        ProbeResult probeVolume(Path volumeRoot);

        ProbeResult probePhysicalDisk(Path path);
    }

    public static final class ProbeResult {
        public boolean removable;
        public boolean usb;
        public boolean fixedInternal;
        public boolean systemDisk;
        public boolean bootDisk;
        public boolean unknown = true;
        public String fileSystem = "—";
        public String identity = "—";
        public long sizeBytes = -1;
    }

    /**
     * Windows probe using CIM/PowerShell. Drive letters alone never decide USB.
     */
    static final class WindowsDeviceProbe implements DeviceProbe {

        @Override
        public ProbeResult probeVolume(Path volumeRoot) {
            ProbeResult result = new ProbeResult();
            if (volumeRoot == null) {
                return result;
            }
            if (isSystemDriveLetter(volumeRoot)) {
                result.systemDisk = true;
                result.bootDisk = true;
                result.fixedInternal = true;
                result.unknown = false;
                result.identity = volumeRoot.toString();
                return result;
            }
            String letter = driveLetter(volumeRoot);
            if (letter == null) {
                return result;
            }
            String script = ""
                    + "$ErrorActionPreference='Stop'; "
                    + "$letter='" + letter + "'; "
                    + "try { "
                    + "  $vol = Get-CimInstance Win32_LogicalDisk -Filter \\\"DeviceID='$letter':\\\" -ErrorAction Stop; "
                    + "  $part = Get-Partition -DriveLetter $letter -ErrorAction SilentlyContinue | Select-Object -First 1; "
                    + "  $disk = $null; if ($part) { $disk = Get-Disk -Number $part.DiskNumber -ErrorAction SilentlyContinue }; "
                    + "  $driveType = if ($vol) { [int]$vol.DriveType } else { -1 }; "
                    + "  $bus = if ($disk) { [string]$disk.BusType } else { '' }; "
                    + "  $isSystem = if ($disk) { [bool]$disk.IsSystem } else { $false }; "
                    + "  $isBoot = if ($disk) { [bool]$disk.IsBoot } else { $false }; "
                    + "  $media = if ($disk) { [string]$disk.MediaType } else { '' }; "
                    + "  $size = if ($vol -and $vol.Size) { [int64]$vol.Size } else { -1 }; "
                    + "  $fs = if ($vol) { [string]$vol.FileSystem } else { '' }; "
                    + "  $model = if ($disk) { [string]$disk.FriendlyName } else { '' }; "
                    + "  Write-Output (\\\"DRIVE_TYPE=$driveType;BUS=$bus;SYSTEM=$isSystem;BOOT=$isBoot;MEDIA=$media;SIZE=$size;FS=$fs;MODEL=$model\\\"); "
                    + "} catch { Write-Output 'ERROR=1' }";
            String line = runPowerShell(script);
            return parseProbe(line, volumeRoot.toString());
        }

        @Override
        public ProbeResult probePhysicalDisk(Path path) {
            ProbeResult result = new ProbeResult();
            if (path == null) {
                return result;
            }
            String text = path.toString().toLowerCase(Locale.ROOT);
            if (!text.contains("physicaldrive") && !text.startsWith("\\\\.\\")) {
                result.unknown = true;
                result.identity = path.toString();
                return result;
            }
            String number = text.replaceAll(".*?physicaldrive(\\d+).*", "$1");
            if (number.equals(text)) {
                return result;
            }
            String script = ""
                    + "$ErrorActionPreference='Stop'; "
                    + "try { "
                    + "  $disk = Get-Disk -Number " + number + " -ErrorAction Stop; "
                    + "  $bus = [string]$disk.BusType; "
                    + "  $isSystem = [bool]$disk.IsSystem; "
                    + "  $isBoot = [bool]$disk.IsBoot; "
                    + "  $media = [string]$disk.MediaType; "
                    + "  $size = [int64]$disk.Size; "
                    + "  $model = [string]$disk.FriendlyName; "
                    + "  $removableHint = if ($bus -match 'USB|SD|Multi-Media') { 2 } else { 3 }; "
                    + "  Write-Output (\\\"DRIVE_TYPE=$removableHint;BUS=$bus;SYSTEM=$isSystem;BOOT=$isBoot;MEDIA=$media;SIZE=$size;FS=;MODEL=$model\\\"); "
                    + "} catch { Write-Output 'ERROR=1' }";
            String line = runPowerShell(script);
            return parseProbe(line, path.toString());
        }

        private static String driveLetter(Path root) {
            String text = root.toString().replace("\\", "");
            if (text.length() >= 1 && Character.isLetter(text.charAt(0))) {
                return String.valueOf(Character.toUpperCase(text.charAt(0)));
            }
            return null;
        }

        private static ProbeResult parseProbe(String line, String identity) {
            ProbeResult result = new ProbeResult();
            result.identity = identity;
            if (line == null || line.isBlank() || line.contains("ERROR=1")) {
                result.unknown = true;
                return result;
            }
            int driveType = intValue(line, "DRIVE_TYPE", -1);
            String bus = stringValue(line, "BUS");
            boolean system = boolValue(line, "SYSTEM");
            boolean boot = boolValue(line, "BOOT");
            String media = stringValue(line, "MEDIA");
            long size = longValue(line, "SIZE", -1);
            String fs = stringValue(line, "FS");
            String model = stringValue(line, "MODEL");

            result.systemDisk = system;
            result.bootDisk = boot;
            result.sizeBytes = size;
            result.fileSystem = fs == null || fs.isBlank() ? "—" : fs;
            if (model != null && !model.isBlank()) {
                result.identity = model + " (" + identity + ")";
            }

            boolean busUsb = bus != null && (bus.equalsIgnoreCase("USB")
                    || bus.equalsIgnoreCase("SD")
                    || bus.toLowerCase(Locale.ROOT).contains("multi-media"));
            boolean removableType = driveType == 2;
            boolean fixedType = driveType == 3;
            boolean optical = driveType == 5;

            if (system || boot) {
                result.fixedInternal = true;
                result.unknown = false;
                return result;
            }
            if (optical) {
                result.fixedInternal = true;
                result.unknown = false;
                return result;
            }
            if (driveType < 0 && (bus == null || bus.isBlank())) {
                result.unknown = true;
                return result;
            }

            // Require both removable DriveType and USB/SD bus when bus is known.
            if (removableType && busUsb) {
                result.removable = true;
                result.usb = true;
                result.fixedInternal = false;
                result.unknown = false;
                return result;
            }
            if (removableType && (bus == null || bus.isBlank())) {
                // Removable without bus confirmation — fail closed.
                result.removable = true;
                result.usb = false;
                result.unknown = true;
                return result;
            }
            if (fixedType || (media != null && media.toLowerCase(Locale.ROOT).contains("hdd"))
                    || (media != null && media.toLowerCase(Locale.ROOT).contains("ssd"))) {
                result.fixedInternal = true;
                result.removable = false;
                result.usb = false;
                result.unknown = false;
                return result;
            }
            result.unknown = true;
            return result;
        }

        private static String runPowerShell(String script) {
            ProcessBuilder builder = new ProcessBuilder(
                    "powershell.exe",
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy", "Bypass",
                    "-Command",
                    script);
            builder.redirectErrorStream(true);
            try {
                Process process = builder.start();
                StringBuilder output = new StringBuilder();
                try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        if (!line.isBlank()) {
                            output.append(line.trim());
                        }
                    }
                }
                if (!process.waitFor(8, TimeUnit.SECONDS)) {
                    process.destroyForcibly();
                    return "ERROR=1";
                }
                return output.toString();
            } catch (IOException | InterruptedException ex) {
                if (ex instanceof InterruptedException) {
                    Thread.currentThread().interrupt();
                }
                LOG.log(Level.FINE, "PowerShell device probe failed", ex);
                return "ERROR=1";
            }
        }

        private static int intValue(String line, String key, int fallback) {
            String value = stringValue(line, key);
            if (value == null) {
                return fallback;
            }
            try {
                return Integer.parseInt(value.trim());
            } catch (NumberFormatException ex) {
                return fallback;
            }
        }

        private static long longValue(String line, String key, long fallback) {
            String value = stringValue(line, key);
            if (value == null) {
                return fallback;
            }
            try {
                return Long.parseLong(value.trim());
            } catch (NumberFormatException ex) {
                return fallback;
            }
        }

        private static boolean boolValue(String line, String key) {
            String value = stringValue(line, key);
            return value != null && ("True".equalsIgnoreCase(value) || "1".equals(value));
        }

        private static String stringValue(String line, String key) {
            String token = key + "=";
            int start = line.indexOf(token);
            if (start < 0) {
                return null;
            }
            start += token.length();
            int end = line.indexOf(';', start);
            if (end < 0) {
                end = line.length();
            }
            return line.substring(start, end).trim();
        }
    }
}
