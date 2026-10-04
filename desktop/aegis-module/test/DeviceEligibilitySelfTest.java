package org.sleuthkit.autopsy.aegis.sanitization;

import java.nio.file.Path;

/**
 * Standalone eligibility checks with an injectable probe. Compile with the
 * module sources (same pattern as ProtocolSelfTest).
 */
public final class DeviceEligibilitySelfTest {

    /** The AEGIS module folder; run from it, or pass -Daegis.module.dir=... */
    private static final Path MODULE = Path.of(System.getProperty("aegis.module.dir", "."));

    public static void main(String[] args) {
        int failures = 0;
        failures += testFileOnInternalSupported();
        failures += testFolderOnInternalSupported();
        failures += testFileOnUsbSupported();
        failures += testInternalSsdVolumeBlocked();
        failures += testInternalHddPhysicalBlocked();
        failures += testSystemDisk();
        failures += testBootDisk();
        failures += testUsbPendriveVolumeClassified();
        failures += testUnknownDevice();
        failures += testMissingTarget();
        failures += testInvalidPath();
        failures += testEngineGateVolume();
        failures += testEngineGateFileOnInternal();
        if (failures != 0) {
            System.err.println(failures + " eligibility test(s) failed");
            System.exit(1);
        }
        System.out.println("device eligibility tests passed");
    }

    private static int testFileOnInternalSupported() {
        DeviceEligibilityService service = new DeviceEligibilityService(probe(fixed("SSD")));
        Path self = MODULE.resolve("src/org/sleuthkit/autopsy/aegis/sanitization/TargetType.java");
        DeviceClassification c = service.classify(self, TargetType.FILE);
        return expect(c.eligibility() == DeviceEligibility.SUPPORTED, "file on internal SSD supported");
    }

    private static int testFolderOnInternalSupported() {
        DeviceEligibilityService service = new DeviceEligibilityService(probe(fixed("HDD")));
        Path folder = MODULE.resolve("src");
        DeviceClassification c = service.classify(folder, TargetType.FOLDER);
        return expect(c.eligibility() == DeviceEligibility.SUPPORTED, "folder on internal HDD supported");
    }

    private static int testFileOnUsbSupported() {
        DeviceEligibilityService service = new DeviceEligibilityService(probe(usb()));
        Path self = MODULE.resolve("src/org/sleuthkit/autopsy/aegis/sanitization/TargetType.java");
        DeviceClassification c = service.classify(self, TargetType.FILE);
        return expect(c.eligibility() == DeviceEligibility.SUPPORTED && c.usb() && c.removable(),
                "file on USB host supported");
    }

    private static int testInternalSsdVolumeBlocked() {
        DeviceEligibilityService service = new DeviceEligibilityService(probe(fixed("SSD")));
        DeviceClassification c = service.classify(Path.of("D:\\"), TargetType.VOLUME);
        return expect(c.eligibility() == DeviceEligibility.UNSUPPORTED && c.fixedInternal(),
                "internal SSD volume disabled");
    }

    private static int testInternalHddPhysicalBlocked() {
        DeviceEligibilityService service = new DeviceEligibilityService(probe(fixed("HDD")));
        DeviceClassification c = service.classify(Path.of("E:\\"), TargetType.PHYSICAL_DISK);
        return expect(c.eligibility() == DeviceEligibility.UNSUPPORTED && c.fixedInternal(),
                "internal HDD physical disk disabled");
    }

    private static int testSystemDisk() {
        DeviceEligibilityService service = new DeviceEligibilityService(probe(system()));
        DeviceClassification c = service.classify(Path.of("C:\\"), TargetType.VOLUME);
        return expect(c.eligibility() == DeviceEligibility.UNSUPPORTED && c.systemDisk(),
                "system disk disabled");
    }

    private static int testBootDisk() {
        DeviceEligibilityService service = new DeviceEligibilityService(probe(boot()));
        DeviceClassification c = service.classify(Path.of("\\\\.\\PhysicalDrive0"), TargetType.PHYSICAL_DISK);
        return expect(c.eligibility() == DeviceEligibility.UNSUPPORTED && c.bootDisk(),
                "boot disk disabled");
    }

    private static int testUsbPendriveVolumeClassified() {
        DeviceEligibilityService service = new DeviceEligibilityService(probe(usb()));
        DeviceClassification c = service.classify(Path.of("F:\\"), TargetType.VOLUME);
        return expect(c.eligibility() == DeviceEligibility.SUPPORTED && c.removable() && c.usb(),
                "USB pendrive volume classified (execution still gated)");
    }

    private static int testUnknownDevice() {
        DeviceEligibilityService service = new DeviceEligibilityService(probe(unknown()));
        DeviceClassification c = service.classify(Path.of("G:\\"), TargetType.VOLUME);
        return expect(c.eligibility() == DeviceEligibility.UNKNOWN, "unknown device disabled");
    }

    private static int testMissingTarget() {
        DeviceEligibilityService service = new DeviceEligibilityService(rejectingProbe());
        DeviceClassification c = service.classify(Path.of("D:/definitely-missing-aegis-target-xyz.bin"), TargetType.FILE);
        return expect(c.eligibility() == DeviceEligibility.UNSUPPORTED
                && c.kind() == DeviceClassification.Kind.MISSING, "missing target");
    }

    private static int testInvalidPath() {
        DeviceEligibilityService service = new DeviceEligibilityService(rejectingProbe());
        DeviceClassification c = service.classify(null, TargetType.FILE);
        return expect(c.eligibility() == DeviceEligibility.UNSUPPORTED
                && c.kind() == DeviceClassification.Kind.MISSING, "null path");
    }

    private static int testEngineGateVolume() {
        DeviceEligibilityService service = new DeviceEligibilityService(probe(usb()));
        boolean execute = service.mayExecute(Path.of("F:\\"), TargetType.VOLUME);
        return expect(execute && DeviceEligibilityService.ENGINE_SUPPORTS_VOLUME_OR_DISK,
                "removable USB volume passes the device-aware engine gate");
    }

    private static int testEngineGateFileOnInternal() {
        DeviceEligibilityService service = new DeviceEligibilityService(probe(fixed("SSD")));
        Path self = MODULE.resolve("src/org/sleuthkit/autopsy/aegis/sanitization/TargetType.java");
        boolean execute = service.mayExecute(self, TargetType.FILE);
        return expect(execute, "file on internal disk can execute");
    }

    private static DeviceEligibilityService.DeviceProbe probe(DeviceEligibilityService.ProbeResult result) {
        return new DeviceEligibilityService.DeviceProbe() {
            @Override
            public DeviceEligibilityService.ProbeResult probeVolume(Path volumeRoot) {
                return result;
            }

            @Override
            public DeviceEligibilityService.ProbeResult probePhysicalDisk(Path path) {
                return result;
            }
        };
    }

    private static DeviceEligibilityService.DeviceProbe rejectingProbe() {
        return probe(unknown());
    }

    private static DeviceEligibilityService.ProbeResult fixed(String media) {
        DeviceEligibilityService.ProbeResult result = new DeviceEligibilityService.ProbeResult();
        result.unknown = false;
        result.fixedInternal = true;
        result.removable = false;
        result.usb = false;
        result.fileSystem = "NTFS";
        result.identity = media;
        return result;
    }

    private static DeviceEligibilityService.ProbeResult system() {
        DeviceEligibilityService.ProbeResult result = fixed("SYSTEM");
        result.systemDisk = true;
        result.bootDisk = true;
        return result;
    }

    private static DeviceEligibilityService.ProbeResult boot() {
        DeviceEligibilityService.ProbeResult result = fixed("BOOT");
        result.bootDisk = true;
        return result;
    }

    private static DeviceEligibilityService.ProbeResult usb() {
        DeviceEligibilityService.ProbeResult result = new DeviceEligibilityService.ProbeResult();
        result.unknown = false;
        result.removable = true;
        result.usb = true;
        result.fixedInternal = false;
        result.fileSystem = "FAT32";
        result.identity = "USB Pendrive";
        result.sizeBytes = 8L * 1024 * 1024 * 1024;
        return result;
    }

    private static DeviceEligibilityService.ProbeResult unknown() {
        DeviceEligibilityService.ProbeResult result = new DeviceEligibilityService.ProbeResult();
        result.unknown = true;
        return result;
    }

    private static int expect(boolean condition, String message) {
        if (!condition) {
            System.err.println("FAIL: " + message);
            return 1;
        }
        System.out.println("PASS: " + message);
        return 0;
    }
}
