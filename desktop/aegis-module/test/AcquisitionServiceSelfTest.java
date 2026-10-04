import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import org.sleuthkit.autopsy.aegis.acquisition.AcquisitionService;
import org.sleuthkit.autopsy.aegis.audit.AuditLedgerService;
import org.sleuthkit.autopsy.aegis.device.DeviceCapabilityEngine;

/** Safe acquisition check using a disposable regular-file fixture, never a disk device. */
public final class AcquisitionServiceSelfTest {

    public static void main(String[] args) throws Exception {
        Path dir = Files.createTempDirectory("aegis-acquisition-selftest-");
        try {
            Path source = dir.resolve("source-fixture.bin");
            Path destination = dir.resolve("fixture.raw");
            byte[] fixture = new byte[1024 * 128 + 37];
            for (int i = 0; i < fixture.length; i++) fixture[i] = (byte) (i * 31);
            Files.write(source, fixture);

            DeviceCapabilityEngine.DeviceInfo device = new DeviceCapabilityEngine.DeviceInfo();
            device.physicalPath = source.toString();
            device.model = "Disposable test fixture";
            device.serial = "FIXTURE-ONLY";
            device.sizeBytes = fixture.length;
            device.sectorSize = 512;
            device.fileSystem = "TEST";

            AcquisitionService.Request request = new AcquisitionService.Request();
            request.device = device;
            request.destination = destination;
            request.format = AcquisitionService.Format.RAW;
            request.caseId = "fixture-test";

            AcquisitionService.Result result = new AcquisitionService(new AuditLedgerService()).acquire(request, null);
            String expected = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(fixture));
            if (!result.success || !result.verificationMatch || result.bytes != fixture.length
                    || !expected.equalsIgnoreCase(result.sha256)
                    || !java.util.Arrays.equals(fixture, Files.readAllBytes(destination))) {
                throw new AssertionError("Acquisition or image read-back verification failed: " + result.message);
            }
            System.out.println("PASS real RAW fixture acquisition and read-back SHA-256 verification");
        } finally {
            try (var paths = Files.walk(dir)) {
                paths.sorted(java.util.Comparator.reverseOrder()).forEach(path -> {
                    try { Files.deleteIfExists(path); } catch (Exception ignored) { }
                });
            }
        }
    }
}
