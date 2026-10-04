import java.util.List;
import org.sleuthkit.autopsy.aegis.device.DeviceCapabilityEngine;

/** Read-only smoke check that enumerates real Windows disks without printing identifiers. */
public final class DeviceEnumerationSelfTest {

    public static void main(String[] args) {
        DeviceCapabilityEngine engine = new DeviceCapabilityEngine();
        List<DeviceCapabilityEngine.DeviceInfo> devices = engine.listDevices();
        long systemDisks = devices.stream().filter(d -> d.systemDisk).count();
        if (devices.isEmpty() && !engine.lastEnumerationError().isBlank()) {
            System.out.println("BLOCKED Windows physical disk enumeration: "
                    + engine.lastEnumerationError());
            System.exit(77);
        }
        if (devices.isEmpty() || systemDisks < 1) {
            throw new AssertionError("Windows returned no disks or did not identify a system disk.");
        }
        System.out.println("PASS Windows physical disk enumeration: " + devices.size()
                + " disk(s); " + systemDisks + " system disk(s) identified.");
    }
}
