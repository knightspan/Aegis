package org.sleuthkit.autopsy.aegis.device;

/**
 * Read-only HPA/DCO statement.
 * The Variant detector uses hdparm, which is not a Windows capability of this build.
 * This service does not issue SET MAX or DCO modify commands.
 */
public final class HiddenAreaService {

    public static final class Report {
        public String inspected = "NOT INSPECTED";
        public String hpa = "NOT INSPECTED";
        public String dco = "NOT INSPECTED";
        public String modified = "NOT MODIFIED";
        public String coverage = "";
        public String detail = "";
    }

    public Report inspect(DeviceCapabilityEngine.DeviceInfo device) {
        Report report = new Report();
        report.modified = "NOT MODIFIED";
        if (device == null) {
            report.detail = "No device selected. No hidden-area command was sent.";
            report.coverage = "No sector range was compared.";
            return report;
        }
        boolean usb = device.busType != null && device.busType.toLowerCase(java.util.Locale.ROOT).contains("usb");
        report.coverage = "Kernel-visible size " + device.sizeBytes + " bytes on " + device.physicalPath
                + ". ATA/NVMe native-max was not queried.";
        if (usb || device.removable) {
            report.detail = "USB and removable bridges are not given an ATA pass-through verdict. "
                    + "A bridge reply can be invented or refused, so HPA/DCO was not probed. "
                    + "No SET MAX or DCO change was sent.";
            return report;
        }
        report.detail = "This Windows build does not include an ATA IDENTIFY or NVMe Identify passthrough. "
                + "hdparm-style HPA/DCO detection from the Variant is not available here. "
                + "Absence of a probe is not a finding of 'not detected'. No hidden area was modified.";
        return report;
    }
}
