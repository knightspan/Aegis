package org.sleuthkit.autopsy.aegis.ui.kit;

import java.awt.Color;

/** Semantic status colours shared by every AEGIS state badge. */
public enum Tone {
    SUCCESS(new Color(0x0F9F6E), new Color(0xE6F7EF)),
    WARNING(new Color(0xB45309), new Color(0xFEF3E2)),
    ERROR(new Color(0xDC2626), new Color(0xFDECEC)),
    INFO(new Color(0x2D6CDF), new Color(0xE7F0FF)),
    NEUTRAL(new Color(0x64748B), new Color(0xF1F5F9)),
    PURPLE(new Color(0x7C3AED), new Color(0xF3EEFF));

    public final Color fg;
    public final Color bg;

    Tone(Color fg, Color bg) {
        this.fg = fg;
        this.bg = bg;
    }

    /** Maps an engine/AEGIS status word to a tone. Unknown words are neutral, never green. */
    public static Tone of(String status) {
        if (status == null) {
            return NEUTRAL;
        }
        String s = status.trim().toUpperCase(java.util.Locale.ROOT).replace(' ', '_');
        return switch (s) {
            case "SUCCESS", "READY", "VERIFIED", "VALID", "PASSED", "PASS", "OK", "SUPPORTED", "COMPLETE",
                    "COMPLETED", "HIGH", "INTACT", "ELIGIBLE", "SANITIZED", "REMOVED", "YES", "IDENTITY_RESOLVED" -> SUCCESS;
            case "SUCCESS_WITH_WARNINGS", "VERIFIED_WITH_LIMITATIONS", "WARNING", "MEDIUM", "NEEDS_REVIEW",
                    "PARTIAL", "REQUIRES_PRIVILEGE", "DEVICE-DEPENDENT", "DEVICE_DEPENDENT", "INCONCLUSIVE",
                    "FRAGMENTED", "REPORT_ONLY", "PENDING", "UNVERIFIED", "IMPLEMENTED_DEVICE_DEPENDENT" -> WARNING;
            case "FAILED", "ERROR", "INVALID", "BROKEN", "BLOCKED", "CORRUPT", "LOW", "SYSTEM_DISK", "PROTECTED",
                    "FAILED_VERIFICATION", "NO", "REFUSED", "MISMATCH" -> ERROR;
            case "RUNNING", "VERIFYING", "IN_PROGRESS", "SCANNING", "INFO" -> INFO;
            default -> NEUTRAL;
        };
    }
}
