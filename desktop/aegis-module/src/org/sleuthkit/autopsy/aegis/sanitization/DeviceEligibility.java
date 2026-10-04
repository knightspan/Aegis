package org.sleuthkit.autopsy.aegis.sanitization;

/**
 * Fail-closed eligibility result for volume / physical-disk targets.
 */
public enum DeviceEligibility {
    SUPPORTED,
    UNSUPPORTED,
    UNKNOWN;

    public boolean isAllowed() {
        return this == SUPPORTED;
    }
}
