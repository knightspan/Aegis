package org.sleuthkit.autopsy.aegis.sanitization;

import java.util.Objects;

/**
 * Classification of a path for sanitization safety checks.
 */
public final class DeviceClassification {

    public enum Kind {
        FILE,
        FOLDER,
        VOLUME,
        PHYSICAL_DISK,
        MISSING,
        INVALID
    }

    private final Kind kind;
    private final DeviceEligibility eligibility;
    private final boolean removable;
    private final boolean usb;
    private final boolean fixedInternal;
    private final boolean systemDisk;
    private final boolean bootDisk;
    private final String fileSystem;
    private final String deviceIdentity;
    private final String reason;
    private final long sizeBytes;

    private DeviceClassification(Builder builder) {
        this.kind = builder.kind;
        this.eligibility = builder.eligibility;
        this.removable = builder.removable;
        this.usb = builder.usb;
        this.fixedInternal = builder.fixedInternal;
        this.systemDisk = builder.systemDisk;
        this.bootDisk = builder.bootDisk;
        this.fileSystem = builder.fileSystem;
        this.deviceIdentity = builder.deviceIdentity;
        this.reason = builder.reason;
        this.sizeBytes = builder.sizeBytes;
    }

    public Kind kind() {
        return kind;
    }

    public DeviceEligibility eligibility() {
        return eligibility;
    }

    public boolean removable() {
        return removable;
    }

    public boolean usb() {
        return usb;
    }

    public boolean fixedInternal() {
        return fixedInternal;
    }

    public boolean systemDisk() {
        return systemDisk;
    }

    public boolean bootDisk() {
        return bootDisk;
    }

    public String fileSystem() {
        return fileSystem;
    }

    public String deviceIdentity() {
        return deviceIdentity;
    }

    public String reason() {
        return reason;
    }

    public long sizeBytes() {
        return sizeBytes;
    }

    public static Builder builder(Kind kind) {
        return new Builder(kind);
    }

    public static final class Builder {
        private final Kind kind;
        private DeviceEligibility eligibility = DeviceEligibility.UNKNOWN;
        private boolean removable;
        private boolean usb;
        private boolean fixedInternal;
        private boolean systemDisk;
        private boolean bootDisk;
        private String fileSystem = "—";
        private String deviceIdentity = "—";
        private String reason = "";
        private long sizeBytes = -1;

        private Builder(Kind kind) {
            this.kind = Objects.requireNonNull(kind);
        }

        public Builder eligibility(DeviceEligibility value) {
            this.eligibility = value;
            return this;
        }

        public Builder removable(boolean value) {
            this.removable = value;
            return this;
        }

        public Builder usb(boolean value) {
            this.usb = value;
            return this;
        }

        public Builder fixedInternal(boolean value) {
            this.fixedInternal = value;
            return this;
        }

        public Builder systemDisk(boolean value) {
            this.systemDisk = value;
            return this;
        }

        public Builder bootDisk(boolean value) {
            this.bootDisk = value;
            return this;
        }

        public Builder fileSystem(String value) {
            this.fileSystem = value == null || value.isBlank() ? "—" : value;
            return this;
        }

        public Builder deviceIdentity(String value) {
            this.deviceIdentity = value == null || value.isBlank() ? "—" : value;
            return this;
        }

        public Builder reason(String value) {
            this.reason = value == null ? "" : value;
            return this;
        }

        public Builder sizeBytes(long value) {
            this.sizeBytes = value;
            return this;
        }

        public DeviceClassification build() {
            return new DeviceClassification(this);
        }
    }
}
