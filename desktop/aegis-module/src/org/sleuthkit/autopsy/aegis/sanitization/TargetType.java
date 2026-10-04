package org.sleuthkit.autopsy.aegis.sanitization;

/**
 * Sanitization target kinds exposed by the workspace.
 */
public enum TargetType {
    FILE("File", "Sanitize a single file"),
    FOLDER("Folder", "Sanitize a folder"),
    VOLUME("Volume", "USB/pendrive only"),
    PHYSICAL_DISK("Physical Disk", "USB/pendrive only");

    private final String label;
    private final String hint;

    TargetType(String label, String hint) {
        this.label = label;
        this.hint = hint;
    }

    public String label() {
        return label;
    }

    public String hint() {
        return hint;
    }

    public boolean requiresRemovableMedia() {
        return this == VOLUME || this == PHYSICAL_DISK;
    }
}
