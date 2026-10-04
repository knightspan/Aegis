package org.sleuthkit.autopsy.aegis.recovery.carve;

import java.util.ArrayList;
import java.util.List;

public final class CarveReport {

    public final List<CarveCandidate> candidates = new ArrayList<>();
    public final List<MediaRegion> media = new ArrayList<>();
    public long bytesScanned;
    public long sourceSize;
    public boolean scanTruncated;
    public int accepted;
    public int reassembled;
    public int identified;
    public int rejected;
    public long elapsedMillis;
    public String note = "";

    public static final class MediaRegion {
        public long offset;
        public long length;
        public String kind;

        public MediaRegion(long offset, long length, String kind) {
            this.offset = offset;
            this.length = length;
            this.kind = kind;
        }
    }
}
