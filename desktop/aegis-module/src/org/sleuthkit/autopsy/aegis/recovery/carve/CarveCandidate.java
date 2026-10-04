package org.sleuthkit.autopsy.aegis.recovery.carve;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * One carving result. {@code scoreBasisPoints} is a weighted sum of named
 * components on a 0–10000 scale. It is not a probability.
 */
public final class CarveCandidate {

    public enum Disposition {
        ACCEPTED,
        REASSEMBLED,
        IDENTIFIED,
        REJECTED
    }

    public String format = "";
    public String extension = "";
    public Disposition disposition = Disposition.REJECTED;
    public long offset;
    public long length;
    public long fragment2Offset = -1;
    public String sha256 = "";
    public int scoreBasisPoints;
    public String bucket = "REJECT";
    public boolean header;
    public boolean exactLength;
    public boolean structure;
    public boolean decoder;
    public String decoderName = "";
    public boolean entropyMatch;
    public int entropyMillibits;
    public boolean reassembled;
    /** Joined derivative for a bifragment hypothesis. Null when the object is contiguous on the medium. */
    public byte[] derivative;
    public String reason = "";
    public final Map<String, Integer> components = new LinkedHashMap<>();

    public String scoreExplanation() {
        StringBuilder sb = new StringBuilder();
        sb.append("Score ").append(scoreBasisPoints).append("/10000 (").append(bucket).append("). ");
        sb.append("This is a sum of named components, not a probability. ");
        components.forEach((k, v) -> sb.append(k).append('=').append(v).append("; "));
        if (reassembled) {
            sb.append("Reassembled objects are capped below HIGH because the gap is an inference. ");
            sb.append("JPEG/PNG bifragment support here is a bounded two-run structural join, ");
            sb.append("not Huffman MCU accounting and not universal fragment reconstruction. ");
        }
        if (!decoderName.isBlank()) {
            sb.append("Decoder: ").append(decoderName).append(". ");
        }
        if (!reason.isBlank()) {
            sb.append(reason);
        }
        return sb.toString().trim();
    }
}
