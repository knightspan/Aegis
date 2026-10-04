package org.sleuthkit.autopsy.aegis.verification;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * States what was hashed or sampled, and what was not.
 */
public final class VerificationService {

    public static final class Result {
        public boolean match;
        public String computedSha256 = "";
        public String expectedSha256 = "";
        public long bytesRead;
        public String verified = "";
        public String notVerified = "";
        public String detail = "";
    }

    public Result verifyFileSha256(Path file, String expected) throws IOException {
        Result result = new Result();
        result.expectedSha256 = expected == null ? "" : expected;
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException ex) {
            result.detail = "SHA-256 is unavailable: " + ex.getMessage();
            result.notVerified = "entire file";
            return result;
        }
        try (InputStream in = Files.newInputStream(file)) {
            byte[] buf = new byte[1024 * 1024];
            int n;
            while ((n = in.read(buf)) >= 0) {
                digest.update(buf, 0, n);
                result.bytesRead += n;
            }
        }
        result.computedSha256 = toHex(digest.digest());
        result.match = !result.expectedSha256.isBlank() && result.expectedSha256.equalsIgnoreCase(result.computedSha256);
        result.verified = "Full read-back of " + file.getFileName() + " (" + result.bytesRead + " bytes), SHA-256.";
        result.notVerified = "Source device was not read a second time. NAND, snapshots, and copies outside this file were not verified.";
        result.detail = result.match ? "Image file hash matches the acquisition hash." : "Image file hash does not match the acquisition hash.";
        return result;
    }

    public Map<String, String> scopeForLogicalFile(boolean contentVerified) {
        Map<String, String> scope = new LinkedHashMap<>();
        scope.put("FILE CONTENT", contentVerified ? "VERIFIED" : "NOT VERIFIED");
        scope.put("SLACK", "NOT VERIFIED");
        scope.put("UNALLOCATED", "NOT VERIFIED");
        scope.put("NAND", "NOT VERIFIED");
        scope.put("SNAPSHOT", "NOT VERIFIED");
        scope.put("CLOUD COPY", "NOT VERIFIED");
        return scope;
    }

    private static String toHex(byte[] dig) {
        StringBuilder sb = new StringBuilder(dig.length * 2);
        for (byte b : dig) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
