package org.sleuthkit.autopsy.aegis.acquisition;

import java.io.FileInputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;
import org.sleuthkit.autopsy.aegis.SanitizerBridge;
import org.sleuthkit.autopsy.aegis.audit.AuditLedgerService;
import org.sleuthkit.autopsy.aegis.device.DeviceCapabilityEngine;
import org.sleuthkit.autopsy.aegis.evidence.EvidenceHandle;

/**
 * Read-only forensic imaging service. Prefers aegis_cli acquire; falls back to
 * a Java RAW path that never opens the source for write.
 */
public final class AcquisitionService {

    public enum Format {
        RAW,
        E01
    }

    public static final class Request {
        public DeviceCapabilityEngine.DeviceInfo device;
        public Path destination;
        public Format format = Format.RAW;
        public String caseId = "";
        public String evidenceId = "";
        public String operator = "";
    }

    public static final class Result {
        public boolean success;
        public String status = "FAILED";
        public String message = "";
        public Path imagePath;
        public String sha256 = "";
        public long bytes = 0;
        public EvidenceHandle handle;
        public String verificationDetail = "";
        public boolean verificationMatch;
        public String registrationMessage = "Not registered.";
    }

    public static final class Progress {
        public String phase = "";
        public long bytes;
        public long total;
        public double percent;
        public String message = "";
    }

    private final AuditLedgerService ledger;
    private final SanitizerBridge bridge = new SanitizerBridge();

    public AcquisitionService(AuditLedgerService ledger) {
        this.ledger = Objects.requireNonNull(ledger);
    }

    public Result acquire(Request request, Consumer<Progress> onProgress) throws IOException, InterruptedException {
        Result result = new Result();
        if (request == null || request.device == null || request.destination == null) {
            result.message = "Missing device or destination.";
            return result;
        }
        if (request.device.systemDisk || request.device.bootDisk) {
            result.status = "UNSUPPORTED";
            result.message = "Refusing to acquire a system/boot disk in this workflow.";
            ledger.append("", "acquire.rejected", result.message);
            return result;
        }
        if (request.format == Format.E01) {
            result.status = "UNSUPPORTED";
            result.message = "E01/EWF write acquisition is not enabled in the AEGIS-native CLI yet. Use RAW, then analyze with Autopsy E01 open when you have an E01 from another tool.";
            ledger.append(request.caseId, "acquire.e01.unsupported", result.message);
            return result;
        }
        Path parent = request.destination.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }

        Path cli = bridge.locateCli();
        if (cli != null) {
            Result cliResult = acquireViaCli(cli, request, onProgress);
            if (cliResult.success || !"aegis_cli acquire unavailable".equals(cliResult.message)) {
                return cliResult;
            }
        }
        return acquireViaJava(request, onProgress);
    }

    private Result acquireViaCli(Path cli, Request request, Consumer<Progress> onProgress)
            throws IOException, InterruptedException {
        Result result = new Result();
        List<String> cmd = new ArrayList<>();
        cmd.add(cli.toString());
        cmd.add("acquire");
        cmd.add(request.device.physicalPath);
        cmd.add(request.destination.toString());
        if (request.device.sizeBytes > 0) {
            cmd.add("--size");
            cmd.add(Long.toString(request.device.sizeBytes));
        }
        if (!request.device.removable || !request.device.usb) {
            cmd.add("--allow-non-removable-read");
        }

        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true);
        Process process = pb.start();
        StringBuilder last = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                last.append(line).append('\n');
                Progress p = parseProgress(line);
                if (onProgress != null && p != null) {
                    onProgress.accept(p);
                }
                if (line.contains("\"sha256\"")) {
                    result.sha256 = extractJsonString(line, "sha256");
                }
                if (line.contains("\"bytes\"")) {
                    result.bytes = extractJsonLong(line, "bytes");
                }
                if (line.contains("\"status\"")) {
                    result.status = extractJsonString(line, "status");
                }
                if (line.contains("\"message\"")) {
                    result.message = extractJsonString(line, "message");
                }
            }
        }
        int code = process.waitFor();
        if (last.toString().contains("Unknown command") || last.toString().contains("Usage:")) {
            result.message = "aegis_cli acquire unavailable";
            result.success = false;
            return result;
        }
        result.success = code == 0 && ("SUCCESS".equals(result.status) || "SUCCESS_WITH_WARNINGS".equals(result.status));
        return finalizeSuccess(request, result, last.toString(), code);
    }

    private Result acquireViaJava(Request request, Consumer<Progress> onProgress) throws IOException {
        Result result = new Result();
        String source = request.device.physicalPath;
        if (source == null || source.isBlank()) {
            result.message = "Device physical path is empty.";
            return result;
        }
        long total = request.device.sizeBytes > 0 ? request.device.sizeBytes : -1;
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException ex) {
            result.message = "SHA-256 unavailable: " + ex.getMessage();
            return result;
        }

        // Open source read-only. Never open with write. Prefer FileInputStream for \\.\ device paths.
        try (InputStream raw = new FileInputStream(source);
                DigestInputStream in = new DigestInputStream(raw, digest);
                OutputStream out = Files.newOutputStream(request.destination)) {
            byte[] buf = new byte[1024 * 1024];
            long copied = 0;
            while (true) {
                if (total > 0 && copied >= total) {
                    break;
                }
                int want = buf.length;
                if (total > 0) {
                    long left = total - copied;
                    if (left < want) {
                        want = (int) left;
                    }
                }
                int n = in.read(buf, 0, want);
                if (n < 0) {
                    break;
                }
                out.write(buf, 0, n);
                copied += n;
                if (onProgress != null) {
                    Progress p = new Progress();
                    p.phase = "acquire";
                    p.bytes = copied;
                    p.total = total > 0 ? total : copied;
                    p.percent = total > 0 ? (100.0 * copied) / total : 0;
                    onProgress.accept(p);
                }
            }
            result.bytes = copied;
            result.sha256 = toHex(digest.digest());
            result.status = "SUCCESS";
            result.message = "RAW acquisition completed via AEGIS Java read-only path.";
            result.success = true;
            return finalizeSuccess(request, result, "", 0);
        } catch (IOException ex) {
            result.message = "Java acquire failed: " + ex.getMessage();
            ledger.append(request.caseId, "acquire.failed", result.message);
            return result;
        }
    }

    private static String toHex(byte[] dig) {
        StringBuilder sb = new StringBuilder(dig.length * 2);
        for (byte b : dig) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private Result finalizeSuccess(Request request, Result result, String last, int code) {
        if (result.success) {
            try {
                result.verificationMatch = verifyImage(request.destination, result);
                result.verificationDetail = result.verificationMatch
                        ? "Image read-back byte count and SHA-256 match the acquisition result."
                        : "Image read-back did not match the acquired byte count or SHA-256.";
            } catch (IOException ex) {
                result.verificationMatch = false;
                result.verificationDetail = "Image read-back failed: " + ex.getMessage();
            }
            if (!result.verificationMatch) {
                result.success = false;
                result.status = "INVALID";
                result.message = result.verificationDetail;
                ledger.append(request.caseId, "acquire.verification.failed", result.message);
            }
        }
        if (result.success) {
            result.imagePath = request.destination;
            result.handle = EvidenceHandle.builder(EvidenceHandle.Kind.RAW_IMAGE)
                    .path(request.destination)
                    .caseId(request.caseId)
                    .evidenceId(request.evidenceId)
                    .displayName(request.destination.getFileName().toString())
                    .model(request.device.model)
                    .serial(request.device.serial)
                    .sizeBytes(result.bytes > 0 ? result.bytes : request.device.sizeBytes)
                    .removable(request.device.removable)
                    .readOnlySource(true)
                    .sectorSize(request.device.sectorSize)
                    .filesystem(request.device.fileSystem)
                    .sha256(result.sha256)
                    .build();
            ledger.append(request.caseId, "acquire.success",
                    "path=" + request.destination + ";sha256=" + result.sha256 + ";bytes=" + result.bytes);
        } else {
            if (result.message == null || result.message.isBlank()) {
                result.message = "Acquisition failed (exit " + code + "). " + last;
            }
            ledger.append(request.caseId, "acquire.failed", result.message);
        }
        return result;
    }

    private static boolean verifyImage(Path image, Result result) throws IOException {
        if (image == null || result.sha256 == null || result.sha256.isBlank() || result.bytes <= 0
                || !Files.isRegularFile(image)) {
            return false;
        }
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException ex) {
            throw new IOException("SHA-256 is unavailable for read-back verification.", ex);
        }
        long count = 0;
        try (InputStream in = Files.newInputStream(image)) {
            byte[] buffer = new byte[1024 * 1024];
            int read;
            while ((read = in.read(buffer)) >= 0) {
                if (read == 0) {
                    continue;
                }
                digest.update(buffer, 0, read);
                count += read;
            }
        }
        return count == result.bytes && toHex(digest.digest()).equalsIgnoreCase(result.sha256);
    }

    private static Progress parseProgress(String line) {
        if (line == null || !line.contains("\"type\":\"progress\"")) {
            return null;
        }
        Progress p = new Progress();
        p.phase = extractJsonString(line, "phase");
        p.bytes = extractJsonLong(line, "bytes");
        if (p.bytes == 0) {
            p.bytes = extractJsonLong(line, "bytes_completed");
        }
        p.total = extractJsonLong(line, "total");
        if (p.total == 0) {
            p.total = extractJsonLong(line, "bytes_total");
        }
        p.message = extractJsonString(line, "message");
        if (p.total > 0) {
            p.percent = (100.0 * p.bytes) / p.total;
        }
        return p;
    }

    private static String extractJsonString(String json, String key) {
        String needle = "\"" + key + "\":\"";
        int i = json.indexOf(needle);
        if (i < 0) {
            return "";
        }
        int start = i + needle.length();
        int end = json.indexOf('"', start);
        if (end < 0) {
            return "";
        }
        return json.substring(start, end);
    }

    private static long extractJsonLong(String json, String key) {
        String needle = "\"" + key + "\":";
        int i = json.indexOf(needle);
        if (i < 0) {
            return 0;
        }
        int start = i + needle.length();
        while (start < json.length() && Character.isWhitespace(json.charAt(start))) {
            start++;
        }
        int end = start;
        while (end < json.length() && (Character.isDigit(json.charAt(end)) || json.charAt(end) == '-')) {
            end++;
        }
        try {
            return Long.parseLong(json.substring(start, end));
        } catch (NumberFormatException ex) {
            return 0;
        }
    }
}
