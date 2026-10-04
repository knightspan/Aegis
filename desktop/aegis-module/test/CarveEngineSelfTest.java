package org.sleuthkit.autopsy.aegis;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.CRC32;
import java.util.zip.GZIPOutputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import org.sleuthkit.autopsy.aegis.audit.AuditLedgerService;
import org.sleuthkit.autopsy.aegis.audit.ReportSigner;
import org.sleuthkit.autopsy.aegis.recovery.RecoveryService;
import org.sleuthkit.autopsy.aegis.recovery.carve.CarveCandidate;
import org.sleuthkit.autopsy.aegis.recovery.carve.CarveReport;
import org.sleuthkit.autopsy.aegis.recovery.carve.CarvingEngine;
import org.sleuthkit.autopsy.aegis.recovery.carve.FileByteSource;
import org.sleuthkit.autopsy.aegis.verification.VerificationService;

/**
 * Standalone behavioral checks for the AEGIS carver, ledger, and signer.
 * Run with the JDK used to compile the module sources. Does not touch a live disk.
 */
public final class CarveEngineSelfTest {

    public static void main(String[] args) throws Exception {
        RecoveryService recovery = new RecoveryService(new AuditLedgerService());
        int failed = 0;
        failed += expectAccepted(recovery, png(), "PNG", false);
        failed += expectRejected(recovery, badPng(), "PNG");
        failed += expectRejected(recovery, truncatedJpeg(), "JPEG");
        failed += expectAccepted(recovery, jpeg(), "JPEG", false);
        failed += expectRejected(recovery, "%PDF-1.4\nnot a trailer".getBytes(java.nio.charset.StandardCharsets.US_ASCII), "PDF");
        failed += expectAccepted(recovery, pdf(), "PDF", false);
        failed += expectAccepted(recovery, zip(), "ZIP", false);
        failed += expectRejected(recovery, new byte[]{0x50, 0x4B, 0x03, 0x04, 0x00, 0x00}, "ZIP");
        failed += expectAccepted(recovery, gzip(), "GZIP", false);
        failed += expectRejected(recovery, new byte[]{0x1F, (byte) 0x8B, 0x08, 0x00}, "GZIP");

        CarveReport pngReport = recovery.carveBytes(png(), null);
        for (CarveCandidate candidate : pngReport.candidates) {
            if ("PNG".equals(candidate.format) && candidate.disposition == CarveCandidate.Disposition.ACCEPTED) {
                if (candidate.scoreExplanation().contains("100%")) {
                    failed++;
                    System.out.println("FAIL score rendered as a certainty percentage");
                }
                if (!candidate.scoreExplanation().contains("not a probability")) {
                    failed++;
                    System.out.println("FAIL score explanation omitted the non-probability statement");
                }
            }
        }

        Path dir = Files.createTempDirectory("aegis-ledger");
        Path image = dir.resolve("fixture.raw");
        Files.write(image, png());
        Path recovered = dir.resolve("recovered");
        try (FileByteSource source = new FileByteSource(image)) {
            int exported = recovery.export(pngReport, source, recovered);
            boolean hasExport = false;
            if (Files.isDirectory(recovered)) {
                try (var files = Files.list(recovered)) {
                    hasExport = files.findAny().isPresent();
                }
            }
            if (exported < 1 || !hasExport) {
                failed++;
                System.out.println("FAIL recovery export did not write validated output");
            } else {
                System.out.println("PASS accepted recovery result exported to a derivative file");
            }
        }

        AuditLedgerService ledger = new AuditLedgerService(dir.resolve("ledger.jsonl"));
        ledger.append("case", "unit", "one");
        ledger.append("case", "unit", "two");
        if (!ledger.verifyChain()) {
            failed++;
            System.out.println("FAIL ledger chain");
        }
        AuditLedgerService reloaded = new AuditLedgerService(dir.resolve("ledger.jsonl"));
        if (!reloaded.verifyChain() || reloaded.snapshot().size() != 2) {
            failed++;
            System.out.println("FAIL ledger reload");
        }

        ReportSigner.Signed signed = new ReportSigner().sign("aegis-test-payload");
        if (!signed.verified) {
            failed++;
            System.out.println("FAIL ed25519 self-check");
        }

        Path file = dir.resolve("bytes.bin");
        Files.write(file, new byte[]{1, 2, 3, 4});
        String hash = CarvingEngine.sha256(new byte[]{1, 2, 3, 4});
        VerificationService.Result ok = new VerificationService().verifyFileSha256(file, hash);
        VerificationService.Result bad = new VerificationService().verifyFileSha256(file, "00");
        if (!ok.match || bad.match || ok.notVerified.isBlank()) {
            failed++;
            System.out.println("FAIL verification scope");
        }

        if (failed == 0) {
            System.out.println("PASS " + pngReport.note);
        } else {
            System.out.println("FAILURES " + failed);
            System.exit(1);
        }
    }

    private static int expectAccepted(RecoveryService recovery, byte[] data, String format, boolean reassembled) throws Exception {
        CarveReport report = recovery.carveBytes(data, null);
        for (CarveCandidate candidate : report.candidates) {
            if (!format.equals(candidate.format) && !(format.equals("ZIP") && candidate.format.endsWith("ZIP"))) {
                continue;
            }
            if (candidate.disposition == CarveCandidate.Disposition.ACCEPTED
                    || (reassembled && candidate.disposition == CarveCandidate.Disposition.REASSEMBLED)) {
                System.out.println("OK " + format + " " + candidate.disposition + " score=" + candidate.scoreBasisPoints + " " + candidate.bucket);
                return 0;
            }
        }
        System.out.println("FAIL expected accepted " + format);
        for (CarveCandidate candidate : report.candidates) {
            System.out.println("  " + candidate.format + " " + candidate.disposition + " " + candidate.reason);
        }
        return 1;
    }

    private static int expectRejected(RecoveryService recovery, byte[] data, String format) throws Exception {
        CarveReport report = recovery.carveBytes(data, null);
        boolean saw = false;
        for (CarveCandidate candidate : report.candidates) {
            if (candidate.format.equals(format) || (format.equals("ZIP") && candidate.format.contains("ZIP"))) {
                saw = true;
                if (candidate.disposition == CarveCandidate.Disposition.ACCEPTED
                        || candidate.disposition == CarveCandidate.Disposition.REASSEMBLED) {
                    System.out.println("FAIL malformed " + format + " was accepted: " + candidate.reason);
                    return 1;
                }
            }
        }
        if (!saw && format.equals("ZIP") && data.length < 8) {
            System.out.println("OK " + format + " short header produced no accepted object");
            return 0;
        }
        System.out.println("OK " + format + " rejected or uncorroborated");
        return 0;
    }

    private static byte[] png() throws Exception {
        BufferedImage image = new BufferedImage(2, 2, BufferedImage.TYPE_INT_RGB);
        image.setRGB(0, 0, 0xFF0000);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ImageIO.write(image, "png", out);
        return out.toByteArray();
    }

    private static byte[] badPng() throws Exception {
        byte[] data = png();
        data[data.length / 2] ^= 0x5A;
        CRC32 ignored = new CRC32();
        ignored.update(data);
        return data;
    }

    private static byte[] jpeg() throws Exception {
        BufferedImage image = new BufferedImage(8, 8, BufferedImage.TYPE_INT_RGB);
        image.setRGB(1, 1, 0x112233);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        if (!ImageIO.write(image, "jpg", out)) {
            throw new IllegalStateException("ImageIO JPEG writer missing");
        }
        return out.toByteArray();
    }

    private static byte[] truncatedJpeg() {
        return new byte[]{(byte) 0xFF, (byte) 0xD8, (byte) 0xFF, (byte) 0xE0, 0x00, 0x10};
    }

    private static byte[] pdf() {
        return ("%PDF-1.4\n" + " ".repeat(40) + "1 0 obj<</Type/Catalog>>endobj\nstartxref\n9\n%%EOF\n")
                .getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    }

    private static byte[] zip() throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(out)) {
            zip.putNextEntry(new ZipEntry("note.txt"));
            zip.write("<w/>".getBytes(java.nio.charset.StandardCharsets.UTF_8));
            zip.closeEntry();
        }
        return out.toByteArray();
    }

    private static byte[] gzip() throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (GZIPOutputStream gz = new GZIPOutputStream(out)) {
            gz.write("aegis".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        }
        return out.toByteArray();
    }

    @SuppressWarnings("unused")
    private static void touch(ByteArrayInputStream in) {
    }
}
