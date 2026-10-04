import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import org.sleuthkit.autopsy.aegis.audit.AuditLedgerService;
import org.sleuthkit.autopsy.aegis.audit.ReportSigner;
import org.sleuthkit.autopsy.aegis.report.HtmlSanitizationReport;

/** Signs and independently verifies a disposable report, then confirms tampering is rejected. */
public final class ReportSignerSelfTest {

    public static void main(String[] args) throws Exception {
        Path dir = Files.createTempDirectory("aegis-signature-selftest-");
        try {
            Path report = dir.resolve("signed.html");
            AuditLedgerService ledger = new AuditLedgerService();
            ledger.append("fixture-test", "test.operation", "disposable fixture only");
            new HtmlSanitizationReport().write(report,
                    Map.of("operationId", "fixture-test", "status", "SUCCESS", "target", "fixture.bin"), ledger);

            ReportSigner signer = new ReportSigner();
            ReportSigner.Verification valid = signer.verifyHtmlReport(report);
            if (!valid.valid) throw new AssertionError("Valid report rejected: " + valid.message);

            String html = Files.readString(report, StandardCharsets.UTF_8);
            Files.writeString(report, html.replace("fixture-test|SUCCESS|fixture.bin", "fixture-test|FAILED|fixture.bin"),
                    StandardCharsets.UTF_8);
            ReportSigner.Verification tampered = signer.verifyHtmlReport(report);
            if (tampered.valid) throw new AssertionError("Tampered report was accepted.");
            System.out.println("PASS Ed25519 report verification and tamper rejection");
        } finally {
            try (var paths = Files.walk(dir)) {
                paths.sorted(java.util.Comparator.reverseOrder()).forEach(path -> {
                    try { Files.deleteIfExists(path); } catch (Exception ignored) { }
                });
            }
        }
    }
}
