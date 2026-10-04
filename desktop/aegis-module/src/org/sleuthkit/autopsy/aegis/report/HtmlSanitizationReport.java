package org.sleuthkit.autopsy.aegis.report;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.sleuthkit.autopsy.aegis.audit.AuditLedgerService;

/**
 * AEGIS-native HTML sanitization/operation report (visual language aligned with tokens).
 */
public final class HtmlSanitizationReport {

    public Path write(Path output, Map<String, String> fields, AuditLedgerService ledger) throws IOException {
        StringBuilder html = new StringBuilder();
        html.append("<!DOCTYPE html><html><head><meta charset='utf-8'><title>AEGIS Report</title>");
        html.append("<style>");
        html.append("body{font-family:Segoe UI,Arial,sans-serif;background:#F8FAFC;color:#1F2937;margin:0;padding:32px;}");
        html.append("h1{color:#0F2747;font-size:28px;margin:0 0 8px;}");
        html.append("h2{color:#0F2747;font-size:18px;border-bottom:1px solid #E5EAF0;padding-bottom:6px;}");
        html.append(".card{background:#fff;border:1px solid #E5EAF0;border-radius:8px;padding:16px 20px;margin:16px 0;}");
        html.append(".muted{color:#64748B;} .ok{color:#10B981;} .warn{color:#F59E0B;} .err{color:#EF4444;}");
        html.append("table{border-collapse:collapse;width:100%;} td,th{border:1px solid #E5EAF0;padding:8px;text-align:left;font-size:13px;}");
        html.append("</style></head><body>");
        html.append("<h1>AEGIS</h1>");
        html.append("<div class='muted'>DIGITAL FORENSICS &amp; SECURE DATA SANITIZATION · ")
                .append(esc(Instant.now().toString())).append("</div>");

        section(html, "1. Executive Summary", fields.getOrDefault("executive", "Operation recorded."));
        section(html, "2. Operation Identity", kv(fields, "operationId", "operator", "started", "ended"));
        section(html, "3. Case / Evidence", kv(fields, "caseId", "evidenceId"));
        section(html, "4. Target Identity", kv(fields, "target", "targetType"));
        section(html, "5. Device Identity", kv(fields, "model", "serial", "capacity", "physicalPath"));
        section(html, "6. Filesystem", kv(fields, "filesystem"));
        section(html, "7. Device Capability Analysis", fields.getOrDefault("capabilities", "See operation notes."));
        section(html, "8. Sanitization Method", kv(fields, "method", "passes"));
        section(html, "9. Method Rationale", fields.getOrDefault("rationale", "Selected by operator within AEGIS policy."));
        section(html, "10. Execution Details", kv(fields, "status", "bytes"));
        section(html, "11. Passes", kv(fields, "passes"));
        section(html, "12. Bytes Processed", kv(fields, "bytes"));
        section(html, "13. Slack Handling", fields.getOrDefault("slack", "SLACK: NOT VERIFIED. File shredding does not report cluster slack separately."));
        section(html, "14. Metadata Handling", fields.getOrDefault("metadata",
                "Filesystem metadata, document metadata, and image metadata were not separately stripped. A file-content overwrite includes bytes inside the file and does not claim MFT or directory cleanup."));
        section(html, "15. TRIM / Discard", fields.getOrDefault("trim", "TRIM/DISCARD: NOT ISSUED by this logical-overwrite path."));
        section(html, "16. Verification", kv(fields, "verification"));
        section(html, "17. Verification Scope", scopeTable(fields.getOrDefault("verificationScope",
                "FILE CONTENT: NOT VERIFIED | SLACK: NOT VERIFIED | UNALLOCATED: NOT VERIFIED | NAND: NOT VERIFIED | SNAPSHOT: NOT VERIFIED | CLOUD COPY: NOT VERIFIED")));
        section(html, "18. Hashes", kv(fields, "sha256", "ledgerTip"));
        section(html, "19. Secondary Artifacts", fields.getOrDefault("secondaryArtifacts", "None recorded."));
        section(html, "20. Residual Risk", fields.getOrDefault("residualRisk",
                "Logical overwrite does not verify NAND remapping, VSS, cloud copies, or unallocated space unless explicitly in scope."));
        section(html, "21. Audit Timeline", ledgerTable(ledger));
        section(html, "22. Warnings", fields.getOrDefault("warnings", "—"));
        section(html, "23. Errors", fields.getOrDefault("errors", "—"));
        section(html, "24. Technical Details", fields.getOrDefault("technical", "See the audit payload column."));
        section(html, "25. Forensic Interpretation", fields.getOrDefault("finalInterpretation", "Interpret the result only inside the verification scope."));
        section(html, "26. Final Result", kv(fields, "status"));
        String signedBlock = signBlock(fields, ledger);
        section(html, "27. Cryptographic Integrity",
                "Ledger algorithm SHA-256. Chain verified=" + ledger.verifyChain()
                        + ". This report is tamper-evident for the hash chain. It is not described as tamper-proof.");
        section(html, "28. Signature", signedBlock);
        section(html, "29. Verification Certificate",
                "Recompute SHA-256 over the canonical payload (ledger tip, operation id, status, target) and verify the Ed25519 signature with the embedded public key. "
                        + "A matching signature shows that payload was not altered after signing. It does not widen the verification scope.");

        html.append("</body></html>");
        Files.writeString(output, html.toString(), StandardCharsets.UTF_8);
        return output;
    }

    private static void section(StringBuilder html, String title, String body) {
        html.append("<div class='card'><h2>").append(esc(title)).append("</h2>")
                .append("<div>").append(body).append("</div></div>");
    }

    private static String kv(Map<String, String> fields, String... keys) {
        StringBuilder sb = new StringBuilder("<table>");
        for (String k : keys) {
            sb.append("<tr><th>").append(esc(k)).append("</th><td>")
                    .append(esc(fields.getOrDefault(k, "—"))).append("</td></tr>");
        }
        sb.append("</table>");
        return sb.toString();
    }

    private static String scopeTable(String scope) {
        StringBuilder sb = new StringBuilder("<table><tr><th>Scope</th><th>Result</th></tr>");
        for (String part : scope.split("\\|")) {
            String[] pair = part.split(":", 2);
            String name = pair[0].trim();
            String value = pair.length > 1 ? pair[1].trim() : "—";
            sb.append("<tr><td>").append(esc(name)).append("</td><td>").append(esc(value)).append("</td></tr>");
        }
        sb.append("</table>");
        return sb.toString();
    }

    private static String signBlock(java.util.Map<String, String> fields, AuditLedgerService ledger) {
        String payload = ledger.tipHash() + "|" + fields.getOrDefault("operationId", "")
                + "|" + fields.getOrDefault("status", "") + "|" + fields.getOrDefault("target", "");
        try {
            org.sleuthkit.autopsy.aegis.audit.ReportSigner.Signed signed = new org.sleuthkit.autopsy.aegis.audit.ReportSigner().sign(payload);
            return "<table><tr><th>Algorithm</th><td>" + esc(signed.algorithm) + "</td></tr>"
                    + "<tr><th>Payload SHA-256</th><td>" + esc(signed.payloadSha256) + "</td></tr>"
                    + "<tr><th>Signature</th><td>" + esc(signed.signatureBase64) + "</td></tr>"
                    + "<tr><th>Public key</th><td>" + esc(signed.publicKeyBase64) + "</td></tr>"
                    + "<tr><th>Self-check</th><td>" + signed.verified + "</td></tr>"
                    + "<tr><th>Canonical payload</th><td>" + esc(payload) + "</td></tr></table>";
        } catch (Exception ex) {
            return "Signature was not produced: " + esc(ex.getMessage());
        }
    }

    private static String ledgerTable(AuditLedgerService ledger) {
        List<AuditLedgerService.Entry> entries = ledger.snapshot();
        StringBuilder sb = new StringBuilder("<table><tr><th>Time</th><th>Type</th><th>Payload</th><th>Hash</th></tr>");
        for (AuditLedgerService.Entry e : entries) {
            sb.append("<tr><td>").append(esc(e.at.toString())).append("</td><td>")
                    .append(esc(e.type)).append("</td><td>")
                    .append(esc(e.payload)).append("</td><td class='muted'>")
                    .append(esc(e.hash.substring(0, Math.min(16, e.hash.length())))).append("…</td></tr>");
        }
        sb.append("</table>");
        return sb.toString();
    }

    private static String esc(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }
}
