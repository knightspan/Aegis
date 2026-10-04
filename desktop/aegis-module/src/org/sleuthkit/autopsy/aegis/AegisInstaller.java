package org.sleuthkit.autopsy.aegis;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import javax.swing.SwingUtilities;
import org.openide.modules.ModuleInstall;
import org.openide.windows.WindowManager;
import org.sleuthkit.autopsy.casemodule.Case;
import org.sleuthkit.autopsy.casemodule.CaseDetails;
import org.sleuthkit.autopsy.ingest.IngestManager;
import org.sleuthkit.datamodel.Image;
import org.sleuthkit.datamodel.Report;

/**
 * Runs only when a live-test flag file exists. A normal startup does not
 * create a case or sanitize anything.
 */
public final class AegisInstaller extends ModuleInstall {

    private static final String FLAG_NAME = "aegis-phase4.live";

    @Override
    public void restored() {
        System.setProperty("aegis.product.shell", "true");
        WindowManager.getDefault().invokeWhenUIReady(() -> {
            org.sleuthkit.autopsy.aegis.ui.AegisShell.install();
            javax.swing.Timer retry = new javax.swing.Timer(600, event -> {
                if (org.sleuthkit.autopsy.aegis.ui.AegisShell.isInstalled()) {
                    ((javax.swing.Timer) event.getSource()).stop();
                    return;
                }
                org.sleuthkit.autopsy.aegis.ui.AegisShell.install();
            });
            retry.start();
            javax.swing.Timer stop = new javax.swing.Timer(20000, event -> retry.stop());
            stop.setRepeats(false);
            stop.start();
        });
        Path flag = Path.of(System.getProperty("java.io.tmpdir"), FLAG_NAME);
        if (!Files.isRegularFile(flag)) {
            return;
        }
        try {
            Files.deleteIfExists(flag);
        } catch (Exception ex) {
            return;
        }
        Thread worker = new Thread(this::runLiveCase, "aegis-phase4-live");
        worker.setDaemon(true);
        worker.start();
        Thread watchdog = new Thread(() -> {
            try {
                worker.join(8 * 60 * 1000L);
                if (worker.isAlive()) {
                    writeResult(2, List.of("RESULT: FAIL", "reason: timed out after 8 minutes"));
                    Runtime.getRuntime().halt(2);
                }
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
            }
        }, "aegis-phase4-watchdog");
        watchdog.setDaemon(true);
        watchdog.start();
    }

    private void runLiveCase() {
        List<String> lines = new ArrayList<>();
        int code = 2;
        try {
            CountDownLatch uiReady = new CountDownLatch(1);
            WindowManager.getDefault().invokeWhenUIReady(uiReady::countDown);
            if (!uiReady.await(2, TimeUnit.MINUTES)) {
                lines.add("ui_ready: false");
                lines.add(0, "RESULT: FAIL");
                writeResult(2, lines);
                Runtime.getRuntime().halt(2);
                return;
            }
            Thread.sleep(3000);
            boolean ingestBeforeCase = IngestManager.getInstance().isIngestRunning();
            lines.add("ingest_before_case: " + ingestBeforeCase);

            Path root = Path.of(System.getProperty("aegis.phase4.dir", System.getProperty("java.io.tmpdir")));
            String stamp = Long.toString(System.currentTimeMillis());
            Path caseDir = root.resolve("aegis-phase4-case-" + stamp);
            Files.createDirectories(caseDir);
            String displayName = "AEGIS-Phase4-" + stamp;
            lines.add("case_directory: " + caseDir);
            Case.createAsCurrentCase(Case.CaseType.SINGLE_USER_CASE, caseDir.toString(),
                    new CaseDetails(displayName, "P4-" + stamp, "phase4", "", "", "Disposable Phase 4 case. No real evidence."));
            Case current = Case.getCurrentCaseThrows();
            String caseName = current.getName();
            lines.add("case_open: " + Case.isCaseOpen());
            lines.add("case_name: " + caseName);
            lines.add("case_display_name: " + current.getDisplayName());
            lines.add("case_metadata: " + current.getMetadata().getFilePath());
            lines.add("report_directory: " + current.getReportDirectory());
            lines.add("ingest_after_case_open: " + IngestManager.getInstance().isIngestRunning());

            String imageProperty = System.getProperty("aegis.phase4.image", "");
            Path image = imageProperty.isBlank() ? null : Path.of(imageProperty);
            if (image != null && Files.isRegularFile(image)) {
                try {
                    var process = current.getSleuthkitCase().makeAddImageProcess("UTC", true, false, "");
                    process.run(UUID.randomUUID().toString(), new String[]{image.toString()}, 0);
                    long imageId = process.commit();
                    Image added = current.getSleuthkitCase().getImageById(imageId);
                    current.notifyDataSourceAdded(added, UUID.randomUUID());
                    lines.add("evidence_added: " + image);
                    lines.add("evidence_image_id: " + imageId);
                } catch (Exception ex) {
                    lines.add("evidence_added: FAILED " + ex);
                }
            } else {
                lines.add("evidence_added: skipped, disposable image not found");
            }
            lines.add("ingest_after_evidence: " + IngestManager.getInstance().isIngestRunning());

            SwingUtilities.invokeAndWait(() -> {
                SanitizationTopComponent workspace = SanitizationTopComponent.findInstance();
                workspace.open();
                workspace.requestActive();
            });
            lines.add("sanitization_workspace_opened: true");

            Path target = root.resolve("aegis-phase4-target-" + stamp + ".bin");
            Files.writeString(target, "AEGIS phase 4 disposable target\n", StandardCharsets.UTF_8);
            lines.add("target: " + target);
            lines.add("target_inside_case: " + target.startsWith(caseDir));
            lines.add("method: zero");

            SanitizationPanel panel = SanitizationTopComponent.findInstance().getPanel();
            String uiText = panel.runAsConfirmedFile(target);
            lines.add("ui_text_begin");
            lines.add(uiText);
            lines.add("ui_text_end");

            SanitizerBridge.Outcome outcome = panel.lastOutcome();
            lines.add("operation_id: " + (outcome == null ? "" : outcome.operationId));
            lines.add("native_status: " + (outcome == null ? "" : outcome.status));
            lines.add("exit_code: " + (outcome == null ? "" : outcome.exitCode));
            lines.add("registration: " + panel.registrationMessage());
            Path audit = panel.lastAuditPath();
            Path report = panel.lastReportPath();
            lines.add("audit_path: " + audit);
            lines.add("report_path: " + report);
            boolean auditInCase = audit != null && audit.startsWith(Path.of(current.getReportDirectory()));
            boolean reportInCase = report != null && report.startsWith(Path.of(current.getReportDirectory()));
            lines.add("audit_in_report_directory: " + auditInCase);
            lines.add("report_in_report_directory: " + reportInCase);

            String auditText = audit != null && Files.isRegularFile(audit) ? Files.readString(audit) : "";
            String reportText = report != null && Files.isRegularFile(report) ? Files.readString(report) : "";
            lines.add("audit_valid_json: " + looksLikeJson(auditText));
            lines.add("audit_contains_case_name: " + auditText.contains(caseName));
            lines.add("audit_contains_success: " + auditText.contains("\"status\": \"SUCCESS\""));
            lines.add("audit_contains_target: " + auditText.contains(target.getFileName().toString()));
            lines.add("report_contains_success: " + reportText.contains("SUCCESS"));
            lines.add("report_contains_target: " + reportText.contains(target.getFileName().toString()));
            lines.add("ingest_after_sanitization: " + IngestManager.getInstance().isIngestRunning());

            List<Report> reports = current.getAllReports();
            lines.add("reports_before_close: " + reports.size());
            boolean humanVisible = false;
            boolean auditVisible = false;
            for (Report item : reports) {
                lines.add("report_row: id=" + item.getId() + " name=" + item.getReportName() + " path=" + item.getPath());
                String path = item.getPath() == null ? "" : item.getPath();
                if (samePath(audit, path)) {
                    auditVisible = true;
                }
                if (samePath(report, path)) {
                    humanVisible = true;
                }
            }
            lines.add("human_report_visible: " + humanVisible);
            lines.add("audit_report_visible: " + auditVisible);

            String metadata = current.getMetadata().getFilePath().toString();
            Case.closeCurrentCase();
            lines.add("case_closed: " + !Case.isCaseOpen());
            Case.openAsCurrentCase(metadata);
            Case reopened = Case.getCurrentCaseThrows();
            lines.add("case_reopened: " + Case.isCaseOpen());
            lines.add("reopened_name: " + reopened.getName());
            boolean humanAfter = false;
            boolean auditAfter = false;
            for (Report item : reopened.getAllReports()) {
                lines.add("reopen_report_row: id=" + item.getId() + " name=" + item.getReportName() + " path=" + item.getPath());
                String path = item.getPath() == null ? "" : item.getPath();
                if (samePath(audit, path)) {
                    auditAfter = true;
                }
                if (samePath(report, path)) {
                    humanAfter = true;
                }
            }
            lines.add("human_report_after_reopen: " + humanAfter);
            lines.add("audit_report_after_reopen: " + auditAfter);

            boolean pass = Case.isCaseOpen()
                    && outcome != null
                    && "SUCCESS".equals(outcome.status)
                    && outcome.exitCode == 0
                    && auditInCase
                    && reportInCase
                    && looksLikeJson(auditText)
                    && auditText.contains(caseName)
                    && reportText.contains("SUCCESS")
                    && reportText.contains(target.getFileName().toString())
                    && humanVisible
                    && auditVisible
                    && humanAfter
                    && auditAfter
                    && !IngestManager.getInstance().isIngestRunning()
                    && panel.registrationMessage().startsWith("Case registration: human report id");
            lines.add(0, pass ? "RESULT: PASS" : "RESULT: FAIL");
            code = pass ? 0 : 2;
        } catch (Throwable ex) {
            lines.add(0, "RESULT: FAIL");
            lines.add("exception: " + ex);
            for (StackTraceElement frame : ex.getStackTrace()) {
                lines.add("  at " + frame);
            }
            code = 2;
        }
        writeResult(code, lines);
        Runtime.getRuntime().halt(code);
    }

    private static boolean samePath(Path expected, String stored) {
        if (expected == null || stored == null || stored.isBlank()) {
            return false;
        }
        try {
            return expected.toAbsolutePath().normalize().equals(Path.of(stored).toAbsolutePath().normalize());
        } catch (Exception ex) {
            return stored.equals(expected.toString());
        }
    }

    private static boolean looksLikeJson(String text) {
        if (text == null) {
            return false;
        }
        String trimmed = text.trim();
        return trimmed.startsWith("{") && trimmed.endsWith("}") && trimmed.contains("\"operation_id\"") && trimmed.contains("\"status\"");
    }

    private static void writeResult(int code, List<String> lines) {
        List<String> copy = new ArrayList<>(lines);
        copy.add("exit_code_for_harness: " + code);
        String text = String.join(System.lineSeparator(), copy) + System.lineSeparator();
        Path primary = Path.of(System.getProperty("java.io.tmpdir"), "aegis-phase4-result.txt");
        String copyTo = System.getProperty("aegis.phase4.result", "");
        try {
            Files.writeString(primary, text, StandardCharsets.UTF_8);
        } catch (Exception ignored) {
        }
        if (!copyTo.isBlank()) {
            try {
                Files.writeString(Path.of(copyTo), text, StandardCharsets.UTF_8);
            } catch (Exception ignored) {
            }
        }
    }
}
