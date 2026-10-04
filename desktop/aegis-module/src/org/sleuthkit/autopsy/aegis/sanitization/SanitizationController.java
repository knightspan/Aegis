package org.sleuthkit.autopsy.aegis.sanitization;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.ExecutionException;
import java.util.function.Consumer;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import org.sleuthkit.autopsy.aegis.SanitizerBridge;
import org.sleuthkit.autopsy.aegis.SanitizerProtocol;
import org.sleuthkit.autopsy.aegis.audit.AuditLedgerService;
import org.sleuthkit.autopsy.aegis.engine.AegisEngine;
import org.sleuthkit.autopsy.aegis.engine.EngineResult;
import org.sleuthkit.autopsy.aegis.util.AegisJson;
import org.sleuthkit.autopsy.aegis.report.HtmlSanitizationReport;
import org.sleuthkit.autopsy.casemodule.Case;
import org.sleuthkit.autopsy.casemodule.NoCurrentCaseException;
import org.sleuthkit.datamodel.Report;
import org.sleuthkit.datamodel.TskCoreException;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Orchestrates sanitization jobs. Re-validates eligibility before every run.
 */
public final class SanitizationController {

    private final SanitizerBridge bridge = new SanitizerBridge();
    private final DeviceEligibilityService eligibility = new DeviceEligibilityService();
    private final SanitizationUIState state;
    private Path cancelFile;
    private SwingWorker<SanitizerBridge.Outcome, SanitizerProtocol> worker;
    private String registrationMessage = "";
    private long lastProgressUiMs;

    public SanitizationController(SanitizationUIState state) {
        this.state = state;
    }

    public DeviceEligibilityService eligibility() {
        return eligibility;
    }

    public SanitizationUIState state() {
        return state;
    }

    public void refreshCaseContext() {
        if (Case.isCaseOpen()) {
            try {
                state.setCaseName(Case.getCurrentCaseThrows().getDisplayName());
            } catch (NoCurrentCaseException ex) {
                state.setCaseName("");
            }
        } else {
            state.setCaseName("");
        }
    }

    public void inspectTargetAsync(Path path, TargetType type, Runnable onDone) {
        eligibility.invalidate(path);
        SwingWorker<DeviceClassification, Void> inspect = new SwingWorker<>() {
            @Override
            protected DeviceClassification doInBackground() {
                return eligibility.classify(path, type);
            }

            @Override
            protected void done() {
                try {
                    DeviceClassification classification = get();
                    state.setClassification(classification);
                    if (type.requiresRemovableMedia()) {
                        state.setVolumeDiskEligible(classification.eligibility().isAllowed()
                                && DeviceEligibilityService.ENGINE_SUPPORTS_VOLUME_OR_DISK);
                    }
                } catch (InterruptedException ex) {
                    Thread.currentThread().interrupt();
                } catch (ExecutionException ex) {
                    state.setClassification(DeviceClassification.builder(DeviceClassification.Kind.INVALID)
                            .eligibility(DeviceEligibility.UNKNOWN)
                            .reason("Inspection failed: " + ex.getCause().getMessage())
                            .build());
                }
                if (onDone != null) {
                    onDone.run();
                }
            }
        };
        inspect.execute();
    }

    public void startSanitization() {
        if (worker != null && !worker.isDone()) {
            return;
        }
        SanitizerBridge.Request request = buildRequest();
        if (request == null) {
            return;
        }
        state.setStep(SanitizationUIState.Step.EXECUTION);
        state.setPhase("Starting");
        state.setProgressPercent(0);
        state.setTimes(now(), "");
        state.setResult(false, "", "");

        worker = new SwingWorker<>() {
            @Override
            protected SanitizerBridge.Outcome doInBackground() throws Exception {
                return bridge.run(request, this::publish);
            }

            @Override
            protected void process(java.util.List<SanitizerProtocol> chunks) {
                long now = System.currentTimeMillis();
                // Throttle progress UI so the EDT is not flooded during long overwrites.
                boolean force = now - lastProgressUiMs >= 120;
                SanitizerProtocol last = null;
                for (SanitizerProtocol event : chunks) {
                    if (event.getKind() == SanitizerProtocol.Kind.PROGRESS) {
                        last = event;
                    }
                }
                if (last == null || !force) {
                    return;
                }
                lastProgressUiMs = now;
                applyProgress(last);
            }

            @Override
            protected void done() {
                state.setTimes(state.startTime(), now());
                try {
                    SanitizerBridge.Outcome outcome = get();
                    // Paint the Result page immediately; case registration can block and must
                    // not freeze the EDT after a successful sanitization.
                    showOutcome(outcome, "Case registration: pending…");
                    finalizeRegistrationAsync(outcome);
                } catch (InterruptedException ex) {
                    Thread.currentThread().interrupt();
                    state.setResult(false, "SANITIZATION FAILED", "Interrupted. Not a successful sanitization.");
                    state.setStep(SanitizationUIState.Step.RESULT);
                } catch (ExecutionException ex) {
                    state.setResult(false, "SANITIZATION FAILED",
                            ex.getCause() == null ? ex.getMessage() : ex.getCause().getMessage());
                    state.setStep(SanitizationUIState.Step.RESULT);
                }
            }
        };
        lastProgressUiMs = 0;
        worker.execute();
    }

    private void applyProgress(SanitizerProtocol event) {
        String percent = event.get("percentage");
        if (percent != null) {
            try {
                state.setProgressPercent(Math.max(0, Math.min(100, Double.parseDouble(percent))));
            } catch (NumberFormatException ignored) {
            }
        }
        String phase = event.get("phase");
        String pass = event.get("current_pass");
        String totalPasses = event.get("total_passes");
        state.setPhase((phase == null ? "Working" : phase)
                + (pass == null ? "" : "  pass " + pass + "/" + totalPasses));
        state.setProgressDetail(
                nullToDash(event.get("bytes_completed")),
                nullToDash(event.get("bytes_total")),
                nullToDash(event.get("rate")));
    }

    private void finalizeRegistrationAsync(SanitizerBridge.Outcome outcome) {
        boolean auditOk = state.auditPath() != null && Files.isRegularFile(state.auditPath());
        boolean reportOk = state.reportPath() != null && Files.isRegularFile(state.reportPath());
        SwingWorker<String, Void> registration = new SwingWorker<>() {
            @Override
            protected String doInBackground() {
                recordInCaseLedger(outcome);
                return registerWithCase(outcome, reportOk, auditOk);
            }

            @Override
            protected void done() {
                try {
                    registrationMessage = get();
                } catch (InterruptedException ex) {
                    Thread.currentThread().interrupt();
                    registrationMessage = "Case registration: interrupted.";
                } catch (ExecutionException ex) {
                    registrationMessage = "Case registration failed: "
                            + (ex.getCause() == null ? ex.getMessage() : ex.getCause().getMessage());
                }
                String detail = state.resultDetail();
                if (detail != null && detail.contains("Case registration: pending")) {
                    String caseLine = registrationMessage.contains("registration failed") ? "FAILED"
                            : registrationMessage.contains("not attempted") ? "SKIPPED" : "REGISTERED";
                    detail = detail
                            .replace("Case Report: PENDING", "Case Report: " + caseLine)
                            .replace("Case registration: pending…", registrationMessage)
                            .replace("Case registration: pending...", registrationMessage);
                    state.setResult(state.resultSuccess(), state.resultTitle(), detail);
                }
            }
        };
        registration.execute();
    }

    public void requestCancel() {
        if (cancelFile != null) {
            bridge.requestCancel(cancelFile);
        }
        state.setPhase("Cancellation requested. This will not be reported as success.");
    }

    public String registrationMessage() {
        return registrationMessage;
    }

    public SanitizerBridge.Outcome runAsConfirmedFile(Path target) throws Exception {
        java.util.concurrent.atomic.AtomicReference<SanitizerBridge.Request> ref = new java.util.concurrent.atomic.AtomicReference<>();
        java.util.concurrent.atomic.AtomicReference<String> error = new java.util.concurrent.atomic.AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            state.setTargetType(TargetType.FILE);
            state.setTargetPath(target);
            state.setMethod(SanitizationUIState.supportedMethods().get(0));
            state.setConfirmed(true);
            state.setReadBackVerification(true);
            DeviceClassification classification = eligibility.classify(target, TargetType.FILE);
            state.setClassification(classification);
            SanitizerBridge.Request request = buildRequest();
            if (request == null) {
                error.set(state.resultDetail());
            } else {
                ref.set(request);
            }
        });
        if (ref.get() == null) {
            throw new IllegalStateException(error.get() == null ? "Sanitization was not started." : error.get());
        }
        SanitizerBridge.Outcome outcome = bridge.run(ref.get(), null);
        SwingUtilities.invokeAndWait(() -> {
            showOutcome(outcome, "Case registration: pending…");
            finalizeRegistrationAsync(outcome);
        });
        return outcome;
    }

    private SanitizerBridge.Request buildRequest() {
        TargetType type = state.targetType();
        Path target = state.targetPath();
        if (target == null) {
            state.setResult(false, "SANITIZATION FAILED", "Choose a file or folder first. There is no default target.");
            return null;
        }
        if (!state.confirmed()) {
            state.setResult(false, "SANITIZATION FAILED", "Confirmation is required before a destructive operation.");
            return null;
        }
        if (!eligibility.mayExecute(target, type)) {
            DeviceClassification classification = state.classification();
            String detail = classification != null && !classification.reason().isBlank()
                    ? classification.reason()
                    : DeviceEligibilityService.usbOnlyMessage();
            state.setResult(false, "SANITIZATION FAILED", detail + " No command was run.");
            state.setStep(SanitizationUIState.Step.RESULT);
            return null;
        }
        if (type == TargetType.FOLDER && DeviceEligibilityService.isBlockedDirectory(target)) {
            state.setResult(false, "SANITIZATION FAILED",
                    "Refusing the Windows directory or a volume root. No sanitizer process was started.");
            state.setStep(SanitizationUIState.Step.RESULT);
            return null;
        }
        boolean deviceTarget = type == TargetType.VOLUME || type == TargetType.PHYSICAL_DISK;
        if (deviceTarget) {
            // The C++ volume/disk wipe cannot bind a device identity and cannot prove a
            // drive is removable. Device sanitization runs only through the engine's
            // identity-bound, removable-media-only workflow; this path is refused.
            state.setResult(false, "SANITIZATION REFUSED", "Volume and disk sanitization run only in the Physical Device "
                    + "workflow, which accepts removable USB/SD media and refuses every internal drive. No command was run.");
            state.setStep(SanitizationUIState.Step.RESULT);
            return null;
        }
        if (!deviceTarget && !Files.exists(target)) {
            state.setResult(false, "SANITIZATION FAILED", "Target does not exist: " + target);
            state.setStep(SanitizationUIState.Step.RESULT);
            return null;
        }

        SanitizationUIState.MethodChoice method = state.method();
        SanitizerBridge.Request request = new SanitizerBridge.Request();
        request.target = resolveWipeTarget(target, type);
        request.directory = !deviceTarget && (type == TargetType.FOLDER || Files.isDirectory(target));
        request.wipeDisk = deviceTarget;
        request.method = method == null ? "zero" : method.cli;
        request.passes = state.passes();
        request.zeroFill = true;
        try {
            cancelFile = Files.createTempFile("aegis-cancel-", ".flag");
            Files.deleteIfExists(cancelFile);
        } catch (IOException ex) {
            state.setResult(false, "SANITIZATION FAILED", "Could not create a cancellation flag: " + ex.getMessage());
            state.setStep(SanitizationUIState.Step.RESULT);
            return null;
        }
        request.cancelFile = cancelFile;
        Path outputDir = outputDirectory();
        String stamp = Long.toString(System.currentTimeMillis());
        Path auditPath = outputDir.resolve("aegis-audit-" + stamp + ".json");
        Path reportPath = outputDir.resolve("aegis-report-" + stamp + ".txt");
        request.auditPath = auditPath;
        request.reportPath = reportPath;
        state.setAuditPath(auditPath);
        state.setReportPath(reportPath);
        if (Case.isCaseOpen()) {
            try {
                request.caseId = Case.getCurrentCaseThrows().getName();
            } catch (NoCurrentCaseException ex) {
                request.caseId = "";
            }
        }
        request.operator = System.getProperty("user.name", "");
        return request;
    }

    /**
     * Maps UI volume roots (E:\\) to Windows volume device paths (\\\\.\\E:) for wipe-disk.
     * Physical paths are passed through unchanged.
     */
    private static Path resolveWipeTarget(Path target, TargetType type) {
        if (target == null) {
            return null;
        }
        if (type == TargetType.PHYSICAL_DISK) {
            return target;
        }
        if (type != TargetType.VOLUME) {
            return target;
        }
        String text = target.toAbsolutePath().normalize().toString().replace('/', '\\');
        if (text.startsWith("\\\\.\\") || text.toLowerCase(java.util.Locale.ROOT).contains("physicaldrive")) {
            return target;
        }
        if (text.length() >= 2 && Character.isLetter(text.charAt(0)) && text.charAt(1) == ':') {
            char letter = Character.toUpperCase(text.charAt(0));
            return Path.of("\\\\.\\" + letter + ":");
        }
        return target;
    }

    private void showOutcome(SanitizerBridge.Outcome outcome, String registrationStatus) {
        boolean auditOk = state.auditPath() != null && Files.isRegularFile(state.auditPath());
        boolean reportOk = state.reportPath() != null && Files.isRegularFile(state.reportPath());
        boolean sanitizerOk = outcome.verifiedSuccess();
        boolean fullySuccessful = sanitizerOk && auditOk && reportOk;
        state.setOperationId(outcome.operationId == null ? "" : outcome.operationId);
        registrationMessage = registrationStatus == null ? "" : registrationStatus;

        StringBuilder detail = new StringBuilder();
        if (fullySuccessful) {
            detail.append("Verification: PASSED\n");
            detail.append("Audit Record: CREATED\n");
            detail.append("Case Report: ").append(registrationMessage.contains("registration failed") ? "FAILED"
                    : registrationMessage.contains("pending") ? "PENDING" : "REGISTERED").append('\n');
        } else if (sanitizerOk) {
            detail.append("The sanitizer status was ").append(outcome.status)
                    .append(" but the audit or human-readable report was not written. This is not a fully successful operation.\n");
        } else {
            detail.append("Status: ").append(outcome.status).append('\n');
            detail.append("Exit code: ").append(outcome.exitCode).append('\n');
        }
        if (outcome.message != null && !outcome.message.isBlank()) {
            detail.append(outcome.message).append('\n');
        }
        detail.append("Operation ID: ").append(outcome.operationId == null ? "—" : outcome.operationId).append('\n');
        detail.append("Start Time: ").append(state.startTime()).append('\n');
        detail.append("End Time: ").append(state.endTime()).append('\n');
        detail.append("Bytes Processed: ").append(state.bytesCompleted()).append(" / ").append(state.bytesTotal()).append('\n');
        detail.append(registrationMessage).append('\n');
        detail.append("Logical overwrite does not guarantee SSD, flash, snapshot, or metadata destruction.\n");

        Path htmlPath = null;
        try {
            htmlPath = writeHtmlReport(outcome, fullySuccessful);
            if (htmlPath != null) {
                detail.append("HTML Report: ").append(htmlPath).append('\n');
                state.setReportPath(htmlPath);
            }
        } catch (IOException ex) {
            detail.append("HTML Report: failed (").append(ex.getMessage()).append(")\n");
        }

        if (fullySuccessful) {
            state.setResult(true, "SANITIZATION COMPLETE", detail.toString());
        } else {
            state.setResult(false, "SANITIZATION FAILED", detail.toString());
        }
        state.setStep(SanitizationUIState.Step.RESULT);
    }

    private Path writeHtmlReport(SanitizerBridge.Outcome outcome, boolean fullySuccessful) throws IOException {
        Path outputDir = outputDirectory();
        Path html = outputDir.resolve("aegis-report-" + System.currentTimeMillis() + ".html");
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("executive", fullySuccessful
                ? "Sanitization completed within the stated logical-overwrite scope."
                : "Sanitization did not complete successfully.");
        fields.put("operationId", outcome.operationId == null ? "" : outcome.operationId);
        fields.put("operator", System.getProperty("user.name", ""));
        fields.put("started", state.startTime());
        fields.put("ended", state.endTime());
        fields.put("caseId", state.caseName());
        fields.put("evidenceId", "—");
        fields.put("target", state.targetPath() == null ? "—" : state.targetPath().toString());
        fields.put("targetType", state.targetType() == null ? "—" : state.targetType().name());
        DeviceClassification c = state.classification();
        if (c != null) {
            fields.put("model", c.deviceIdentity());
            fields.put("filesystem", c.fileSystem());
            fields.put("capacity", c.sizeBytes() >= 0 ? Long.toString(c.sizeBytes()) : "—");
            fields.put("serial", "—");
            fields.put("physicalPath", c.deviceIdentity());
            fields.put("capabilities", "removable=" + c.removable() + "; usb=" + c.usb()
                    + "; system=" + c.systemDisk() + "; boot=" + c.bootDisk());
        }
        SanitizationUIState.MethodChoice method = state.method();
        fields.put("method", method == null ? "—" : method.cli);
        fields.put("passes", Integer.toString(state.passes()));
        fields.put("rationale", method == null ? "—" : method.label);
        fields.put("status", outcome.status);
        fields.put("bytes", state.bytesCompleted() + " / " + state.bytesTotal());
        fields.put("verification", state.verificationSummary());
        fields.put("verificationScope", "FILE CONTENT: "
                + (fullySuccessful ? "VERIFIED" : "NOT VERIFIED")
                + " | SLACK: NOT VERIFIED | UNALLOCATED: NOT VERIFIED | NAND: NOT VERIFIED | SNAPSHOT: NOT VERIFIED | CLOUD COPY: NOT VERIFIED");
        fields.put("sha256", "See audit ledger tip");
        fields.put("finalInterpretation", fullySuccessful
                ? "Logical overwrite completed for the selected target scope."
                : "Do not treat this run as a successful sanitization.");
        fields.put("residualRisk",
                "Logical overwrite does not verify NAND remapping, VSS, cloud copies, or unallocated space unless explicitly in scope.");
        AuditLedgerService ledger = AuditLedgerService.shared();
        ledger.append(state.caseName(), "sanitization.result", outcome.status + " " + outcome.message);
        fields.put("ledgerTip", ledger.tipHash());
        return new HtmlSanitizationReport().write(html, fields, ledger);
    }

    private String registerWithCase(SanitizerBridge.Outcome outcome, boolean reportOk, boolean auditOk) {
        if (!reportOk) {
            return "Case registration: not attempted because the sanitization report file is missing.";
        }
        if (!Case.isCaseOpen()) {
            return "Case registration: not attempted because no case is open. Files were not added to a case.";
        }
        try {
            Case current = Case.getCurrentCaseThrows();
            Report human = current.addReport(state.reportPath().toString(), "AEGIS Sanitization",
                    "AEGIS sanitization " + outcome.status, null);
            StringBuilder message = new StringBuilder();
            message.append("Case registration: human report id ").append(human.getId());
            if (auditOk) {
                Report audit = current.addReport(state.auditPath().toString(), "AEGIS Sanitization",
                        "AEGIS audit " + outcome.operationId, null);
                message.append("; audit report id ").append(audit.getId());
            } else {
                message.append("; audit file missing so it was not registered");
            }
            return message.toString();
        } catch (NoCurrentCaseException | TskCoreException ex) {
            return "Sanitization status was " + outcome.status + ", but case report registration failed: " + ex.getMessage();
        }
    }

    private Path outputDirectory() {
        if (Case.isCaseOpen()) {
            try {
                Path reports = Path.of(Case.getCurrentCaseThrows().getReportDirectory());
                Files.createDirectories(reports);
                return reports;
            } catch (NoCurrentCaseException | IOException ex) {
                // Fall through.
            }
        }
        try {
            Path dir = Path.of(System.getProperty("java.io.tmpdir"), "aegis-reports");
            Files.createDirectories(dir);
            return dir;
        } catch (IOException ex) {
            return Path.of(System.getProperty("java.io.tmpdir"));
        }
    }

    private static String now() {
        return LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
    }

    private static String nullToDash(String value) {
        return value == null || value.isBlank() ? "—" : value;
    }

    public void openPath(Path path, Consumer<String> onError) {
        if (path == null || !Files.isRegularFile(path)) {
            if (onError != null) {
                onError.accept("The file is not available.");
            }
            return;
        }
        // Desktop.open can block on Windows file associations — never call it on the EDT.
        new Thread(() -> {
            try {
                java.awt.Desktop.getDesktop().open(path.toFile());
            } catch (IOException ex) {
                if (onError != null) {
                    SwingUtilities.invokeLater(() -> onError.accept(ex.getMessage()));
                }
            }
        }, "aegis-open-path").start();
    }

    /** The file or folder the last verified sanitization erased, for the trace sweep. */
    private Path lastErased;
    private boolean lastErasedDirectory;

    /** Appends the C++ sanitizer outcome to the open case's hash-chained ledger (aegis.desktop.*). */
    private void recordInCaseLedger(SanitizerBridge.Outcome outcome) {
        Path target = state.targetPath();
        if (outcome != null && outcome.verifiedSuccess() && target != null && !Files.exists(target)) {
            lastErased = target;
            lastErasedDirectory = state.targetType() == TargetType.FOLDER;
        }
        try {
            AegisJson.AegisJsonObject params = new AegisJson.AegisJsonObject()
                    .put("target", target == null ? "" : target.toString())
                    .put("target_type", state.targetType() == null ? "" : state.targetType().name())
                    .put("method", state.method() == null ? "" : state.method().cli)
                    .put("passes", state.passes())
                    .put("engine", "AEGIS C++ sanitizer (aegis_cli.exe)")
                    .put("operation_id", outcome == null ? "" : outcome.operationId)
                    .put("audit", state.auditPath() == null ? "" : state.auditPath().toString())
                    .put("report", state.reportPath() == null ? "" : state.reportPath().toString());
            AegisJson.AegisJsonObject result = new AegisJson.AegisJsonObject()
                    .put("status", outcome == null ? "FAILED" : outcome.status)
                    .put("verified", outcome != null && outcome.verifiedSuccess())
                    .put("exit_code", outcome == null ? -1 : outcome.exitCode)
                    .put("message", outcome == null ? "" : outcome.message);
            AegisEngine.record("aegis.desktop.sanitize.file", params, result);
        } catch (RuntimeException ex) {
            java.util.logging.Logger.getLogger(SanitizationController.class.getName())
                    .log(java.util.logging.Level.WARNING, "Case ledger record failed", ex);
        }
    }

    /**
     * Deep Forensic Purge through the AEGIS Variant trace sweep: Recent
     * shortcuts, jump lists and Recycle Bin items the engine ties on evidence to
     * the path just erased are removed; weaker matches are reported, not touched.
     * The Windows thumbnail cache cannot be tied to one path, so clearing it is a
     * separate explicit opt-in (Restart Manager coordinated, nothing force-killed).
     */
    public void startDeepPurge(Consumer<String> onDone) {
        startDeepPurge(false, onDone);
    }

    public void startDeepPurge(boolean includeThumbnailCache, Consumer<String> onDone) {
        final Path erased = lastErased;
        final boolean directory = lastErasedDirectory;
        state.setPhase("Deep Forensic Purge: sweeping secondary artifacts…");
        new SwingWorker<String[], Void>() {
            @Override
            protected String[] doInBackground() {
                StringBuilder detail = new StringBuilder();
                boolean ok = true;
                if (erased == null) {
                    detail.append("No verified file or folder sanitization in this session, so there is no erased path to sweep for. ")
                            .append("Sanitize a target first; Deep Forensic Purge then removes the traces the host kept of it.\n");
                    ok = false;
                } else {
                    EngineResult r = AegisEngine.traces(java.util.List.of(erased), directory, false, "", null);
                    detail.append("Trace sweep for ").append(erased).append(": ").append(r.summary()).append('\n');
                    if (r.succeeded()) {
                        AegisJson.AegisJsonObject sweep = r.result.object("sweep");
                        for (AegisJson.AegisJsonObject t : sweep.array("traces").objects()) {
                            detail.append(" • ").append(t.optString("kind")).append(": ").append(t.optString("location"))
                                    .append(" → ").append(t.optBoolean("removed", false) ? "REMOVED"
                                    : t.optBoolean("report_only", false) ? "REPORTED ONLY (" + t.optString("report_only_reason") + ")"
                                    : t.optString("error", "NOT REMOVED")).append('\n');
                        }
                        detail.append("Searched: ").append(String.join("; ", sweep.optStringList("searched"))).append('\n');
                        detail.append("Not searched on this platform: ").append(String.join("; ", sweep.optStringList("not_searched"))).append('\n');
                        if (sweep.array("traces").length() == 0) {
                            detail.append("No trace of the erased path was found in the places searched.\n");
                        }
                    } else {
                        ok = false;
                    }
                }
                if (includeThumbnailCache) {
                    EngineResult t = AegisEngine.thumbcache(false);
                    detail.append("Thumbnail cache: ").append(t.summary()).append(" — cleared ")
                            .append(t.result.optLong("cleared", 0)).append(", not cleared ").append(t.result.optLong("failed", 0)).append('\n');
                    for (String w : t.warnings) {
                        detail.append("   ").append(w).append('\n');
                    }
                    ok = ok && t.succeeded();
                }
                return new String[]{ok ? "1" : "0", detail.toString()};
            }

            @Override
            protected void done() {
                try {
                    String[] r = get();
                    boolean success = "1".equals(r[0]);
                    state.setResult(success, success ? "DEEP FORENSIC PURGE COMPLETE" : "DEEP FORENSIC PURGE INCOMPLETE", r[1]);
                    state.setStep(SanitizationUIState.Step.RESULT);
                    if (onDone != null) {
                        onDone.accept(r[1]);
                    }
                } catch (InterruptedException ex) {
                    Thread.currentThread().interrupt();
                } catch (ExecutionException ex) {
                    if (onDone != null) {
                        onDone.accept(ex.getCause() == null ? ex.getMessage() : ex.getCause().getMessage());
                    }
                }
            }
        }.execute();
    }
}
