package org.sleuthkit.autopsy.aegis.engine;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Typed entry points over {@link EngineBridge}, one per bridge command. Every
 * call is bound to the open case's workspace, case id and operator. All calls
 * block: run them from a SwingWorker or another background thread.
 */
public final class AegisEngine {

    private AegisEngine() {
    }

    private static List<String> common() {
        List<String> a = new ArrayList<>();
        String caseId = CaseWorkspace.caseId();
        if (!caseId.isBlank()) {
            a.add("--case-id");
            a.add(b64(caseId));
        }
        a.add("--operator");
        a.add(b64(CaseWorkspace.operator()));
        return a;
    }

    private static EngineResult run(String command, List<String> args, EngineProgress.Listener l,
            EngineBridge.Cancel c, long timeout) {
        return EngineBridge.get().run(command, args, CaseWorkspace.stateDir(), l, c, timeout);
    }

    public static EngineResult devices() {
        return run("devices", common(), null, null, 180);
    }

    /** Request for a read-only acquisition. */
    public static final class AcquireRequest {

        public String source;
        public Path destination;
        public String format = "raw";
        public String expectedSerial = "";
        public long expectedSize;
        public int sectorSize = 512;
        public String evidenceNumber = "";
        public String description = "";
        public String notes = "";
        public String deviceModel = "";
    }

    public static EngineResult acquire(AcquireRequest r, EngineProgress.Listener l, EngineBridge.Cancel c) {
        List<String> a = common();
        a.addAll(List.of("--source", r.source, "--dest", r.destination.toString(), "--format", r.format,
                "--sector-size", Integer.toString(r.sectorSize), "--examiner", b64(CaseWorkspace.operator())));
        if (r.expectedSerial != null && !r.expectedSerial.isBlank()) {
            a.addAll(List.of("--expected-serial", b64(r.expectedSerial)));
        }
        if (r.expectedSize > 0) {
            a.addAll(List.of("--expected-size", Long.toString(r.expectedSize)));
        }
        addIf(a, "--evidence-number", r.evidenceNumber);
        addIf(a, "--description", r.description);
        addIf(a, "--notes", r.notes);
        addIf(a, "--device-model", r.deviceModel);
        return run("acquire", a, l, c, 0);
    }

    public static EngineResult verifyImage(String jobId, EngineProgress.Listener l) {
        List<String> a = common();
        a.addAll(List.of("--job-id", jobId));
        return run("verify-image", a, l, null, 0);
    }

    public static EngineResult recover(Path image, String sourceJob, boolean undelete, boolean carve,
            boolean mediaMap, EngineProgress.Listener l, EngineBridge.Cancel c) {
        return recover(image, sourceJob, undelete, carve, mediaMap, true, l, c);
    }

    public static EngineResult recover(Path image, String sourceJob, boolean undelete, boolean carve,
            boolean mediaMap, boolean writeCopies, EngineProgress.Listener l, EngineBridge.Cancel c) {
        List<String> a = common();
        a.addAll(List.of("--image", image.toString()));
        addIf(a, "--source-job", sourceJob);
        if (!undelete) {
            a.add("--no-undelete");
        }
        if (!carve) {
            a.add("--no-carve");
        }
        if (!mediaMap) {
            a.add("--no-media-map");
        }
        if (!writeCopies) {
            a.add("--no-write");
        }
        return run("recover", a, l, c, 0);
    }

    public static EngineResult prepareDevice(String deviceId, String typedSerial) {
        List<String> a = common();
        a.addAll(List.of("--device", deviceId, "--typed-serial", b64(typedSerial)));
        return run("prepare-device", a, null, null, 300);
    }

    /** Request for a destructive device sanitization. Every gate is re-checked by the engine. */
    public static final class SanitizeRequest {

        public String deviceId;
        public String typedSerial;
        public String expectedSerial;
        public long expectedSize;
        public String level = "CLEAR";
        public String overwriteMethod = "";
        public String backupJob = "";
        public String waiveBackup = "";
        public boolean confirmDestructive;
    }

    public static EngineResult sanitizeDevice(SanitizeRequest r, EngineProgress.Listener l, EngineBridge.Cancel c) {
        List<String> a = common();
        a.addAll(List.of("--device", r.deviceId, "--typed-serial", b64(r.typedSerial), "--level", r.level));
        addIf(a, "--expected-serial", r.expectedSerial);
        if (r.expectedSize > 0) {
            a.addAll(List.of("--expected-size", Long.toString(r.expectedSize)));
        }
        addIf(a, "--overwrite-method", r.overwriteMethod);
        addIf(a, "--backup-job", r.backupJob);
        addIf(a, "--waive-backup", r.waiveBackup);
        if (r.confirmDestructive) {
            a.add("--confirm-destructive");
        }
        return run("sanitize-device", a, l, c, 0);
    }

    public static EngineResult traces(List<Path> erased, boolean directory, boolean findOnly, String sourceJob,
            EngineProgress.Listener l) {
        List<String> a = common();
        for (Path p : erased) {
            a.add("--erased");
            a.add(p.toString());
        }
        if (directory) {
            a.add("--directory");
        }
        if (findOnly) {
            a.add("--find-only");
        }
        addIf(a, "--source-job", sourceJob);
        return run("traces", a, l, null, 900);
    }

    public static EngineResult thumbcache(boolean findOnly) {
        List<String> a = common();
        if (findOnly) {
            a.add("--find-only");
        }
        return run("thumbcache", a, null, null, 600);
    }

    public static EngineResult ledgerVerify() {
        return run("ledger-verify", common(), null, null, 600);
    }

    public static EngineResult ledgerList(String job) {
        List<String> a = common();
        addIf(a, "--job", job);
        return run("ledger-list", a, null, null, 600);
    }

    /** Appends a desktop event ({@code aegis.desktop.*}) to the open case's hash-chained ledger. */
    public static EngineResult record(String operation, org.sleuthkit.autopsy.aegis.util.AegisJson.AegisJsonObject params,
            org.sleuthkit.autopsy.aegis.util.AegisJson.AegisJsonObject result) {
        List<String> a = common();
        a.addAll(List.of("--operation", operation, "--params-json", b64(params == null ? "{}" : params.toString()),
                "--result-json", b64(result == null ? "{}" : result.toString())));
        return run("record", a, null, null, 120);
    }

    public static EngineResult report(String jobId) {
        List<String> a = common();
        a.addAll(List.of("--job-id", jobId));
        return run("report", a, null, null, 600);
    }

    public static EngineResult verifyReport(Path report) {
        List<String> a = common();
        a.addAll(List.of("--report", report.toString()));
        return run("verify-report", a, null, null, 600);
    }

    public static EngineResult enhance(Path input, String model, int scale, EngineProgress.Listener l,
            EngineBridge.Cancel c) {
        List<String> a = common();
        a.addAll(List.of("--input", input.toString(), "--model", model, "--scale", Integer.toString(scale)));
        return run("enhance", a, l, c, 0);
    }

    private static String b64(String json) {
        return "b64:" + java.util.Base64.getEncoder().encodeToString(json.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    /** Adds a free-text argument, base64-wrapped so Windows command-line quoting cannot alter it. */
    private static void addIf(List<String> a, String flag, String value) {
        if (value != null && !value.isBlank()) {
            a.add(flag);
            a.add(b64(value));
        }
    }
}
