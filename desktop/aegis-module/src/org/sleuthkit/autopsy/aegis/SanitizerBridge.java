package org.sleuthkit.autopsy.aegis;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import org.openide.modules.InstalledFileLocator;

/**
 * Launches aegis_cli without a shell. Stdout events are parsed; a crash is never success.
 */
public final class SanitizerBridge {

    public static final class Request {
        public Path target;
        public boolean directory;
        /** When true, invoke wipe-disk (removable volume/physical only). */
        public boolean wipeDisk;
        public String method = "zero";
        public int passes = 1;
        public boolean zeroFill = true;
        public String caseId = "";
        public String operator = "";
        public Path auditPath;
        public Path reportPath;
        public Path cancelFile;
    }

    public static final class Outcome {
        public int exitCode = -1;
        public String status = "FAILED";
        public String operationId = "";
        public Path auditPath;
        public Path reportPath;
        public boolean auditWritten;
        public boolean reportWritten;
        public String message = "";
        public boolean processCrashed;

        public boolean verifiedSuccess() {
            return SanitizerProtocol.acceptExit(exitCode, status);
        }
    }

    private volatile Process process;
    private volatile boolean cancelRequested;

    public Path locateCli() {
        String property = System.getProperty("aegis.cli");
        if (property != null && !property.isBlank() && Files.isRegularFile(Path.of(property))) {
            return Path.of(property);
        }
        String env = System.getenv("AEGIS_CLI");
        if (env != null && !env.isBlank() && Files.isRegularFile(Path.of(env))) {
            return Path.of(env);
        }
        java.io.File installed = InstalledFileLocator.getDefault().locate(
                "bin/aegis_cli.exe", "org.sleuthkit.autopsy.aegis", false);
        if (installed != null && installed.isFile()) {
            return installed.toPath();
        }
        return null;
    }

    public Outcome run(Request request, Consumer<SanitizerProtocol> onEvent) throws IOException, InterruptedException {
        Path cli = locateCli();
        Outcome outcome = new Outcome();
        outcome.auditPath = request.auditPath;
        outcome.reportPath = request.reportPath;
        if (cli == null) {
            outcome.status = "FAILED";
            outcome.message = "aegis_cli.exe was not found. Set aegis.cli or AEGIS_CLI, or install the module binary.";
            return outcome;
        }
        List<String> command = new ArrayList<>();
        command.add(cli.toString());
        if (request.wipeDisk) {
            command.add("wipe-disk");
            command.add(request.target.toString());
            command.add("--force");
            command.add("--method");
            command.add(request.method == null || request.method.isBlank() ? "zero" : request.method);
            command.add("--passes");
            command.add(Integer.toString(Math.max(1, request.passes)));
            if (request.auditPath != null) {
                command.add("--audit");
                command.add(request.auditPath.toString());
            }
            if (request.reportPath != null) {
                command.add("--report");
                command.add(request.reportPath.toString());
            }
            if (request.caseId != null && !request.caseId.isBlank()) {
                command.add("--case-id");
                command.add(request.caseId);
            }
            if (request.operator != null && !request.operator.isBlank()) {
                command.add("--operator");
                command.add(request.operator);
            }
            if (request.cancelFile != null) {
                command.add("--cancel-file");
                command.add(request.cancelFile.toString());
            }
        } else {
            command.add("shred");
            command.add(request.target.toString());
            if (request.directory) {
                command.add("--recursive");
            }
            command.add("--method");
            command.add(request.method);
            command.add("--passes");
            command.add(Integer.toString(request.passes));
            if (!request.zeroFill) {
                command.add("--no-zero");
            }
            command.add("--audit");
            command.add(request.auditPath.toString());
            command.add("--report");
            command.add(request.reportPath.toString());
            if (request.caseId != null && !request.caseId.isBlank()) {
                command.add("--case-id");
                command.add(request.caseId);
            }
            if (request.operator != null && !request.operator.isBlank()) {
                command.add("--operator");
                command.add(request.operator);
            }
            if (request.cancelFile != null) {
                command.add("--cancel-file");
                command.add(request.cancelFile.toString());
            }
        }

        ProcessBuilder builder = new ProcessBuilder(command);
        builder.redirectErrorStream(false);
        process = builder.start();
        StringBuilder diagnostics = new StringBuilder();
        Thread stderr = new Thread(() -> drain(process.getErrorStream(), diagnostics), "aegis-cli-stderr");
        stderr.setDaemon(true);
        stderr.start();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                SanitizerProtocol event = SanitizerProtocol.parse(line);
                if (onEvent != null) {
                    onEvent.accept(event);
                }
                if (event.getKind() == SanitizerProtocol.Kind.RESULT) {
                    outcome.status = value(event, "status", "FAILED");
                    outcome.operationId = value(event, "operation_id", "");
                    outcome.auditWritten = "true".equals(event.get("audit_written"));
                    outcome.reportWritten = "true".equals(event.get("report_written"));
                    outcome.message = value(event, "message", "");
                }
            }
        }
        outcome.exitCode = process.waitFor();
        stderr.join(2000);
        if (diagnostics.length() > 0) {
            String text = diagnostics.toString().trim();
            if (text.length() > 2000) {
                text = text.substring(text.length() - 2000);
            }
            outcome.message = outcome.message == null || outcome.message.isBlank()
                    ? text
                    : outcome.message + "\n" + text;
        }
        if (cancelRequested) {
            outcome.status = "CANCELLED";
            outcome.message = "Cancellation was requested. The operation is not a successful sanitization.";
        } else if (outcome.exitCode != 0 && SanitizerProtocol.isSuccessfulStatus(outcome.status)) {
            outcome.status = "FAILED";
            outcome.processCrashed = true;
            outcome.message = "The sanitizer process exited " + outcome.exitCode + " after reporting a success status. Treated as failure.";
        } else if (outcome.status == null || outcome.status.isBlank() || "FAILED".equals(outcome.status) && outcome.exitCode < 0) {
            outcome.processCrashed = true;
            outcome.status = "FAILED";
        }
        if (!SanitizerProtocol.acceptExit(outcome.exitCode, outcome.status)) {
            outcome.status = outcome.status == null || outcome.status.isBlank() ? "FAILED" : outcome.status;
        }
        return outcome;
    }

    public void requestCancel(Path cancelFile) {
        cancelRequested = true;
        try {
            if (cancelFile != null) {
                Files.writeString(cancelFile, "cancel\n", StandardCharsets.UTF_8);
            }
        } catch (IOException ex) {
            // The process destroy below is the fallback.
        }
        Process current = process;
        if (current != null) {
            current.destroy();
        }
    }

    private static String value(SanitizerProtocol event, String key, String fallback) {
        String value = event.get(key);
        return value == null ? fallback : value;
    }

    private static void drain(java.io.InputStream stream, StringBuilder diagnostics) {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (diagnostics.length() < 8000) {
                    diagnostics.append(line).append('\n');
                }
            }
        } catch (IOException ex) {
            diagnostics.append("stderr closed: ").append(ex.getMessage()).append('\n');
        }
    }
}
