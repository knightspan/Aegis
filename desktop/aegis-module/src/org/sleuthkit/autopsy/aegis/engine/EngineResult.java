package org.sleuthkit.autopsy.aegis.engine;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.sleuthkit.autopsy.aegis.util.AegisJson.AegisJsonObject;

/**
 * The structured outcome of one engine bridge command. Status words are the
 * bridge's own: SUCCESS, SUCCESS_WITH_WARNINGS, FAILED, BLOCKED, UNSUPPORTED,
 * UNAVAILABLE, CANCELLED. Nothing in the desktop may present an operation as
 * successful unless {@link #succeeded()} is true.
 */
public final class EngineResult {

    public String status = "UNAVAILABLE";
    public String command = "";
    public String operationId = "";
    public AegisJsonObject result = new AegisJsonObject();
    public final List<String> warnings = new ArrayList<>();
    public String errorType = "";
    public String errorMessage = "";
    public String remediation = "";
    public int exitCode = -1;
    public String stderrLog = "";

    public boolean succeeded() {
        return "SUCCESS".equals(status) || "SUCCESS_WITH_WARNINGS".equals(status);
    }

    public boolean blocked() {
        return "BLOCKED".equals(status);
    }

    public boolean cancelled() {
        return "CANCELLED".equals(status);
    }

    /** The full result written by the engine for large outputs, or the inline result. */
    public AegisJsonObject fullResult() {
        String file = result.optString("result_file", "");
        if (file.isBlank()) {
            return result;
        }
        try {
            AegisJsonObject job = AegisJsonObject.parseStrict(Files.readString(Path.of(file), StandardCharsets.UTF_8));
            AegisJsonObject inner = job.optJSONObject("result");
            return inner != null ? inner : job;
        } catch (Exception ex) {
            AegisJsonObject err = new AegisJsonObject();
            err.put("result_file_error", ex.getMessage());
            return err;
        }
    }

    /** One-line human summary for status labels and audit text. */
    public String summary() {
        if (succeeded()) {
            return warnings.isEmpty() ? status : status + " (" + warnings.size() + " warning(s))";
        }
        String msg = errorMessage == null || errorMessage.isBlank() ? "" : ": " + errorMessage;
        return status + (errorType.isBlank() ? "" : " [" + errorType + "]") + msg;
    }

    static EngineResult unavailable(String command, String message, String remediation) {
        EngineResult r = new EngineResult();
        r.command = command;
        r.status = "UNAVAILABLE";
        r.errorType = "EngineUnavailable";
        r.errorMessage = message;
        r.remediation = remediation == null ? "" : remediation;
        return r;
    }
}
