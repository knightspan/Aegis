package org.sleuthkit.autopsy.aegis;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import org.sleuthkit.autopsy.aegis.util.AegisJson.AegisJsonArray;
import org.sleuthkit.autopsy.aegis.util.AegisJson.AegisJsonObject;

/**
 * Unified AEGIS Engine Bridge connecting the Java RCP Swing Desktop to the Python/Win32 engine.
 */
public final class AegisEngineBridge {

    private static final AegisEngineBridge INSTANCE = new AegisEngineBridge();

    public static AegisEngineBridge getInstance() {
        return INSTANCE;
    }

    private AegisEngineBridge() {}

    public Path locatePythonEngineScript() {
        String prop = System.getProperty("aegis.engine.script");
        if (prop != null && !prop.isBlank() && Files.isRegularFile(Path.of(prop))) {
            return Path.of(prop).toAbsolutePath();
        }
        String envScript = System.getenv("AEGIS_ENGINE_SCRIPT");
        if (envScript != null && !envScript.isBlank() && Files.isRegularFile(Path.of(envScript))) {
            return Path.of(envScript).toAbsolutePath();
        }
        List<Path> candidates = new ArrayList<>();
        String home = System.getenv("AEGIS_HOME");
        if (home != null && !home.isBlank()) {
            Path root = Path.of(home);
            candidates.add(root.resolve("external/aegis variant/aegis_engine_cli.py"));
            candidates.add(root.resolve("aegis-engine/aegis_engine_cli.py"));
        }
        Path cwd = Path.of(System.getProperty("user.dir", ".")).toAbsolutePath().normalize();
        candidates.add(cwd.resolve("external/aegis variant/aegis_engine_cli.py"));
        candidates.add(cwd.resolve("aegis-engine/aegis_engine_cli.py"));
        candidates.add(cwd.resolve("autopsy/aegis-engine/aegis_engine_cli.py"));
        candidates.add(cwd.resolve("../external/aegis variant/aegis_engine_cli.py"));
        candidates.add(cwd.resolve("../aegis-engine/aegis_engine_cli.py"));
        for (Path cand : candidates) {
            if (Files.isRegularFile(cand)) {
                return cand.toAbsolutePath();
            }
        }
        return null;
    }

    private AegisJsonObject runEngineCommand(List<String> args, Consumer<AegisJsonObject> eventListener) {
        Path script = locatePythonEngineScript();
        AegisJsonObject result = new AegisJsonObject();
        result.put("status", "UNAVAILABLE");

        if (script == null) {
            result.put("message", "The AEGIS Variant engine script was not found. Set AEGIS_ENGINE_SCRIPT or AEGIS_HOME.");
            return result;
        }

        List<String> cmd = new ArrayList<>();
        String python = System.getProperty("aegis.python");
        if (python == null || python.isBlank()) {
            python = System.getenv("AEGIS_PYTHON");
        }
        if (python == null || python.isBlank()) python = "python";
        cmd.add(python);
        cmd.add(script.toAbsolutePath().toString());
        cmd.addAll(args);

        ProcessBuilder pb = new ProcessBuilder(cmd);
        if (script != null) {
            pb.directory(script.getParent().toFile());
        }
        pb.redirectErrorStream(true);

        try {
            Process p = pb.start();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    line = line.trim();
                    if (line.startsWith("{") && line.contains("AEGIS_EVENT")) {
                        try {
                            AegisJsonObject json = new AegisJsonObject(line);
                            if (eventListener != null) {
                                eventListener.accept(json);
                            }
                            String evt = json.optString("AEGIS_EVENT", "");
                            if (evt.endsWith("_RESULT")) {
                                result = json;
                            }
                        } catch (Exception e) {
                            // ignore non-JSON lines
                        }
                    }
                }
            }
            int code = p.waitFor();
            if (code != 0 && !"SUCCESS".equals(result.optString("status", ""))
                    && !"SUCCESS_WITH_WARNINGS".equals(result.optString("status", ""))
                    && !"UNAVAILABLE".equals(result.optString("status", ""))) {
                result.put("status", "FAILED");
                result.put("exitCode", code);
            }
        } catch (Exception ex) {
            result.put("status", "UNAVAILABLE");
            result.put("message", ex.getMessage());
        }
        return result;
    }

    public AegisJsonArray enumerateDevices() {
        AegisJsonObject res = runEngineCommand(List.of("devices"), null);
        AegisJsonArray arr = res.optJSONArray("devices");
        return arr != null ? arr : new AegisJsonArray();
    }

    public AegisJsonObject acquireDiskImage(String source, String dest, String format, String hashAlgo, String caseId, String evidenceName, Consumer<AegisJsonObject> progressConsumer) {
        List<String> args = new ArrayList<>(List.of("acquire", source, dest, "--format", format, "--hash", hashAlgo, "--case-id", caseId, "--evidence-name", evidenceName));
        return runEngineCommand(args, progressConsumer);
    }

    public AegisJsonObject scanRecovery(String imagePath, Consumer<AegisJsonObject> progressConsumer) {
        return runEngineCommand(List.of("scan-recovery", imagePath), progressConsumer);
    }

    public AegisJsonObject sanitizeDevice(String targetPath, String serialConfirm, String method, int passes, Consumer<AegisJsonObject> progressConsumer) {
        List<String> args = List.of("sanitize-device", targetPath, "--serial", serialConfirm, "--method", method, "--passes", String.valueOf(passes));
        return runEngineCommand(args, progressConsumer);
    }

    public AegisJsonObject verifyReportSignature(String reportPath) {
        return runEngineCommand(List.of("verify-report", reportPath), null);
    }

    public AegisJsonObject verifyAuditLedger() {
        return runEngineCommand(List.of("verify-audit"), null);
    }

    public AegisJsonObject getOracleGraph(String caseId) {
        return runEngineCommand(List.of("oracle-graph", caseId), null);
    }

    public AegisJsonObject enhanceMedia(String inputPath, String outputPath) {
        return runEngineCommand(List.of("enhance-media", inputPath, outputPath), null);
    }
}
