package org.sleuthkit.autopsy.aegis.engine;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.sleuthkit.autopsy.aegis.util.AegisJson.AegisJsonObject;

/**
 * Process bridge from the AEGIS desktop to the AEGIS Variant engine.
 *
 * <p>The engine is a packaged CPython 3.11 runtime running
 * {@code aegis_engine_cli.py}, which calls the Variant's own acquisition,
 * recovery, sanitization, ledger and report code. Every command is one child
 * process speaking a JSON-lines protocol on stdout (HELLO, PROGRESS, LOG,
 * RESULT); stderr is the engine's structured log and is written to a file.
 * Cancellation writes {@code CANCEL} to the child's stdin so the engine closes
 * its generator and ledgers what it had done; the process is only destroyed if
 * it does not exit after that.
 *
 * <p>All methods block and must never run on the Swing event dispatch thread.
 */
public final class EngineBridge {

    private static final Logger LOG = Logger.getLogger(EngineBridge.class.getName());
    private static final EngineBridge INSTANCE = new EngineBridge();
    private static final DateTimeFormatter STAMP = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss");

    private volatile EngineResult health;
    private volatile Layout layout;

    public static EngineBridge get() {
        return INSTANCE;
    }

    private EngineBridge() {
    }

    /** Where the engine pieces live. */
    public static final class Layout {

        public Path home;
        public Path python;
        public Path cli;
        public Path libewf;
        public String problem = "";

        public boolean usable() {
            return problem.isBlank();
        }
    }

    /**
     * Cancellation handle for one running command. Cancelling creates a flag
     * file the engine checks between steps; the engine then closes its
     * generator, which ledgers what had been done. The engine never reads
     * stdin (a blocked pipe read deadlocks DLL loading on Windows).
     */
    public static final class Cancel {

        private final Path flag;
        private volatile boolean requested;

        public Cancel() {
            Path f;
            try {
                f = Files.createTempFile("aegis-cancel-", ".flag");
                Files.deleteIfExists(f);
            } catch (IOException ex) {
                f = Path.of(System.getProperty("java.io.tmpdir"), "aegis-cancel-" + System.nanoTime() + ".flag");
            }
            flag = f;
        }

        public void request() {
            requested = true;
            try {
                Files.writeString(flag, "CANCEL");
            } catch (IOException ex) {
                LOG.log(Level.WARNING, "Could not create the cancel flag " + flag, ex);
            }
        }

        public boolean requested() {
            return requested;
        }

        Path flag() {
            return flag;
        }

        void cleanup() {
            try {
                Files.deleteIfExists(flag);
            } catch (IOException ignored) {
                // temp file; the OS cleans it up
            }
        }
    }

    // ------------------------------------------------------------------
    // Layout resolution
    // ------------------------------------------------------------------

    /**
     * Resolves the engine home. Order: system property {@code aegis.engine.home},
     * environment {@code AEGIS_ENGINE_HOME}, then {@code aegis-engine} beside the
     * installation (the packaged layout), then the development bundle.
     */
    public synchronized Layout layout() {
        if (layout != null) {
            return layout;
        }
        List<Path> candidates = new ArrayList<>();
        addCandidate(candidates, System.getProperty("aegis.engine.home"));
        addCandidate(candidates, System.getenv("AEGIS_ENGINE_HOME"));
        String nbHome = System.getProperty("netbeans.home");
        if (nbHome != null) {
            Path install = Path.of(nbHome).toAbsolutePath().getParent();
            if (install != null) {
                candidates.add(install.resolve("aegis-engine"));
                if (install.getParent() != null) {
                    candidates.add(install.getParent().resolve("aegis-engine"));
                }
            }
        }
        String user = System.getProperty("user.dir");
        if (user != null) {
            Path dir = Path.of(user).toAbsolutePath();
            for (int i = 0; i < 5 && dir != null; i++, dir = dir.getParent()) {
                candidates.add(dir.resolve("aegis-engine"));
                candidates.add(dir.resolve("working").resolve("engine-home"));
            }
        }
        Layout found = null;
        for (Path home : candidates) {
            Layout l = probe(home);
            if (l.usable()) {
                found = l;
                break;
            }
            if (found == null && Files.isDirectory(home)) {
                found = l;
            }
        }
        if (found == null) {
            found = new Layout();
            found.problem = "The AEGIS engine was not found. Expected an 'aegis-engine' folder beside the AEGIS installation "
                    + "(or set AEGIS_ENGINE_HOME).";
        }
        layout = found;
        LOG.info("AEGIS engine layout: home=" + found.home + " usable=" + found.usable() + " " + found.problem);
        return found;
    }

    private static void addCandidate(List<Path> list, String value) {
        if (value != null && !value.isBlank()) {
            list.add(Path.of(value.trim()));
        }
    }

    private static Layout probe(Path home) {
        Layout l = new Layout();
        l.home = home.toAbsolutePath().normalize();
        l.python = l.home.resolve("runtime").resolve("python311").resolve("python.exe");
        l.cli = l.home.resolve("engine").resolve("aegis_engine_cli.py");
        l.libewf = l.home.resolve("runtime").resolve("libewf");
        if (!Files.isRegularFile(l.python)) {
            l.problem = "Engine runtime missing: " + l.python;
        } else if (!Files.isRegularFile(l.cli)) {
            l.problem = "Engine bridge missing: " + l.cli;
        }
        return l;
    }

    // ------------------------------------------------------------------
    // Health
    // ------------------------------------------------------------------

    /** Cached health. Runs the engine's health command on first use. */
    public EngineResult health() {
        EngineResult h = health;
        if (h == null) {
            h = run("health", List.of(), null, null, null, 120);
            health = h;
        }
        return h;
    }

    public EngineResult refreshHealth() {
        health = null;
        return health();
    }

    public boolean available() {
        return health().succeeded();
    }

    // ------------------------------------------------------------------
    // Running commands
    // ------------------------------------------------------------------

    /**
     * Runs one engine command.
     *
     * @param command    bridge subcommand
     * @param args       arguments after the subcommand
     * @param stateDir   per-case AEGIS state directory (ledger, jobs, reports); null for the default
     * @param listener   progress listener (may be null)
     * @param cancel     cancellation handle (may be null)
     * @param timeoutSec hard timeout; 0 means none (long operations)
     */
    public EngineResult run(String command, List<String> args, Path stateDir, EngineProgress.Listener listener,
            Cancel cancel, long timeoutSec) {
        Layout l = layout();
        if (!l.usable()) {
            return EngineResult.unavailable(command, l.problem,
                    "Reinstall AEGIS so the aegis-engine folder is present beside the application.");
        }
        List<String> cmd = new ArrayList<>();
        cmd.add(l.python.toString());
        cmd.add("-X");
        cmd.add("utf8");
        cmd.add("-u");
        cmd.add(l.cli.toString());
        cmd.add(command);
        if (stateDir != null) {
            cmd.add("--state");
            cmd.add(stateDir.toString());
        }
        if (cancel != null) {
            cmd.add("--cancel-file");
            cmd.add(cancel.flag().toString());
        }
        cmd.addAll(args);
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectInput(ProcessBuilder.Redirect.from(new java.io.File("NUL")));
        pb.directory(l.cli.getParent().toFile());
        Map<String, String> env = pb.environment();
        env.put("AEGIS_LIBEWF_DIR", l.libewf.toString());
        env.put("PYTHONNOUSERSITE", "1");
        env.put("PYTHONDONTWRITEBYTECODE", "1");
        env.put("PYTHONIOENCODING", "utf-8");
        env.remove("PYTHONPATH");
        env.remove("PYTHONHOME");
        Path logDir = logDir(stateDir);
        Path errLog = logDir.resolve("engine-" + command + "-" + LocalDateTime.now().format(STAMP) + ".log");
        pb.redirectError(errLog.toFile());

        EngineResult result = new EngineResult();
        result.command = command;
        result.stderrLog = errLog.toString();
        Process process;
        try {
            Files.createDirectories(logDir);
            process = pb.start();
        } catch (IOException ex) {
            return EngineResult.unavailable(command, "The engine could not be started: " + ex.getMessage(),
                    "Check that the packaged engine runtime is intact.");
        }
        boolean sawResult = false;
        Thread watchdog = null;
        if (timeoutSec > 0) {
            final Process p = process;
            watchdog = new Thread(() -> {
                try {
                    if (!p.waitFor(timeoutSec, TimeUnit.SECONDS)) {
                        LOG.warning("Engine command " + command + " exceeded " + timeoutSec + "s; terminating.");
                        p.destroyForcibly();
                    }
                } catch (InterruptedException ignored) {
                    Thread.currentThread().interrupt();
                }
            }, "aegis-engine-watchdog");
            watchdog.setDaemon(true);
            watchdog.start();
        }
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8), 1 << 16)) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (!line.startsWith("{")) {
                    continue;
                }
                AegisJsonObject evt;
                try {
                    evt = AegisJsonObject.parseStrict(line);
                } catch (IllegalArgumentException ex) {
                    LOG.log(Level.WARNING, "Malformed engine line ignored: " + abbreviate(line), ex);
                    continue;
                }
                String type = evt.optString("AEGIS_EVENT", "");
                switch (type) {
                    case "HELLO" -> result.operationId = evt.optString("operation_id", "");
                    case "PROGRESS" -> {
                        if (listener != null) {
                            listener.progress(new EngineProgress(evt.optString("phase", ""), evt.optDouble("pct", 0),
                                    evt.optLong("bytes_done", 0), evt.optLong("bytes_total", 0),
                                    evt.optLong("throughput", 0), evt.optLong("eta", 0), evt.optString("message", "")));
                        }
                    }
                    case "LOG" -> {
                        if (listener != null) {
                            listener.log(evt.optString("level", "INFO"), evt.optString("message", ""));
                        }
                    }
                    case "RESULT" -> {
                        sawResult = true;
                        result.status = evt.optString("status", "FAILED");
                        result.operationId = evt.optString("operation_id", result.operationId);
                        AegisJsonObject r = evt.optJSONObject("result");
                        result.result = r == null ? new AegisJsonObject() : r;
                        // The engine's job id is the identity of the recorded operation.
                        if (!result.result.optString("job_id").isBlank()) {
                            result.operationId = result.result.optString("job_id");
                        }
                        result.warnings.addAll(evt.optStringList("warnings"));
                        AegisJsonObject err = evt.optJSONObject("error");
                        if (err != null) {
                            result.errorType = err.optString("type", "");
                            result.errorMessage = err.optString("message", "");
                            result.remediation = err.optString("remediation", "");
                        }
                    }
                    default -> {
                    }
                }
            }
        } catch (IOException ex) {
            LOG.log(Level.WARNING, "Engine output stream failed for " + command, ex);
        }
        try {
            if (!process.waitFor(30, TimeUnit.SECONDS)) {
                process.destroyForcibly();
            }
            result.exitCode = process.exitValue();
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            process.destroyForcibly();
        } catch (IllegalThreadStateException ignored) {
            // still alive after destroy request
        }
        if (watchdog != null) {
            watchdog.interrupt();
        }
        if (cancel != null) {
            cancel.cleanup();
        }
        if (!sawResult) {
            result.status = cancel != null && cancel.requested() ? "CANCELLED" : "FAILED";
            result.errorType = "EngineProtocol";
            result.errorMessage = "The engine exited (code " + result.exitCode + ") without reporting a result. "
                    + "Engine log: " + errLog + tail(errLog);
        }
        return result;
    }

    private static Path logDir(Path stateDir) {
        if (stateDir != null) {
            return stateDir.resolve("logs");
        }
        String local = System.getenv("LOCALAPPDATA");
        Path base = local != null ? Path.of(local) : Path.of(System.getProperty("user.home", "."));
        return base.resolve("AEGIS").resolve("engine-logs");
    }

    private static String tail(Path log) {
        try {
            List<String> lines = Files.readAllLines(log, StandardCharsets.UTF_8);
            int from = Math.max(0, lines.size() - 4);
            return lines.isEmpty() ? "" : " | " + String.join(" / ", lines.subList(from, lines.size()));
        } catch (IOException ex) {
            return "";
        }
    }

    private static String abbreviate(String s) {
        return s.length() > 200 ? s.substring(0, 200) + "…" : s;
    }

    /** Drains a stream on a daemon thread (used by tests and auxiliary processes). */
    static void drain(InputStream in) {
        Thread t = new Thread(() -> {
            try (in) {
                in.transferTo(OutputStream.nullOutputStream());
            } catch (IOException ignored) {
                // nothing to do
            }
        }, "aegis-engine-drain");
        t.setDaemon(true);
        t.start();
    }
}
