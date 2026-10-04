package org.sleuthkit.autopsy.aegis.purge;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.sleuthkit.autopsy.aegis.SanitizerBridge;
import org.sleuthkit.autopsy.aegis.SanitizerProtocol;
import org.sleuthkit.autopsy.aegis.audit.AuditLedgerService;

/**
 * AEGIS Deep Forensic Purge — discovers Windows thumbnail cache DBs and sanitizes
 * unlocked copies via FileShredder. Uses Restart Manager coordination when the
 * native helper supports it; otherwise reports locked files without force-killing Explorer.
 */
public final class DeepPurgeService {

    private static final Logger LOG = Logger.getLogger(DeepPurgeService.class.getName());

    public static final class ArtifactRecord {
        public Path path;
        public String kind = "thumbcache";
        public boolean sanitized;
        public boolean locked;
        public String note = "";
    }

    public static final class Result {
        public final List<ArtifactRecord> artifacts = new ArrayList<>();
        public boolean success;
        public String message = "";
    }

    private final AuditLedgerService ledger;
    private final SanitizerBridge bridge = new SanitizerBridge();

    public DeepPurgeService(AuditLedgerService ledger) {
        this.ledger = Objects.requireNonNull(ledger);
    }

    public List<Path> discoverWindowsThumbcaches() {
        List<Path> found = new ArrayList<>();
        String local = System.getenv("LOCALAPPDATA");
        if (local == null || local.isBlank()) {
            return found;
        }
        Path explorer = Path.of(local, "Microsoft", "Windows", "Explorer");
        if (Files.isDirectory(explorer)) {
            addGlob(found, explorer, "thumbcache_*.db");
            addGlob(found, explorer, "iconcache_*.db");
        }
        return found;
    }

    /**
     * Additional desktop artifact classes (discover + classify; sanitize only when writable files).
     */
    public List<Path> discoverSecondaryArtifacts() {
        List<Path> found = new ArrayList<>();
        String appData = System.getenv("APPDATA");
        String local = System.getenv("LOCALAPPDATA");
        if (appData != null && !appData.isBlank()) {
            Path recent = Path.of(appData, "Microsoft", "Windows", "Recent");
            addGlob(found, recent, "*.lnk");
            Path automatic = Path.of(appData, "Microsoft", "Windows", "Recent", "AutomaticDestinations");
            addGlob(found, automatic, "*.automaticDestinations-ms");
            Path custom = Path.of(appData, "Microsoft", "Windows", "Recent", "CustomDestinations");
            addGlob(found, custom, "*.customDestinations-ms");
        }
        if (local != null && !local.isBlank()) {
            Path quickLook = Path.of(local, "Microsoft", "Windows", "Explorer");
            addGlob(found, quickLook, "thumbcache_*.db");
        }
        return found;
    }

    private static void addGlob(List<Path> found, Path dir, String glob) {
        if (dir == null || !Files.isDirectory(dir)) {
            return;
        }
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(dir, glob)) {
            for (Path p : stream) {
                found.add(p);
            }
        } catch (IOException ex) {
            LOG.log(Level.FINE, "Artifact discovery skipped for " + dir + "/" + glob, ex);
        }
    }

    /**
     * Attempt graceful RM unlock via PowerShell/.NET Restart Manager is complex;
     * we try sanitizing each DB and record locked failures honestly.
     */
    public Result purgeDiscovered(String caseId, String operator) {
        Result result = new Result();
        List<Path> targets = new ArrayList<>(discoverWindowsThumbcaches());
        // Secondary artifacts are discovered and reported; only regular writable files are sanitized.
        List<Path> secondary = discoverSecondaryArtifacts();
        for (Path p : secondary) {
            if (!targets.contains(p)) {
                targets.add(p);
            }
        }
        if (targets.isEmpty()) {
            result.success = true;
            result.message = "No thumbcache/iconcache/recent/jump-list artifacts discovered under user profile paths.";
            ledger.append(caseId, "deeppurge.empty", result.message);
            return result;
        }
        // Coordinate Explorer via Restart Manager using a short PowerShell script when possible.
        tryCoordinateExplorer(targets);
        int ok = 0;
        for (Path target : targets) {
            ArtifactRecord rec = new ArtifactRecord();
            rec.path = target;
            try {
                if (!Files.isWritable(target)) {
                    rec.locked = true;
                    rec.note = "Not writable (likely locked by Explorer). Not force-killed.";
                    result.artifacts.add(rec);
                    ledger.append(caseId, "deeppurge.locked", target.toString());
                    continue;
                }
                SanitizerBridge.Request req = new SanitizerBridge.Request();
                req.target = target;
                req.directory = false;
                req.method = "zero";
                req.passes = 1;
                req.caseId = caseId == null ? "" : caseId;
                req.operator = operator == null ? "" : operator;
                Path tmp = Files.createTempDirectory("aegis-deeppurge");
                req.auditPath = tmp.resolve("audit.json");
                req.reportPath = tmp.resolve("report.txt");
                SanitizerBridge.Outcome outcome = bridge.run(req, (SanitizerProtocol p) -> { });
                rec.sanitized = outcome.verifiedSuccess();
                rec.note = outcome.status + (outcome.message == null ? "" : (": " + outcome.message));
                if (rec.sanitized) {
                    ok++;
                } else if ("FAILED".equalsIgnoreCase(outcome.status)
                        && outcome.message != null
                        && outcome.message.toLowerCase(Locale.ROOT).contains("denied")) {
                    rec.locked = true;
                }
                result.artifacts.add(rec);
                ledger.append(caseId, rec.sanitized ? "deeppurge.sanitized" : "deeppurge.failed",
                        target + " => " + rec.note);
            } catch (Exception ex) {
                rec.locked = true;
                rec.note = ex.getMessage() == null ? ex.getClass().getSimpleName() : ex.getMessage();
                result.artifacts.add(rec);
                ledger.append(caseId, "deeppurge.error", target + " => " + rec.note);
            }
        }
        result.success = !result.artifacts.isEmpty() && ok == result.artifacts.size();
        result.message = "Deep Purge processed " + result.artifacts.size() + " artifact(s); sanitized=" + ok
                + ". Locked artifacts are reported, not force-cleared. An empty discovery is not a successful purge.";
        return result;
    }

    private void tryCoordinateExplorer(List<Path> targets) {
        // Register the files with Restart Manager and request a graceful shutdown of holders.
        // RmForceShutdown is not set. Explorer is not killed with taskkill. RmRestart follows.
        StringBuilder paths = new StringBuilder();
        for (Path target : targets) {
            if (paths.length() > 0) {
                paths.append("','");
            }
            paths.append(target.toAbsolutePath().toString().replace("'", "''"));
        }
        String script = ""
                + "$ErrorActionPreference='Stop'; "
                + "Add-Type -TypeDefinition @'\n"
                + "using System;\nusing System.Runtime.InteropServices;\n"
                + "public static class AegisRm {\n"
                + "  [DllImport(\"rstrtmgr.dll\", CharSet=CharSet.Unicode)] public static extern int RmStartSession(out uint pSession, int dwFlags, string key);\n"
                + "  [DllImport(\"rstrtmgr.dll\", CharSet=CharSet.Unicode)] public static extern int RmRegisterResources(uint h, uint nFiles, string[] files, uint nApps, IntPtr apps, uint nSvc, string[] svcs);\n"
                + "  [DllImport(\"rstrtmgr.dll\")] public static extern int RmShutdown(uint h, int flags, IntPtr cb);\n"
                + "  [DllImport(\"rstrtmgr.dll\")] public static extern int RmRestart(uint h, int flags, IntPtr cb);\n"
                + "  [DllImport(\"rstrtmgr.dll\")] public static extern int RmEndSession(uint h);\n"
                + "}\n'@; "
                + "$key = [guid]::NewGuid().ToString('N').Substring(0,31); "
                + "$session = [uint32]0; "
                + "$start = [AegisRm]::RmStartSession([ref]$session, 0, $key); "
                + "if ($start -ne 0) { Write-Output \"RM_START=$start\"; exit 0 }; "
                + "$files = @('" + paths + "'); "
                + "$reg = [AegisRm]::RmRegisterResources($session, [uint32]$files.Length, $files, 0, [IntPtr]::Zero, 0, $null); "
                + "$shut = [AegisRm]::RmShutdown($session, 0, [IntPtr]::Zero); "
                + "$restart = [AegisRm]::RmRestart($session, 0, [IntPtr]::Zero); "
                + "[void][AegisRm]::RmEndSession($session); "
                + "Write-Output \"RM_REG=$reg;RM_SHUT=$shut;RM_RESTART=$restart\"";
        try {
            ProcessBuilder pb = new ProcessBuilder(
                    "powershell.exe", "-NoProfile", "-NonInteractive",
                    "-ExecutionPolicy", "Bypass", "-Command", script);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String output = new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            p.waitFor(20, TimeUnit.SECONDS);
            ledger.append("", "deeppurge.coordinate", output.isBlank() ? "Restart Manager returned no text." : output.trim());
        } catch (Exception ex) {
            LOG.log(Level.FINE, "Restart Manager coordination failed", ex);
            ledger.append("", "deeppurge.coordinate", "Restart Manager was not completed: " + ex.getMessage()
                    + ". Explorer was not force-killed.");
        }
    }
}
