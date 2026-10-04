package org.sleuthkit.autopsy.aegis.ui;

import java.awt.Component;
import java.awt.Container;
import java.awt.Window;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.function.BooleanSupplier;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.AbstractButton;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import org.sleuthkit.autopsy.aegis.engine.AegisEngine;
import org.sleuthkit.autopsy.aegis.engine.EngineResult;
import org.sleuthkit.autopsy.casemodule.Case;
import org.sleuthkit.autopsy.casemodule.CaseDetails;
import org.sleuthkit.autopsy.ingest.IngestJobSettings;
import org.sleuthkit.autopsy.ingest.IngestManager;

/**
 * End-to-end rehearsal driver, off unless {@code -J-Daegis.uidriver.out=<folder>}
 * and {@code -J-Daegis.uidriver.source=<evidence image>} are set.
 *
 * <p>It runs the demo workflow through the real application: it creates a
 * case, fills the Disk Imager fields as an operator would and presses the real
 * buttons, answers confirmation dialogs (logging their text), and so on through
 * Recovery, enhancement, file sanitization and Deep Forensic Purge, the
 * system-disk refusal, Reports, ORACLE, and a case close and reopen. Each stage
 * is captured as a PNG and every outcome is written to {@code driver-log.txt}.
 * It never selects or writes to a physical device.
 */
final class AegisUiDriver {

    private static final Logger LOG = Logger.getLogger(AegisUiDriver.class.getName());
    private static volatile boolean started;

    private final JFrame frame;
    private final AegisWorkspaceHost host;
    private final Path out;
    private final Path source;
    private final List<Step> steps = new ArrayList<>();
    private int index;
    private long stepStarted;
    private Path caseMeta;
    private Path photo;
    private final List<String> dialogs = new ArrayList<>();

    private record Step(String name, Runnable action, BooleanSupplier done, long timeoutMs) {
    }

    private AegisUiDriver(JFrame frame, AegisWorkspaceHost host, Path out, Path source) {
        this.frame = frame;
        this.host = host;
        this.out = out;
        this.source = source;
    }

    static void startIfRequested(JFrame frame, AegisWorkspaceHost host) {
        String dir = System.getProperty("aegis.uidriver.out", "");
        String src = System.getProperty("aegis.uidriver.source", "");
        if (dir.isBlank() || src.isBlank() || started) {
            return;
        }
        started = true;
        AegisUiDriver d = new AegisUiDriver(frame, host, Path.of(dir), Path.of(src));
        d.script();
        Timer t = new Timer(Integer.getInteger("aegis.uidriver.initial", 15000), e -> d.next());
        t.setRepeats(false);
        t.start();
        Timer dialogs = new Timer(400, e -> d.answerDialogs());
        dialogs.start();
    }

    // ------------------------------------------------------------------ script

    private void script() {
        String stamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss"));
        Path caseBase = Path.of(System.getProperty("aegis.uidriver.casebase", out.resolve("cases").toString()));
        String caseName = System.getProperty("aegis.uidriver.casename", "AEGIS-E2E-" + stamp);
        String caseNumber = System.getProperty("aegis.uidriver.casenumber", "CASE-" + stamp);
        String examiner = System.getProperty("aegis.uidriver.examiner", "AEGIS E2E Examiner");
        step("create case", () -> {
            new Thread(() -> {
                try {
                    Path dir = caseBase.resolve(caseName.replaceAll("[^A-Za-z0-9._-]", "_") + "-" + stamp);
                    Files.createDirectories(caseBase);
                    Case.createAsCurrentCase(Case.CaseType.SINGLE_USER_CASE, dir.toString(),
                            new CaseDetails(caseName, caseNumber, examiner, "", "", "Automated rehearsal"));
                    caseMeta = Path.of(Case.getCurrentCaseThrows().getMetadata().getFilePath().toString());
                    log("case created: " + caseMeta);
                } catch (Exception ex) {
                    log("FAIL create case: " + ex);
                }
            }, "aegis-driver-case").start();
        }, Case::isCaseOpen, 180_000);
        step("home with case", () -> host.show(AegisWorkspaceHost.HOME), () -> waited(9000), 20_000);
        capture("01-home-case");
        step("disk imager: configure E01 acquisition of the demo image", () -> {
            host.show(AegisWorkspaceHost.DISK_IMAGER);
            String evidence = source.getFileName().toString().replaceAll("\\.[^.]+$", "").replaceAll("[^A-Za-z0-9_-]+", "_");
            host.diskImager().driverPrepareFile(source, evidence, "EV-001", true);
        }, () -> waited(6000) && host.diskImager().driverStatus().equals("ready"), 60_000);
        capture("02-disk-imager-configured");
        step("disk imager: start acquisition", () -> click(frame, "Start Acquisition"),
                () -> host.diskImager().driverStatus().startsWith("verified") || host.diskImager().driverStatus().startsWith("failed"), 900_000);
        step("disk imager: verification result", () -> log("acquisition status: " + host.diskImager().driverStatus()
                + " job " + host.diskImager().driverJob()), () -> waited(2500), 10_000);
        capture("03-disk-imager-verified");
        step("disk imager: register with case", () -> click(frame, "Add Image to Case"),
                () -> host.diskImager().driverStatus().equals("registered"), 600_000);
        capture("04-disk-imager-complete");
        step("ingest the registered image (default modules)", () -> {
            try {
                IngestManager.getInstance().queueIngestJob(Case.getCurrentCaseThrows().getDataSources(), new IngestJobSettings("AEGIS-E2E"));
                log("ingest queued");
            } catch (Exception ex) {
                log("FAIL ingest: " + ex);
            }
        }, () -> waited(8000) && !IngestManager.getInstance().isIngestRunning(), 1_800_000);
        step("recovery: scan the acquired E01", () -> {
            host.show(AegisWorkspaceHost.RECOVERY);
            host.recovery().driverSelectImage(host.diskImager().driverImage(), host.diskImager().driverJob());
        }, () -> waited(4000), 20_000);
        step("recovery: start scan", () -> click(frame, "Start Scan"),
                () -> host.recovery().driverStatus().startsWith("done") || host.recovery().driverStatus().startsWith("failed"), 900_000);
        step("recovery: select showcase object", () -> {
            log("recovery status: " + host.recovery().driverStatus());
            Path p = host.recovery().driverSelectShowcase();
            photo = host.recovery().driverPhoto();
            log("showcase copy: " + p + "; photo for enhancement: " + photo);
        }, () -> waited(4000), 20_000);
        capture("05-recovery-results");
        step("recovery: signed report", () -> click(frame, "Signed Report"), () -> waited(9000), 60_000);
        step("recovery: add recovered files to case", () -> click(frame, "Add to Case"), () -> waited(12000), 120_000);
        step("enhancement: derivative of a recovered photo", () -> {
            if (photo != null) {
                org.sleuthkit.autopsy.aegis.ui.recovery.EnhancementDialog.open(host, photo);
            }
        }, () -> waited(4000), 20_000);
        step("enhancement: run EDSR x2", () -> clickInDialogs("Create Enhanced Derivative"),
                () -> dialogText().contains("Enhanced derivative created") || dialogText().contains("FAILED") || dialogText().contains("UNAVAILABLE"),
                900_000);
        step("enhancement: capture", () -> captureDialog("06-enhancement"), () -> waited(1500), 10_000);
        step("enhancement: close", () -> clickInDialogs("Close"), () -> waited(1500), 10_000);
        step("sanitization: file sanitization of a disposable file", this::sanitizeFile, () -> waited(25000), 120_000);
        capture("07-sanitization-file");
        step("sanitization: device view", () -> {
            host.show(AegisWorkspaceHost.SANITIZATION);
            host.sanitizationWorkspace().showDevice();
        }, () -> waited(20000), 60_000);
        capture("08-sanitization-device");
        step("sanitization: read-only eligibility verdicts", this::eligibilityVerdicts, () -> waited(15000), 120_000);
        step("reports", () -> host.show(AegisWorkspaceHost.REPORTS), () -> waited(9000), 30_000);
        capture("09-reports");
        step("reports: verification tab", () -> selectTab("Verification Results"), () -> waited(1500), 10_000);
        step("reports: verify signature and chain", () -> click(frame, "Verify Signature & Chain"), () -> waited(12000), 30_000);
        capture("10-reports-verified");
        step("oracle", () -> host.show(AegisWorkspaceHost.ORACLE), () -> waited(30000), 60_000);
        capture("11-oracle");
        step("oracle: timeline", () -> selectTab("Timeline Correlation"), () -> waited(2500), 10_000);
        capture("12-oracle-timeline");
        step("oracle: insights", () -> selectTab("Case Insights"), () -> waited(2500), 10_000);
        capture("13-oracle-insights");
        step("close case", () -> new Thread(() -> {
            try {
                Case.closeCurrentCase();
                log("case closed");
            } catch (Exception ex) {
                log("FAIL close: " + ex);
            }
        }).start(), () -> !Case.isCaseOpen(), 120_000);
        step("reopen case", () -> new Thread(() -> {
            try {
                Case.openAsCurrentCase(caseMeta.toString());
                log("case reopened: " + caseMeta);
            } catch (Exception ex) {
                log("FAIL reopen: " + ex);
            }
        }).start(), Case::isCaseOpen, 180_000);
        step("reopened: reports persisted", () -> host.show(AegisWorkspaceHost.REPORTS), () -> waited(10000), 30_000);
        capture("14-reopened-reports");
        step("reopened: ledger verification", () -> new Thread(() -> {
            EngineResult r = AegisEngine.ledgerVerify();
            log("ledger after reopen: " + r.summary() + " " + r.result);
        }).start(), () -> waited(15000), 60_000);
        step("reopened: home", () -> host.show(AegisWorkspaceHost.HOME), () -> waited(12000), 30_000);
        capture("15-reopened-home");
    }

    private void sanitizeFile() {
        new Thread(() -> {
            try {
                Path dir = org.sleuthkit.autopsy.aegis.engine.CaseWorkspace.stateDir().resolve("disposable");
                Files.createDirectories(dir);
                Path target = dir.resolve("disposable-secret.txt");
                Files.writeString(target, "AEGIS disposable test file. ".repeat(4000), StandardCharsets.UTF_8);
                log("disposable file written: " + target + " (" + Files.size(target) + " bytes)");
                SwingUtilities.invokeAndWait(() -> host.show(AegisWorkspaceHost.SANITIZATION));
                var view = host.sanitizationView();
                var outcome = view.getController().runAsConfirmedFile(target);
                log("file sanitization: status=" + outcome.status + " verified=" + outcome.verifiedSuccess()
                        + " exists_after=" + Files.exists(target) + " audit=" + outcome.auditPath + " message=" + outcome.message);
                Thread.sleep(4000);
                view.getController().startDeepPurge(false, msg -> log("deep purge: " + msg.replace("\n", " | ")));
            } catch (Exception ex) {
                log("FAIL file sanitization: " + ex);
            }
        }, "aegis-driver-sanitize").start();
    }

    /** Read-only: log the engine's sanitization/acquisition verdict for each disk. No device command is issued. */
    private void eligibilityVerdicts() {
        new Thread(() -> {
            EngineResult devices = AegisEngine.devices();
            for (var d : devices.result.array("devices").objects()) {
                log("DEVICE " + d.optString("id") + " " + d.optString("model") + " bus=" + d.optString("bus_type")
                        + " system=" + d.optBoolean("system_device", false)
                        + " sanitization=" + d.object("sanitization").optString("status") + " (" + d.object("sanitization").optString("reason") + ")"
                        + " acquisition=" + d.object("acquisition").optString("status"));
            }
        }, "aegis-driver-verdicts").start();
    }

    // ------------------------------------------------------------------ engine

    /** Long-running steps (acquisition, ingest, recovery, enhancement) scale with -Daegis.uidriver.timeoutscale for large evidence. */
    private static final double TIMEOUT_SCALE = Math.max(1.0, Double.parseDouble(System.getProperty("aegis.uidriver.timeoutscale", "1")));

    private void step(String name, Runnable action, BooleanSupplier done, long timeout) {
        steps.add(new Step(name, action, done, timeout >= 600_000 ? Math.round(timeout * TIMEOUT_SCALE) : timeout));
    }

    private void capture(String name) {
        steps.add(new Step("capture " + name, () -> AegisUiProbe.capture(frame, out.resolve(name + ".png")), () -> true, 5000));
    }

    private void next() {
        if (index >= steps.size()) {
            log("DRIVER COMPLETE. Dialogs answered: " + dialogs.size());
            if (Boolean.getBoolean("aegis.uidriver.exit")) {
                Timer quit = new Timer(3000, e -> org.openide.LifecycleManager.getDefault().exit());
                quit.setRepeats(false);
                quit.start();
            }
            return;
        }
        Step s = steps.get(index);
        log("STEP " + (index + 1) + "/" + steps.size() + ": " + s.name());
        stepStarted = System.currentTimeMillis();
        try {
            s.action().run();
        } catch (RuntimeException | LinkageError ex) {
            log("FAIL action " + s.name() + ": " + ex);
        }
        Timer poll = new Timer(500, null);
        poll.addActionListener(e -> {
            boolean ok;
            try {
                ok = s.done().getAsBoolean();
            } catch (RuntimeException ex) {
                ok = false;
            }
            long elapsed = System.currentTimeMillis() - stepStarted;
            if (ok || elapsed > s.timeoutMs()) {
                poll.stop();
                if (!ok) {
                    log("TIMEOUT " + s.name() + " after " + elapsed / 1000 + "s");
                } else {
                    log("  done in " + elapsed / 1000.0 + "s");
                }
                index++;
                next();
            }
        });
        poll.start();
    }

    private boolean waited(long ms) {
        return System.currentTimeMillis() - stepStarted >= ms;
    }

    private void log(String line) {
        String text = LocalDateTime.now().withNano(0) + "  " + line;
        LOG.info("AEGIS DRIVER " + text);
        try {
            Files.createDirectories(out);
            Files.writeString(out.resolve("driver-log.txt"), text + System.lineSeparator(), StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (Exception ex) {
            LOG.log(Level.WARNING, "driver log write failed", ex);
        }
    }

    // ------------------------------------------------------------------ UI helpers

    private void answerDialogs() {
        for (Window w : Window.getWindows()) {
            if (!(w instanceof JDialog d) || !d.isShowing() || !d.isModal()) {
                continue;
            }
            JOptionPane pane = find(d, JOptionPane.class);
            if (pane == null) {
                continue;
            }
            String text = pane.getMessage() instanceof Object[] arr ? java.util.Arrays.toString(arr) : String.valueOf(pane.getMessage());
            dialogs.add(text);
            log("DIALOG [" + d.getTitle() + "]: " + text.replace('\n', ' '));
            for (String label : new String[]{"OK", "Yes"}) {
                AbstractButton b = findButton(d, label);
                if (b != null) {
                    b.doClick();
                    break;
                }
            }
        }
    }

    private String dialogText() {
        StringBuilder sb = new StringBuilder();
        for (Window w : Window.getWindows()) {
            if (w instanceof JDialog d && d.isShowing()) {
                collectText(d, sb);
            }
        }
        return sb.toString();
    }

    private static void collectText(Component c, StringBuilder sb) {
        if (c instanceof javax.swing.JProgressBar bar) {
            sb.append(bar.getString()).append(' ');
        } else if (c instanceof javax.swing.JLabel l) {
            sb.append(l.getText()).append(' ');
        }
        if (c instanceof Container ct) {
            for (Component child : ct.getComponents()) {
                collectText(child, sb);
            }
        }
    }

    private void click(Container root, String text) {
        AbstractButton b = findButton(root, text);
        if (b == null) {
            log("  button not found: " + text);
            return;
        }
        if (!b.isEnabled()) {
            log("  button disabled: " + text);
            return;
        }
        b.doClick();
    }

    private void clickInDialogs(String text) {
        for (Window w : Window.getWindows()) {
            if (w instanceof JDialog d && d.isShowing()) {
                AbstractButton b = findButton(d, text);
                if (b != null && b.isEnabled()) {
                    b.doClick();
                    return;
                }
            }
        }
        log("  dialog button not found: " + text);
    }

    private void captureDialog(String name) {
        for (Window w : Window.getWindows()) {
            if (w instanceof JDialog d && d.isShowing()) {
                try {
                    var img = new java.awt.image.BufferedImage(d.getRootPane().getWidth(), d.getRootPane().getHeight(),
                            java.awt.image.BufferedImage.TYPE_INT_RGB);
                    var g = img.createGraphics();
                    d.getRootPane().paint(g);
                    g.dispose();
                    javax.imageio.ImageIO.write(img, "png", out.resolve(name + ".png").toFile());
                    return;
                } catch (Exception ex) {
                    log("dialog capture failed: " + ex);
                }
            }
        }
    }

    private void selectTab(String title) {
        javax.swing.JTabbedPane tabs = findTabs(frame, title);
        if (tabs != null) {
            tabs.setSelectedIndex(tabs.indexOfTab(title));
        } else {
            log("  tab not found: " + title);
        }
    }

    private static javax.swing.JTabbedPane findTabs(Container root, String title) {
        for (Component c : root.getComponents()) {
            if (c instanceof javax.swing.JTabbedPane t && t.isShowing() && t.indexOfTab(title) >= 0) {
                return t;
            }
            if (c instanceof Container ct) {
                javax.swing.JTabbedPane r = findTabs(ct, title);
                if (r != null) {
                    return r;
                }
            }
        }
        return null;
    }

    private static AbstractButton findButton(Container root, String text) {
        for (Component c : root.getComponents()) {
            if (c instanceof AbstractButton b && b.isShowing() && b.getText() != null && b.getText().trim().startsWith(text)) {
                return b;
            }
            if (c instanceof Container ct) {
                AbstractButton r = findButton(ct, text);
                if (r != null) {
                    return r;
                }
            }
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private static <T> T find(Container root, Class<T> type) {
        for (Component c : root.getComponents()) {
            if (type.isInstance(c)) {
                return (T) c;
            }
            if (c instanceof Container ct) {
                T r = find(ct, type);
                if (r != null) {
                    return r;
                }
            }
        }
        return null;
    }
}
