package org.sleuthkit.autopsy.aegis.ui;

import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.imageio.ImageIO;
import javax.swing.JFrame;
import javax.swing.JRootPane;
import javax.swing.SwingUtilities;
import javax.swing.Timer;

/**
 * Visual acceptance probe, off unless {@code -J-Daegis.uiprobe.dir=<folder>} is set.
 *
 * <p>Shows each requested page in the running application, waits for it to
 * load its live data, and paints the frame's root pane into a PNG in that
 * folder. It renders the real application off-screen, so the comparison with
 * the UI reference screenshots uses exactly what an operator would see, without
 * taking the screen or the input focus. {@code aegis.uiprobe.pages} lists the
 * pages (default: the reference screens); {@code aegis.uiprobe.delay} is the
 * wait per page in milliseconds; {@code aegis.uiprobe.exit=true} exits after.
 */
final class AegisUiProbe {

    private static final Logger LOG = Logger.getLogger(AegisUiProbe.class.getName());
    private static final java.util.concurrent.atomic.AtomicBoolean STARTED = new java.util.concurrent.atomic.AtomicBoolean();

    private AegisUiProbe() {
    }

    static void startIfRequested(JFrame frame, AegisWorkspaceHost host) {
        String dir = System.getProperty("aegis.uiprobe.dir", "");
        if (dir.isBlank() || !STARTED.compareAndSet(false, true)) {
            return;
        }
        Path out = Path.of(dir);
        List<String> pages = new ArrayList<>(Arrays.asList(System.getProperty("aegis.uiprobe.pages",
                "HOME,DISK_IMAGER,RECOVERY,SANITIZATION,REPORTS,ORACLE").split(",")));
        int delay = Integer.getInteger("aegis.uiprobe.delay", 9000);
        int initial = Integer.getInteger("aegis.uiprobe.initial", 12000);
        LOG.info("AEGIS UI probe: " + pages + " -> " + out);
        Timer first = new Timer(initial, e -> step(frame, host, out, pages, 0, delay));
        first.setRepeats(false);
        first.start();
    }

    private static void step(JFrame frame, AegisWorkspaceHost host, Path out, List<String> pages, int index, int delay) {
        if (index >= pages.size()) {
            LOG.info("AEGIS UI probe complete.");
            if (Boolean.getBoolean("aegis.uiprobe.exit")) {
                Timer quit = new Timer(1500, e -> org.openide.LifecycleManager.getDefault().exit());
                quit.setRepeats(false);
                quit.start();
            }
            return;
        }
        String page = pages.get(index).trim();
        try {
            host.show(page);
        } catch (RuntimeException | LinkageError ex) {
            LOG.log(Level.SEVERE, "AEGIS UI probe: page " + page + " failed to show", ex);
        }
        Timer capture = new Timer(delay, e -> {
            capture(frame, out.resolve(String.format("%02d-%s.png", index + 1, page.toLowerCase(java.util.Locale.ROOT))));
            step(frame, host, out, pages, index + 1, delay);
        });
        capture.setRepeats(false);
        capture.start();
    }

    static void capture(JFrame frame, Path file) {
        if (!SwingUtilities.isEventDispatchThread()) {
            SwingUtilities.invokeLater(() -> capture(frame, file));
            return;
        }
        try {
            Files.createDirectories(file.getParent());
            JRootPane root = frame.getRootPane();
            int w = Math.max(1, root.getWidth());
            int h = Math.max(1, root.getHeight());
            BufferedImage img = new BufferedImage(w, h, BufferedImage.TYPE_INT_RGB);
            Graphics2D g = img.createGraphics();
            root.paint(g);
            g.dispose();
            ImageIO.write(img, "png", new File(file.toString()));
            LOG.info("AEGIS UI probe wrote " + file);
        } catch (Exception ex) {
            LOG.log(Level.WARNING, "AEGIS UI probe capture failed for " + file, ex);
        }
    }
}
