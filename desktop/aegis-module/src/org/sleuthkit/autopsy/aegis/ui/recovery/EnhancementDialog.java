package org.sleuthkit.autopsy.aegis.ui.recovery;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.GridLayout;
import java.awt.Image;
import java.awt.image.BufferedImage;
import java.nio.file.Path;
import javax.imageio.ImageIO;
import javax.swing.BorderFactory;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import javax.swing.border.EmptyBorder;
import org.sleuthkit.autopsy.aegis.engine.AegisEngine;
import org.sleuthkit.autopsy.aegis.engine.EngineBridge;
import org.sleuthkit.autopsy.aegis.engine.EngineResult;
import org.sleuthkit.autopsy.aegis.ui.AegisTokens;
import org.sleuthkit.autopsy.aegis.ui.kit.Badge;
import org.sleuthkit.autopsy.aegis.ui.kit.DetailList;
import org.sleuthkit.autopsy.aegis.ui.kit.Kit;
import org.sleuthkit.autopsy.aegis.ui.kit.Tone;

/**
 * AI super-resolution on a derivative copy (OpenCV dnn_superres, EDSR).
 * The original is read once into a copy; the enhanced image is a separate
 * derivative, hashed and ledgered, and labelled as not evidence.
 */
public final class EnhancementDialog extends JDialog {

    private final Path source;
    private final JLabel original = new JLabel("", JLabel.CENTER);
    private final JLabel enhanced = new JLabel("Not yet enhanced", JLabel.CENTER);
    private final JProgressBar bar = new JProgressBar(0, 100);
    private final DetailList facts = new DetailList();
    private final JComboBox<String> model = new JComboBox<>(new String[]{"EDSR x2", "EDSR x3", "EDSR x4"});
    private final JButton run = Kit.primary("Create Enhanced Derivative", "sparkles");
    private EngineBridge.Cancel cancel;

    public static void open(Component parent, Path image) {
        EnhancementDialog d = new EnhancementDialog(SwingUtilities.getWindowAncestor(parent), image);
        d.setLocationRelativeTo(parent);
        d.setVisible(true);
    }

    private EnhancementDialog(java.awt.Window owner, Path source) {
        super(owner, "AI Media Enhancement — derivative only", ModalityType.MODELESS);
        this.source = source;
        JPanel root = new JPanel(new BorderLayout(0, 12));
        root.setBackground(AegisTokens.BACKGROUND);
        root.setBorder(new EmptyBorder(16, 16, 16, 16));
        root.add(Kit.notice(Tone.INFO, "Enhancement runs on a derivative copy. The recovered original is never modified; "
                + "the enhanced image is an interpretive aid, not evidence."), BorderLayout.NORTH);
        JPanel pair = new JPanel(new GridLayout(1, 2, 12, 0));
        pair.setOpaque(false);
        pair.add(frame("ORIGINAL", original, Tone.NEUTRAL));
        pair.add(frame("ENHANCED DERIVATIVE", enhanced, Tone.PURPLE));
        root.add(pair, BorderLayout.CENTER);
        JPanel south = new JPanel(new BorderLayout(0, 8));
        south.setOpaque(false);
        facts.put("Source", source.toString()).done();
        south.add(facts, BorderLayout.CENTER);
        bar.setStringPainted(true);
        bar.setString("Ready");
        JButton close = Kit.outline("Close");
        close.addActionListener(e -> {
            if (cancel != null) {
                cancel.request();
            }
            dispose();
        });
        run.addActionListener(e -> start());
        south.add(Kit.column(6, bar, Kit.row(8, Kit.caption("Model"), model, run, close)), BorderLayout.SOUTH);
        root.add(south, BorderLayout.SOUTH);
        setContentPane(root);
        setSize(980, 720);
        load(original, source);
    }

    private static JPanel frame(String title, JLabel image, Tone tone) {
        JPanel p = new JPanel(new BorderLayout(0, 6));
        p.setBackground(AegisTokens.SURFACE);
        p.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(AegisTokens.BORDER), new EmptyBorder(8, 8, 8, 8)));
        p.add(new Badge(title, tone), BorderLayout.NORTH);
        image.setPreferredSize(new Dimension(440, 380));
        p.add(image, BorderLayout.CENTER);
        return p;
    }

    private static void load(JLabel target, Path file) {
        new SwingWorker<BufferedImage, Void>() {
            @Override
            protected BufferedImage doInBackground() throws Exception {
                return ImageIO.read(file.toFile());
            }

            @Override
            protected void done() {
                try {
                    BufferedImage img = get();
                    if (img == null) {
                        target.setText("Not decodable");
                        return;
                    }
                    double s = Math.min(430.0 / img.getWidth(), 370.0 / img.getHeight());
                    s = Math.min(s, 4.0);
                    target.setIcon(new ImageIcon(img.getScaledInstance(Math.max(1, (int) (img.getWidth() * s)),
                            Math.max(1, (int) (img.getHeight() * s)), Image.SCALE_SMOOTH)));
                    target.setText("");
                    target.setToolTipText(img.getWidth() + " x " + img.getHeight() + " px");
                } catch (Exception ex) {
                    target.setText("Preview unavailable");
                }
            }
        }.execute();
    }

    private void start() {
        run.setEnabled(false);
        cancel = new EngineBridge.Cancel();
        int scale = Integer.parseInt(((String) model.getSelectedItem()).replaceAll("\\D", ""));
        bar.setString("Enhancing…");
        final EngineBridge.Cancel token = cancel;
        new SwingWorker<EngineResult, Void>() {
            @Override
            protected EngineResult doInBackground() {
                return AegisEngine.enhance(source, "EDSR", scale, p -> SwingUtilities.invokeLater(() -> {
                    bar.setValue((int) p.pct);
                    bar.setString(p.message);
                }), token);
            }

            @Override
            protected void done() {
                cancel = null;
                run.setEnabled(true);
                try {
                    EngineResult r = get();
                    if (!r.succeeded()) {
                        bar.setString(r.summary());
                        facts.clear().put("Source", source.toString()).put("Result", r.summary()).put("Remediation", r.remediation).done();
                        return;
                    }
                    bar.setValue(100);
                    bar.setString("Enhanced derivative created");
                    load(enhanced, Path.of(r.result.optString("enhanced")));
                    facts.clear().put("Original", r.result.optString("source"))
                            .put("Original SHA-256", DetailList.mono(r.result.optString("source_sha256")))
                            .put("Original unchanged", r.result.optBoolean("source_unchanged", false) ? "Yes (re-hashed after enhancement)" : "NO")
                            .put("Derivative copy SHA-256", DetailList.mono(r.result.optString("derivative_copy_sha256")))
                            .put("Enhanced file", r.result.optString("enhanced"))
                            .put("Enhanced SHA-256", DetailList.mono(r.result.optString("enhanced_sha256")))
                            .put("Model", r.result.optString("model") + " x" + r.result.optString("scale") + " (" + r.result.optString("model_file") + ")")
                            .put("Model SHA-256", DetailList.mono(Kit.shortHash(r.result.optString("model_sha256"))))
                            .put("Framework", r.result.optString("framework"))
                            .put("Parameters", "tile " + r.result.optString("tile") + " px, input " + r.result.optJSONArray("input_size")
                                    + " -> output " + r.result.optJSONArray("output_size"))
                            .put("Operator / time", r.result.optString("operator") + " / " + r.result.optString("timestamp"))
                            .put("Ledger", "aegis.enhance recorded in the case ledger (job " + r.operationId + ")").done();
                } catch (Exception ex) {
                    bar.setString("Failed: " + ex.getMessage());
                }
            }
        }.execute();
    }
}
