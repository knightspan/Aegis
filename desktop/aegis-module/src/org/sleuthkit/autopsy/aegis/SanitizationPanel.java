package org.sleuthkit.autopsy.aegis;

import java.awt.BorderLayout;
import java.nio.file.Path;
import javax.swing.JPanel;
import org.sleuthkit.autopsy.aegis.sanitization.SanitizationController;
import org.sleuthkit.autopsy.aegis.ui.sanitization.SanitizationView;

/**
 * Compatibility wrapper around {@link SanitizationView}. The shell hosts the
 * view directly; this panel remains for evidence-context callers.
 */
public final class SanitizationPanel extends JPanel {

    private final SanitizationView view;

    public SanitizationPanel() {
        this(new SanitizationView());
    }

    public SanitizationPanel(SanitizationView view) {
        super(new BorderLayout());
        this.view = view;
        add(view, BorderLayout.CENTER);
    }

    public void prefillExistingFile(Path path) {
        view.prefillFile(path);
    }

    public String runAsConfirmedFile(Path target) throws Exception {
        SanitizerBridge.Outcome outcome = view.getController().runAsConfirmedFile(target);
        return outcome == null ? "FAILED" : outcome.status + "\n" + view.getController().registrationMessage();
    }

    public Path lastAuditPath() {
        return view.getController().state().auditPath();
    }

    public Path lastReportPath() {
        return view.getController().state().reportPath();
    }

    public String registrationMessage() {
        return view.getController().registrationMessage();
    }

    public SanitizerBridge.Outcome lastOutcome() {
        return null;
    }

    public SanitizationController controller() {
        return view.getController();
    }
}
