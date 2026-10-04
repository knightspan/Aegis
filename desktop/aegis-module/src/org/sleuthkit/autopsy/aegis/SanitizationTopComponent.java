package org.sleuthkit.autopsy.aegis;

import java.awt.BorderLayout;
import java.nio.file.Path;
import org.openide.util.NbBundle;
import org.openide.windows.TopComponent;
import org.sleuthkit.autopsy.aegis.ui.AegisHomeTopComponent;
import org.sleuthkit.autopsy.aegis.ui.sanitization.SanitizationView;

/**
 * Legacy TopComponent entry. Opens the single shell Sanitization workspace.
 */
@TopComponent.Description(preferredID = "SanitizationTopComponent", persistenceType = TopComponent.PERSISTENCE_NEVER)
@TopComponent.Registration(mode = "aegis", openAtStartup = false)
public final class SanitizationTopComponent extends TopComponent {

    private static SanitizationTopComponent instance;

    public SanitizationTopComponent() {
        if (instance == null) {
            instance = this;
        }
        setLayout(new BorderLayout());
        setName(NbBundle.getMessage(SanitizationTopComponent.class, "AEGIS_Sanitization"));
        setToolTipText("Explicit AEGIS logical sanitization. Not an ingest module.");
    }

    public static synchronized SanitizationTopComponent findInstance() {
        if (instance == null) {
            instance = new SanitizationTopComponent();
        }
        return instance;
    }

    @Override
    protected void componentOpened() {
        super.componentOpened();
        AegisHomeTopComponent.showSanitization();
        close();
    }

    public void offerFile(Path path) {
        AegisHomeTopComponent.showSanitizationWithFile(path);
    }

    public SanitizationView getView() {
        return AegisHomeTopComponent.findInstance().sanitizationView();
    }

    /** @deprecated Prefer {@link #getView()}. */
    @Deprecated
    public SanitizationPanel getPanel() {
        return new SanitizationPanel(getView());
    }
}
