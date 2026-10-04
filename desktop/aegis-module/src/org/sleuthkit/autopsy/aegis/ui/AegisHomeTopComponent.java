package org.sleuthkit.autopsy.aegis.ui;

import java.awt.BorderLayout;
import java.awt.Container;
import java.nio.file.Path;
import javax.swing.JPanel;
import org.openide.windows.TopComponent;

@TopComponent.Description(preferredID = "AegisHomeTopComponent", persistenceType = TopComponent.PERSISTENCE_NEVER)
@TopComponent.Registration(mode = "editor", openAtStartup = true)
public final class AegisHomeTopComponent extends TopComponent {

    private static AegisHomeTopComponent instance;
    private static AegisWorkspaceHost sharedHost;
    private final AegisWorkspaceHost host;

    public AegisHomeTopComponent() {
        instance = this;
        setLayout(new BorderLayout());
        setName("AEGIS");
        setDisplayName("AEGIS");
        setToolTipText(null);
        setBackground(AegisTokens.BACKGROUND);
        if (sharedHost == null) {
            sharedHost = new AegisWorkspaceHost(new JPanel());
        }
        this.host = sharedHost;
        Container parent = sharedHost.getParent();
        if (parent != null) {
            parent.remove(sharedHost);
        }
        add(host, BorderLayout.CENTER);
    }

    @Override
    public java.awt.Dimension getPreferredSize() {
        Container parent = getParent();
        if (parent != null && parent.getWidth() > 0 && parent.getHeight() > 0) {
            return new java.awt.Dimension(parent.getWidth(), parent.getHeight());
        }
        return new java.awt.Dimension(960, 640);
    }

    @Override
    public java.awt.Dimension getMinimumSize() {
        return new java.awt.Dimension(720, 480);
    }

    AegisWorkspaceHost host() {
        return host;
    }

    public static void showSanitization() {
        AegisHomeTopComponent page = findInstance();
        page.open();
        page.requestActive();
        page.host().show(AegisWorkspaceHost.SANITIZATION);
    }

    public static void showSanitizationWithFile(Path path) {
        showSanitization();
        if (path != null) {
            findInstance().host().sanitizationView().prefillFile(path);
        }
    }

    public org.sleuthkit.autopsy.aegis.ui.sanitization.SanitizationView sanitizationView() {
        return host.sanitizationView();
    }

    public static synchronized AegisHomeTopComponent findInstance() {
        if (instance == null) {
            instance = new AegisHomeTopComponent();
        }
        return instance;
    }

    @Override
    protected void componentOpened() {
        super.componentOpened();
        AegisShell.install();
    }
}
