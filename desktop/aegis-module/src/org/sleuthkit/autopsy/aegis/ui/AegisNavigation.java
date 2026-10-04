package org.sleuthkit.autopsy.aegis.ui;

import javax.swing.SwingUtilities;

/** Public page navigation for AEGIS feature views in other packages. */
public final class AegisNavigation {

    public static final String HOME = AegisWorkspaceHost.HOME;
    public static final String CASES = AegisWorkspaceHost.CASES;
    public static final String DISK_IMAGER = AegisWorkspaceHost.DISK_IMAGER;
    public static final String RECOVERY = AegisWorkspaceHost.RECOVERY;
    public static final String SANITIZATION = AegisWorkspaceHost.SANITIZATION;
    public static final String REPORTS = AegisWorkspaceHost.REPORTS;
    public static final String ORACLE = AegisWorkspaceHost.ORACLE;
    public static final String ANALYSIS = AegisWorkspaceHost.ANALYSIS;

    private AegisNavigation() {
    }

    public static void show(String page) {
        SwingUtilities.invokeLater(() -> {
            AegisWorkspaceHost host = AegisHomeTopComponent.findInstance().host();
            if (host != null) {
                host.show(page);
            }
        });
    }
}
