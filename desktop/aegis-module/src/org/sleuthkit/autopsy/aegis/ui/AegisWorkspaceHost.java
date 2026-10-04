package org.sleuthkit.autopsy.aegis.ui;

import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Dimension;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;

final class AegisWorkspaceHost extends JPanel {

    static final String HOME = "HOME";
    static final String CASES = "CASES";
    static final String INGEST = "INGEST";
    static final String DISK_IMAGER = "DISK_IMAGER";
    static final String SEARCH = "SEARCH";
    static final String TIMELINE = "TIMELINE";
    static final String ANALYSIS = "ANALYSIS";
    static final String ARTIFACTS = "ARTIFACTS";
    static final String MEDIA = "MEDIA";
    static final String COMMUNICATIONS = "COMMUNICATIONS";
    static final String REGISTRY = "REGISTRY";
    static final String TAGS = "TAGS";
    static final String RECOVERY = "RECOVERY";
    static final String REPORTS = "REPORTS";
    static final String SANITIZATION = "SANITIZATION";
    static final String ORACLE = "ORACLE";
    static final String SETTINGS = "SETTINGS";
    static final String DESKTOP = "DESKTOP";

    private static final java.util.Set<String> AEGIS_PAGES = java.util.Set.of(HOME, CASES, INGEST, DISK_IMAGER, RECOVERY,
            REPORTS, SANITIZATION, ORACLE, SETTINGS);
    private final CardLayout cards = new CardLayout();
    private final JPanel stack = new CardStack(cards);
    private final Map<String, JComponent> pages = new LinkedHashMap<>();
    private final AegisHomePanel home;
    private final AegisCasesPanel cases = new AegisCasesPanel();
    private final AegisIngestPanel ingest = new AegisIngestPanel();
    private final AegisReportsPanel reports = new AegisReportsPanel();
    private final AegisSanitizationWorkspace sanitization = new AegisSanitizationWorkspace();
    private final org.sleuthkit.autopsy.aegis.ui.diskimager.DiskImagerView diskImager
            = new org.sleuthkit.autopsy.aegis.ui.diskimager.DiskImagerView();
    private final org.sleuthkit.autopsy.aegis.ui.recovery.AdvancedRecoveryView recovery
            = new org.sleuthkit.autopsy.aegis.ui.recovery.AdvancedRecoveryView();
    private final org.sleuthkit.autopsy.aegis.ui.oracle.OracleView oracle
            = new org.sleuthkit.autopsy.aegis.ui.oracle.OracleView();
    private String current = HOME;
    private AegisSidebar sidebar;
    private AegisTopBar topBar;
    private AegisStatusBar statusBar;

    AegisWorkspaceHost(JComponent desktop) {
        super(new BorderLayout());
        setBackground(AegisTokens.BACKGROUND);
        setOpaque(true);
        home = new AegisHomePanel(this);
        stack.setOpaque(true);
        stack.setBackground(AegisTokens.BACKGROUND);
        addPage(HOME, home);
        addPage(CASES, cases);
        addPage(INGEST, ingest);
        addPage(DISK_IMAGER, diskImager);
        addPage(SEARCH, new AegisSearchPanel());
        addPage(REPORTS, reports);
        addPage(RECOVERY, recovery);
        addPage(SANITIZATION, sanitization);
        addPage(ORACLE, oracle);
        addPage(SETTINGS, new AegisSettingsPanel());
        addPage(ANALYSIS, desktopPage("Analysis", "Open a case to work in the evidence tree, viewers, and inspectors."));
        addPage(ARTIFACTS, desktopPage("Artifacts", "Artifact nodes stay in the existing evidence tree. Open a case to continue."));
        addPage(REGISTRY, desktopPage("Registry", "Open a registry hive in the existing viewer after a case is loaded."));
        addPage(TAGS, desktopPage("Tags", "Tags and interesting items stay in the existing case tree."));
        addPage(TIMELINE, desktopPage("Timeline", "Open a case to use the forensic timeline."));
        addPage(MEDIA, desktopPage("Media", "Images, video, and audio use the existing gallery and viewers."));
        addPage(COMMUNICATIONS, desktopPage("Communications", "Email, messages, and contacts use the existing communications tool."));
        addPage(DESKTOP, desktop);
        add(stack, BorderLayout.CENTER);
        showCard(HOME, () -> { });
    }

    @Override
    public Dimension getPreferredSize() {
        java.awt.Container parent = getParent();
        if (parent != null && parent.getWidth() > 0 && parent.getHeight() > 0) {
            return new Dimension(parent.getWidth(), parent.getHeight());
        }
        return new Dimension(960, 640);
    }

    @Override
    public Dimension getMinimumSize() {
        return new Dimension(720, 480);
    }

    void bind(AegisSidebar sidebar, AegisTopBar topBar, AegisStatusBar statusBar) {
        this.sidebar = sidebar;
        this.topBar = topBar;
        this.statusBar = statusBar;
    }

    void show(String page) {
        if (!SwingUtilities.isEventDispatchThread()) {
            SwingUtilities.invokeLater(() -> show(page));
            return;
        }
        final String target = pages.containsKey(page) ? page : HOME;
        if (!target.equals(current)) {
            StackTraceElement[] st = Thread.currentThread().getStackTrace();
            StringBuilder caller = new StringBuilder();
            for (int i = 2; i < Math.min(st.length, 7); i++) {
                caller.append(st[i].getClassName().replace("org.sleuthkit.autopsy.", "")).append('.').append(st[i].getMethodName()).append(" < ");
            }
            java.util.logging.Logger.getLogger(AegisWorkspaceHost.class.getName())
                    .info("AEGIS navigate " + current + " -> " + target + " by " + caller);
        }
        current = target;
        ensureDashboardOpen();
        if (AEGIS_PAGES.contains(target)) {
            // AEGIS workspaces use the whole editor area; the Autopsy tree and
            // viewers return when the operator chooses an investigation page.
            AegisActions.closeForensicWorkspace();
        }
        switch (target) {
            case HOME -> showCard(HOME, () -> home.refresh());
            case CASES -> showCard(CASES, cases::refresh);
            case INGEST -> showCard(INGEST, ingest::refresh);
            case DISK_IMAGER -> showCard(DISK_IMAGER, diskImager::refresh);
            case SEARCH -> {
                showCard(SEARCH, () -> { });
                if (AegisActions.caseOpen()) {
                    AegisActions.fileSearch();
                }
            }
            case TIMELINE -> {
                showCard(TIMELINE, () -> { });
                if (AegisActions.caseOpen()) {
                    AegisActions.timeline();
                }
            }
            case ANALYSIS, ARTIFACTS, REGISTRY, TAGS -> {
                showCard(target, () -> { });
                if (AegisActions.caseOpen()) {
                    AegisActions.openForensicWorkspace();
                }
            }
            case MEDIA -> {
                showCard(MEDIA, () -> { });
                if (AegisActions.caseOpen()) {
                    AegisActions.imageGallery();
                }
            }
            case COMMUNICATIONS -> {
                showCard(COMMUNICATIONS, () -> { });
                if (AegisActions.caseOpen()) {
                    AegisActions.communications();
                }
            }
            case RECOVERY -> showCard(RECOVERY, recovery::refresh);
            case REPORTS -> showCard(REPORTS, reports::refresh);
            case SANITIZATION -> showCard(SANITIZATION, () -> { });
            case ORACLE -> showCard(ORACLE, oracle::refresh);
            case SETTINGS -> showCard(SETTINGS, () -> { });
            default -> showCard(HOME, () -> home.refresh());
        }
        if (sidebar != null) {
            sidebar.select(current);
        }
        if (topBar != null) {
            topBar.refresh();
        }
        if (statusBar != null) {
            statusBar.refresh();
        }
    }

    private void addPage(String name, JComponent page) {
        page.setOpaque(true);
        pages.put(name, page);
        stack.add(page, name);
    }

    private void showCard(String page, Runnable refresh) {
        try {
            refresh.run();
        } catch (RuntimeException ex) {
            java.util.logging.Logger.getLogger(AegisWorkspaceHost.class.getName())
                    .log(java.util.logging.Level.WARNING, "AEGIS page refresh failed for " + page, ex);
        }
        for (Map.Entry<String, JComponent> entry : pages.entrySet()) {
            entry.getValue().setVisible(entry.getKey().equals(page));
        }
        cards.show(stack, page);
        JComponent active = pages.get(page);
        if (active != null) {
            active.setVisible(true);
        }
        stack.revalidate();
        stack.repaint();
        revalidate();
        repaint();
        java.awt.Window window = SwingUtilities.getWindowAncestor(this);
        if (window != null) {
            window.revalidate();
            window.repaint();
        }
    }

    private void ensureDashboardOpen() {
        AegisHomeTopComponent pageHost = AegisHomeTopComponent.findInstance();
        if (!pageHost.isOpened()) {
            pageHost.open();
        }
        pageHost.requestActive();
    }

    String current() {
        return current;
    }

    org.sleuthkit.autopsy.aegis.ui.diskimager.DiskImagerView diskImager() {
        return diskImager;
    }

    org.sleuthkit.autopsy.aegis.ui.recovery.AdvancedRecoveryView recovery() {
        return recovery;
    }

    AegisSanitizationWorkspace sanitizationWorkspace() {
        return sanitization;
    }

    public org.sleuthkit.autopsy.aegis.ui.sanitization.SanitizationView sanitizationView() {
        return sanitization.view();
    }

    void refreshChrome() {
        switch (current) {
            case HOME -> home.refresh();
            case CASES -> cases.refresh();
            case INGEST -> ingest.refresh();
            case REPORTS -> reports.refresh();
            default -> {
            }
        }
        if (topBar != null) {
            topBar.refresh();
        }
        if (statusBar != null) {
            statusBar.refresh();
        }
    }

    private static JPanel desktopPage(String title, String body) {
        JPanel page = new AegisPage();
        JLabel heading = new JLabel(title);
        heading.setFont(AegisTokens.H1);
        heading.setForeground(AegisTokens.NAVY);
        page.add(heading, BorderLayout.NORTH);
        page.add(new AegisEmptyState("analysis", title, body), BorderLayout.CENTER);
        return page;
    }

    /**
     * Card stack that reports preferred size from the allocated parent, not the
     * tallest card. CardLayout otherwise sums/maxes page preferred heights and
     * can push page-owned SOUTH action bars outside the visible editor area.
     */
    private static final class CardStack extends JPanel {

        CardStack(CardLayout layout) {
            super(layout);
        }

        @Override
        public Dimension getPreferredSize() {
            java.awt.Container parent = getParent();
            if (parent != null && parent.getWidth() > 0 && parent.getHeight() > 0) {
                return new Dimension(parent.getWidth(), parent.getHeight());
            }
            return new Dimension(960, 640);
        }

        @Override
        public Dimension getMinimumSize() {
            return new Dimension(720, 480);
        }

        @Override
        public Dimension getMaximumSize() {
            return new Dimension(Integer.MAX_VALUE, Integer.MAX_VALUE);
        }
    }
}
