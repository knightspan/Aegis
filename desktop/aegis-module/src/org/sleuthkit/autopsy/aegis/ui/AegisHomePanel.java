package org.sleuthkit.autopsy.aegis.ui;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.GridLayout;
import java.awt.RenderingHints;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.image.BufferedImage;
import java.io.File;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.border.EmptyBorder;
import org.openide.util.Lookup;
import org.sleuthkit.autopsy.ingest.IngestModuleFactory;

final class AegisHomePanel extends AegisPage {

    private final AegisWorkspaceHost host;
    private final JPanel recentRows = new JPanel();
    private final JLabel searchState = new JLabel("Checking");
    private final JLabel hashState = new JLabel("Checking");
    private final JLabel timelineState = new JLabel("Checking");
    private final JLabel reportState = new JLabel("Checking");
    private final JLabel engineState = new JLabel("Checking");
    private final JLabel e01State = new JLabel("Checking");
    private final JLabel sanitizerState = new JLabel("Checking");
    private final JLabel privilegeState = new JLabel("Checking");
    private final JLabel ledgerState = new JLabel("Checking");
    private final JLabel signedReports = new JLabel("Checking");
    private boolean liveChecking;

    AegisHomePanel(AegisWorkspaceHost host) {
        this.host = host;
        setBorder(new EmptyBorder(16, 18, 12, 18));
        setLayout(new BorderLayout(0, 14));

        JPanel top = new HomeBody();
        top.setOpaque(false);
        top.setLayout(new BoxLayout(top, BoxLayout.Y_AXIS));
        HeroBanner hero = new HeroBanner(loadHero());
        hero.setAlignmentX(LEFT_ALIGNMENT);
        top.add(hero);
        top.add(Box.createVerticalStrut(14));
        JPanel cards = new JPanel(new GridLayout(2, 4, 14, 14));
        cards.setOpaque(false);
        cards.setAlignmentX(LEFT_ALIGNMENT);
        cards.setMaximumSize(new Dimension(Integer.MAX_VALUE, 250));
        cards.add(action("new-case", "Create New Case", "Start a new investigation", () -> AegisActions.newCase()));
        cards.add(action("open-case", "Open Existing Case", "Open a previously saved case", () -> AegisActions.openCase()));
        cards.add(action("ingest", "Ingest Data", "Add data sources to a case", () -> {
            host.show(AegisWorkspaceHost.INGEST);
            if (AegisActions.caseOpen()) {
                AegisActions.addDataSource();
            }
        }));
        cards.add(action("sanitization", "Sanitization", "Securely delete data with verification", () -> host.show(AegisWorkspaceHost.SANITIZATION)));
        cards.add(action("add-source", "Disk Imager", "Read-only RAW/E01 imaging, SHA-256 + BLAKE3", () -> host.show(AegisWorkspaceHost.DISK_IMAGER)));
        cards.add(action("restore", "Recovery", "Undelete, carving and fragment reassembly", () -> host.show(AegisWorkspaceHost.RECOVERY)));
        cards.add(action("affiliate", "Oracle", "Case knowledge graph with provenance", () -> host.show(AegisWorkspaceHost.ORACLE)));
        cards.add(action("reports", "Reports", "Signed reports and audit verification", () -> host.show(AegisWorkspaceHost.REPORTS)));
        top.add(cards);

        recentRows.setOpaque(false);
        recentRows.setLayout(new BoxLayout(recentRows, BoxLayout.Y_AXIS));

        JPanel lower = new JPanel(new GridLayout(1, 2, 14, 0));
        lower.setOpaque(false);
        lower.setAlignmentX(LEFT_ALIGNMENT);
        lower.setPreferredSize(new Dimension(0, 280));
        lower.setMaximumSize(new Dimension(Integer.MAX_VALUE, 320));
        lower.add(recentCard());
        lower.add(statusCard());

        JPanel quote = quoteBar();
        quote.setAlignmentX(LEFT_ALIGNMENT);
        quote.setMaximumSize(new Dimension(Integer.MAX_VALUE, 72));

        top.add(Box.createVerticalStrut(14));
        top.add(lower);
        top.add(Box.createVerticalStrut(14));
        top.add(quote);

        JScrollPane scroll = new JScrollPane(top);
        scroll.setBorder(null);
        scroll.setOpaque(false);
        scroll.getViewport().setOpaque(false);
        scroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        scroll.getVerticalScrollBar().setUnitIncrement(16);
        add(scroll, BorderLayout.CENTER);
        refresh();
    }

    void refresh() {
        recentRows.removeAll();
        List<AegisActions.RecentCase> recent = AegisActions.recentCases();
        if (recent.isEmpty()) {
            recentRows.add(caseRow(null, "No recent cases", "Create or open a case", ""));
        } else {
            SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm");
            for (AegisActions.RecentCase item : recent) {
                String opened = "";
                File file = new File(item.path());
                if (file.isFile()) {
                    opened = format.format(new Date(file.lastModified()));
                }
                recentRows.add(caseRow(item, item.name(), item.path(), opened));
            }
        }
        boolean keyword = false;
        boolean hash = false;
        try {
            for (IngestModuleFactory factory : Lookup.getDefault().lookupAll(IngestModuleFactory.class)) {
                String name = factory.getModuleDisplayName() == null ? "" : factory.getModuleDisplayName().toLowerCase();
                if (name.contains("keyword")) {
                    keyword = true;
                }
                if (name.contains("hash")) {
                    hash = true;
                }
            }
        } catch (RuntimeException ex) {
            keyword = false;
            hash = false;
        }
        searchState.setText(keyword ? "Loaded" : "Not installed");
        hashState.setText(hash ? "Loaded" : "Not installed");
        timelineState.setText(installed("org.sleuthkit.autopsy.timeline.TimeLineTopComponent") ? "Loaded" : "Not installed");
        reportState.setText(installed("org.sleuthkit.autopsy.report.infrastructure.ReportWizardAction") ? "Loaded" : "Not installed");
        refreshLive();
        revalidate();
        repaint();
    }

    /** Live engine and case checks, off the EDT. Every value is measured; nothing is assumed loaded. */
    private void refreshLive() {
        if (liveChecking) {
            return;
        }
        liveChecking = true;
        new javax.swing.SwingWorker<String[], Void>() {
            @Override
            protected String[] doInBackground() {
                org.sleuthkit.autopsy.aegis.engine.EngineResult h = org.sleuthkit.autopsy.aegis.engine.EngineBridge.get().health();
                String engine = h.succeeded() ? "Ready (Python " + h.result.optString("python") + ")" : "Unavailable";
                String e01 = !h.succeeded() ? "Unavailable" : h.result.object("e01_write").optBoolean("supported", false)
                        ? "Ready (libewf " + h.result.object("e01_write").optString("writer_library") + ")" : "Unavailable";
                String priv = !h.succeeded() ? "Unknown" : h.result.optBoolean("elevated", false) ? "Administrator" : "Standard user";
                java.nio.file.Path cli = new org.sleuthkit.autopsy.aegis.SanitizerBridge().locateCli();
                String san = cli != null && java.nio.file.Files.isRegularFile(cli) ? "Ready" : "Not found";
                String ledger = "No case open";
                String reports = "No case open";
                if (AegisActions.caseOpen() && h.succeeded()) {
                    org.sleuthkit.autopsy.aegis.engine.EngineResult l = org.sleuthkit.autopsy.aegis.engine.AegisEngine.ledgerVerify();
                    ledger = l.succeeded() ? ("EMPTY".equals(l.result.optString("status")) ? "Empty" : "Valid ("
                            + l.result.optString("entry_count") + ")") : "INVALID";
                    java.nio.file.Path dir = org.sleuthkit.autopsy.aegis.engine.CaseWorkspace.stateDir().resolve("reports");
                    int n = 0;
                    if (java.nio.file.Files.isDirectory(dir)) {
                        try (var st = java.nio.file.Files.newDirectoryStream(dir)) {
                            for (java.nio.file.Path d : st) {
                                if (java.nio.file.Files.isRegularFile(d.resolve("aegis-report.meta.json"))) {
                                    n++;
                                }
                            }
                        } catch (java.io.IOException ignored) {
                            // counted as none
                        }
                    }
                    reports = Integer.toString(n);
                }
                return new String[]{engine, e01, san, priv, ledger, reports};
            }

            @Override
            protected void done() {
                liveChecking = false;
                try {
                    String[] r = get();
                    engineState.setText(r[0]);
                    e01State.setText(r[1]);
                    sanitizerState.setText(r[2]);
                    privilegeState.setText(r[3]);
                    ledgerState.setText(r[4]);
                    signedReports.setText(r[5]);
                } catch (Exception ex) {
                    engineState.setText("Unavailable");
                }
            }
        }.execute();
    }

    private JPanel recentCard() {
        RoundedPanel card = new RoundedPanel(new BorderLayout(0, 8));
        JPanel header = new JPanel(new BorderLayout());
        header.setOpaque(false);
        JLabel title = new JLabel("Recent Cases");
        title.setFont(AegisTokens.H3);
        title.setForeground(AegisTokens.NAVY);
        JLabel viewAll = link("View All", () -> host.show(AegisWorkspaceHost.CASES));
        header.add(title, BorderLayout.WEST);
        header.add(viewAll, BorderLayout.EAST);

        JPanel columns = new JPanel(new GridLayout(1, 3));
        columns.setOpaque(false);
        columns.setBackground(AegisTokens.SURFACE_ALT);
        columns.add(headerLabel("Case Name"));
        columns.add(headerLabel("Location"));
        columns.add(headerLabel("Last Opened"));
        JPanel columnWrap = new JPanel(new BorderLayout());
        columnWrap.setBackground(new Color(0xF8FAFC));
        columnWrap.setBorder(new EmptyBorder(6, 8, 6, 8));
        columnWrap.add(columns, BorderLayout.CENTER);

        JPanel body = new JPanel(new BorderLayout(0, 8));
        body.setOpaque(false);
        body.add(columnWrap, BorderLayout.NORTH);
        body.add(recentRows, BorderLayout.CENTER);
        card.add(header, BorderLayout.NORTH);
        card.add(body, BorderLayout.CENTER);
        return card;
    }

    private JPanel caseRow(AegisActions.RecentCase item, String name, String location, String opened) {
        JPanel row = new JPanel(new GridLayout(1, 3));
        row.setOpaque(false);
        row.setBorder(new EmptyBorder(7, 8, 7, 8));
        row.setMaximumSize(new Dimension(Integer.MAX_VALUE, 36));
        JLabel caseName = new JLabel(name);
        caseName.setFont(AegisTokens.BODY);
        caseName.setForeground(AegisTokens.NAVY);
        caseName.setIcon(AegisIcons.get("folder", AegisTokens.BLUE));
        JLabel path = new JLabel(location);
        path.setFont(AegisTokens.BODY_SMALL);
        path.setForeground(AegisTokens.TEXT_SECONDARY);
        JLabel when = new JLabel(opened);
        when.setFont(AegisTokens.BODY_SMALL);
        when.setForeground(AegisTokens.TEXT_SECONDARY);
        row.add(caseName);
        row.add(path);
        row.add(when);
        if (item != null) {
            row.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
            row.addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent e) {
                    AegisActions.openRecent(item.path(), item.name());
                }
            });
        }
        return row;
    }

    private JPanel statusCard() {
        RoundedPanel card = new RoundedPanel(new BorderLayout(0, 8));
        JPanel header = new JPanel(new BorderLayout());
        header.setOpaque(false);
        JLabel title = new JLabel("System Status");
        title.setFont(AegisTokens.H3);
        title.setForeground(AegisTokens.NAVY);
        header.add(title, BorderLayout.WEST);
        header.add(link("Details", () -> host.show(AegisWorkspaceHost.SETTINGS)), BorderLayout.EAST);

        JPanel checks = new JPanel();
        checks.setOpaque(false);
        checks.setLayout(new BoxLayout(checks, BoxLayout.Y_AXIS));
        checks.setBorder(new EmptyBorder(0, 0, 0, 16));
        checks.add(statusRow("Core Modules", "Loaded"));
        checks.add(statusRow("Search Engine", searchState));
        checks.add(statusRow("Timeline Engine", timelineState));
        checks.add(statusRow("Hash Database", hashState));
        checks.add(statusRow("Reporting", reportState));
        checks.add(statusRow("AEGIS Engine", engineState));
        checks.add(statusRow("E01 Writer", e01State));
        checks.add(statusRow("File Sanitizer", sanitizerState));
        checks.add(statusRow("Privilege", privilegeState));
        checks.add(statusRow("Case Ledger", ledgerState));
        checks.add(statusRow("Signed Reports", signedReports));

        JPanel facts = new JPanel();
        facts.setOpaque(false);
        facts.setLayout(new BoxLayout(facts, BoxLayout.Y_AXIS));
        facts.setBorder(new EmptyBorder(0, 16, 0, 0));
        facts.add(fact("Version", "AEGIS " + AegisTokens.VERSION));
        facts.add(fact("Java", System.getProperty("java.version", "")));
        facts.add(fact("Database", "<html>SQLite (Case)<br>PostgreSQL (Multi-user)</html>"));
        String arch = System.getProperty("os.arch", "");
        if ("amd64".equals(arch) || "x86_64".equals(arch)) {
            arch = "x64";
        }
        facts.add(fact("Platform", System.getProperty("os.name", "Windows") + (arch.isBlank() ? "" : " (" + arch + ")")));

        JPanel body = new JPanel(new BorderLayout());
        body.setOpaque(false);
        body.setBorder(new EmptyBorder(4, 0, 0, 0));
        JPanel left = new JPanel(new BorderLayout());
        left.setOpaque(false);
        left.setBorder(new EmptyBorder(0, 0, 0, 12));
        left.add(checks, BorderLayout.CENTER);
        JPanel right = new JPanel(new BorderLayout());
        right.setOpaque(false);
        right.setBorder(new EmptyBorder(0, 12, 0, 0));
        right.add(facts, BorderLayout.CENTER);
        javax.swing.JSeparator divider = new javax.swing.JSeparator(javax.swing.SwingConstants.VERTICAL);
        divider.setForeground(AegisTokens.BORDER);
        divider.setBackground(AegisTokens.BORDER);
        JPanel split = new JPanel(new BorderLayout());
        split.setOpaque(false);
        split.add(left, BorderLayout.CENTER);
        split.add(divider, BorderLayout.EAST);
        JPanel columns = new JPanel(new GridLayout(1, 2, 0, 0));
        columns.setOpaque(false);
        columns.add(split);
        columns.add(right);
        body.add(columns, BorderLayout.CENTER);
        card.add(header, BorderLayout.NORTH);
        card.add(body, BorderLayout.CENTER);
        return card;
    }

    private static JPanel statusRow(String name, String state) {
        JLabel value = new JLabel(state);
        return statusRow(name, value);
    }

    /** Icon from the measured value: a tick only for a positive result. */
    private static javax.swing.Icon stateIcon(String text) {
        String t = text == null ? "" : text.toLowerCase(java.util.Locale.ROOT);
        if (t.contains("unavailable") || t.contains("invalid") || t.contains("not found") || t.contains("not installed")) {
            return AegisIcons.get("error", AegisTokens.ERROR);
        }
        if (t.contains("checking") || t.contains("unknown") || t.contains("no case") || t.contains("standard") || t.equals("0") || t.contains("empty")) {
            return AegisIcons.get("clock", AegisTokens.TEXT_MUTED);
        }
        return AegisIcons.get("check", AegisTokens.SUCCESS);
    }

    private static JPanel statusRow(String name, JLabel state) {
        JPanel row = new JPanel(new BorderLayout(8, 0));
        row.setOpaque(false);
        row.setAlignmentX(java.awt.Component.LEFT_ALIGNMENT);
        row.setBorder(new EmptyBorder(2, 0, 2, 0));
        row.setMaximumSize(new Dimension(Integer.MAX_VALUE, 28));
        JLabel label = new JLabel(name);
        label.setFont(AegisTokens.BODY);
        label.setForeground(AegisTokens.TEXT);
        label.setIcon(stateIcon(state.getText()));
        state.addPropertyChangeListener("text", ev -> label.setIcon(stateIcon(state.getText())));
        state.setFont(AegisTokens.BODY_SMALL);
        state.setForeground(AegisTokens.TEXT_SECONDARY);
        state.setHorizontalAlignment(javax.swing.SwingConstants.RIGHT);
        row.add(label, BorderLayout.CENTER);
        row.add(state, BorderLayout.EAST);
        return row;
    }

    private static JPanel fact(String name, String value) {
        JPanel row = new JPanel(new BorderLayout(12, 0));
        row.setOpaque(false);
        row.setAlignmentX(java.awt.Component.LEFT_ALIGNMENT);
        row.setBorder(new EmptyBorder(2, 0, 8, 0));
        row.setMaximumSize(new Dimension(Integer.MAX_VALUE, 48));
        JLabel key = new JLabel(name);
        key.setFont(AegisTokens.CAPTION);
        key.setForeground(AegisTokens.TEXT_MUTED);
        key.setPreferredSize(new Dimension(72, 18));
        key.setVerticalAlignment(javax.swing.SwingConstants.TOP);
        JLabel val = new JLabel(value);
        val.setFont(AegisTokens.BODY_SMALL);
        val.setForeground(AegisTokens.TEXT);
        val.setVerticalAlignment(javax.swing.SwingConstants.TOP);
        row.add(key, BorderLayout.WEST);
        row.add(val, BorderLayout.CENTER);
        return row;
    }

    private JPanel quoteBar() {
        RoundedPanel bar = new RoundedPanel(new BorderLayout());
        bar.setPreferredSize(new Dimension(0, 72));
        JLabel quote = new JLabel("<html><div style='font-style:italic'>&quot;A safer tomorrow through knowledge,<br>accountability, and secure data handling.&quot;</div><div style='color:#64748B'>— AEGIS</div></html>");
        quote.setFont(AegisTokens.BODY);
        quote.setForeground(AegisTokens.NAVY);
        quote.setIcon(AegisIcons.get("shield", AegisTokens.BLUE, 22));
        quote.setIconTextGap(12);
        JLabel motto = new JLabel("PEOPLE   |   EVIDENCE   |   A SAFER TOMORROW");
        motto.setFont(AegisTokens.CAPTION);
        motto.setForeground(AegisTokens.TEXT_SECONDARY);
        bar.add(quote, BorderLayout.WEST);
        bar.add(motto, BorderLayout.EAST);
        return bar;
    }

    private JPanel action(String icon, String title, String subtitle, Runnable action) {
        RoundedPanel card = new RoundedPanel(new BorderLayout(12, 0));
        card.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        JLabel mark = new JLabel(AegisIcons.get(icon, AegisTokens.BLUE, 24));
        JLabel heading = new JLabel(title);
        heading.setFont(AegisTokens.H3);
        heading.setForeground(AegisTokens.NAVY);
        JLabel detail = new JLabel("<html><body style='width:150px'>" + subtitle + "</body></html>");
        detail.setFont(AegisTokens.BODY_SMALL);
        detail.setForeground(AegisTokens.TEXT_SECONDARY);
        JPanel text = new JPanel();
        text.setOpaque(false);
        text.setLayout(new BoxLayout(text, BoxLayout.Y_AXIS));
        text.add(heading);
        text.add(Box.createVerticalStrut(4));
        text.add(detail);
        JLabel chevron = new JLabel(AegisIcons.get("chevron", AegisTokens.TEXT_MUTED, 18));
        card.add(mark, BorderLayout.WEST);
        card.add(text, BorderLayout.CENTER);
        card.add(chevron, BorderLayout.EAST);
        MouseAdapter click = new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                action.run();
            }
        };
        card.addMouseListener(click);
        heading.addMouseListener(click);
        detail.addMouseListener(click);
        return card;
    }

    private static JLabel headerLabel(String text) {
        JLabel label = new JLabel(text);
        label.setFont(AegisTokens.CAPTION);
        label.setForeground(AegisTokens.TEXT_SECONDARY);
        return label;
    }

    private static JLabel link(String text, Runnable action) {
        JLabel label = new JLabel(text);
        label.setFont(AegisTokens.BODY);
        label.setForeground(AegisTokens.BLUE);
        label.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        label.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                action.run();
            }
        });
        return label;
    }

    private static boolean installed(String className) {
        try {
            Class.forName(className, false, Thread.currentThread().getContextClassLoader());
            return true;
        } catch (Throwable ex) {
            try {
                Class.forName(className);
                return true;
            } catch (Throwable again) {
                return false;
            }
        }
    }

    private static BufferedImage loadHero() {
        return AegisIcons.banner();
    }

    private static final class HomeBody extends JPanel implements javax.swing.Scrollable {

        @Override
        public Dimension getPreferredScrollableViewportSize() {
            return getPreferredSize();
        }

        @Override
        public int getScrollableUnitIncrement(java.awt.Rectangle visible, int orientation, int direction) {
            return 16;
        }

        @Override
        public int getScrollableBlockIncrement(java.awt.Rectangle visible, int orientation, int direction) {
            return 48;
        }

        @Override
        public boolean getScrollableTracksViewportWidth() {
            return true;
        }

        @Override
        public boolean getScrollableTracksViewportHeight() {
            return false;
        }
    }

    private static final class HeroBanner extends JPanel {

        private final BufferedImage image;

        HeroBanner(BufferedImage image) {
            this.image = image;
            setOpaque(false);
            int height = image == null ? 220 : 280;
            setPreferredSize(new Dimension(100, height));
            setMaximumSize(new Dimension(Integer.MAX_VALUE, height));
            addComponentListener(new java.awt.event.ComponentAdapter() {
                @Override
                public void componentResized(java.awt.event.ComponentEvent e) {
                    fitAspect();
                }
            });
        }

        private void fitAspect() {
            if (image == null || getWidth() <= 0) {
                return;
            }
            int height = (int) Math.round(getWidth() * (image.getHeight() / (double) image.getWidth()));
            if (Math.abs(getPreferredSize().height - height) > 1) {
                setPreferredSize(new Dimension(getWidth(), height));
                setMaximumSize(new Dimension(Integer.MAX_VALUE, height));
                revalidate();
            }
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_INTERPOLATION, RenderingHints.VALUE_INTERPOLATION_BICUBIC);
            g2.setRenderingHint(RenderingHints.KEY_RENDERING, RenderingHints.VALUE_RENDER_QUALITY);
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            if (image == null) {
                g2.setColor(new Color(0xE8EEF4));
                g2.fillRoundRect(0, 0, getWidth(), getHeight(), 12, 12);
                g2.dispose();
                return;
            }
            double scale = Math.min(getWidth() / (double) image.getWidth(), getHeight() / (double) image.getHeight());
            int width = (int) Math.round(image.getWidth() * scale);
            int height = (int) Math.round(image.getHeight() * scale);
            int x = (getWidth() - width) / 2;
            int y = (getHeight() - height) / 2;
            g2.setClip(new java.awt.geom.RoundRectangle2D.Float(0, 0, getWidth(), getHeight(), 12, 12));
            g2.drawImage(image, x, y, width, height, null);
            g2.dispose();
        }
    }

    private static final class RoundedPanel extends JPanel {

        RoundedPanel(java.awt.LayoutManager layout) {
            super(layout);
            setOpaque(false);
            setBorder(new EmptyBorder(14, 16, 14, 16));
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g2.setColor(Color.WHITE);
            g2.fillRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 16, 16);
            g2.setColor(AegisTokens.BORDER);
            g2.drawRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 16, 16);
            g2.dispose();
        }
    }
}
