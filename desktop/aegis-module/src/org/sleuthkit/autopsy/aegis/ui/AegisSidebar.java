package org.sleuthkit.autopsy.aegis.ui;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.border.EmptyBorder;

final class AegisSidebar extends JPanel {

    private final Map<String, AegisSidebarItem> items = new LinkedHashMap<>();
    private final AegisWorkspaceHost host;

    AegisSidebar(AegisWorkspaceHost host) {
        this.host = host;
        setLayout(new BorderLayout());
        setBackground(AegisTokens.SIDEBAR);
        setBorder(new javax.swing.border.MatteBorder(0, 0, 0, 1, AegisTokens.BORDER));
        setPreferredSize(new Dimension(212, 0));

        JPanel brand = new JPanel(new BorderLayout());
        brand.setOpaque(false);
        brand.setBorder(new EmptyBorder(18, 16, 14, 16));
        JLabel mark = new JLabel(AegisIcons.logo(34));
        brand.add(mark, BorderLayout.WEST);

        JPanel nav = new JPanel();
        nav.setOpaque(false);
        nav.setLayout(new BoxLayout(nav, BoxLayout.Y_AXIS));
        addItem(nav, AegisWorkspaceHost.HOME, "home", "Home");
        addItem(nav, AegisWorkspaceHost.CASES, "cases", "Cases");
        addItem(nav, AegisWorkspaceHost.INGEST, "ingest", "Ingest");
        addItem(nav, AegisWorkspaceHost.DISK_IMAGER, "add-source", "Disk Imager");
        addItem(nav, AegisWorkspaceHost.SEARCH, "search", "Search");
        addItem(nav, AegisWorkspaceHost.TIMELINE, "timeline", "Timeline");
        addItem(nav, AegisWorkspaceHost.ANALYSIS, "analysis", "Analysis");
        addItem(nav, AegisWorkspaceHost.ARTIFACTS, "artifacts", "Artifacts");
        addItem(nav, AegisWorkspaceHost.MEDIA, "media", "Media");
        addItem(nav, AegisWorkspaceHost.COMMUNICATIONS, "communications", "Communications");
        addItem(nav, AegisWorkspaceHost.REGISTRY, "registry", "Registry");
        addItem(nav, AegisWorkspaceHost.TAGS, "tags", "Tags");
        addItem(nav, AegisWorkspaceHost.RECOVERY, "restore", "Recovery");
        addItem(nav, AegisWorkspaceHost.REPORTS, "reports", "Reports");
        nav.add(Box.createVerticalStrut(12));
        addItem(nav, AegisWorkspaceHost.SANITIZATION, "sanitization", "Sanitization");
        addItem(nav, AegisWorkspaceHost.ORACLE, "affiliate", "Oracle");
        addItem(nav, AegisWorkspaceHost.SETTINGS, "settings", "Settings");
        nav.add(Box.createVerticalGlue());

        JScrollPane navScroll = new JScrollPane(nav);
        navScroll.setBorder(null);
        navScroll.setOpaque(false);
        navScroll.getViewport().setOpaque(false);
        navScroll.setHorizontalScrollBarPolicy(javax.swing.ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        navScroll.getVerticalScrollBar().setUnitIncrement(16);
        navScroll.setViewportBorder(null);

        JPanel south = new JPanel();
        south.setOpaque(false);
        south.setLayout(new BoxLayout(south, BoxLayout.Y_AXIS));
        south.setBorder(new EmptyBorder(8, 18, 16, 12));
        JLabel version = new JLabel("AEGIS " + AegisTokens.VERSION);
        version.setFont(AegisTokens.CAPTION);
        version.setForeground(AegisTokens.TEXT);
        JLabel about = new JLabel("<html>Digital Forensics &amp;<br>Secure Data Sanitization</html>");
        about.setFont(AegisTokens.CAPTION);
        about.setForeground(AegisTokens.TEXT_SECONDARY);
        about.setCursor(java.awt.Cursor.getPredefinedCursor(java.awt.Cursor.HAND_CURSOR));
        about.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent e) {
                AegisActions.about();
            }
        });
        caseBox.setAlignmentX(LEFT_ALIGNMENT);
        version.setAlignmentX(LEFT_ALIGNMENT);
        about.setAlignmentX(LEFT_ALIGNMENT);
        south.add(caseBox);
        south.add(Box.createVerticalStrut(10));
        south.add(version);
        south.add(Box.createVerticalStrut(2));
        south.add(about);

        add(brand, BorderLayout.NORTH);
        add(navScroll, BorderLayout.CENTER);
        add(south, BorderLayout.SOUTH);
        select(AegisWorkspaceHost.HOME);
    }

    void select(String page) {
        items.forEach((key, item) -> item.setSelected(key.equals(page)));
        refreshCase();
    }

    private final JLabel caseTitle = new JLabel();
    private final JLabel caseDetail = new JLabel();
    private final JPanel caseBox = buildCaseBox();

    private JPanel buildCaseBox() {
        JPanel box = new JPanel(new BorderLayout(0, 2)) {
            @Override
            protected void paintComponent(java.awt.Graphics g) {
                java.awt.Graphics2D g2 = (java.awt.Graphics2D) g.create();
                g2.setRenderingHint(java.awt.RenderingHints.KEY_ANTIALIASING, java.awt.RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(AegisTokens.SURFACE);
                g2.fillRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 10, 10);
                g2.setColor(AegisTokens.BORDER);
                g2.drawRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 10, 10);
                g2.dispose();
            }
        };
        box.setOpaque(false);
        box.setBorder(new EmptyBorder(8, 10, 8, 10));
        box.setMaximumSize(new java.awt.Dimension(200, 80));
        JLabel head = new JLabel("Current Case", AegisIcons.get("folder", AegisTokens.BLUE, 14), JLabel.LEFT);
        head.setFont(AegisTokens.CAPTION);
        head.setForeground(AegisTokens.TEXT_SECONDARY);
        caseTitle.setFont(AegisTokens.TITLE);
        caseTitle.setForeground(AegisTokens.NAVY);
        caseDetail.setFont(AegisTokens.CAPTION);
        caseDetail.setForeground(AegisTokens.TEXT_SECONDARY);
        JPanel text = new JPanel(new java.awt.GridLayout(2, 1));
        text.setOpaque(false);
        text.add(caseTitle);
        text.add(caseDetail);
        box.add(head, BorderLayout.NORTH);
        box.add(text, BorderLayout.CENTER);
        box.setCursor(java.awt.Cursor.getPredefinedCursor(java.awt.Cursor.HAND_CURSOR));
        box.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mousePressed(java.awt.event.MouseEvent e) {
                navigate(AegisWorkspaceHost.CASES);
            }
        });
        return box;
    }

    private void refreshCase() {
        if (AegisActions.caseOpen()) {
            String id = org.sleuthkit.autopsy.aegis.engine.CaseWorkspace.caseId();
            String name = AegisActions.currentCaseName();
            caseTitle.setText(id.isBlank() ? name : id);
            caseDetail.setText(id.isBlank() || id.equals(name) ? "Open" : name);
        } else {
            caseTitle.setText("No active case");
            caseDetail.setText("Select or create a case to begin.");
        }
    }

    private void addItem(JPanel nav, String page, String icon, String label) {
        AegisSidebarItem item = new AegisSidebarItem(page, icon, label);
        java.awt.event.MouseAdapter navigation = new java.awt.event.MouseAdapter() {
            @Override
            public void mousePressed(java.awt.event.MouseEvent e) {
                navigate(page);
            }
        };
        item.addMouseListener(navigation);
        // Labels sit on top of the row. Swing does not deliver their clicks to the parent.
        for (java.awt.Component child : item.getComponents()) {
            child.addMouseListener(navigation);
        }
        items.put(page, item);
        nav.add(item);
    }

    private void navigate(String page) {
        AegisWorkspaceHost live = AegisHomeTopComponent.findInstance().host();
        if (live != null) {
            live.show(page);
        } else {
            host.show(page);
        }
    }
}
