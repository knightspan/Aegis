package org.sleuthkit.autopsy.aegis.ui;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridBagLayout;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;
import javax.swing.border.MatteBorder;

final class AegisTopBar extends JPanel {

    private final AegisWorkspaceHost host;

    AegisTopBar(AegisWorkspaceHost host) {
        this.host = host;
        setLayout(new BorderLayout());
        setBackground(AegisTokens.SURFACE);
        setPreferredSize(new Dimension(0, 56));
        setMinimumSize(new Dimension(0, 56));
        setBorder(new MatteBorder(0, 0, 1, 0, AegisTokens.BORDER));

        JLabel tagline = new JLabel("INVESTIGATE. UNDERSTAND. PROTECT.");
        tagline.setFont(AegisTokens.LABEL);
        tagline.setForeground(AegisTokens.TEXT_SECONDARY);
        JPanel center = new JPanel(new GridBagLayout());
        center.setOpaque(false);
        center.add(tagline);

        JLabel mark = new JLabel(AegisIcons.logo(28));
        mark.setBorder(new EmptyBorder(0, 18, 0, 10));

        AegisSearchField search = new AegisSearchField("Search cases, files, artifacts...");
        search.setPreferredSize(new Dimension(420, 34));
        search.setMinimumSize(new Dimension(280, 34));
        search.setMaximumSize(new Dimension(480, 34));
        search.addActionListener(e -> AegisCommandPalette.open(host));

        JPanel icons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
        icons.setOpaque(false);
        icons.add(iconButton("notification", "Notifications", e -> host.show(AegisWorkspaceHost.REPORTS)));
        icons.add(iconButton("settings", "Settings", e -> host.show(AegisWorkspaceHost.SETTINGS)));
        icons.add(iconButton("user", "Account", e -> AegisActions.about()));

        // Search fills remaining east space so the full placeholder stays visible.
        JPanel right = new JPanel(new BorderLayout(10, 0));
        right.setOpaque(false);
        right.setBorder(new EmptyBorder(11, 0, 11, 16));
        right.setPreferredSize(new Dimension(560, 56));
        right.add(search, BorderLayout.CENTER);
        right.add(icons, BorderLayout.EAST);

        add(mark, BorderLayout.WEST);
        add(center, BorderLayout.CENTER);
        add(right, BorderLayout.EAST);
    }

    void refresh() {
    }

    private static AegisButton iconButton(String icon, String tip, java.awt.event.ActionListener listener) {
        AegisButton button = new AegisButton("", AegisButton.Kind.GHOST);
        button.setIcon(AegisIcons.get(icon, AegisTokens.TEXT_SECONDARY, 18));
        button.setToolTipText(tip);
        button.setBorder(new EmptyBorder(4, 6, 4, 6));
        button.addActionListener(listener);
        return button;
    }
}
