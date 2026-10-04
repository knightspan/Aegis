package org.sleuthkit.autopsy.aegis.ui;

import java.awt.BorderLayout;
import java.awt.GridLayout;
import javax.swing.JLabel;
import javax.swing.JPanel;

final class AegisSettingsPanel extends AegisPage {

    AegisSettingsPanel() {
        JLabel title = new JLabel("Settings");
        title.setFont(AegisTokens.H1);
        title.setForeground(AegisTokens.NAVY);
        JLabel subtitle = new JLabel("Opens the existing configuration system. Appearance, ingest, search, hash databases, and reports stay there.");
        subtitle.setFont(AegisTokens.BODY);
        subtitle.setForeground(AegisTokens.TEXT_SECONDARY);

        JPanel grid = new JPanel(new GridLayout(0, 2, 12, 12));
        grid.setOpaque(false);
        String[] sections = {
            "General", "Appearance", "Forensics", "Ingest",
            "Search", "Timeline", "Hash Databases", "Reports",
            "Sanitization", "Audit", "Performance", "Advanced"
        };
        for (String section : sections) {
            AegisCard card = new AegisCard();
            JLabel name = new JLabel(section);
            name.setFont(AegisTokens.TITLE);
            name.setForeground(AegisTokens.NAVY);
            card.add(name, BorderLayout.WEST);
            grid.add(card);
        }

        AegisButton open = new AegisButton("Open AEGIS options", AegisButton.Kind.PRIMARY);
        open.addActionListener(e -> AegisActions.options());
        AegisActionRow row = new AegisActionRow();
        row.add(open);

        JPanel header = new JPanel(new BorderLayout());
        header.setOpaque(false);
        header.add(title, BorderLayout.NORTH);
        header.add(subtitle, BorderLayout.SOUTH);
        add(header, BorderLayout.NORTH);
        add(grid, BorderLayout.CENTER);
        add(row, BorderLayout.SOUTH);
    }
}
