package org.sleuthkit.autopsy.aegis.ui;

import java.awt.BorderLayout;
import javax.swing.JLabel;
import javax.swing.JPanel;
import org.sleuthkit.autopsy.casemodule.Case;

final class AegisSearchPanel extends AegisPage {

    AegisSearchPanel() {
        JLabel title = new JLabel("Search");
        title.setFont(AegisTokens.H1);
        title.setForeground(AegisTokens.NAVY);
        JLabel subtitle = new JLabel("Search evidence using the existing file and keyword engines.");
        subtitle.setFont(AegisTokens.BODY);
        subtitle.setForeground(AegisTokens.TEXT_SECONDARY);

        AegisSearchField field = new AegisSearchField("Search cases, files, artifacts, keywords...");
        AegisButton search = new AegisButton("Open file search", AegisButton.Kind.PRIMARY);
        search.addActionListener(e -> AegisActions.fileSearch());

        AegisCard card = new AegisCard(new BorderLayout(12, 12));
        card.add(new AegisEmptyState("search",
                Case.isCaseOpen() ? "Search this case" : "Open a case to search",
                "File search, keyword search, and hash lookup stay on the existing forensic engines. This screen opens those tools."),
                BorderLayout.CENTER);
        JPanel row = new JPanel(new BorderLayout(8, 0));
        row.setOpaque(false);
        row.add(field, BorderLayout.CENTER);
        row.add(search, BorderLayout.EAST);
        card.add(row, BorderLayout.SOUTH);

        JPanel header = new JPanel(new BorderLayout());
        header.setOpaque(false);
        header.add(title, BorderLayout.NORTH);
        header.add(subtitle, BorderLayout.SOUTH);
        add(header, BorderLayout.NORTH);
        add(card, BorderLayout.CENTER);
    }
}
