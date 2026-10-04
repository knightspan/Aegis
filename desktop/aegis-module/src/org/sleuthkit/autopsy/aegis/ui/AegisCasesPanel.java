package org.sleuthkit.autopsy.aegis.ui;

import java.awt.BorderLayout;
import java.util.List;
import javax.swing.JLabel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;
import org.sleuthkit.autopsy.casemodule.Case;

final class AegisCasesPanel extends AegisPage {

    private final DefaultTableModel model = new DefaultTableModel(
            new Object[]{"Case Name", "Location", "Status"}, 0) {
        @Override
        public boolean isCellEditable(int row, int column) {
            return false;
        }
    };
    private final JTable table = new JTable(model);
    private final JLabel overview = new JLabel();

    AegisCasesPanel() {
        JLabel title = new JLabel("Cases");
        title.setFont(AegisTokens.H1);
        title.setForeground(AegisTokens.NAVY);

        AegisActionRow actions = new AegisActionRow();
        AegisButton create = new AegisButton("New case", AegisButton.Kind.PRIMARY);
        create.addActionListener(e -> AegisActions.newCase());
        AegisButton open = new AegisButton("Open case", AegisButton.Kind.OUTLINE);
        open.addActionListener(e -> AegisActions.openCase());
        AegisButton close = new AegisButton("Close case", AegisButton.Kind.SECONDARY);
        close.addActionListener(e -> AegisActions.closeCase());
        AegisButton openSelected = new AegisButton("Open selected", AegisButton.Kind.GHOST);
        openSelected.setForeground(AegisTokens.BLUE);
        openSelected.addActionListener(e -> openSelected());
        actions.add(create);
        actions.add(open);
        actions.add(close);
        actions.add(openSelected);

        table.setFont(AegisTokens.BODY);
        table.setRowHeight(28);
        table.getTableHeader().setFont(AegisTokens.LABEL);
        table.setGridColor(AegisTokens.BORDER);
        table.setSelectionBackground(AegisTokens.SELECTION);
        table.setSelectionForeground(AegisTokens.NAVY);

        overview.setFont(AegisTokens.BODY);
        overview.setForeground(AegisTokens.TEXT_SECONDARY);

        AegisCard tableCard = new AegisCard(new BorderLayout(8, 8));
        tableCard.add(new AegisSectionHeader("RECENT AND CURRENT CASES"), BorderLayout.NORTH);
        tableCard.add(new JScrollPane(table), BorderLayout.CENTER);
        tableCard.add(overview, BorderLayout.SOUTH);

        add(title, BorderLayout.NORTH);
        add(tableCard, BorderLayout.CENTER);
        add(actions, BorderLayout.SOUTH);
        refresh();
    }

    void refresh() {
        model.setRowCount(0);
        if (Case.isCaseOpen()) {
            model.addRow(new Object[]{AegisActions.currentCaseName(), AegisActions.currentCasePath(), "Open"});
            try {
                Case current = Case.getCurrentCaseThrows();
                overview.setText("Investigator: " + current.getExaminer()
                        + "   •   Sources: " + current.getDataSources().size()
                        + "   •   Reports: " + current.getAllReports().size());
            } catch (Exception ex) {
                overview.setText(AegisActions.currentCaseName());
            }
        } else {
            overview.setText("No case is open. Create or open a case to continue.");
        }
        List<AegisActions.RecentCase> recent = AegisActions.recentCases();
        for (AegisActions.RecentCase item : recent) {
            if (Case.isCaseOpen() && item.name().equals(AegisActions.currentCaseName())) {
                continue;
            }
            model.addRow(new Object[]{item.name(), item.path(), "Recent"});
        }
    }

    private void openSelected() {
        int row = table.getSelectedRow();
        if (row < 0) {
            AegisActions.openCase();
            return;
        }
        String status = String.valueOf(model.getValueAt(row, 2));
        if ("Open".equals(status)) {
            return;
        }
        AegisActions.openRecent(String.valueOf(model.getValueAt(row, 1)), String.valueOf(model.getValueAt(row, 0)));
    }
}
