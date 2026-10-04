package org.sleuthkit.autopsy.aegis.ui;

import java.awt.BorderLayout;
import javax.swing.JLabel;
import javax.swing.JTextArea;
import org.openide.util.Lookup;
import org.sleuthkit.autopsy.casemodule.Case;
import org.sleuthkit.autopsy.ingest.IngestManager;
import org.sleuthkit.autopsy.ingest.IngestModuleFactory;

final class AegisIngestPanel extends AegisPage {

    private final JLabel status = new JLabel();
    private final JTextArea modules = new JTextArea();
    private static String installedModules;

    AegisIngestPanel() {
        JLabel title = new JLabel("Ingest");
        title.setFont(AegisTokens.H1);
        title.setForeground(AegisTokens.NAVY);
        JLabel subtitle = new JLabel("Installed ingest modules for this case. Start runs the existing ingest pipeline.");
        subtitle.setFont(AegisTokens.BODY);
        subtitle.setForeground(AegisTokens.TEXT_SECONDARY);

        status.setFont(AegisTokens.H3);
        status.setForeground(AegisTokens.NAVY);

        modules.setEditable(false);
        modules.setFont(AegisTokens.BODY);
        modules.setBackground(AegisTokens.SURFACE);
        modules.setForeground(AegisTokens.TEXT);
        modules.setBorder(new javax.swing.border.EmptyBorder(12, 12, 12, 12));

        AegisActionRow actions = new AegisActionRow();
        AegisButton add = new AegisButton("Add data source", AegisButton.Kind.PRIMARY);
        add.addActionListener(e -> AegisActions.addDataSource());
        AegisButton run = new AegisButton("Run ingest", AegisButton.Kind.OUTLINE);
        run.addActionListener(e -> AegisActions.runIngest());
        actions.add(add);
        actions.add(run);

        AegisCard card = new AegisCard(new BorderLayout(8, 8));
        card.add(status, BorderLayout.NORTH);
        card.add(new javax.swing.JScrollPane(modules), BorderLayout.CENTER);

        javax.swing.JPanel header = new javax.swing.JPanel(new BorderLayout());
        header.setOpaque(false);
        header.add(title, BorderLayout.NORTH);
        header.add(subtitle, BorderLayout.SOUTH);

        add(header, BorderLayout.NORTH);
        add(card, BorderLayout.CENTER);
        add(actions, BorderLayout.SOUTH);
        refresh();
    }

    void refresh() {
        boolean running = IngestManager.getInstance().isIngestRunning();
        status.setText(running ? "INGEST RUNNING" : (Case.isCaseOpen() ? "INGEST IDLE" : "NO CASE OPEN"));
        if (installedModules == null) {
            StringBuilder text = new StringBuilder();
            text.append("Installed ingest modules:\n\n");
            try {
                for (IngestModuleFactory factory : Lookup.getDefault().lookupAll(IngestModuleFactory.class)) {
                    text.append("• ").append(factory.getModuleDisplayName());
                    if (factory.getModuleDescription() != null && !factory.getModuleDescription().isBlank()) {
                        text.append("  —  ").append(factory.getModuleDescription());
                    }
                    text.append('\n');
                }
            } catch (Exception ex) {
                text.append("Module list unavailable: ").append(ex.getMessage());
            }
            installedModules = text.toString();
        }
        String extra = Case.isCaseOpen()
                ? ""
                : "\nOpen a case, then add a data source. Ingest runs through the existing engine.";
        modules.setText(installedModules + extra);
        modules.setCaretPosition(0);
    }
}
