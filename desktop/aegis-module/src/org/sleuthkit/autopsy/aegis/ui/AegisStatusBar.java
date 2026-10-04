package org.sleuthkit.autopsy.aegis.ui;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;
import javax.swing.border.MatteBorder;
import org.sleuthkit.autopsy.casemodule.Case;
import org.sleuthkit.autopsy.ingest.IngestManager;

final class AegisStatusBar extends JPanel {

    private final JLabel caseLabel = label();
    private final JLabel evidenceLabel = label();
    private final JLabel operationLabel = label();
    private final JLabel statusLabel = label();

    AegisStatusBar() {
        setLayout(new BorderLayout());
        setBackground(AegisTokens.SURFACE);
        setPreferredSize(new Dimension(0, 0));
        setVisible(false);
        setBorder(new MatteBorder(1, 0, 0, 0, AegisTokens.BORDER));
        JPanel left = new JPanel(new FlowLayout(FlowLayout.LEFT, 16, 4));
        left.setOpaque(false);
        left.add(caseLabel);
        left.add(evidenceLabel);
        left.add(operationLabel);
        left.add(statusLabel);
        JLabel product = label();
        product.setText("AEGIS " + AegisTokens.VERSION);
        product.setBorder(new EmptyBorder(0, 0, 0, 12));
        add(left, BorderLayout.WEST);
        add(product, BorderLayout.EAST);
        refresh();
    }

    void refresh() {
        caseLabel.setText("Case: " + (AegisActions.caseOpen() ? AegisActions.currentCaseName() : "none"));
        String evidence = "0";
        if (Case.isCaseOpen()) {
            try {
                evidence = Integer.toString(Case.getCurrentCaseThrows().getDataSources().size());
            } catch (Exception ex) {
                evidence = "—";
            }
        }
        evidenceLabel.setText("Evidence: " + evidence);
        boolean ingest = IngestManager.getInstance().isIngestRunning();
        operationLabel.setText("Operation: " + (ingest ? "ingest" : "idle"));
        statusLabel.setText("Status: " + (ingest ? "processing" : "ready"));
    }

    private static JLabel label() {
        JLabel label = new JLabel();
        label.setFont(AegisTokens.CAPTION);
        label.setForeground(AegisTokens.TEXT_SECONDARY);
        return label;
    }
}
