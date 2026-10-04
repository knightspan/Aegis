package org.sleuthkit.autopsy.aegis.ui.sanitization;

import java.awt.BorderLayout;
import java.awt.GridLayout;
import java.nio.file.Path;
import java.text.CharacterIterator;
import java.text.StringCharacterIterator;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.SwingConstants;
import javax.swing.border.EmptyBorder;
import org.sleuthkit.autopsy.aegis.sanitization.DeviceClassification;
import org.sleuthkit.autopsy.aegis.sanitization.SanitizationUIState;
import org.sleuthkit.autopsy.aegis.ui.AegisIcons;
import org.sleuthkit.autopsy.aegis.ui.AegisTokens;

final class TargetInformationPanel extends SanitizationCard {

    private final JPanel empty = new JPanel();
    private final JPanel details = new JPanel();
    private final JLabel typeValue = valueLabel();
    private final JLabel pathValue = valueLabel();
    private final JLabel sizeValue = valueLabel();
    private final JLabel fsValue = valueLabel();
    private final JLabel deviceValue = valueLabel();
    private final JLabel removableValue = valueLabel();
    private final JLabel caseValue = valueLabel();

    TargetInformationPanel() {
        JLabel title = new JLabel("TARGET INFORMATION");
        title.setFont(AegisTokens.LABEL);
        title.setForeground(AegisTokens.TEXT_SECONDARY);
        add(title, BorderLayout.NORTH);

        empty.setOpaque(false);
        empty.setLayout(new BoxLayout(empty, BoxLayout.Y_AXIS));
        JLabel icon = new JLabel(AegisIcons.get("folder", AegisTokens.TEXT_MUTED, 36));
        icon.setAlignmentX(CENTER_ALIGNMENT);
        JLabel heading = new JLabel("No target selected");
        heading.setFont(AegisTokens.TITLE);
        heading.setForeground(AegisTokens.TEXT_SECONDARY);
        heading.setAlignmentX(CENTER_ALIGNMENT);
        JLabel body = new JLabel("<html><div style='text-align:center'>Select a file, folder, volume, or physical disk to view details here.</div></html>");
        body.setFont(AegisTokens.CAPTION);
        body.setForeground(AegisTokens.TEXT_MUTED);
        body.setAlignmentX(CENTER_ALIGNMENT);
        empty.add(Box.createVerticalStrut(24));
        empty.add(icon);
        empty.add(Box.createVerticalStrut(12));
        empty.add(heading);
        empty.add(Box.createVerticalStrut(6));
        empty.add(body);
        empty.add(Box.createVerticalStrut(24));

        details.setOpaque(false);
        details.setLayout(new GridLayout(0, 1, 0, 6));
        details.add(row("Type", typeValue));
        details.add(row("Path", pathValue));
        details.add(row("Size", sizeValue));
        details.add(row("File System", fsValue));
        details.add(row("Device", deviceValue));
        details.add(row("Removable", removableValue));
        details.add(row("Case", caseValue));

        add(empty, BorderLayout.CENTER);
    }

    void sync(SanitizationUIState state) {
        Path path = state.targetPath();
        DeviceClassification classification = state.classification();
        remove(empty);
        remove(details);
        if (path == null || classification == null) {
            add(empty, BorderLayout.CENTER);
        } else {
            typeValue.setText(state.targetType().label());
            pathValue.setText(path.toString());
            pathValue.setToolTipText(path.toString());
            sizeValue.setText(formatSize(classification.sizeBytes()));
            fsValue.setText(classification.fileSystem());
            deviceValue.setText(classification.deviceIdentity());
            removableValue.setText(classification.removable() ? "Yes" : "No");
            caseValue.setText(state.caseName().isBlank() ? "—" : state.caseName());
            add(details, BorderLayout.CENTER);
        }
        revalidate();
        repaint();
    }

    private static JPanel row(String label, JLabel value) {
        JPanel row = new JPanel(new BorderLayout(8, 0));
        row.setOpaque(false);
        JLabel key = new JLabel(label);
        key.setFont(AegisTokens.CAPTION);
        key.setForeground(AegisTokens.TEXT_SECONDARY);
        value.setHorizontalAlignment(SwingConstants.RIGHT);
        row.add(key, BorderLayout.WEST);
        row.add(value, BorderLayout.CENTER);
        return row;
    }

    private static JLabel valueLabel() {
        JLabel label = new JLabel("—");
        label.setFont(AegisTokens.BODY_SMALL);
        label.setForeground(AegisTokens.TEXT);
        return label;
    }

    private static String formatSize(long bytes) {
        if (bytes < 0) {
            return "—";
        }
        if (bytes < 1024) {
            return bytes + " B";
        }
        long abs = bytes;
        CharacterIterator ci = new StringCharacterIterator("KMGTPE");
        for (int i = 40; i >= 0 && abs > 0xfffccccccccccccL >> i; i -= 10) {
            abs >>= 10;
            ci.next();
        }
        return String.format("%.1f %cB", abs / 1024.0, ci.current());
    }
}

final class OperationPreviewPanel extends SanitizationCard {

    private final JLabel target = value();
    private final JLabel type = value();
    private final JLabel path = value();
    private final JLabel size = value();
    private final JLabel fs = value();
    private final JLabel method = value();
    private final JLabel passes = value();
    private final JLabel verification = value();
    private final JLabel eta = value();

    OperationPreviewPanel() {
        JLabel title = new JLabel("OPERATION PREVIEW");
        title.setFont(AegisTokens.LABEL);
        title.setForeground(AegisTokens.TEXT_SECONDARY);
        add(title, BorderLayout.NORTH);
        JPanel grid = new JPanel(new GridLayout(0, 1, 0, 6));
        grid.setOpaque(false);
        grid.add(row("Target", target));
        grid.add(row("Target Type", type));
        grid.add(row("Path", path));
        grid.add(row("Size", size));
        grid.add(row("File System", fs));
        grid.add(row("Method", method));
        grid.add(row("Passes", passes));
        grid.add(row("Verification", verification));
        grid.add(row("Estimated Time", eta));
        add(grid, BorderLayout.CENTER);
    }

    void sync(SanitizationUIState state) {
        boolean has = state.targetPath() != null;
        target.setText(has ? state.targetDisplayName() : "—");
        type.setText(has ? state.targetType().label() : "—");
        path.setText(has ? state.targetPath().toString() : "—");
        path.setToolTipText(has ? state.targetPath().toString() : null);
        DeviceClassification classification = state.classification();
        size.setText(classification == null ? "—" : format(classification.sizeBytes()));
        fs.setText(classification == null ? "—" : classification.fileSystem());
        method.setText(state.method() == null ? "—" : state.method().label);
        passes.setText(Integer.toString(state.passes()));
        verification.setText(state.verificationSummary());
        eta.setText("—");
    }

    private static String format(long bytes) {
        if (bytes < 0) {
            return "—";
        }
        if (bytes < 1024) {
            return bytes + " B";
        }
        double value = bytes;
        String[] units = {"B", "KB", "MB", "GB", "TB"};
        int idx = 0;
        while (value >= 1024 && idx < units.length - 1) {
            value /= 1024;
            idx++;
        }
        return String.format("%.1f %s", value, units[idx]);
    }

    private static JPanel row(String label, JLabel value) {
        JPanel row = new JPanel(new BorderLayout(8, 0));
        row.setOpaque(false);
        JLabel key = new JLabel(label);
        key.setFont(AegisTokens.CAPTION);
        key.setForeground(AegisTokens.TEXT_SECONDARY);
        value.setHorizontalAlignment(SwingConstants.RIGHT);
        row.add(key, BorderLayout.WEST);
        row.add(value, BorderLayout.CENTER);
        return row;
    }

    private static JLabel value() {
        JLabel label = new JLabel("—");
        label.setFont(AegisTokens.BODY_SMALL);
        label.setForeground(AegisTokens.TEXT);
        return label;
    }
}

final class ImportantNotesPanel extends SanitizationCard {

    ImportantNotesPanel() {
        JPanel header = new JPanel(new BorderLayout(8, 0));
        header.setOpaque(false);
        header.add(new JLabel(AegisIcons.get("info", AegisTokens.BLUE, 16)), BorderLayout.WEST);
        JLabel title = new JLabel("IMPORTANT NOTES");
        title.setFont(AegisTokens.LABEL);
        title.setForeground(AegisTokens.TEXT_SECONDARY);
        header.add(title, BorderLayout.CENTER);
        add(header, BorderLayout.NORTH);

        javax.swing.JTextArea notes = new javax.swing.JTextArea(
                "• The operation permanently modifies the selected data.\n"
                + "• Ensure the correct target is selected.\n"
                + "• Volume and Physical Disk sanitization are restricted to supported removable USB storage.\n"
                + "• Internal SSDs and hard drives are not eligible for Volume/Physical Disk sanitization.\n"
                + "• An audit record will be created for the operation.");
        notes.setFont(AegisTokens.BODY_SMALL);
        notes.setForeground(AegisTokens.TEXT);
        notes.setLineWrap(true);
        notes.setWrapStyleWord(true);
        notes.setEditable(false);
        notes.setOpaque(false);
        notes.setBorder(new EmptyBorder(8, 0, 0, 0));
        notes.setFocusable(false);
        add(notes, BorderLayout.CENTER);
    }
}

final class ConfirmationPanel extends SanitizationCard {

    interface Actions {
        void confirmedChanged(boolean value);
    }

    private final JLabel target = new JLabel();
    private final JLabel method = new JLabel();
    private final JLabel verification = new JLabel();
    private final javax.swing.JCheckBox confirm = new javax.swing.JCheckBox(
            "I understand this operation permanently modifies the selected data.");
    private boolean syncing;

    ConfirmationPanel(Actions actions) {
        JPanel body = new JPanel();
        body.setOpaque(false);
        body.setLayout(new BoxLayout(body, BoxLayout.Y_AXIS));
        JLabel title = new JLabel("SANITIZE DATA?");
        title.setFont(AegisTokens.H2);
        title.setForeground(AegisTokens.NAVY);
        title.setAlignmentX(LEFT_ALIGNMENT);
        body.add(title);
        body.add(Box.createVerticalStrut(12));
        body.add(block("Target", target));
        body.add(Box.createVerticalStrut(8));
        body.add(block("Method", method));
        body.add(Box.createVerticalStrut(8));
        body.add(block("Verification", verification));
        body.add(Box.createVerticalStrut(14));

        JPanel warning = new JPanel(new BorderLayout(8, 0));
        warning.setOpaque(true);
        warning.setBackground(new java.awt.Color(0xFFF7ED));
        warning.setBorder(javax.swing.BorderFactory.createCompoundBorder(
                javax.swing.BorderFactory.createLineBorder(new java.awt.Color(0xFDE68A)),
                new EmptyBorder(10, 12, 10, 12)));
        warning.setAlignmentX(LEFT_ALIGNMENT);
        warning.add(new JLabel(AegisIcons.get("warning", AegisTokens.WARNING, 16)), BorderLayout.WEST);
        JLabel warnText = new JLabel("This operation permanently modifies the selected data.");
        warnText.setFont(AegisTokens.BODY_SMALL);
        warnText.setForeground(AegisTokens.TEXT);
        warning.add(warnText, BorderLayout.CENTER);
        body.add(warning);
        body.add(Box.createVerticalStrut(12));
        confirm.setOpaque(false);
        confirm.setFont(AegisTokens.BODY);
        confirm.setForeground(AegisTokens.ERROR);
        confirm.setAlignmentX(LEFT_ALIGNMENT);
        confirm.addActionListener(e -> {
            if (!syncing) {
                actions.confirmedChanged(confirm.isSelected());
            }
        });
        body.add(confirm);
        add(body, BorderLayout.CENTER);
    }

    void sync(SanitizationUIState state) {
        syncing = true;
        try {
            target.setText(state.targetPath() == null ? "—" : state.targetPath().toString());
            method.setText(state.method() == null ? "—" : state.method().label);
            verification.setText(state.verificationSummary());
            confirm.setSelected(state.confirmed());
        } finally {
            syncing = false;
        }
    }

    private static JPanel block(String label, JLabel value) {
        JPanel panel = new JPanel();
        panel.setOpaque(false);
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setAlignmentX(LEFT_ALIGNMENT);
        JLabel key = new JLabel(label);
        key.setFont(AegisTokens.LABEL);
        key.setForeground(AegisTokens.TEXT_SECONDARY);
        key.setAlignmentX(LEFT_ALIGNMENT);
        value.setFont(AegisTokens.BODY);
        value.setForeground(AegisTokens.TEXT);
        value.setAlignmentX(LEFT_ALIGNMENT);
        panel.add(key);
        panel.add(Box.createVerticalStrut(2));
        panel.add(value);
        return panel;
    }
}

final class ExecutionPanel extends SanitizationCard {

    private final JLabel phase = new JLabel("Idle");
    private final javax.swing.JProgressBar progress = new javax.swing.JProgressBar(0, 100);
    private final JLabel bytes = new JLabel("—");
    private final JLabel rate = new JLabel("—");
    private final JLabel method = new JLabel("—");
    private final JLabel target = new JLabel("—");

    ExecutionPanel() {
        JPanel body = new JPanel();
        body.setOpaque(false);
        body.setLayout(new BoxLayout(body, BoxLayout.Y_AXIS));
        JLabel title = new JLabel("EXECUTION");
        title.setFont(AegisTokens.H3);
        title.setForeground(AegisTokens.NAVY);
        title.setAlignmentX(LEFT_ALIGNMENT);
        body.add(title);
        body.add(Box.createVerticalStrut(12));
        target.setAlignmentX(LEFT_ALIGNMENT);
        method.setAlignmentX(LEFT_ALIGNMENT);
        phase.setAlignmentX(LEFT_ALIGNMENT);
        phase.setFont(AegisTokens.BODY);
        phase.setForeground(AegisTokens.TEXT);
        progress.setStringPainted(true);
        progress.setAlignmentX(LEFT_ALIGNMENT);
        body.add(labeled("Target", target));
        body.add(Box.createVerticalStrut(6));
        body.add(labeled("Method", method));
        body.add(Box.createVerticalStrut(10));
        body.add(phase);
        body.add(Box.createVerticalStrut(8));
        body.add(progress);
        body.add(Box.createVerticalStrut(10));
        body.add(labeled("Bytes", bytes));
        body.add(Box.createVerticalStrut(4));
        body.add(labeled("Speed", rate));
        add(body, BorderLayout.CENTER);
    }

    void sync(SanitizationUIState state) {
        target.setText(state.targetPath() == null ? "—" : state.targetPath().toString());
        method.setText(state.method() == null ? "—" : state.method().label);
        phase.setText(state.phase());
        progress.setValue((int) Math.round(state.progressPercent()));
        progress.setString(String.format("%.0f%%", state.progressPercent()));
        bytes.setText(state.bytesCompleted() + " / " + state.bytesTotal());
        rate.setText(state.rate());
    }

    private static JPanel labeled(String label, JLabel value) {
        JPanel row = new JPanel(new BorderLayout(8, 0));
        row.setOpaque(false);
        row.setAlignmentX(LEFT_ALIGNMENT);
        JLabel key = new JLabel(label);
        key.setFont(AegisTokens.CAPTION);
        key.setForeground(AegisTokens.TEXT_SECONDARY);
        value.setFont(AegisTokens.BODY_SMALL);
        value.setForeground(AegisTokens.TEXT);
        row.add(key, BorderLayout.WEST);
        row.add(value, BorderLayout.CENTER);
        return row;
    }
}

final class ResultPanel extends SanitizationCard {

    interface Actions {
        void openAudit();

        void openReport();

        void deepPurge();

        void closeResult();
    }

    private final JLabel title = new JLabel();
    private final JLabel detail = new JLabel();
    private final javax.swing.JButton audit = UiButtons.outline("Open Audit");
    private final javax.swing.JButton report = UiButtons.outline("Open Report");
    private final javax.swing.JButton deepPurge = UiButtons.outline("Deep Forensic Purge");
    private final javax.swing.JButton close = UiButtons.primary("Close");

    ResultPanel(Actions actions) {
        JPanel body = new JPanel();
        body.setOpaque(false);
        body.setLayout(new BoxLayout(body, BoxLayout.Y_AXIS));
        title.setFont(AegisTokens.H2);
        title.setAlignmentX(LEFT_ALIGNMENT);
        detail.setFont(AegisTokens.BODY_SMALL);
        detail.setForeground(AegisTokens.TEXT);
        detail.setAlignmentX(LEFT_ALIGNMENT);
        body.add(title);
        body.add(Box.createVerticalStrut(12));
        body.add(detail);
        body.add(Box.createVerticalStrut(16));
        JPanel buttons = new JPanel(new java.awt.FlowLayout(java.awt.FlowLayout.LEFT, 8, 0));
        buttons.setOpaque(false);
        buttons.setAlignmentX(LEFT_ALIGNMENT);
        audit.addActionListener(e -> actions.openAudit());
        report.addActionListener(e -> actions.openReport());
        deepPurge.addActionListener(e -> actions.deepPurge());
        close.addActionListener(e -> actions.closeResult());
        buttons.add(audit);
        buttons.add(report);
        buttons.add(deepPurge);
        buttons.add(close);
        body.add(buttons);
        add(body, BorderLayout.CENTER);
    }

    void sync(SanitizationUIState state) {
        title.setText(state.resultTitle().isBlank() ? "Result" : state.resultTitle());
        title.setForeground(state.resultSuccess() ? AegisTokens.SUCCESS : AegisTokens.ERROR);
        detail.setText("<html><body style='width:640px'>"
                + state.resultDetail().replace("\n", "<br>")
                + "</body></html>");
        boolean auditOk = state.auditPath() != null;
        boolean reportOk = state.reportPath() != null;
        audit.setEnabled(auditOk && state.resultSuccess());
        report.setEnabled(reportOk);
        if (!state.resultSuccess()) {
            audit.setEnabled(state.auditPath() != null);
        }
    }
}
