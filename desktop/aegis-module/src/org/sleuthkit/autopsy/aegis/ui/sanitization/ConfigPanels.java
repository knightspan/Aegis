package org.sleuthkit.autopsy.aegis.ui.sanitization;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.nio.file.Path;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.border.EmptyBorder;
import org.sleuthkit.autopsy.aegis.sanitization.DeviceEligibilityService;
import org.sleuthkit.autopsy.aegis.sanitization.SanitizationUIState;
import org.sleuthkit.autopsy.aegis.sanitization.TargetType;
import org.sleuthkit.autopsy.aegis.ui.AegisIcons;
import org.sleuthkit.autopsy.aegis.ui.AegisTokens;

final class TargetSelectionPanel extends SanitizationCard {

    interface Actions {
        void browse();
    }

    private final JTextField pathField = new JTextField();
    private final JButton browse = UiButtons.outline("Browse...");
    private final JLabel pathLabel = new JLabel("Target Path");
    private final CardHeader header;

    TargetSelectionPanel(Actions actions) {
        JPanel body = new JPanel();
        body.setOpaque(false);
        body.setLayout(new BoxLayout(body, BoxLayout.Y_AXIS));
        body.setAlignmentX(LEFT_ALIGNMENT);
        // The target type is chosen in the page's File / Folder / Volume / Physical Device row.
        header = new CardHeader("file", "1. Select Target", "Choose the file to be sanitized.");
        stretchLeft(header);
        body.add(header);
        body.add(Box.createVerticalStrut(14));

        pathLabel.setFont(AegisTokens.LABEL);
        pathLabel.setForeground(AegisTokens.TEXT_SECONDARY);
        stretchLeft(pathLabel);
        body.add(pathLabel);

        pathField.setEditable(false);
        pathField.setFont(AegisTokens.BODY);
        pathField.setBorder(javax.swing.BorderFactory.createCompoundBorder(
                javax.swing.BorderFactory.createLineBorder(AegisTokens.BORDER),
                new EmptyBorder(8, 10, 8, 10)));
        pathField.setText("No file selected");
        pathField.setForeground(AegisTokens.TEXT_MUTED);

        browse.setIcon(AegisIcons.get("folder-open", AegisTokens.TEXT_SECONDARY, 16));
        browse.addActionListener(e -> actions.browse());

        JPanel pathRow = new JPanel(new BorderLayout(8, 0));
        pathRow.setOpaque(false);
        stretchLeft(pathRow);
        pathRow.setMaximumSize(new java.awt.Dimension(Integer.MAX_VALUE, 40));
        browse.setPreferredSize(new java.awt.Dimension(118, 34));
        pathRow.add(pathField, BorderLayout.CENTER);
        pathRow.add(browse, BorderLayout.EAST);
        body.add(Box.createVerticalStrut(6));
        body.add(pathRow);
        body.add(Box.createVerticalStrut(12));
        // Not stretchLeft: that caps the height at one line, measured before the text has a width to wrap to.
        body.add(infoBanner());

        add(body, BorderLayout.CENTER);
    }

    void sync(SanitizationUIState state) {
        header.setSubtitle(state.targetType() == TargetType.FOLDER ? "Choose the folder to be sanitized, with everything in it."
                : "Choose the file to be sanitized.");
        Path path = state.targetPath();
        if (path == null) {
            String placeholder = state.targetType() == TargetType.FOLDER ? "No folder selected"
                    : state.targetType().requiresRemovableMedia() ? "No device selected" : "No file selected";
            pathField.setText(placeholder);
            pathField.setForeground(AegisTokens.TEXT_MUTED);
            pathField.setToolTipText(null);
        } else {
            String full = path.toString();
            pathField.setText(full);
            pathField.setForeground(AegisTokens.TEXT);
            pathField.setToolTipText(full);
            pathField.setCaretPosition(0);
        }
        boolean browseOk = !state.targetType().requiresRemovableMedia() || state.volumeDiskEligible();
        browse.setEnabled(browseOk);
    }

    private static JPanel infoBanner() {
        JPanel banner = new JPanel(new BorderLayout(10, 0)) {
            @Override
            public java.awt.Dimension getMaximumSize() {
                return new java.awt.Dimension(Integer.MAX_VALUE, getPreferredSize().height);
            }
        };
        banner.setBackground(new java.awt.Color(0xEAF2FF));
        banner.setBorder(javax.swing.BorderFactory.createCompoundBorder(
                javax.swing.BorderFactory.createLineBorder(new java.awt.Color(0xC9DBF8)),
                new EmptyBorder(10, 12, 10, 12)));
        banner.setOpaque(true);
        banner.setAlignmentX(LEFT_ALIGNMENT);
        JLabel icon = new JLabel(AegisIcons.get("info", AegisTokens.BLUE, 16));
        icon.setVerticalAlignment(javax.swing.SwingConstants.TOP);
        javax.swing.JTextArea text = new javax.swing.JTextArea("Files and folders are overwritten and verified by the AEGIS "
                + "file sanitizer. Volume and Physical Device open the device workflow: " + DeviceEligibilityService.usbOnlyMessage());
        text.setFont(AegisTokens.BODY_SMALL);
        text.setForeground(AegisTokens.TEXT);
        text.setLineWrap(true);
        text.setWrapStyleWord(true);
        text.setEditable(false);
        text.setOpaque(false);
        text.setBorder(null);
        text.setFocusable(false);
        banner.add(icon, BorderLayout.WEST);
        banner.add(text, BorderLayout.CENTER);
        return banner;
    }

    /** BoxLayout.Y_AXIS left-packs only when alignmentX is LEFT and width can grow. */
    private static void stretchLeft(javax.swing.JComponent c) {
        c.setAlignmentX(LEFT_ALIGNMENT);
        java.awt.Dimension pref = c.getPreferredSize();
        c.setMaximumSize(new java.awt.Dimension(Integer.MAX_VALUE, Math.max(pref.height, 1)));
    }
}

final class MethodSelectionPanel extends SanitizationCard {

    interface Actions {
        void methodChanged(SanitizationUIState.MethodChoice choice);

        void passesChanged(int passes);
    }

    private final javax.swing.JComboBox<SanitizationUIState.MethodChoice> methods = new javax.swing.JComboBox<>();
    private final javax.swing.JSpinner passes = new javax.swing.JSpinner(new javax.swing.SpinnerNumberModel(1, 1, 35, 1));
    private final JLabel description = new JLabel();
    private boolean syncing;

    MethodSelectionPanel(Actions actions) {
        for (SanitizationUIState.MethodChoice choice : SanitizationUIState.supportedMethods()) {
            methods.addItem(choice);
        }
        methods.setFont(AegisTokens.BODY);
        passes.setFont(AegisTokens.BODY);
        description.setFont(AegisTokens.BODY_SMALL);
        description.setForeground(AegisTokens.TEXT_SECONDARY);

        methods.addActionListener(e -> {
            if (syncing) {
                return;
            }
            SanitizationUIState.MethodChoice choice = (SanitizationUIState.MethodChoice) methods.getSelectedItem();
            actions.methodChanged(choice);
        });
        passes.addChangeListener(e -> {
            if (syncing) {
                return;
            }
            actions.passesChanged((Integer) passes.getValue());
        });

        JPanel body = new JPanel();
        body.setOpaque(false);
        body.setLayout(new BoxLayout(body, BoxLayout.Y_AXIS));
        body.setAlignmentX(LEFT_ALIGNMENT);
        CardHeader header = new CardHeader("settings", "2. Choose Method",
                "Select a secure deletion method and configuration.");
        header.setAlignmentX(LEFT_ALIGNMENT);
        header.setMaximumSize(new java.awt.Dimension(Integer.MAX_VALUE, 64));
        body.add(header);
        body.add(Box.createVerticalStrut(12));

        JPanel row = new JPanel(new GridBagLayout());
        row.setOpaque(false);
        row.setAlignmentX(LEFT_ALIGNMENT);
        row.setMaximumSize(new java.awt.Dimension(Integer.MAX_VALUE, 40));
        GridBagConstraints gc = new GridBagConstraints();
        gc.gridy = 0;
        gc.fill = GridBagConstraints.HORIZONTAL;
        gc.anchor = GridBagConstraints.WEST;
        gc.gridx = 0;
        gc.weightx = 0.72;
        gc.insets = new java.awt.Insets(0, 0, 0, 12);
        methods.setMaximumSize(new java.awt.Dimension(Integer.MAX_VALUE, 32));
        row.add(methods, gc);

        JPanel passesWrap = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        passesWrap.setOpaque(false);
        JLabel passesLabel = new JLabel("Number of Passes:");
        passesLabel.setFont(AegisTokens.BODY_SMALL);
        passesLabel.setForeground(AegisTokens.TEXT_SECONDARY);
        passes.setPreferredSize(new java.awt.Dimension(64, 28));
        passesWrap.add(passesLabel);
        passesWrap.add(passes);
        gc.gridx = 1;
        gc.weightx = 0.28;
        gc.insets = new java.awt.Insets(0, 0, 0, 0);
        row.add(passesWrap, gc);
        body.add(row);
        body.add(Box.createVerticalStrut(8));
        description.setAlignmentX(LEFT_ALIGNMENT);
        description.setMaximumSize(new java.awt.Dimension(Integer.MAX_VALUE, 40));
        body.add(description);
        add(body, BorderLayout.CENTER);
    }

    void sync(SanitizationUIState state) {
        syncing = true;
        try {
            methods.setSelectedItem(state.method());
            passes.setValue(state.passes());
            passes.setEnabled(state.method() != null && state.method().passesConfigurable);
            description.setText(state.method() == null ? "" : state.method().description);
        } finally {
            syncing = false;
        }
    }
}

final class VerificationOptionsPanel extends SanitizationCard {

    interface Actions {
        void readBackChanged(boolean value);

        void hashChanged(boolean value);
    }

    private final javax.swing.JCheckBox readBack = new javax.swing.JCheckBox("Perform read-back verification after sanitization");
    private final javax.swing.JCheckBox hash = new javax.swing.JCheckBox("Generate hash before and after sanitization");
    private boolean syncing;

    VerificationOptionsPanel(Actions actions) {
        readBack.setFont(AegisTokens.BODY);
        readBack.setOpaque(false);
        hash.setFont(AegisTokens.BODY);
        hash.setOpaque(false);
        readBack.addActionListener(e -> {
            if (!syncing) {
                actions.readBackChanged(readBack.isSelected());
            }
        });
        hash.addActionListener(e -> {
            if (!syncing) {
                actions.hashChanged(hash.isSelected());
            }
        });

        JPanel body = new JPanel();
        body.setOpaque(false);
        body.setLayout(new BoxLayout(body, BoxLayout.Y_AXIS));
        body.setAlignmentX(LEFT_ALIGNMENT);
        CardHeader header = new CardHeader("verification", "3. Verification Options",
                "Confirm written data and optional audit hashing where supported.");
        header.setAlignmentX(LEFT_ALIGNMENT);
        header.setMaximumSize(new java.awt.Dimension(Integer.MAX_VALUE, 64));
        body.add(header);
        body.add(Box.createVerticalStrut(10));
        body.add(option(readBack, "Verifies the written data through read-back comparison."));
        body.add(Box.createVerticalStrut(8));
        body.add(option(hash, "Creates cryptographic hashes for audit and comparison where supported."));
        add(body, BorderLayout.CENTER);
    }

    void sync(SanitizationUIState state) {
        syncing = true;
        try {
            readBack.setSelected(state.readBackVerification());
            hash.setSelected(state.generateHash());
            hash.setEnabled(state.hashOptionSupported());
            hash.setVisible(true);
            if (!state.hashOptionSupported()) {
                hash.setToolTipText("Hash before/after is not implemented in the current sanitization engine.");
            }
        } finally {
            syncing = false;
        }
    }

    private static JPanel option(javax.swing.JCheckBox box, String hint) {
        JPanel panel = new JPanel();
        panel.setOpaque(false);
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setAlignmentX(LEFT_ALIGNMENT);
        panel.setMaximumSize(new java.awt.Dimension(Integer.MAX_VALUE, 56));
        box.setAlignmentX(LEFT_ALIGNMENT);
        box.setHorizontalAlignment(javax.swing.SwingConstants.LEFT);
        JLabel sub = new JLabel(hint);
        sub.setFont(AegisTokens.CAPTION);
        sub.setForeground(AegisTokens.TEXT_SECONDARY);
        sub.setBorder(new EmptyBorder(0, 24, 0, 0));
        sub.setAlignmentX(LEFT_ALIGNMENT);
        panel.add(box);
        panel.add(sub);
        return panel;
    }
}
