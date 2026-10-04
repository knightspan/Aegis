package org.sleuthkit.autopsy.aegis.ui.sanitization;

import java.awt.BorderLayout;
import java.awt.Window;
import java.util.List;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JTextField;
import javax.swing.border.EmptyBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import org.sleuthkit.autopsy.aegis.ui.AegisTokens;
import org.sleuthkit.autopsy.aegis.ui.kit.DetailList;
import org.sleuthkit.autopsy.aegis.ui.kit.Kit;
import org.sleuthkit.autopsy.aegis.ui.kit.Tone;
import org.sleuthkit.autopsy.aegis.util.AegisJson.AegisJsonObject;

/**
 * The destructive-operation gate. "Authorize" stays disabled until the operator
 * has typed the device serial exactly, acknowledged that every byte will be
 * destroyed, and either chosen a verified acquisition of this serial as the
 * backup or typed the waiver NO BACKUP. The engine re-checks all of it.
 */
final class DeviceAuthorizationDialog extends JDialog {

    private final String serial;
    private final JTextField typed = new JTextField();
    private final JCheckBox acknowledge = new JCheckBox();
    private final JRadioButton useBackup = new JRadioButton("Verified acquisition of this device (recommended)");
    private final JRadioButton noBackup = new JRadioButton("No backup — type NO BACKUP to proceed without one");
    private final JComboBox<String> backupBox = new JComboBox<>();
    private final JTextField waiverField = new JTextField();
    private final JButton authorize = Kit.danger("Authorize & Sanitize");
    private final JLabel status = Kit.caption("");
    private final List<String[]> backups;
    private boolean ok;

    DeviceAuthorizationDialog(Window owner, AegisJsonObject device, String method, String level, List<String[]> backups,
            boolean mounted) {
        super(owner, "Authorize destructive sanitization", ModalityType.APPLICATION_MODAL);
        this.serial = device.optString("serial").trim();
        this.backups = backups;
        JPanel root = new JPanel(new BorderLayout(0, 12));
        root.setBackground(AegisTokens.BACKGROUND);
        root.setBorder(new EmptyBorder(18, 18, 14, 18));
        root.add(Kit.notice(Tone.ERROR, "This permanently destroys all data on the selected device. It cannot be undone."),
                BorderLayout.NORTH);
        DetailList id = new DetailList().put("Device", device.optString("model")).put("Serial", DetailList.mono(serial))
                .put("Capacity", Kit.bytesExact(device.optLong("capacity_bytes", -1))).put("Physical path", device.optString("path"))
                .put("Mounted volumes", device.optStringList("mount_points").isEmpty() ? "None" : String.join(", ", device.optStringList("mount_points")))
                .put("Method", method).put("Requested outcome", level).done();
        JPanel center = Kit.column(10, id);
        if (mounted) {
            center.add(Kit.notice(Tone.WARNING, "Volumes on this device are mounted. AEGIS will first take the disk offline "
                    + "(not persistent; it returns at the next replug) after checking the typed serial. Close any open files on it."));
        }
        ButtonGroup g = new ButtonGroup();
        g.add(useBackup);
        g.add(noBackup);
        for (String[] b : backups) {
            backupBox.addItem(b[1]);
        }
        useBackup.setEnabled(!backups.isEmpty());
        useBackup.setSelected(!backups.isEmpty());
        noBackup.setSelected(backups.isEmpty());
        backupBox.setEnabled(!backups.isEmpty());
        useBackup.setOpaque(false);
        noBackup.setOpaque(false);
        JPanel backupPanel = Kit.column(4, Kit.label("Backup gate", AegisTokens.TITLE, AegisTokens.NAVY), useBackup,
                backups.isEmpty() ? Kit.caption("No verified Disk Imager acquisition of serial " + serial + " exists in this case.")
                : backupBox, noBackup, waiverField);
        center.add(backupPanel);
        acknowledge.setText("I understand every byte on this device will be overwritten and the data is unrecoverable.");
        acknowledge.setOpaque(false);
        center.add(acknowledge);
        center.add(Kit.label("Type the device serial number exactly to confirm:", AegisTokens.BODY_SMALL, AegisTokens.TEXT));
        typed.setFont(AegisTokens.MONO);
        center.add(typed);
        center.add(status);
        root.add(center, BorderLayout.CENTER);
        JButton cancel = Kit.outline("Cancel");
        cancel.addActionListener(e -> dispose());
        authorize.addActionListener(e -> {
            ok = check() == null;
            if (ok) {
                dispose();
            }
        });
        root.add(Kit.row(10, cancel, authorize), BorderLayout.SOUTH);
        DocumentListener dl = new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                update();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                update();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
            }
        };
        typed.getDocument().addDocumentListener(dl);
        waiverField.getDocument().addDocumentListener(dl);
        acknowledge.addActionListener(e -> update());
        useBackup.addActionListener(e -> update());
        noBackup.addActionListener(e -> update());
        setContentPane(root);
        setSize(620, mounted ? 640 : 580);
        setLocationRelativeTo(owner);
        update();
    }

    private String check() {
        if (serial.isBlank()) {
            return "The device reports no serial; it cannot be authorized.";
        }
        if (!typed.getText().trim().equals(serial)) {
            return "The typed serial does not match the device.";
        }
        if (!acknowledge.isSelected()) {
            return "Acknowledge that the data will be destroyed.";
        }
        if (useBackup.isSelected() && backups.isEmpty()) {
            return "No verified acquisition is available.";
        }
        if (noBackup.isSelected() && !"NO BACKUP".equals(waiverField.getText().trim())) {
            return "Type NO BACKUP to proceed without a verified acquisition.";
        }
        return null;
    }

    private void update() {
        waiverField.setEnabled(noBackup.isSelected());
        backupBox.setEnabled(useBackup.isSelected() && !backups.isEmpty());
        String problem = check();
        authorize.setEnabled(problem == null);
        status.setText(problem == null ? "All gates satisfied. The engine re-checks identity before the first write." : problem);
        status.setForeground(problem == null ? Tone.SUCCESS.fg : Tone.WARNING.fg);
    }

    boolean authorized() {
        return ok;
    }

    String typedSerial() {
        return typed.getText().trim();
    }

    String backupJob() {
        if (!useBackup.isSelected() || backups.isEmpty()) {
            return "";
        }
        return backups.get(Math.max(0, backupBox.getSelectedIndex()))[0];
    }

    String waiver() {
        return noBackup.isSelected() ? waiverField.getText().trim() : "";
    }
}
