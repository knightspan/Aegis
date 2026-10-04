package org.sleuthkit.autopsy.aegis.ui;

import java.awt.BorderLayout;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.border.EmptyBorder;
import org.openide.windows.WindowManager;

public final class AegisAboutDialog {

    private AegisAboutDialog() {
    }

    public static void showDialog() {
        JDialog dialog = new JDialog(WindowManager.getDefault().getMainWindow(), "About AEGIS", true);
        JPanel root = new JPanel(new BorderLayout(16, 16));
        root.setBackground(AegisTokens.BACKGROUND);
        root.setBorder(new EmptyBorder(24, 24, 24, 24));

        JLabel mark = new JLabel(AegisIcons.logo(42));
        JLabel title = new JLabel(AegisTokens.PRODUCT);
        title.setFont(AegisTokens.DISPLAY);
        title.setForeground(AegisTokens.NAVY);
        JLabel descriptor = new JLabel(AegisTokens.DESCRIPTOR);
        descriptor.setFont(AegisTokens.H3);
        descriptor.setForeground(AegisTokens.BLUE);
        JLabel version = new JLabel("Version " + AegisTokens.VERSION);
        version.setFont(AegisTokens.BODY);
        version.setForeground(AegisTokens.TEXT_SECONDARY);

        JPanel header = new JPanel();
        header.setOpaque(false);
        header.setLayout(new javax.swing.BoxLayout(header, javax.swing.BoxLayout.Y_AXIS));
        mark.setAlignmentX(java.awt.Component.LEFT_ALIGNMENT);
        title.setAlignmentX(java.awt.Component.LEFT_ALIGNMENT);
        descriptor.setAlignmentX(java.awt.Component.LEFT_ALIGNMENT);
        version.setAlignmentX(java.awt.Component.LEFT_ALIGNMENT);
        header.add(mark);
        header.add(javax.swing.Box.createVerticalStrut(8));
        header.add(title);
        header.add(descriptor);
        header.add(version);

        JTextArea legal = new JTextArea();
        legal.setEditable(false);
        legal.setLineWrap(true);
        legal.setWrapStyleWord(true);
        legal.setFont(AegisTokens.BODY_SMALL);
        legal.setBackground(AegisTokens.SURFACE);
        legal.setForeground(AegisTokens.TEXT);
        legal.setBorder(new EmptyBorder(12, 12, 12, 12));
        legal.setText(
                "AEGIS is a digital forensics and secure data sanitization platform.\n"
                + AegisTokens.TAGLINE + "\n\n"
                + "Forensic analysis uses The Sleuth Kit and other tools. "
                + "The window system is Apache NetBeans Platform 15. "
                + "Search uses Apache Solr. Native disk and image parsing uses Sleuth Kit JNI.\n\n"
                + "Required third-party copyrights, licenses, and attribution remain in the application and license files. "
                + "Those components are not AEGIS-owned.\n\n"
                + "Upstream project information: https://www.sleuthkit.org/\n"
                + "Copyright notices for Sleuth Kit Labs and other maintainers remain in Help > About.");

        AegisButton close = new AegisButton("Close", AegisButton.Kind.PRIMARY);
        close.addActionListener(e -> dialog.dispose());
        AegisActionRow row = new AegisActionRow();
        row.add(close);

        root.add(header, BorderLayout.NORTH);
        root.add(legal, BorderLayout.CENTER);
        root.add(row, BorderLayout.SOUTH);
        dialog.setContentPane(root);
        dialog.setSize(560, 420);
        dialog.setLocationRelativeTo(WindowManager.getDefault().getMainWindow());
        dialog.setVisible(true);
    }
}
