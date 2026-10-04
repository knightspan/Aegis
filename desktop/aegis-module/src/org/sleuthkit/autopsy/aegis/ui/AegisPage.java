package org.sleuthkit.autopsy.aegis.ui;

import java.awt.BorderLayout;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;

/** Shared AEGIS page panel for feature workspaces. */
public class AegisPage extends JPanel {

    public AegisPage() {
        super(new BorderLayout(16, 16));
        setBackground(AegisTokens.BACKGROUND);
        setBorder(new EmptyBorder(24, 24, 24, 24));
    }
}
