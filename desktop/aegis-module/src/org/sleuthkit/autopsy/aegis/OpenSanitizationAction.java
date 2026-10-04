package org.sleuthkit.autopsy.aegis;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.nio.file.Files;
import java.nio.file.Path;
import org.openide.awt.ActionID;
import org.openide.awt.ActionReference;
import org.openide.awt.ActionRegistration;
import org.openide.util.NbBundle.Messages;
import org.sleuthkit.autopsy.aegis.ui.AegisHomeTopComponent;
import org.sleuthkit.datamodel.AbstractFile;

@ActionID(category = "Tools", id = "org.sleuthkit.autopsy.aegis.OpenSanitizationAction")
@ActionRegistration(displayName = "#CTL_OpenSanitizationAction", lazy = true)
@ActionReference(path = "Menu/Tools", position = 1850)
@Messages("CTL_OpenSanitizationAction=AEGIS Sanitization")
public final class OpenSanitizationAction implements ActionListener {

    @Override
    public void actionPerformed(ActionEvent event) {
        AegisHomeTopComponent.showSanitization();
    }

    public static void offerSelectedEvidence(AbstractFile file) {
        if (file == null || file.getLocalAbsPath() == null) {
            AegisHomeTopComponent.showSanitization();
            return;
        }
        Path path = Path.of(file.getLocalAbsPath());
        if (!Files.isRegularFile(path)) {
            AegisHomeTopComponent.showSanitization();
            return;
        }
        AegisHomeTopComponent.showSanitizationWithFile(path);
    }
}
