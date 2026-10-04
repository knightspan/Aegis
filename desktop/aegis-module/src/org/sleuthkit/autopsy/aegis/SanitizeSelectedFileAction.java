package org.sleuthkit.autopsy.aegis;

import java.awt.event.ActionEvent;
import javax.swing.AbstractAction;
import org.openide.awt.ActionID;
import org.openide.awt.ActionReference;
import org.openide.awt.ActionRegistration;
import org.openide.util.Lookup;
import org.openide.util.NbBundle.Messages;
import org.openide.util.Utilities;
import org.sleuthkit.datamodel.AbstractFile;

/**
 * Pre-fills a real local file only. Disk-image content is not sanitized automatically.
 */
@ActionID(category = "Tools", id = "org.sleuthkit.autopsy.aegis.SanitizeSelectedFileAction")
@ActionRegistration(displayName = "#CTL_SanitizeSelectedFileAction", lazy = false)
@ActionReference(path = "Menu/Tools", position = 1860)
@Messages("CTL_SanitizeSelectedFileAction=Sanitize Selected File...")
public final class SanitizeSelectedFileAction extends AbstractAction {

    public SanitizeSelectedFileAction() {
        putValue(NAME, Bundle.CTL_SanitizeSelectedFileAction());
    }

    @Override
    public void actionPerformed(ActionEvent event) {
        Lookup lookup = Utilities.actionsGlobalContext();
        AbstractFile file = lookup.lookup(AbstractFile.class);
        OpenSanitizationAction.offerSelectedEvidence(file);
    }
}
