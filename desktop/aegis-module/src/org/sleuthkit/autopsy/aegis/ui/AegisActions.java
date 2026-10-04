package org.sleuthkit.autopsy.aegis.ui;

import java.awt.event.ActionEvent;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import javax.swing.Action;
import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;
import org.openide.filesystems.FileUtil;
import org.openide.util.Lookup;
import org.openide.windows.WindowManager;
import org.sleuthkit.autopsy.casemodule.Case;
import org.sleuthkit.autopsy.corecomponentinterfaces.CoreComponentControl;
import org.sleuthkit.autopsy.casemodule.CaseActionException;
import org.sleuthkit.autopsy.casemodule.CaseCloseAction;
import org.sleuthkit.autopsy.casemodule.CaseNewActionInterface;
import org.sleuthkit.autopsy.casemodule.CaseOpenAction;
import org.sleuthkit.autopsy.casemodule.AddImageAction;
import org.sleuthkit.autopsy.coreutils.ModuleSettings;
import org.sleuthkit.autopsy.filesearch.FileSearchAction;
import org.sleuthkit.autopsy.ingest.RunIngestAction;
import org.openide.util.actions.CallableSystemAction;

/**
 * Invokes existing Autopsy/AEGIS actions. Does not reimplement forensic work.
 */
public final class AegisActions {

    public record RecentCase(String name, String path) {
    }

    private AegisActions() {
    }

    public static void newCase() {
        CaseNewActionInterface action = Lookup.getDefault().lookup(CaseNewActionInterface.class);
        if (action != null) {
            action.actionPerformed(event("new-case"));
        }
    }

    public static void openCase() {
        CaseOpenAction action = Lookup.getDefault().lookup(CaseOpenAction.class);
        if (action != null) {
            action.actionPerformed(event("open-case"));
        }
    }

    public static void closeCase() {
        CallableSystemAction.get(CaseCloseAction.class).actionPerformed(event("close-case"));
    }

    public static void addDataSource() {
        if (!Case.isCaseOpen()) {
            Object[] options = {"New Case", "Open Case", "Cancel"};
            int choice = JOptionPane.showOptionDialog(
                    WindowManager.getDefault().getMainWindow(),
                    "A case must be open before a data source can be added.",
                    "AEGIS",
                    JOptionPane.DEFAULT_OPTION,
                    JOptionPane.INFORMATION_MESSAGE,
                    null,
                    options,
                    options[0]);
            if (choice == 0) {
                newCase();
            } else if (choice == 1) {
                openCase();
            }
            return;
        }
        CallableSystemAction.get(AddImageAction.class).actionPerformed(event("add-source"));
    }

    public static void runIngest() {
        RunIngestAction.getInstance().actionPerformed(event("ingest"));
    }

    public static void fileSearch() {
        FileSearchAction.getDefault().actionPerformed(event("file-search"));
    }

    public static void openForensicWorkspace() {
        SwingUtilities.invokeLater(() -> {
            try {
                CoreComponentControl.openCoreWindows();
            } catch (RuntimeException ex) {
                java.util.logging.Logger.getLogger(AegisActions.class.getName())
                        .log(java.util.logging.Level.SEVERE, "Could not open the forensic workspace", ex);
            }
        });
    }

    public static void closeForensicWorkspace() {
        if (!caseOpen()) {
            return;
        }
        SwingUtilities.invokeLater(() -> {
            try {
                CoreComponentControl.closeCoreWindows();
            } catch (RuntimeException ex) {
                java.util.logging.Logger.getLogger(AegisActions.class.getName())
                        .log(java.util.logging.Level.FINE, "Could not close the forensic workspace", ex);
            }
        });
    }

    public static void timeline() {
        invokeLayer("Actions/Tools/org-sleuthkit-autopsy-timeline-Timeline.instance");
    }

    public static void communications() {
        invokeLayer("Actions/Tools/org-sleuthkit-autopsy-communicationsVisualization-OpenCVTAction.instance");
    }

    public static void reports() {
        invokeLayer("Actions/Tools/org-sleuthkit-autopsy-report-infrastructure-ReportWizardAction.instance");
    }

    public static void imageGallery() {
        invokeLayer("Actions/Tools/org-sleuthkit-autopsy-imagegallery-OpenAction.instance");
    }

    public static void options() {
        invokeLayer("Actions/Window/org-netbeans-modules-options-OptionsWindowAction.instance");
    }

    public static void about() {
        AegisAboutDialog.showDialog();
    }

    public static void help() {
        invokeLayer("Actions/Help/org-sleuthkit-autopsy-corecomponents-OfflineHelpAction.instance");
    }

    public static void openRecent(String metadataPath, String name) {
        if (metadataPath == null || metadataPath.isBlank() || !new File(metadataPath).exists()) {
            JOptionPane.showMessageDialog(WindowManager.getDefault().getMainWindow(),
                    "Case " + name + " is no longer on disk.",
                    "AEGIS",
                    JOptionPane.ERROR_MESSAGE);
            return;
        }
        new Thread(() -> {
            try {
                Case.openAsCurrentCase(metadataPath);
            } catch (CaseActionException ex) {
                SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(
                        WindowManager.getDefault().getMainWindow(),
                        ex.getMessage(),
                        "AEGIS",
                        JOptionPane.ERROR_MESSAGE));
            }
        }, "aegis-open-case").start();
    }

    public static List<RecentCase> recentCases() {
        List<RecentCase> list = new ArrayList<>();
        for (int i = 1; i <= 6; i++) {
            String name = ModuleSettings.getConfigSetting(ModuleSettings.MAIN_SETTINGS, "LBL_RecentCase_Name" + i);
            String path = ModuleSettings.getConfigSetting(ModuleSettings.MAIN_SETTINGS, "LBL_RecentCase_Path" + i);
            if (name != null && !name.isBlank() && path != null && !path.isBlank()) {
                list.add(new RecentCase(name, path));
            }
        }
        return list;
    }

    public static boolean caseOpen() {
        return Case.isCaseOpen();
    }

    public static String currentCaseName() {
        try {
            return Case.getCurrentCaseThrows().getDisplayName();
        } catch (Exception ex) {
            return "No case selected";
        }
    }

    public static String currentCasePath() {
        try {
            return Case.getCurrentCaseThrows().getCaseDirectory();
        } catch (Exception ex) {
            return "";
        }
    }

    private static void invokeLayer(String path) {
        Action action = FileUtil.getConfigObject(path, Action.class);
        if (action != null) {
            action.actionPerformed(event(path));
        }
    }

    private static ActionEvent event(String command) {
        return new ActionEvent(AegisActions.class, ActionEvent.ACTION_PERFORMED, command);
    }
}
