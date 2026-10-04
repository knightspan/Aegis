package org.sleuthkit.autopsy.aegis.ui;

import java.awt.BorderLayout;
import javax.swing.border.EmptyBorder;
import org.sleuthkit.autopsy.aegis.ui.reports.ReportViewerView;

/** Reports page: hosts the AEGIS Report Viewer. */
final class AegisReportsPanel extends AegisPage {

    private final ReportViewerView viewer = new ReportViewerView();

    AegisReportsPanel() {
        setBorder(new EmptyBorder(0, 0, 0, 0));
        setLayout(new BorderLayout());
        add(viewer, BorderLayout.CENTER);
    }

    void refresh() {
        viewer.refresh();
    }
}
