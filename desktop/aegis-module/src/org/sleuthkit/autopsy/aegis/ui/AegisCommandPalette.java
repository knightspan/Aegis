package org.sleuthkit.autopsy.aegis.ui;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import javax.swing.DefaultListModel;
import javax.swing.JDialog;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.border.EmptyBorder;
import org.openide.windows.WindowManager;

final class AegisCommandPalette {

    private record Command(String label, Runnable run) {
    }

    private AegisCommandPalette() {
    }

    static void open(AegisWorkspaceHost host) {
        JDialog dialog = new JDialog(WindowManager.getDefault().getMainWindow(), "AEGIS command palette", true);
        List<Command> commands = commands(host);
        DefaultListModel<String> model = new DefaultListModel<>();
        commands.forEach(command -> model.addElement(command.label()));
        JList<String> list = new JList<>(model);
        list.setFont(AegisTokens.BODY);
        list.setSelectionBackground(AegisTokens.SELECTION);
        list.setSelectionForeground(AegisTokens.NAVY);
        list.setSelectedIndex(0);

        AegisSearchField field = new AegisSearchField("Type a command");
        field.addKeyListener(new KeyAdapter() {
            @Override
            public void keyReleased(KeyEvent e) {
                String query = field.getText().toLowerCase(Locale.ROOT);
                model.clear();
                for (Command command : commands) {
                    if (command.label().toLowerCase(Locale.ROOT).contains(query)) {
                        model.addElement(command.label());
                    }
                }
                if (model.getSize() > 0) {
                    list.setSelectedIndex(0);
                }
                if (e.getKeyCode() == KeyEvent.VK_ENTER) {
                    runSelected(dialog, host, commands, list.getSelectedValue());
                } else if (e.getKeyCode() == KeyEvent.VK_ESCAPE) {
                    dialog.dispose();
                }
            }
        });
        list.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent e) {
                if (e.getClickCount() == 2) {
                    runSelected(dialog, host, commands, list.getSelectedValue());
                }
            }
        });

        JPanel root = new JPanel(new BorderLayout(8, 8));
        root.setBackground(AegisTokens.SURFACE);
        root.setBorder(new EmptyBorder(12, 12, 12, 12));
        root.add(field, BorderLayout.NORTH);
        root.add(new JScrollPane(list), BorderLayout.CENTER);
        dialog.setContentPane(root);
        dialog.setSize(new Dimension(520, 360));
        dialog.setLocationRelativeTo(WindowManager.getDefault().getMainWindow());
        field.requestFocusInWindow();
        dialog.setVisible(true);
    }

    private static void runSelected(JDialog dialog, AegisWorkspaceHost host, List<Command> commands, String label) {
        if (label == null) {
            return;
        }
        dialog.dispose();
        for (Command command : commands) {
            if (command.label().equals(label)) {
                command.run().run();
                return;
            }
        }
    }

    private static List<Command> commands(AegisWorkspaceHost host) {
        List<Command> list = new ArrayList<>();
        list.add(new Command("Create Case", AegisActions::newCase));
        list.add(new Command("Open Case", AegisActions::openCase));
        list.add(new Command("Close Case", AegisActions::closeCase));
        list.add(new Command("Add Data Source", AegisActions::addDataSource));
        list.add(new Command("Search Evidence", AegisActions::fileSearch));
        list.add(new Command("Open Timeline", AegisActions::timeline));
        list.add(new Command("Open Analysis", () -> host.show(AegisWorkspaceHost.ANALYSIS)));
        list.add(new Command("Generate Report", AegisActions::reports));
        list.add(new Command("Open Disk Imager", () -> host.show(AegisWorkspaceHost.DISK_IMAGER)));
        list.add(new Command("Open Recovery", () -> host.show(AegisWorkspaceHost.RECOVERY)));
        list.add(new Command("Open Oracle", () -> host.show(AegisWorkspaceHost.ORACLE)));
        list.add(new Command("Open Sanitization", () -> host.show(AegisWorkspaceHost.SANITIZATION)));
        list.add(new Command("Settings", AegisActions::options));
        list.add(new Command("About", AegisActions::about));
        list.add(new Command("Home", () -> host.show(AegisWorkspaceHost.HOME)));
        return list;
    }
}
