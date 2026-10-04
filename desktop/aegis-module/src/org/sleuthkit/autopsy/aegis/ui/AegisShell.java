package org.sleuthkit.autopsy.aegis.ui;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Container;
import java.awt.Dimension;
import java.awt.KeyEventDispatcher;
import java.awt.KeyboardFocusManager;
import java.awt.LayoutManager;
import java.awt.Window;
import java.awt.event.KeyEvent;
import java.beans.PropertyChangeEvent;
import java.util.EnumSet;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;
import javax.swing.JToolBar;
import javax.swing.Timer;
import org.openide.windows.WindowManager;
import org.sleuthkit.autopsy.casemodule.Case;
import org.sleuthkit.autopsy.ingest.IngestManager;

/**
 * Installs the AEGIS chrome around the existing NetBeans desktop.
 */
public final class AegisShell {

    private static boolean installed;

    private AegisShell() {
    }

    public static synchronized void install() {
        System.setProperty("aegis.product.shell", "true");
        if (installed) {
            return;
        }
        try {
            installNow();
        } catch (Throwable ex) {
            java.util.logging.Logger.getLogger(AegisShell.class.getName())
                    .log(java.util.logging.Level.SEVERE, "AEGIS shell install failed", ex);
            installed = false;
        }
    }

    private static void installNow() {
        java.util.logging.Logger.getLogger(AegisShell.class.getName())
                .info("AEGIS-STARTUP AegisShell.installNow()");
        Window window = WindowManager.getDefault().getMainWindow();
        if (!(window instanceof JFrame frame)) {
            java.util.logging.Logger.getLogger(AegisShell.class.getName())
                    .warning("AEGIS-STARTUP main window is not a JFrame yet");
            return;
        }
        hideWelcomeDialogs();
        frame.setJMenuBar(null);
        hidePlatformChrome(frame);
        syncTitle(frame);
        frame.setIconImages(AegisIcons.windowIcons());
        frame.getContentPane().setBackground(AegisTokens.BACKGROUND);
        AegisHomeTopComponent home = AegisHomeTopComponent.findInstance();
        if (!installed) {
            installChrome(frame, home.host());
            installShortcut();
            listenForCaseChanges();
        }
        installed = true;
        home.open();
        home.requestActive();
        if (home.host() != null) {
            String page = System.getProperty("aegis.open.page", "");
            if (Boolean.getBoolean("aegis.open.sanitization")) {
                home.host().show(AegisWorkspaceHost.SANITIZATION);
            } else if (!page.isBlank()) {
                home.host().show(page.trim().toUpperCase(java.util.Locale.ROOT));
            } else {
                home.host().show(AegisWorkspaceHost.HOME);
            }
            AegisUiProbe.startIfRequested(frame, home.host());
            AegisUiDriver.startIfRequested(frame, home.host());
        }
        hideWelcomeDialogs();
        hidePlatformChrome(frame);
        frame.revalidate();
        frame.repaint();
        Timer keepChromeHidden = new Timer(700, event -> {
            if (!frame.isDisplayable()) {
                ((Timer) event.getSource()).stop();
                return;
            }
            if (frame.getJMenuBar() != null) {
                frame.setJMenuBar(null);
            }
            hidePlatformChrome(frame);
            frame.setIconImages(AegisIcons.windowIcons());
            syncTitle(frame);
            frame.revalidate();
        });
        keepChromeHidden.setRepeats(true);
        keepChromeHidden.start();
    }

    /**
     * Autopsy's case code titles the frame "case - <app> <Autopsy version>" on every
     * case open and close; the product title is "case — AEGIS <AEGIS version>".
     */
    private static void syncTitle(JFrame frame) {
        String product = "AEGIS " + AegisTokens.VERSION;
        String title = product;
        try {
            if (Case.isCaseOpen()) {
                title = Case.getCurrentCaseThrows().getDisplayName() + " " + (char) 0x2014 + " " + product;
            }
        } catch (Exception ignored) {
            // No current case (closing): the product title alone.
        }
        if (!title.equals(frame.getTitle())) {
            frame.setTitle(title);
        }
    }

    private static void installChrome(JFrame frame, AegisWorkspaceHost host) {
        if (host == null) {
            return;
        }
        Container content = frame.getContentPane();
        if (!(content.getLayout() instanceof BorderLayout)) {
            content.setLayout(new BorderLayout());
        }
        AegisSidebar sidebar = new AegisSidebar(host);
        AegisTopBar topBar = new AegisTopBar(host);
        AegisStatusBar statusBar = new AegisStatusBar();
        host.bind(sidebar, topBar, statusBar);
        JPanel root = new JPanel(new BorderLayout());
        root.setBackground(AegisTokens.BACKGROUND);
        root.add(topBar, BorderLayout.NORTH);
        root.add(sidebar, BorderLayout.WEST);
        root.add(statusBar, BorderLayout.SOUTH);
        JPanel desktop = new JPanel(new BorderLayout());
        desktop.setBackground(AegisTokens.BACKGROUND);
        Component[] children = content.getComponents();
        BorderLayout layout = (BorderLayout) content.getLayout();
        for (Component child : children) {
            Object constraints = layout.getConstraints(child);
            content.remove(child);
            desktop.add(child, constraints == null ? BorderLayout.CENTER : constraints);
        }
        root.add(desktop, BorderLayout.CENTER);
        content.add(root, BorderLayout.CENTER);
    }

    private static void hideWelcomeDialogs() {
        for (Window extra : Window.getWindows()) {
            if (extra instanceof javax.swing.JDialog dialog) {
                String title = dialog.getTitle();
                if (title != null && (title.equals("Welcome") || title.equals("AEGIS")) && dialog.getWidth() <= 900 && dialog.getHeight() <= 500) {
                    dialog.setVisible(false);
                    dialog.dispose();
                }
            }
        }
    }

    public static void showHome() {
        AegisHomeTopComponent home = AegisHomeTopComponent.findInstance();
        home.open();
        home.requestActive();
        if (home.host() != null) {
            if (Boolean.getBoolean("aegis.open.sanitization")) {
                home.host().show(AegisWorkspaceHost.SANITIZATION);
            } else {
                home.host().show(AegisWorkspaceHost.HOME);
            }
        }
        java.util.logging.Logger.getLogger(AegisShell.class.getName())
                .info("AEGIS-STARTUP showHome current=" +
                        (home.host() == null ? "null" : home.host().current()));
        SwingUtilities.invokeLater(() -> {
            AegisHomeTopComponent again = AegisHomeTopComponent.findInstance();
            again.open();
            again.requestActive();
            if (again.host() != null) {
                if (Boolean.getBoolean("aegis.open.sanitization")) {
                    again.host().show(AegisWorkspaceHost.SANITIZATION);
                } else {
                    again.host().show(AegisWorkspaceHost.HOME);
                }
            }
        });
    }

    public static boolean isInstalled() {
        return installed;
    }

    /**
     * The concept window has no NetBeans menu, toolbar, document tabs, or
     * status line. Mode contents stay; only the platform chrome is collapsed.
     */
    private static void hidePlatformChrome(Component component) {
        if (component == null) {
            return;
        }
        String name = component.getClass().getName();
        if (component instanceof JToolBar bar) {
            bar.setVisible(false);
        }
        if (name.contains("TabDisplayer") || name.contains("StatusLine")) {
            component.setVisible(false);
            if (component instanceof JComponent jc) {
                Dimension zero = new Dimension(0, 0);
                jc.setPreferredSize(zero);
                jc.setMinimumSize(zero);
                jc.setMaximumSize(new Dimension(Integer.MAX_VALUE, 0));
            }
        }
        if (component instanceof Container container) {
            for (Component child : container.getComponents()) {
                hidePlatformChrome(child);
            }
        }
    }

    private static void restyleMenu(JFrame frame) {
        JMenuBar bar = frame.getJMenuBar();
        if (bar == null) {
            return;
        }
        bar.setBackground(AegisTokens.NAVY);
        bar.setForeground(Color.WHITE);
        bar.setBorderPainted(false);
        for (Component child : bar.getComponents()) {
            if (child instanceof JMenu menu) {
                menu.setForeground(Color.WHITE);
                menu.setFont(AegisTokens.BODY);
            }
        }
    }

    private static void transferChildren(Container from, JComponent to) {
        LayoutManager layout = from.getLayout();
        Component[] children = from.getComponents();
        if (layout instanceof BorderLayout border) {
            for (Component child : children) {
                Object constraint = border.getConstraints(child);
                from.remove(child);
                if (constraint != null) {
                    to.add(child, constraint);
                } else {
                    to.add(child, BorderLayout.CENTER);
                }
            }
        } else {
            for (Component child : children) {
                from.remove(child);
                to.add(child);
            }
        }
    }

    private static void installShortcut() {
        KeyboardFocusManager.getCurrentKeyboardFocusManager().addKeyEventDispatcher(new KeyEventDispatcher() {
            @Override
            public boolean dispatchKeyEvent(KeyEvent e) {
                if (e.getID() == KeyEvent.KEY_PRESSED
                        && e.getKeyCode() == KeyEvent.VK_K
                        && e.isControlDown()) {
                    AegisWorkspaceHost workspace = AegisHomeTopComponent.findInstance().host();
                    if (workspace != null) {
                        AegisCommandPalette.open(workspace);
                    }
                    e.consume();
                    return true;
                }
                return false;
            }
        });
    }

    private static void listenForCaseChanges() {
        Case.addEventTypeSubscriber(EnumSet.of(Case.Events.CURRENT_CASE, Case.Events.DATA_SOURCE_ADDED),
                (PropertyChangeEvent evt) -> SwingUtilities.invokeLater(() -> {
                    AegisWorkspaceHost workspace = AegisHomeTopComponent.findInstance().host();
                    if (workspace != null) {
                        if (Case.Events.DATA_SOURCE_ADDED.toString().equals(evt.getPropertyName())) {
                            // Stay in an AEGIS workflow that added the source (Disk Imager, Recovery);
                            // the Add Data Source wizard path continues to Analysis as before.
                            String here = workspace.current();
                            if (!AegisWorkspaceHost.DISK_IMAGER.equals(here) && !AegisWorkspaceHost.RECOVERY.equals(here)) {
                                workspace.show(AegisWorkspaceHost.ANALYSIS);
                            } else {
                                workspace.refreshChrome();
                            }
                        } else if (Case.Events.CURRENT_CASE.toString().equals(evt.getPropertyName()) && evt.getNewValue() != null) {
                            workspace.show(AegisWorkspaceHost.CASES);
                        } else {
                            workspace.refreshChrome();
                        }
                    }
                }));
        IngestManager.getInstance().addIngestJobEventListener(
                (PropertyChangeEvent evt) -> SwingUtilities.invokeLater(() -> {
                    AegisWorkspaceHost workspace = AegisHomeTopComponent.findInstance().host();
                    if (workspace != null) {
                        workspace.refreshChrome();
                    }
                }));
    }
}
