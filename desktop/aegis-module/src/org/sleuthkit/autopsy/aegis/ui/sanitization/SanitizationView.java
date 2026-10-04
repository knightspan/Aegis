package org.sleuthkit.autopsy.aegis.ui.sanitization;

import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.GridLayout;
import java.awt.Insets;
import java.awt.Rectangle;
import java.io.File;
import java.nio.file.Path;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.Scrollable;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.border.EmptyBorder;
import javax.swing.border.MatteBorder;
import org.sleuthkit.autopsy.aegis.sanitization.DeviceEligibilityService;
import org.sleuthkit.autopsy.aegis.sanitization.SanitizationController;
import org.sleuthkit.autopsy.aegis.sanitization.SanitizationUIState;
import org.sleuthkit.autopsy.aegis.sanitization.TargetType;
import org.sleuthkit.autopsy.aegis.ui.AegisIcons;
import org.sleuthkit.autopsy.aegis.ui.AegisTokens;
import org.sleuthkit.autopsy.aegis.ui.kit.Kit;
import org.sleuthkit.autopsy.aegis.ui.kit.Stepper;

/**
 * Sanitization page root.
 * <pre>
 * NORTH  — page header + stepper (fixed)
 * CENTER — JScrollPane → two-column workspace only
 * SOUTH  — SanitizationActionBar (fixed, reserved height)
 * </pre>
 * Cancel / Next are never owned by the outer application frame.
 */
public final class SanitizationView extends JPanel {

    private static final int PAGE_PAD = 22;
    private static final int COLUMN_GAP = 18;
    private static final int CARD_GAP = 16;
    private static final double LEFT_WEIGHT = 0.72;
    private static final double RIGHT_WEIGHT = 0.28;
    private static final int ACTION_BAR_HEIGHT = 60;

    private final SanitizationUIState state = new SanitizationUIState();
    private final SanitizationController controller = new SanitizationController(state);

    // Same chrome as DeviceSanitizationView: kit stepper and the File / Folder / Volume / Physical Device row.
    private final Stepper stepper = new Stepper(
            new String[]{"Target Selection", "Method Selection", "Verification", "Confirmation", "Execution", "Results"},
            new String[]{"Choose what to sanitize", "Select sanitization method", "Read-back and hashing", "Review & confirm",
                "Sanitize with verification", "View report & audit"});
    private final JPanel typeRow = new JPanel(new GridLayout(1, 4, 10, 0));
    private TargetType shownType;
    private final TargetSelectionPanel targetPanel;
    private final MethodSelectionPanel methodPanel;
    private final VerificationOptionsPanel verificationPanel;
    private final TargetInformationPanel targetInfo = new TargetInformationPanel();
    private final OperationPreviewPanel preview = new OperationPreviewPanel();
    private final ImportantNotesPanel notes = new ImportantNotesPanel();
    private final ConfirmationPanel confirmationPanel;
    private final ExecutionPanel executionPanel = new ExecutionPanel();
    private final ResultPanel resultPanel;

    private final CardLayout stageCards = new CardLayout();
    private final JPanel stageHost = new JPanel(stageCards);
    private final JButton cancel = UiButtons.outline("Cancel");
    private final JButton next = UiButtons.primary("Next →");
    private final JButton back = UiButtons.outline("Back");
    private final JButton sanitize = UiButtons.danger("I UNDERSTAND — SANITIZE");
    private final JButton cancelRun = UiButtons.outline("Cancel");
    private final SanitizationActionBar actionBar = new SanitizationActionBar();
    private final WorkspacePanel workspace = new WorkspacePanel();
    private final JPanel northChrome = new JPanel(new BorderLayout(0, 18));
    private final JScrollPane workspaceScroll = new JScrollPane();

    public SanitizationView() {
        setLayout(new BorderLayout());
        setBorder(new EmptyBorder(20, 24, 0, 24));
        setBackground(AegisTokens.BACKGROUND);
        setOpaque(true);

        targetPanel = new TargetSelectionPanel(this::browseTarget);

        methodPanel = new MethodSelectionPanel(new MethodSelectionPanel.Actions() {
            @Override
            public void methodChanged(SanitizationUIState.MethodChoice choice) {
                state.setMethod(choice);
            }

            @Override
            public void passesChanged(int passes) {
                state.setPasses(passes);
            }
        });

        verificationPanel = new VerificationOptionsPanel(new VerificationOptionsPanel.Actions() {
            @Override
            public void readBackChanged(boolean value) {
                state.setReadBackVerification(value);
            }

            @Override
            public void hashChanged(boolean value) {
                state.setGenerateHash(value);
            }
        });

        confirmationPanel = new ConfirmationPanel(value -> state.setConfirmed(value));
        resultPanel = new ResultPanel(new ResultPanel.Actions() {
            @Override
            public void openAudit() {
                controller.openPath(state.auditPath(),
                        msg -> JOptionPane.showMessageDialog(SanitizationView.this, msg));
            }

            @Override
            public void openReport() {
                controller.openPath(state.reportPath(),
                        msg -> JOptionPane.showMessageDialog(SanitizationView.this, msg));
            }

            @Override
            public void deepPurge() {
                javax.swing.JCheckBox thumbs = new javax.swing.JCheckBox(
                        "Also clear the whole Windows thumbnail cache (cannot be tied to one file; Explorer is asked to restart)");
                Object[] message = {"Deep Forensic Purge sweeps Recent shortcuts, jump lists and Recycle Bin items that the\n"
                        + "AEGIS engine ties on evidence to the path you just sanitized, and removes them.\n"
                        + "Weaker matches are reported, never removed. Nothing is force-killed.\n\n", thumbs};
                int confirm = JOptionPane.showConfirmDialog(SanitizationView.this, message, "AEGIS Deep Forensic Purge",
                        JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
                if (confirm != JOptionPane.OK_OPTION) {
                    return;
                }
                state.setStep(SanitizationUIState.Step.EXECUTION);
                state.setPhase("Deep Forensic Purge running\u2026");
                refresh();
                controller.startDeepPurge(thumbs.isSelected(), msg -> SwingUtilities.invokeLater(() -> refresh()));
            }

            @Override
            public void closeResult() {
                state.resetWorkflow();
                state.setStep(SanitizationUIState.Step.TARGET);
                refresh();
            }
        });

        stageHost.setOpaque(false);
        stageHost.setName("sanitization.stageHost");
        stageHost.add(buildConfigStage(), "CONFIG");
        stageHost.add(wrap(confirmationPanel), "CONFIRM");
        stageHost.add(wrap(executionPanel), "EXECUTE");
        stageHost.add(wrap(resultPanel), "RESULT");

        workspace.setOpaque(false);
        workspace.setName("sanitization.workspace");
        workspace.setLayout(new BorderLayout());
        workspace.add(stageHost, BorderLayout.NORTH);

        wireActions();

        typeRow.setOpaque(false);
        typeRow.setPreferredSize(new Dimension(720, 38));
        JPanel typeWrap = new JPanel(new BorderLayout());
        typeWrap.setOpaque(false);
        typeWrap.add(typeRow, BorderLayout.WEST);
        northChrome.setOpaque(false);
        northChrome.setName("sanitization.north");
        northChrome.setBorder(new EmptyBorder(0, 0, 14, 0));
        northChrome.add(Kit.column(12, Kit.pageHeader("Data Sanitization", "Secure Data Sanitization & Verification",
                "Securely and permanently sanitize files, folders, volumes or physical devices with verification and audit logging."),
                stepper, typeWrap), BorderLayout.CENTER);

        workspaceScroll.setViewportView(workspace);
        workspaceScroll.setName("sanitization.scroll");
        workspaceScroll.setBorder(null);
        workspaceScroll.setOpaque(true);
        workspaceScroll.setBackground(AegisTokens.BACKGROUND);
        workspaceScroll.getViewport().setOpaque(true);
        workspaceScroll.getViewport().setBackground(AegisTokens.BACKGROUND);
        workspaceScroll.getVerticalScrollBar().setUnitIncrement(18);
        workspaceScroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        workspaceScroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);

        add(northChrome, BorderLayout.NORTH);
        add(workspaceScroll, BorderLayout.CENTER);
        add(actionBar, BorderLayout.SOUTH);

        addComponentListener(new java.awt.event.ComponentAdapter() {
            @Override
            public void componentResized(java.awt.event.ComponentEvent e) {
                syncToParentAllocation();
                revalidate();
                repaint();
            }
        });
        addHierarchyBoundsListener(new java.awt.event.HierarchyBoundsAdapter() {
            @Override
            public void ancestorResized(java.awt.event.HierarchyEvent e) {
                syncToParentAllocation();
            }
        });

        state.addListener(s -> SwingUtilities.invokeLater(this::refresh));
        controller.refreshCaseContext();
        refresh();
    }

    /**
     * Pin this page to the immediate parent's allocated size so CardLayout /
     * TopComponent preferred-size inflation cannot stretch the page and push
     * {@link SanitizationActionBar} below the clipped editor edge.
     */
    private void syncToParentAllocation() {
        java.awt.Container parent = getParent();
        if (parent == null) {
            return;
        }
        int pw = parent.getWidth();
        int ph = parent.getHeight();
        if (pw > 0 && ph > 0 && (getWidth() != pw || getHeight() != ph)) {
            setSize(pw, ph);
        }
    }

    /**
     * CardLayout / TopComponent preferred-size propagation must NOT inflate to
     * the full workspace content height. That was pushing the action bar below
     * the window and clipping Verification. Prefer the parent allocation so
     * BorderLayout can reserve SOUTH for {@link SanitizationActionBar}.
     */
    @Override
    public Dimension getPreferredSize() {
        java.awt.Container parent = getParent();
        if (parent != null && parent.getWidth() > 0 && parent.getHeight() > 0) {
            return new Dimension(parent.getWidth(), parent.getHeight());
        }
        return new Dimension(960, 640);
    }

    @Override
    public Dimension getMinimumSize() {
        return new Dimension(720, 480);
    }

    @Override
    public Dimension getMaximumSize() {
        return new Dimension(Integer.MAX_VALUE, Integer.MAX_VALUE);
    }

    private Runnable onPhysicalDevice;

    /** Physical-device targets are handled by the engine-backed device view. */
    public void setPhysicalDeviceHandler(Runnable handler) {
        this.onPhysicalDevice = handler;
    }

    /** Selects a File, Folder or Volume target type (used when returning from the device view). */
    public void selectTargetType(TargetType type) {
        if (type == TargetType.PHYSICAL_DISK || type == TargetType.VOLUME) {
            return;
        }
        selectType(type);
    }

    private void selectType(TargetType type) {
        // A volume wipe by drive letter cannot be bound to a device identity, so
        // Volume and Physical Device both go to the identity-bound device workflow.
        if (type == TargetType.PHYSICAL_DISK || type == TargetType.VOLUME) {
            if (onPhysicalDevice != null) {
                onPhysicalDevice.run();
            }
            return;
        }
        if (state.step() != SanitizationUIState.Step.TARGET && state.step() != SanitizationUIState.Step.METHOD
                && state.step() != SanitizationUIState.Step.VERIFICATION) {
            return;
        }
        state.setTargetType(type);
        state.setTargetPath(null);
        state.setClassification(null);
        state.setConfirmed(false);
        refresh();
    }

    public SanitizationController getController() {
        return controller;
    }

    public void prefillFile(Path path) {
        state.setTargetType(TargetType.FILE);
        state.setTargetPath(path);
        state.setConfirmed(false);
        state.setStep(SanitizationUIState.Step.TARGET);
        controller.inspectTargetAsync(path, TargetType.FILE, this::refresh);
        refresh();
    }

    /** File / Folder / Volume / Physical Device row; the active type is the filled button. */
    private void syncTypeRow() {
        TargetType active = state.targetType();
        if (active == shownType) {
            return;
        }
        shownType = active;
        typeRow.removeAll();
        typeRow.add(typeButton("File", "file", TargetType.FILE, active));
        typeRow.add(typeButton("Folder", "folder", TargetType.FOLDER, active));
        typeRow.add(typeButton("Volume", "device-usb", TargetType.VOLUME, active));
        typeRow.add(typeButton("Physical Device", "disk", TargetType.PHYSICAL_DISK, active));
        typeRow.revalidate();
        typeRow.repaint();
    }

    private JButton typeButton(String text, String icon, TargetType type, TargetType active) {
        JButton b = type == active ? Kit.primary(text, icon) : Kit.outline(text, icon);
        b.setName("sanitization.type." + type.name());
        b.addActionListener(e -> selectType(type));
        return b;
    }

    private JPanel buildConfigStage() {
        JPanel left = new JPanel();
        left.setOpaque(false);
        left.setName("sanitization.leftColumn");
        left.setLayout(new BoxLayout(left, BoxLayout.Y_AXIS));
        for (JPanel card : new JPanel[]{targetPanel, methodPanel, verificationPanel}) {
            card.setAlignmentX(LEFT_ALIGNMENT);
        }
        left.add(targetPanel);
        left.add(Box.createVerticalStrut(CARD_GAP));
        left.add(methodPanel);
        left.add(Box.createVerticalStrut(CARD_GAP));
        left.add(verificationPanel);
        // Trailing strut so the last card is never flush against the action bar when scrolled to end.
        left.add(Box.createVerticalStrut(8));

        JPanel right = new JPanel();
        right.setOpaque(false);
        right.setName("sanitization.rightColumn");
        right.setLayout(new BoxLayout(right, BoxLayout.Y_AXIS));
        for (JPanel card : new JPanel[]{targetInfo, preview, notes}) {
            card.setAlignmentX(LEFT_ALIGNMENT);
        }
        right.add(targetInfo);
        right.add(Box.createVerticalStrut(CARD_GAP));
        right.add(preview);
        right.add(Box.createVerticalStrut(CARD_GAP));
        right.add(notes);
        right.add(Box.createVerticalStrut(8));

        JPanel grid = new JPanel(new GridBagLayout());
        grid.setOpaque(false);
        grid.setName("sanitization.mainGrid");
        GridBagConstraints c = new GridBagConstraints();
        c.gridy = 0;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.anchor = GridBagConstraints.NORTHWEST;
        c.weighty = 0;

        c.gridx = 0;
        c.weightx = LEFT_WEIGHT;
        c.insets = new Insets(0, 0, 0, COLUMN_GAP);
        grid.add(left, c);

        c.gridx = 1;
        c.weightx = RIGHT_WEIGHT;
        c.insets = new Insets(0, 0, 0, 0);
        grid.add(right, c);

        // Absorb leftover vertical space below both columns (keeps tops aligned).
        c.gridx = 0;
        c.gridy = 1;
        c.gridwidth = 2;
        c.weightx = 1;
        c.weighty = 1;
        c.fill = GridBagConstraints.BOTH;
        JPanel spacer = new JPanel();
        spacer.setOpaque(false);
        grid.add(spacer, c);
        return grid;
    }

    private static JPanel wrap(JPanel card) {
        JPanel wrap = new JPanel(new BorderLayout());
        wrap.setOpaque(false);
        wrap.add(card, BorderLayout.NORTH);
        return wrap;
    }

    private void wireActions() {
        cancel.addActionListener(e -> {
            state.resetWorkflow();
            state.setTargetPath(null);
            state.setClassification(null);
            state.setConfirmed(false);
            refresh();
        });
        back.addActionListener(e -> {
            if (state.step() == SanitizationUIState.Step.CONFIRMATION) {
                state.setStep(SanitizationUIState.Step.TARGET);
                state.setConfirmed(false);
            }
            refresh();
        });
        next.addActionListener(e -> {
            if (!state.canProceedFromTarget()) {
                return;
            }
            state.setStep(SanitizationUIState.Step.CONFIRMATION);
            refresh();
        });
        sanitize.addActionListener(e -> {
            if (!state.confirmed()) {
                JOptionPane.showMessageDialog(this,
                        "Confirmation is required before a destructive operation.",
                        "AEGIS Sanitization",
                        JOptionPane.WARNING_MESSAGE);
                return;
            }
            controller.startSanitization();
        });
        cancelRun.addActionListener(e -> controller.requestCancel());
    }

    private void browseTarget() {
        TargetType type = state.targetType();
        if (type.requiresRemovableMedia() && !state.volumeDiskEligible()) {
            JOptionPane.showMessageDialog(this, DeviceEligibilityService.usbOnlyMessage(),
                    "AEGIS Sanitization", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        JFileChooser chooser = new JFileChooser();
        if (type == TargetType.FOLDER) {
            chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        } else if (type == TargetType.FILE) {
            chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
        } else {
            chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        }
        if (chooser.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        Path path = chooser.getSelectedFile().toPath();
        state.setTargetPath(path);
        state.setConfirmed(false);
        controller.inspectTargetAsync(path, type, this::refresh);
        refresh();
    }

    private void refresh() {
        controller.refreshCaseContext();
        targetPanel.sync(state);
        methodPanel.sync(state);
        verificationPanel.sync(state);
        targetInfo.sync(state);
        preview.sync(state);
        confirmationPanel.sync(state);
        executionPanel.sync(state);
        resultPanel.sync(state);

        syncTypeRow();
        SanitizationUIState.Step step = state.step();
        boolean configuring = step == SanitizationUIState.Step.TARGET || step == SanitizationUIState.Step.METHOD
                || step == SanitizationUIState.Step.VERIFICATION;
        for (java.awt.Component c : typeRow.getComponents()) {
            c.setEnabled(configuring);
        }
        int completed = switch (step) {
            case TARGET -> -1;
            case METHOD, VERIFICATION -> step.index() - 1;
            case CONFIRMATION -> 2;
            case EXECUTION -> 3;
            case RESULT -> 5;
        };
        stepper.setState(step.index(), completed);

        switch (step) {
            case TARGET, METHOD, VERIFICATION -> {
                stageCards.show(stageHost, "CONFIG");
                next.setEnabled(state.canProceedFromTarget());
                actionBar.showActions(cancel, next);
            }
            case CONFIRMATION -> {
                stageCards.show(stageHost, "CONFIRM");
                sanitize.setEnabled(state.confirmed());
                actionBar.showActions(back, sanitize);
            }
            case EXECUTION -> {
                stageCards.show(stageHost, "EXECUTE");
                actionBar.showActions(null, cancelRun);
            }
            case RESULT -> {
                stageCards.show(stageHost, "RESULT");
                actionBar.clearActions();
            }
        }
        revalidate();
        repaint();
    }

    /**
     * Fixed page footer owned by {@link SanitizationView}. Opaque so the
     * scrollable workspace cannot paint through or under it.
     */
    private static final class SanitizationActionBar extends JPanel {

        private final JPanel west = new JPanel(new java.awt.FlowLayout(java.awt.FlowLayout.LEFT, 0, 0));
        private final JPanel east = new JPanel(new java.awt.FlowLayout(java.awt.FlowLayout.RIGHT, 8, 0));

        SanitizationActionBar() {
            super(new BorderLayout());
            setName("sanitization.actionBar");
            setOpaque(true);
            setBackground(AegisTokens.BACKGROUND);
            setBorder(javax.swing.BorderFactory.createCompoundBorder(
                    new MatteBorder(1, 0, 0, 0, AegisTokens.BORDER),
                    new EmptyBorder(12, PAGE_PAD, 14, PAGE_PAD)));
            west.setOpaque(false);
            east.setOpaque(false);
            add(west, BorderLayout.WEST);
            add(east, BorderLayout.EAST);
        }

        @Override
        public Dimension getPreferredSize() {
            return new Dimension(100, ACTION_BAR_HEIGHT);
        }

        @Override
        public Dimension getMinimumSize() {
            return new Dimension(100, ACTION_BAR_HEIGHT);
        }

        @Override
        public Dimension getMaximumSize() {
            return new Dimension(Integer.MAX_VALUE, ACTION_BAR_HEIGHT);
        }

        void showActions(JButton left, JButton right) {
            west.removeAll();
            east.removeAll();
            if (left != null) {
                west.add(left);
            }
            if (right != null) {
                east.add(right);
            }
            setVisible(true);
            revalidate();
            repaint();
        }

        void clearActions() {
            west.removeAll();
            east.removeAll();
            setVisible(false);
            revalidate();
            repaint();
        }
    }

    /**
     * Scrollable workspace that always tracks the viewport width so the
     * two-column grid never forces horizontal overflow.
     */
    private static final class WorkspacePanel extends JPanel implements Scrollable {

        @Override
        public Dimension getPreferredSize() {
            Dimension d = super.getPreferredSize();
            // Prefer content height; width is tracked to the viewport.
            return new Dimension(Math.max(d.width, 100), Math.max(d.height, 100));
        }

        @Override
        public Dimension getMinimumSize() {
            return new Dimension(200, 120);
        }

        @Override
        public Dimension getPreferredScrollableViewportSize() {
            return getPreferredSize();
        }

        @Override
        public int getScrollableUnitIncrement(Rectangle visibleRect, int orientation, int direction) {
            return 18;
        }

        @Override
        public int getScrollableBlockIncrement(Rectangle visibleRect, int orientation, int direction) {
            return Math.max(visibleRect.height - 36, 36);
        }

        @Override
        public boolean getScrollableTracksViewportWidth() {
            return true;
        }

        @Override
        public boolean getScrollableTracksViewportHeight() {
            return false;
        }
    }
}
