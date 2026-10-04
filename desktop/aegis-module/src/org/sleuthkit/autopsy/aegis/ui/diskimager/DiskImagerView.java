package org.sleuthkit.autopsy.aegis.ui.diskimager;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.GridLayout;
import java.awt.Insets;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import javax.swing.BorderFactory;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import javax.swing.Timer;
import javax.swing.border.EmptyBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.DefaultTableModel;
import org.sleuthkit.autopsy.aegis.engine.AegisEngine;
import org.sleuthkit.autopsy.aegis.engine.CaseWorkspace;
import org.sleuthkit.autopsy.aegis.engine.EngineBridge;
import org.sleuthkit.autopsy.aegis.engine.EngineProgress;
import org.sleuthkit.autopsy.aegis.engine.EngineResult;
import org.sleuthkit.autopsy.aegis.evidence.EvidenceRegistrationService;
import org.sleuthkit.autopsy.aegis.ui.AegisTokens;
import org.sleuthkit.autopsy.aegis.ui.kit.Badge;
import org.sleuthkit.autopsy.aegis.ui.kit.DetailList;
import org.sleuthkit.autopsy.aegis.ui.kit.Kit;
import org.sleuthkit.autopsy.aegis.ui.kit.KitCard;
import org.sleuthkit.autopsy.aegis.ui.kit.ProgressRing;
import org.sleuthkit.autopsy.aegis.ui.kit.Stepper;
import org.sleuthkit.autopsy.aegis.ui.kit.Tone;
import org.sleuthkit.autopsy.aegis.util.AegisJson.AegisJsonArray;
import org.sleuthkit.autopsy.aegis.util.AegisJson.AegisJsonObject;

/**
 * AEGIS Disk Imager: a nine-step, read-only forensic acquisition workflow.
 *
 * <p>Every device fact, hash, progress figure and verdict on this page comes
 * from the AEGIS engine (the Variant's Windows device discovery and its
 * {@code core.carve.acquire} imaging pass). If the engine cannot report a
 * value the page says "Not available"; it never fills one in.
 */
public final class DiskImagerView extends JPanel {

    private static final String[] STEPS = {"Select Source", "Preflight", "Device Identity", "Case & Evidence",
        "Image Configuration", "Acquisition", "Verification", "Registration", "Complete"};
    private static final String[] CAPTIONS = {"Choose device", "Check & validate", "View details", "Set information",
        "Format & options", "Create image", "Verify integrity", "Add to case", "View outcome"};

    private final Stepper stepper = new Stepper(STEPS, CAPTIONS);
    private int step;
    private int completed = -1;

    // Source
    private final DefaultTableModel deviceModel = new DefaultTableModel(new Object[]{"Device", "Type", "Model",
        "Serial Number", "Capacity", "Filesystem", "Mount", "Removable", "System", "Status"}, 0) {
        @Override
        public boolean isCellEditable(int r, int c) {
            return false;
        }
    };
    private final JTable deviceTable = new JTable(deviceModel) {
        @Override
        public boolean getScrollableTracksViewportWidth() {
            return getParent() == null || getPreferredSize().width < getParent().getWidth();
        }
    };
    private final List<AegisJsonObject> devices = new ArrayList<>();
    private final JLabel enumStatus = Kit.caption("Devices are enumerated when this page opens.");
    private final JRadioButton sourceDevice = new JRadioButton("Physical / removable device", true);
    private final JRadioButton sourceFile = new JRadioButton("Image or file");
    private final JTextField filePath = new JTextField();
    private final JPanel sourceCards = new JPanel(new java.awt.CardLayout());
    private AegisJsonObject selected;
    private boolean enumerating;
    private long lastEnumeration;
    private String discoveryNote = "";

    // Preflight / identity
    private final JPanel preflightChecks = Kit.column(0);
    private final DetailList preflightDetails = new DetailList();
    private final DetailList identityList = new DetailList();
    private final JPanel identityNotice = new JPanel(new BorderLayout());

    // Case & evidence
    private final JLabel caseLabel = Kit.label("", AegisTokens.BODY, AegisTokens.NAVY);
    private final JTextField evidenceName = new JTextField();
    private final JTextField evidenceNumber = new JTextField();
    private final JTextArea description = new JTextArea(2, 20);

    // Configuration
    private final JRadioButton formatRaw = new JRadioButton("RAW (dd)", true);
    private final JRadioButton formatE01 = new JRadioButton("E01 (Expert Witness Format)");
    private final JTextField destinationDir = new JTextField();
    private final JTextField imageName = new JTextField();
    private final JLabel e01Support = Kit.caption("");
    private boolean imageNameEdited;

    // Acquisition
    private final ProgressRing ring = new ProgressRing(150);
    private final DetailList acquireStats = new DetailList();
    private final JTextArea acquireLog = new JTextArea(6, 40);
    private final JButton startButton = Kit.primary("Start Acquisition", "play");
    private final JButton cancelButton = Kit.outline("Cancel Acquisition", "stop");
    private EngineBridge.Cancel cancel;
    private Timer clock;
    private long startedAt;
    private EngineProgress lastProgress;
    private EngineResult acquisition;

    // Verification / registration / complete
    private final JPanel verificationBody = Kit.column(0);
    private final JPanel registrationBody = Kit.column(0);
    private final JPanel completeBody = Kit.column(0);
    private String registrationMessage = "";
    private long dataSourceId = -1;
    private String reportPath = "";

    // Right column
    private final DetailList deviceInfo = new DetailList();
    private final Badge deviceBadge = new Badge("", Tone.NEUTRAL);
    private final DetailList caseInfo = new DetailList();
    private final DetailList destinationInfo = new DetailList();

    // Bottom bar
    private final JButton back = Kit.outline("Back");
    private final JButton next = Kit.primary("Next  →");
    private final JLabel gateMessage = Kit.caption("");

    private final List<KitCard> cards = new ArrayList<>();
    private final JPanel main = new JPanel();
    private final JScrollPane mainScroll;

    public DiskImagerView() {
        super(new BorderLayout());
        setBackground(AegisTokens.BACKGROUND);
        setOpaque(true);

        JPanel north = Kit.column(14,
                Kit.pageHeader("DISK IMAGER", "Forensic Acquisition & Evidence Imaging",
                        "Create forensic disk images from physical drives and removable media with integrity verification and audit logging."),
                stepper);
        north.setBorder(new EmptyBorder(20, 24, 6, 24));
        add(north, BorderLayout.NORTH);

        main.setOpaque(false);
        main.setLayout(new javax.swing.BoxLayout(main, javax.swing.BoxLayout.Y_AXIS));
        main.setBorder(new EmptyBorder(8, 0, 16, 0));
        cards.add(sourceCard());
        cards.add(preflightCard());
        cards.add(identityCard());
        cards.add(caseCard());
        cards.add(configCard());
        cards.add(acquisitionCard());
        cards.add(verificationCard());
        cards.add(registrationCard());
        cards.add(completeCard());
        for (KitCard c : cards) {
            c.setAlignmentX(Component.LEFT_ALIGNMENT);
            main.add(c);
            main.add(javax.swing.Box.createVerticalStrut(14));
        }
        mainScroll = Kit.scroll(new ScrollTrack(main));

        JPanel right = Kit.column(14, deviceInfoCard(), caseInfoCard(), destinationCard());
        right.setBorder(new EmptyBorder(8, 0, 16, 0));
        JScrollPane rightScroll = Kit.scroll(new ScrollTrack(right));
        rightScroll.setPreferredSize(new Dimension(390, 400));
        rightScroll.setMinimumSize(new Dimension(320, 200));

        JPanel center = new JPanel(new BorderLayout(16, 0));
        center.setOpaque(false);
        center.setBorder(new EmptyBorder(0, 24, 0, 24));
        center.add(mainScroll, BorderLayout.CENTER);
        center.add(rightScroll, BorderLayout.EAST);
        add(center, BorderLayout.CENTER);

        JButton cancelAll = Kit.outline("Cancel");
        cancelAll.addActionListener(e -> resetWorkflow());
        back.addActionListener(e -> goTo(step - 1));
        next.addActionListener(e -> advance());
        JPanel right2 = Kit.row(10, gateMessage, back, next);
        add(Kit.actionBar(cancelAll, right2), BorderLayout.SOUTH);

        wireInputs();
        defaults();
        evaluate();
    }

    /** Called when the workspace shows this page. Never blocks the EDT. */
    public void refresh() {
        defaults();
        if (!enumerating && System.currentTimeMillis() - lastEnumeration > 15_000 && cancel == null) {
            refreshDevices();
        }
        evaluate();
    }

    // =====================================================================
    // Cards
    // =====================================================================

    private KitCard sourceCard() {
        KitCard card = new KitCard("device-usb", "1. Select Source Device",
                "Choose a physical or removable device to image read-only, or an existing image/file. Only real detected devices are shown.");
        JButton refresh = Kit.outline("Refresh Devices", "refresh");
        refresh.addActionListener(e -> refreshDevices());
        card.action(refresh);

        Kit.styleTable(deviceTable);
        deviceTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        deviceTable.getColumnModel().getColumn(9).setCellRenderer(Kit.badgeRenderer());
        deviceTable.setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS);
        int[] widths = {180, 150, 90, 200, 80, 80, 100, 78, 62, 140};
        for (int i = 0; i < widths.length; i++) {
            deviceTable.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);
            deviceTable.getColumnModel().getColumn(i).setMinWidth(Math.min(widths[i], 60));
        }
        deviceTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int r = deviceTable.getSelectedRow();
                selected = r >= 0 && r < devices.size() ? devices.get(r) : null;
                evaluate();
            }
        });
        JScrollPane tableScroll = Kit.tableScroll(deviceTable);
        tableScroll.setPreferredSize(new Dimension(600, 190));

        JPanel deviceMode = new JPanel(new BorderLayout(0, 8));
        deviceMode.setOpaque(false);
        deviceMode.add(tableScroll, BorderLayout.CENTER);
        deviceMode.add(enumStatus, BorderLayout.SOUTH);

        JPanel fileMode = new JPanel(new BorderLayout(8, 8));
        fileMode.setOpaque(false);
        JButton browse = Kit.outline("Browse…", "folder-open");
        browse.addActionListener(e -> chooseSourceFile());
        fileMode.add(filePath, BorderLayout.CENTER);
        fileMode.add(browse, BorderLayout.EAST);
        fileMode.add(Kit.caption("An existing RAW/DD image or file is re-imaged read-only with SHA-256 and BLAKE3; "
                + "this is not a physical-device acquisition."), BorderLayout.SOUTH);

        sourceCards.setOpaque(false);
        sourceCards.add(deviceMode, "device");
        sourceCards.add(fileMode, "file");

        ButtonGroup g = new ButtonGroup();
        g.add(sourceDevice);
        g.add(sourceFile);
        for (JRadioButton b : new JRadioButton[]{sourceDevice, sourceFile}) {
            b.setOpaque(false);
            b.setFont(AegisTokens.BODY_SMALL);
            b.addActionListener(e -> {
                ((java.awt.CardLayout) sourceCards.getLayout()).show(sourceCards, sourceFile.isSelected() ? "file" : "device");
                evaluate();
            });
        }
        JPanel body = new JPanel(new BorderLayout(0, 10));
        body.setOpaque(false);
        body.add(Kit.row(16, sourceDevice, sourceFile), BorderLayout.NORTH);
        body.add(sourceCards, BorderLayout.CENTER);
        return card.content(body);
    }

    private KitCard preflightCard() {
        KitCard card = new KitCard("settings", "2. Preflight Check",
                "Verify device eligibility and system conditions before acquisition.");
        JPanel grid = new JPanel(new GridLayout(1, 2, 16, 0));
        grid.setOpaque(false);
        preflightChecks.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(AegisTokens.BORDER), new EmptyBorder(8, 10, 8, 10)));
        preflightChecks.setOpaque(true);
        preflightChecks.setBackground(AegisTokens.SURFACE);
        JPanel details = new JPanel(new BorderLayout(0, 6));
        details.setBackground(new java.awt.Color(0xF8FAFC));
        details.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(AegisTokens.BORDER), new EmptyBorder(10, 12, 10, 12)));
        details.add(Kit.label("Preflight Details", AegisTokens.TITLE, AegisTokens.NAVY), BorderLayout.NORTH);
        details.add(preflightDetails, BorderLayout.CENTER);
        grid.add(preflightChecks);
        grid.add(details);
        return card.content(grid);
    }

    private KitCard identityCard() {
        KitCard card = new KitCard("fingerprint", "3. Device Identity",
                "The identity the engine binds to the open read handle. A different disk at the same path is refused.");
        JPanel body = new JPanel(new BorderLayout(0, 10));
        body.setOpaque(false);
        identityNotice.setOpaque(false);
        body.add(identityList, BorderLayout.CENTER);
        body.add(identityNotice, BorderLayout.SOUTH);
        return card.content(body);
    }

    private KitCard caseCard() {
        KitCard card = new KitCard("file-description", "4. Case & Evidence Information",
                "Associate this image with the open case and record evidence details.");
        JPanel form = new JPanel(new GridBagLayout());
        form.setOpaque(false);
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(4, 0, 4, 12);
        c.anchor = GridBagConstraints.WEST;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.gridy = 0;
        addField(form, c, "Case", caseLabel);
        JButton newCase = Kit.outline("Create Case");
        newCase.addActionListener(e -> org.sleuthkit.autopsy.aegis.ui.AegisActions.newCase());
        JButton openCase = Kit.outline("Open Case");
        openCase.addActionListener(e -> org.sleuthkit.autopsy.aegis.ui.AegisActions.openCase());
        c.gridx = 2;
        form.add(Kit.row(6, newCase, openCase), c);
        c.gridy++;
        addField(form, c, "Evidence Name", evidenceName);
        c.gridy++;
        addField(form, c, "Evidence Number", evidenceNumber);
        c.gridy++;
        description.setLineWrap(true);
        description.setWrapStyleWord(true);
        description.setFont(AegisTokens.BODY_SMALL);
        JScrollPane d = new JScrollPane(description);
        d.setPreferredSize(new Dimension(300, 52));
        addField(form, c, "Description (optional)", d);
        return card.content(form);
    }

    private KitCard configCard() {
        KitCard card = new KitCard("adjustments-horizontal", "5. Image Configuration",
                "Choose the container format and destination. SHA-256 and BLAKE3 are computed in the same read pass.");
        JPanel form = new JPanel(new GridBagLayout());
        form.setOpaque(false);
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(4, 0, 4, 12);
        c.anchor = GridBagConstraints.WEST;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.gridy = 0;
        ButtonGroup g = new ButtonGroup();
        g.add(formatRaw);
        g.add(formatE01);
        formatRaw.setOpaque(false);
        formatE01.setOpaque(false);
        formatRaw.setFont(AegisTokens.BODY_SMALL);
        formatE01.setFont(AegisTokens.BODY_SMALL);
        formatRaw.addActionListener(e -> {
            syncImageName();
            evaluate();
        });
        formatE01.addActionListener(e -> {
            syncImageName();
            evaluate();
        });
        addField(form, c, "Image Format", Kit.column(2, Kit.row(14, formatRaw, formatE01), e01Support));
        c.gridy++;
        JButton browse = Kit.outline("Browse…", "folder-open");
        browse.addActionListener(e -> chooseDestination());
        JPanel dest = new JPanel(new BorderLayout(6, 0));
        dest.setOpaque(false);
        dest.add(destinationDir, BorderLayout.CENTER);
        dest.add(browse, BorderLayout.EAST);
        addField(form, c, "Destination", dest);
        c.gridy++;
        addField(form, c, "Image Name", imageName);
        c.gridy++;
        JCheckBox sha = new JCheckBox("SHA-256", true);
        JCheckBox b3 = new JCheckBox("BLAKE3", true);
        JCheckBox verify = new JCheckBox("Re-read and verify the image after writing", true);
        for (JCheckBox b : new JCheckBox[]{sha, b3, verify}) {
            b.setEnabled(false);
            b.setOpaque(false);
            b.setFont(AegisTokens.BODY_SMALL);
        }
        addField(form, c, "Hashes", Kit.row(14, sha, b3));
        c.gridy++;
        addField(form, c, "Verification", verify);
        return card.content(form);
    }

    private KitCard acquisitionCard() {
        KitCard card = new KitCard("download", "6. Acquisition",
                "Read-only imaging through the engine. Unreadable sectors are retried, filled and recorded, never dropped.");
        JPanel body = new JPanel(new BorderLayout(18, 10));
        body.setOpaque(false);
        ring.setUnknown();
        body.add(ring, BorderLayout.WEST);
        JPanel stats = new JPanel(new BorderLayout(0, 10));
        stats.setOpaque(false);
        stats.add(acquireStats, BorderLayout.CENTER);
        cancelButton.setEnabled(false);
        startButton.addActionListener(e -> startAcquisition());
        cancelButton.addActionListener(e -> {
            if (cancel != null) {
                cancel.request();
                appendLog("Cancellation requested; the engine will record how far the read got.");
            }
        });
        stats.add(Kit.row(10, startButton, cancelButton), BorderLayout.SOUTH);
        body.add(stats, BorderLayout.CENTER);
        acquireLog.setEditable(false);
        acquireLog.setFont(AegisTokens.MONO);
        acquireLog.setForeground(AegisTokens.TEXT);
        JScrollPane log = new JScrollPane(acquireLog);
        log.setBorder(BorderFactory.createLineBorder(AegisTokens.BORDER));
        log.setPreferredSize(new Dimension(400, 110));
        body.add(log, BorderLayout.SOUTH);
        resetStats();
        return card.content(body);
    }

    private KitCard verificationCard() {
        return new KitCard("shield-check", "7. Verification",
                "The engine re-reads the written image and compares both hashes and every chunk to the acquisition record.")
                .content(verificationBody);
    }

    private KitCard registrationCard() {
        return new KitCard("database-plus", "8. Registration",
                "Add the verified image to the open case as a data source and record it in the case ledger.")
                .content(registrationBody);
    }

    private KitCard completeCard() {
        return new KitCard("circle-check", "9. Complete", "Outcome, signed acquisition report and next steps.")
                .content(completeBody);
    }

    private KitCard deviceInfoCard() {
        KitCard card = new KitCard("disk", "Device Information", null);
        card.action(deviceBadge);
        return card.content(deviceInfo);
    }

    private KitCard caseInfoCard() {
        KitCard card = new KitCard("folder", "Case & Evidence", null);
        JButton change = Kit.outline("Change");
        change.addActionListener(e -> goTo(3));
        card.action(change);
        return card.content(caseInfo);
    }

    private KitCard destinationCard() {
        KitCard card = new KitCard("eye", "Destination & Image Settings (Preview)", null);
        return card.content(destinationInfo);
    }

    private static void addField(JPanel form, GridBagConstraints c, String label, JComponent field) {
        c.gridx = 0;
        c.weightx = 0;
        JLabel l = Kit.label(label, AegisTokens.BODY_SMALL, AegisTokens.TEXT_SECONDARY);
        l.setPreferredSize(new Dimension(150, 24));
        form.add(l, c);
        c.gridx = 1;
        c.weightx = 1;
        if (field instanceof JTextField tf) {
            tf.setFont(AegisTokens.BODY_SMALL);
            tf.setPreferredSize(new Dimension(320, 30));
        }
        form.add(field, c);
    }

    // =====================================================================
    // Inputs and defaults
    // =====================================================================

    private void wireInputs() {
        DocumentListener changed = new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                SwingUtilities.invokeLater(DiskImagerView.this::evaluate);
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                SwingUtilities.invokeLater(DiskImagerView.this::evaluate);
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
            }
        };
        evidenceName.getDocument().addDocumentListener(changed);
        evidenceName.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                SwingUtilities.invokeLater(DiskImagerView.this::syncImageName);
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                SwingUtilities.invokeLater(DiskImagerView.this::syncImageName);
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
            }
        });
        destinationDir.getDocument().addDocumentListener(changed);
        imageName.getDocument().addDocumentListener(changed);
        filePath.getDocument().addDocumentListener(changed);
        imageName.addKeyListener(new java.awt.event.KeyAdapter() {
            @Override
            public void keyTyped(java.awt.event.KeyEvent e) {
                imageNameEdited = true;
            }
        });
    }

    private void defaults() {
        if (destinationDir.getText().isBlank() && CaseWorkspace.caseOpen()) {
            destinationDir.setText(CaseWorkspace.evidenceDir().toString());
        }
        caseLabel.setText(CaseWorkspace.caseOpen() ? CaseWorkspace.caseDisplayName() + "  (" + CaseWorkspace.caseId() + ")"
                : "No case is open");
        caseLabel.setForeground(CaseWorkspace.caseOpen() ? AegisTokens.NAVY : Tone.ERROR.fg);
        EngineResult h = engineHealthIfKnown();
        if (h != null) {
            boolean e01 = h.result.object("e01_write").optBoolean("supported", false);
            formatE01.setEnabled(e01);
            e01Support.setText(e01 ? "E01 writer: " + h.result.object("e01_write").optString("backend", "")
                    + " (libewf " + h.result.object("e01_write").optString("writer_library", "") + "), compressed, verified through pyewf"
                    : "E01 unavailable: " + h.result.object("e01_write").optString("reason", "no write-capable libewf"));
            if (!e01 && formatE01.isSelected()) {
                formatRaw.setSelected(true);
            }
        }
    }

    private EngineResult health;

    private EngineResult engineHealthIfKnown() {
        return health;
    }

    private void syncImageName() {
        if (imageNameEdited) {
            evaluate();
            return;
        }
        String base = evidenceName.getText().isBlank() ? "evidence" : evidenceName.getText().trim();
        base = base.replaceAll("[^A-Za-z0-9._-]+", "_");
        String date = LocalDate.now().format(DateTimeFormatter.BASIC_ISO_DATE);
        imageName.setText(base + "_" + date + (formatE01.isSelected() ? ".E01" : ".raw"));
        imageNameEdited = false;
        evaluate();
    }

    private void chooseSourceFile() {
        JFileChooser ch = new JFileChooser();
        ch.setDialogTitle("Select an image or file to acquire");
        if (ch.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            filePath.setText(ch.getSelectedFile().getAbsolutePath());
            if (evidenceName.getText().isBlank()) {
                evidenceName.setText(ch.getSelectedFile().getName().replaceAll("\\.[^.]+$", ""));
            }
        }
    }

    private void chooseDestination() {
        JFileChooser ch = new JFileChooser(destinationDir.getText().isBlank() ? null : new File(destinationDir.getText()));
        ch.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        ch.setDialogTitle("Select the destination folder");
        if (ch.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            destinationDir.setText(ch.getSelectedFile().getAbsolutePath());
        }
    }

    // =====================================================================
    // Device enumeration
    // =====================================================================

    private void refreshDevices() {
        if (enumerating) {
            return;
        }
        enumerating = true;
        enumStatus.setText("Enumerating storage devices through the AEGIS engine (Windows Storage module)…");
        new SwingWorker<EngineResult[], Void>() {
            @Override
            protected EngineResult[] doInBackground() {
                EngineResult h = EngineBridge.get().health();
                EngineResult d = h.succeeded() ? AegisEngine.devices() : h;
                return new EngineResult[]{h, d};
            }

            @Override
            protected void done() {
                enumerating = false;
                lastEnumeration = System.currentTimeMillis();
                try {
                    EngineResult[] r = get();
                    health = r[0];
                    defaults();
                    applyDevices(r[1]);
                } catch (Exception ex) {
                    enumStatus.setText("Device enumeration failed: " + rootMessage(ex));
                }
                evaluate();
            }
        }.execute();
    }

    private void applyDevices(EngineResult result) {
        String keep = selected == null ? null : selected.optString("id", "");
        deviceModel.setRowCount(0);
        devices.clear();
        selected = null;
        if (!result.succeeded()) {
            enumStatus.setText("Device enumeration " + result.summary()
                    + (result.remediation.isBlank() ? "" : " — " + result.remediation));
            enumStatus.setForeground(Tone.ERROR.fg);
            return;
        }
        AegisJsonArray arr = result.result.array("devices");
        boolean elevated = result.result.object("discovery").optBoolean("elevated", false);
        for (AegisJsonObject d : arr.objects()) {
            devices.add(d);
            deviceModel.addRow(new Object[]{
                text(d.optString("model")), deviceType(d), text(d.optString("vendor")),
                text(d.optString("serial").trim()), Kit.bytes(d.optLong("capacity_bytes", -1)),
                joined(d.optStringList("filesystems")), joined(d.optStringList("mount_points")),
                yesNo(d.opt("removable")), d.optBoolean("system_device", false) ? "Yes" : "No",
                statusWord(d)});
        }
        discoveryNote = (elevated ? "Elevated process: raw reads available. " : "Standard (non-elevated) process: raw device reads need Run as administrator. ")
                + arr.length() + " disk(s) reported by Windows.";
        enumStatus.setText(discoveryNote);
        enumStatus.setForeground(elevated ? AegisTokens.TEXT_SECONDARY : Tone.WARNING.fg);
        if (keep != null) {
            for (int i = 0; i < devices.size(); i++) {
                if (keep.equals(devices.get(i).optString("id"))) {
                    deviceTable.setRowSelectionInterval(i, i);
                }
            }
        }
    }

    public static String deviceTypeOf(AegisJsonObject d) {
        return deviceType(d);
    }

    static String deviceType(AegisJsonObject d) {
        String iface = d.optString("interface", "unknown").toLowerCase(Locale.ROOT);
        String media = d.optString("media_type", "unknown").toLowerCase(Locale.ROOT);
        Object removable = d.opt("removable");
        String kind = switch (media) {
            case "ssd" -> "SSD";
            case "hdd" -> "HDD";
            case "flash" -> "Flash";
            default -> "Drive";
        };
        return switch (iface) {
            case "usb" -> Boolean.TRUE.equals(removable) || "flash".equals(media) ? "USB Drive (Removable)" : "External " + kind + " (USB)";
            case "sd", "mmc" -> "Memory Card";
            case "nvme" -> "Internal NVMe " + kind;
            case "sata", "ata" -> "Internal SATA " + kind;
            case "virtual" -> "Virtual Disk";
            default -> (Boolean.TRUE.equals(removable) ? "Removable " : "") + kind + " (" + iface.toUpperCase(Locale.ROOT) + ")";
        };
    }

    private static String statusWord(AegisJsonObject d) {
        if (d.optBoolean("system_device", false)) {
            return "SYSTEM DISK";
        }
        return d.object("acquisition").optString("status", "UNAVAILABLE");
    }

    // =====================================================================
    // Gate evaluation
    // =====================================================================

    private boolean fileMode() {
        return sourceFile.isSelected();
    }

    private Path sourceFilePath() {
        String t = filePath.getText().trim();
        return t.isEmpty() ? null : Path.of(t);
    }

    private long sourceSize() {
        if (fileMode()) {
            try {
                Path p = sourceFilePath();
                return p != null && Files.isRegularFile(p) ? Files.size(p) : -1;
            } catch (Exception ex) {
                return -1;
            }
        }
        return selected == null ? -1 : selected.optLong("capacity_bytes", -1);
    }

    private Path destinationPath() {
        String dir = destinationDir.getText().trim();
        String name = imageName.getText().trim();
        if (dir.isEmpty() || name.isEmpty()) {
            return null;
        }
        try {
            return Path.of(dir).resolve(name).toAbsolutePath().normalize();
        } catch (Exception ex) {
            return null;
        }
    }

    /** Returns a blocking reason for a step, or null if its gate passes. */
    private String gate(int s) {
        switch (s) {
            case 0 -> {
                if (health != null && !health.succeeded()) {
                    return "AEGIS engine unavailable: " + health.errorMessage;
                }
                if (fileMode()) {
                    Path p = sourceFilePath();
                    return p != null && Files.isRegularFile(p) ? null : "Select an existing image or file.";
                }
                if (selected == null) {
                    return "Select a source device.";
                }
                if (!selected.object("acquisition").optBoolean("eligible", false)) {
                    return selected.object("acquisition").optString("reason", "This device cannot be acquired.");
                }
                return null;
            }
            case 1 -> {
                for (String[] check : preflight()) {
                    if ("FAILED".equals(check[0])) {
                        return check[1];
                    }
                }
                return null;
            }
            case 2 -> {
                return fileMode() || !selected.optString("serial").isBlank() ? null : "The device reports no serial number.";
            }
            case 3 -> {
                if (!CaseWorkspace.caseOpen()) {
                    return "Create or open a case first.";
                }
                return evidenceName.getText().isBlank() ? "Enter an evidence name." : null;
            }
            case 4 -> {
                if (acquisition != null && acquisition.succeeded()) {
                    return null;
                }
                Path dest = destinationPath();
                if (dest == null) {
                    return "Choose a destination folder and image name.";
                }
                if (!Files.isDirectory(dest.getParent())) {
                    return "The destination folder does not exist.";
                }
                if (Files.exists(dest)) {
                    return "An image with this name already exists; choose another name.";
                }
                if (formatE01.isSelected() && !formatE01.isEnabled()) {
                    return "E01 is not available in this engine.";
                }
                return null;
            }
            case 5 -> {
                return acquisition != null && acquisition.succeeded() ? null : "Run the acquisition.";
            }
            case 6 -> {
                return acquisition != null && acquisition.succeeded()
                        && acquisition.result.object("verification").optBoolean("passed", false) ? null : "Verification has not passed.";
            }
            case 7 -> {
                return dataSourceId >= 0 ? null : "Register the image with the case.";
            }
            default -> {
                return null;
            }
        }
    }

    /** {state, text} rows. States: SUCCESS, FAILED, WARNING, PENDING. */
    private List<String[]> preflight() {
        List<String[]> rows = new ArrayList<>();
        boolean engineOk = health != null && health.succeeded();
        rows.add(new String[]{health == null ? "PENDING" : engineOk ? "SUCCESS" : "FAILED",
            engineOk ? "AEGIS engine available (" + health.result.optString("bridge_version") + ", Python "
            + health.result.optString("python") + ")" : "AEGIS engine " + (health == null ? "not yet checked" : "unavailable: " + health.errorMessage)});
        if (fileMode()) {
            Path p = sourceFilePath();
            boolean ok = p != null && Files.isRegularFile(p) && Files.isReadable(p);
            rows.add(new String[]{ok ? "SUCCESS" : "FAILED", ok ? "Source file readable" : "Source file not readable"});
        } else if (selected != null) {
            boolean system = selected.optBoolean("system_device", false);
            rows.add(new String[]{system ? "FAILED" : "SUCCESS", system ? "System/boot disk refused: "
                + String.join(" ", selected.optStringList("system_reasons")) : "Not a system or boot disk"});
            boolean serial = !selected.optString("serial").isBlank();
            rows.add(new String[]{serial ? "SUCCESS" : "FAILED", serial ? "Identity can be bound (serial reported)"
                : "No serial reported; identity cannot be bound"});
            boolean elevated = health != null && health.result.optBoolean("elevated", false);
            rows.add(new String[]{elevated ? "SUCCESS" : "FAILED", elevated ? "Read-only raw device access available (elevated)"
                : "Raw device reads need Run as administrator"});
            rows.add(new String[]{"WARNING", "Windows has no software write blocker; the source is opened read-only. Use a hardware write blocker for court evidence."});
        } else {
            rows.add(new String[]{"PENDING", "Select a source"});
        }
        Path dest = destinationPath();
        long size = sourceSize();
        if (dest != null && Files.isDirectory(dest.getParent())) {
            try {
                long free = Files.getFileStore(dest.getParent()).getUsableSpace();
                boolean ok = size > 0 && free > size;
                rows.add(new String[]{ok ? "SUCCESS" : "FAILED", ok ? "Sufficient destination space (" + Kit.bytes(free) + " free)"
                    : "Insufficient destination space: " + Kit.bytes(free) + " free, " + Kit.bytes(size) + " needed"});
            } catch (Exception ex) {
                rows.add(new String[]{"FAILED", "Destination capacity unreadable: " + rootMessage(ex)});
            }
            if (!fileMode() && selected != null) {
                String root = dest.getRoot() == null ? "" : dest.getRoot().toString().toUpperCase(Locale.ROOT);
                boolean onSource = selected.optStringList("mount_points").stream()
                        .anyMatch(m -> m.toUpperCase(Locale.ROOT).startsWith(root) && !root.isEmpty());
                rows.add(new String[]{onSource ? "FAILED" : "SUCCESS", onSource ? "Destination is on the source device"
                    : "Destination is not on the source device"});
            }
        } else {
            rows.add(new String[]{"PENDING", "Destination not set (step 5)"});
        }
        return rows;
    }

    private void evaluate() {
        // Preflight checklist
        preflightChecks.removeAll();
        for (String[] row : preflight()) {
            preflightChecks.add(Kit.check(row[0], row[1]));
        }
        preflightChecks.revalidate();
        long size = sourceSize();
        preflightDetails.clear();
        if (fileMode()) {
            Path p = sourceFilePath();
            preflightDetails.put("Source path", p == null ? "" : p.toString()).put("Source type", "Image / file (not a device)")
                    .put("Capacity", Kit.bytesExact(size));
        } else if (selected != null) {
            preflightDetails.put("Device path", selected.optString("path"))
                    .put("Current mount", joined(selected.optStringList("mount_points")))
                    .put("Removable", yesNo(selected.opt("removable")))
                    .put("Capacity", Kit.bytesExact(size))
                    .put("Sector size", sectorText(selected))
                    .put("Bus", text(selected.optString("bus_type")))
                    .put("Partition style", text(selected.optString("partition_style")))
                    .put("Engine assessment", text(selected.object("assessment").optString("headline")));
        }
        preflightDetails.done();

        // Identity
        identityList.clear();
        identityNotice.removeAll();
        if (fileMode()) {
            Path p = sourceFilePath();
            identityList.put("Source", p == null ? "" : p.toString()).put("Size", Kit.bytesExact(size))
                    .put("Binding", "Path and size; files carry no hardware serial");
        } else if (selected != null) {
            identityList.put("Model", selected.optString("model")).put("Vendor", selected.optString("vendor"))
                    .put("Serial number", DetailList.mono(selected.optString("serial").trim()))
                    .put("Stable ID", selected.optString("stable_id")).put("Capacity", Kit.bytesExact(size))
                    .put("Physical path", selected.optString("path")).put("Media", selected.optString("media_basis"));
            if (selected.optBoolean("system_device", false)) {
                identityNotice.add(Kit.notice(Tone.ERROR, "PROTECTED: " + String.join(" ", selected.optStringList("system_reasons"))));
            } else {
                identityNotice.add(Kit.notice(Tone.INFO, "The engine opens \\\\.\\PhysicalDrive read-only and checks this serial "
                        + "and size on the open handle before the first read. A mismatch stops the acquisition."));
            }
        } else {
            identityList.put("Device", "Select a device in step 1");
        }
        identityList.done();
        identityNotice.revalidate();

        // Right column
        deviceInfo.clear();
        if (fileMode()) {
            Path p = sourceFilePath();
            deviceInfo.put("Source", p == null ? "" : p.getFileName().toString()).put("Type", "Image / file")
                    .put("Size", Kit.bytesExact(size));
            deviceBadge.set(p != null && Files.isRegularFile(p) ? "Ready" : "", Tone.SUCCESS);
        } else if (selected != null) {
            deviceInfo.put("Device", selected.optString("model")).put("Type", deviceType(selected))
                    .put("Model", selected.optString("vendor")).put("Serial Number", selected.optString("serial").trim())
                    .put("Capacity", Kit.bytesExact(size)).put("Sector Size", sectorText(selected))
                    .put("Filesystem", joined(selected.optStringList("filesystems")))
                    .put("Removable", yesNo(selected.opt("removable")))
                    .put("System Disk", selected.optBoolean("system_device", false) ? "Yes" : "No")
                    .put("Boot Device", yesNo(selected.opt("is_boot")))
                    .put("Mounted", selected.optBoolean("mounted", false) ? "Yes (" + joined(selected.optStringList("mount_points")) + ")" : "No")
                    .put("Physical Path", selected.optString("path"));
            deviceBadge.setStatus(statusWord(selected));
        } else {
            deviceInfo.put("Device", "No device selected");
            deviceBadge.set("", Tone.NEUTRAL);
        }
        deviceInfo.done();

        caseInfo.clear().put("Case", CaseWorkspace.caseOpen() ? CaseWorkspace.caseDisplayName() : "No case open")
                .put("Case ID", CaseWorkspace.caseId()).put("Examiner", CaseWorkspace.operator())
                .put("Evidence Name", evidenceName.getText().trim()).put("Evidence No.", evidenceNumber.getText().trim()).done();
        Path dest = destinationPath();
        destinationInfo.clear().put("Image Format", formatE01.isSelected() ? "E01 (Expert Witness Format)" : "RAW (dd)")
                .put("Destination", destinationDir.getText().trim()).put("Image Name", imageName.getText().trim())
                .put("Hash Algorithms", "SHA-256 + BLAKE3 (single pass)")
                .put("Verification", "Full re-read, per-chunk SHA-256")
                .put("Output path", dest == null ? "" : dest.toString()).done();

        // Stepper and buttons
        String reason = gate(step);
        boolean running = cancel != null;
        back.setEnabled(step > 0 && !running);
        next.setEnabled(reason == null && step < STEPS.length - 1 && !running);
        next.setText(step == 4 ? "Next: Acquire  →" : "Next  →");
        gateMessage.setText(reason == null ? "" : reason);
        gateMessage.setForeground(Tone.WARNING.fg);
        startButton.setEnabled(!running && acquisition == null && step >= 5 && allGatesThrough(4));
        stepper.setState(step, completed);
        revalidate();
        repaint();
    }

    private boolean allGatesThrough(int s) {
        for (int i = 0; i <= s; i++) {
            if (gate(i) != null) {
                return false;
            }
        }
        return true;
    }

    private void advance() {
        String reason = gate(step);
        if (reason != null) {
            gateMessage.setText(reason);
            return;
        }
        completed = Math.max(completed, step);
        goTo(step + 1);
    }

    private void goTo(int s) {
        if (s < 0 || s >= STEPS.length) {
            return;
        }
        if (s > step) {
            for (int i = 0; i < s; i++) {
                if (gate(i) != null) {
                    s = i;
                    break;
                }
            }
        }
        step = s;
        evaluate();
        KitCard target = cards.get(step);
        SwingUtilities.invokeLater(() -> main.scrollRectToVisible(new java.awt.Rectangle(0, target.getY(),
                10, Math.min(target.getHeight(), mainScroll.getViewport().getHeight()))));
    }

    private void resetWorkflow() {
        if (cancel != null) {
            JOptionPane.showMessageDialog(this, "An acquisition is running. Cancel it first.", "Acquisition running",
                    JOptionPane.WARNING_MESSAGE);
            return;
        }
        acquisition = null;
        dataSourceId = -1;
        registrationMessage = "";
        reportPath = "";
        completed = -1;
        imageNameEdited = false;
        evidenceName.setText("");
        evidenceNumber.setText("");
        description.setText("");
        resetStats();
        ring.setUnknown();
        acquireLog.setText("");
        verificationBody.removeAll();
        registrationBody.removeAll();
        completeBody.removeAll();
        goTo(0);
    }

    // =====================================================================
    // Acquisition
    // =====================================================================

    private void resetStats() {
        acquireStats.clear().put("Current stage", "Not started").put("Elapsed time", "")
                .put("Estimated time", "").put("Speed", "").put("Bytes copied", "").put("Unreadable sectors", "").done();
    }

    private void startAcquisition() {
        if (!allGatesThrough(4)) {
            evaluate();
            return;
        }
        AegisEngine.AcquireRequest req = new AegisEngine.AcquireRequest();
        Path dest = destinationPath();
        req.destination = dest;
        req.format = formatE01.isSelected() ? "e01" : "raw";
        req.evidenceNumber = evidenceNumber.getText().trim();
        req.description = description.getText().trim();
        req.notes = "AEGIS Disk Imager; evidence name " + evidenceName.getText().trim();
        if (fileMode()) {
            req.source = sourceFilePath().toString();
        } else {
            req.source = selected.optString("path");
            req.expectedSerial = selected.optString("serial").trim();
            req.expectedSize = selected.optLong("capacity_bytes", 0);
            int ls = selected.optInt("logical_sector_size", 0);
            req.sectorSize = ls > 0 ? ls : 512;
            req.deviceModel = selected.optString("model");
        }
        String confirm = "Read-only acquisition\n\nSource: " + req.source
                + (fileMode() ? "" : "\nModel: " + req.deviceModel + "\nSerial: " + req.expectedSerial)
                + "\nCapacity: " + Kit.bytesExact(sourceSize()) + "\nFormat: " + req.format.toUpperCase(Locale.ROOT)
                + "\nHashes: SHA-256 + BLAKE3\nDestination: " + dest + "\n\nThe source is opened read-only. Continue?";
        if (JOptionPane.showConfirmDialog(this, confirm, "Confirm acquisition", JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.QUESTION_MESSAGE) != JOptionPane.OK_OPTION) {
            return;
        }
        cancel = new EngineBridge.Cancel();
        cancelButton.setEnabled(true);
        startButton.setEnabled(false);
        startedAt = System.currentTimeMillis();
        lastProgress = null;
        appendLog("Acquisition started: " + req.source + " -> " + dest);
        clock = new Timer(1000, e -> updateStats());
        clock.start();
        evaluate();
        final EngineBridge.Cancel token = cancel;
        new SwingWorker<EngineResult, Void>() {
            @Override
            protected EngineResult doInBackground() {
                return AegisEngine.acquire(req, new EngineProgress.Listener() {
                    @Override
                    public void progress(EngineProgress p) {
                        SwingUtilities.invokeLater(() -> {
                            lastProgress = p;
                            ring.setValue(p.pct);
                            updateStats();
                        });
                    }

                    @Override
                    public void log(String level, String message) {
                        SwingUtilities.invokeLater(() -> appendLog(level + ": " + message));
                    }
                }, token);
            }

            @Override
            protected void done() {
                clock.stop();
                cancel = null;
                cancelButton.setEnabled(false);
                try {
                    acquisition = get();
                } catch (Exception ex) {
                    acquisition = new EngineResult();
                    acquisition.status = "FAILED";
                    acquisition.errorMessage = rootMessage(ex);
                }
                onAcquisitionFinished();
            }
        }.execute();
    }

    private void updateStats() {
        long elapsed = (System.currentTimeMillis() - startedAt) / 1000;
        EngineProgress p = lastProgress;
        acquireStats.clear().put("Current stage", p == null ? "Opening source" : Kit.humanize(p.phase) + (p.message.isBlank() ? "" : " — " + p.message))
                .put("Elapsed time", Kit.duration(elapsed))
                .put("Estimated time", p == null || p.etaSeconds <= 0 ? "" : Kit.duration(p.etaSeconds))
                .put("Speed", p == null ? "" : Kit.rate(p.throughput))
                .put(p != null && "verify".equals(p.phase) ? "Bytes verified" : "Bytes copied",
                        p == null ? "" : Kit.bytes(p.bytesDone) + " / " + Kit.bytes(p.bytesTotal))
                .put("Unreadable sectors", "Recorded in the result").done();
    }

    private void onAcquisitionFinished() {
        EngineResult r = acquisition;
        AegisJsonObject rec = r.result.object("record");
        AegisJsonObject ver = r.result.object("verification");
        if (r.succeeded()) {
            ring.setValue(100);
            ring.setColor(Tone.SUCCESS.fg);
            long bad = r.result.optLong("bad_sector_count", 0);
            acquireStats.clear().put("Current stage", "Complete").put("Elapsed time", Kit.duration((System.currentTimeMillis() - startedAt) / 1000))
                    .put("Bytes copied", Kit.bytesExact(rec.optLong("bytes_read", -1)))
                    .put("SHA-256", DetailList.mono(Kit.shortHash(rec.optString("sha256"))))
                    .put("BLAKE3", DetailList.mono(Kit.shortHash(rec.optString("blake3"))))
                    .put("Unreadable sectors", bad == 0 ? "None (0 ranges)" : bad + " sector(s) in " + rec.array("bad_sectors").length() + " range(s); filled and recorded")
                    .done();
            appendLog("Engine result: " + r.summary() + " (job " + r.operationId + ")");
            for (String w : r.warnings) {
                appendLog("WARNING: " + w);
            }
            completed = Math.max(completed, 5);
            buildVerification(r);
            goTo(6);
        } else {
            ring.setColor(Tone.ERROR.fg);
            stepper.setFailed(5);
            acquireStats.clear().put("Current stage", r.status).put("Reason", r.errorMessage)
                    .put("Remediation", r.remediation).done();
            appendLog("Acquisition " + r.summary());
            if (!r.remediation.isBlank()) {
                appendLog("Remediation: " + r.remediation);
            }
            JOptionPane.showMessageDialog(this, r.summary() + (r.remediation.isBlank() ? "" : "\n\n" + r.remediation),
                    "Acquisition " + Kit.humanize(r.status), r.blocked() ? JOptionPane.WARNING_MESSAGE : JOptionPane.ERROR_MESSAGE);
            acquisition = null;
            evaluate();
        }
        if (ver != null) {
            evaluate();
        }
    }

    private void buildVerification(EngineResult r) {
        AegisJsonObject rec = r.result.object("record");
        AegisJsonObject v = r.result.object("verification");
        verificationBody.removeAll();
        boolean passed = v.optBoolean("passed", false);
        verificationBody.add(Kit.check(v.optBoolean("sha256_matches", false) ? "SUCCESS" : "FAILED", "SHA-256 of the written image matches the acquisition hash"));
        verificationBody.add(Kit.check(v.optBoolean("blake3_matches", false) ? "SUCCESS" : "FAILED", "BLAKE3 of the written image matches the acquisition hash"));
        int mism = v.array("mismatched_chunks").length();
        verificationBody.add(Kit.check(mism == 0 ? "SUCCESS" : "FAILED", mism == 0 ? "All " + rec.array("chunk_hashes").length()
                + " chunk hash(es) match" : mism + " chunk(s) differ"));
        DetailList d = new DetailList().put("Verdict", Badge.of(passed ? "VERIFIED" : "INVALID"))
                .put("Acquisition SHA-256", DetailList.mono(rec.optString("sha256")))
                .put("Verification SHA-256", DetailList.mono(v.optString("actual_sha256")))
                .put("Acquisition BLAKE3", DetailList.mono(rec.optString("blake3")))
                .put("Verification BLAKE3", DetailList.mono(v.optString("actual_blake3")))
                .put("Bytes verified", Kit.bytesExact(v.optLong("bytes_verified", -1)))
                .put("Image", r.result.optString("image_path"))
                .put("Write block", rec.optBoolean("write_blocked", false) ? "Applied and verified" : "Not available on Windows (opened read-only)")
                .done();
        d.setBorder(new EmptyBorder(8, 0, 0, 0));
        verificationBody.add(d);
        AegisJsonArray bad = rec.array("bad_sectors");
        if (bad.length() > 0) {
            StringBuilder sb = new StringBuilder("Unreadable ranges (filled with 0x00 and recorded): ");
            for (AegisJsonObject b : bad.objects()) {
                sb.append(b.toString()).append("; ");
            }
            verificationBody.add(Kit.notice(Tone.WARNING, sb.toString()));
        }
        for (String w : r.warnings) {
            verificationBody.add(Kit.notice(Tone.NEUTRAL, w));
        }
        JButton reverify = Kit.outline("Re-verify Image", "refresh");
        reverify.addActionListener(e -> reverify());
        verificationBody.add(Kit.row(8, reverify));
        verificationBody.revalidate();

        registrationBody.removeAll();
        JButton register = Kit.primary("Add Image to Case", "database-plus");
        register.addActionListener(e -> register(register));
        registrationBody.add(Kit.notice(Tone.INFO, "Adds " + r.result.optString("image_path")
                + " to case " + CaseWorkspace.caseDisplayName() + " through the Sleuth Kit add-image process and stores its SHA-256."));
        registrationBody.add(Kit.row(8, register));
        registrationBody.revalidate();
    }

    private void reverify() {
        final String job = acquisition.operationId;
        appendLog("Re-verifying " + job + "…");
        new SwingWorker<EngineResult, Void>() {
            @Override
            protected EngineResult doInBackground() {
                return AegisEngine.verifyImage(job, null);
            }

            @Override
            protected void done() {
                try {
                    EngineResult r = get();
                    appendLog("Re-verification: " + r.summary());
                    JOptionPane.showMessageDialog(DiskImagerView.this, r.succeeded() ? "The image still matches its acquisition record (SHA-256 and BLAKE3)."
                            : r.summary(), "Re-verification", r.succeeded() ? JOptionPane.INFORMATION_MESSAGE : JOptionPane.ERROR_MESSAGE);
                } catch (Exception ex) {
                    appendLog("Re-verification failed: " + rootMessage(ex));
                }
            }
        }.execute();
    }

    private void register(JButton button) {
        if (!CaseWorkspace.caseOpen()) {
            JOptionPane.showMessageDialog(this, "Open a case first.");
            return;
        }
        button.setEnabled(false);
        final EngineResult r = acquisition;
        final Path image = Path.of(r.result.optString("image_path"));
        final String sha = r.result.object("record").optString("sha256");
        final int sector = r.result.object("record").object("source").optInt("sector_size", 512);
        final String name = evidenceName.getText().trim();
        registrationBody.add(Kit.caption("Adding to case… the Sleuth Kit is reading the volume structure."));
        registrationBody.revalidate();
        new SwingWorker<Object[], Void>() {
            @Override
            protected Object[] doInBackground() {
                EvidenceRegistrationService.Result reg = new EvidenceRegistrationService().registerRawImage(image, sector, sha,
                        "aegis-" + name.replaceAll("[^A-Za-z0-9._-]+", "_") + "-" + r.operationId);
                EngineResult ledger = null;
                EngineResult report = null;
                if (reg.success) {
                    AegisJsonObject p = new AegisJsonObject().put("job_id", r.operationId).put("image", image.toString())
                            .put("data_source_id", reg.imageId).put("evidence_name", name).put("sha256", sha)
                            .put("blake3", r.result.object("record").optString("blake3"));
                    ledger = AegisEngine.record("aegis.desktop.evidence.registered", p, new AegisJsonObject().put("message", reg.message));
                    report = AegisEngine.report(r.operationId);
                }
                return new Object[]{reg, ledger, report};
            }

            @Override
            protected void done() {
                try {
                    Object[] out = get();
                    EvidenceRegistrationService.Result reg = (EvidenceRegistrationService.Result) out[0];
                    EngineResult ledger = (EngineResult) out[1];
                    EngineResult report = (EngineResult) out[2];
                    registrationBody.removeAll();
                    registrationBody.add(Kit.check(reg.success ? "SUCCESS" : "FAILED", reg.message));
                    if (ledger != null) {
                        registrationBody.add(Kit.check(ledger.succeeded() ? "SUCCESS" : "FAILED", ledger.succeeded()
                                ? "Recorded in the case ledger (entry " + ledger.result.optString("seq") + ")" : "Ledger: " + ledger.summary()));
                    }
                    if (report != null) {
                        reportPath = report.succeeded() ? report.result.optString("json") : "";
                        registrationBody.add(Kit.check(report.succeeded() ? "SUCCESS" : "FAILED", report.succeeded()
                                ? "Signed acquisition report: " + report.result.optString("pdf") : "Report: " + report.summary()));
                    }
                    registrationMessage = reg.message;
                    if (reg.success) {
                        dataSourceId = reg.imageId;
                        completed = Math.max(completed, 7);
                        buildComplete();
                        goTo(8);
                    } else {
                        button.setEnabled(true);
                        registrationBody.add(Kit.row(8, button));
                    }
                    registrationBody.revalidate();
                    evaluate();
                } catch (Exception ex) {
                    button.setEnabled(true);
                    registrationBody.add(Kit.notice(Tone.ERROR, "Registration failed: " + rootMessage(ex)));
                    registrationBody.revalidate();
                }
            }
        }.execute();
    }

    private void buildComplete() {
        completeBody.removeAll();
        AegisJsonObject rec = acquisition.result.object("record");
        completeBody.add(Kit.notice(Tone.SUCCESS, "Acquisition complete and verified. The image is registered with the case as data source "
                + dataSourceId + "."));
        completeBody.add(new DetailList().put("Evidence", evidenceName.getText().trim())
                .put("Image", acquisition.result.optString("image_path")).put("Format", rec.optString("fmt").toUpperCase(Locale.ROOT))
                .put("Bytes", Kit.bytesExact(rec.optLong("bytes_read", -1)))
                .put("SHA-256", DetailList.mono(rec.optString("sha256")))
                .put("BLAKE3", DetailList.mono(rec.optString("blake3")))
                .put("Engine job", acquisition.operationId).put("Signed report", reportPath).done());
        JButton analysis = Kit.outline("Open Analysis", "chart-line");
        analysis.addActionListener(e -> org.sleuthkit.autopsy.aegis.ui.AegisActions.openForensicWorkspace());
        JButton recover = Kit.primary("Advanced Recovery", "photo-search");
        recover.addActionListener(e -> org.sleuthkit.autopsy.aegis.ui.recovery.AdvancedRecoveryView.openWithImage(
                Path.of(acquisition.result.optString("image_path")), acquisition.operationId));
        JButton another = Kit.outline("New Acquisition", "refresh");
        another.addActionListener(e -> resetWorkflow());
        completeBody.add(Kit.row(8, recover, analysis, another));
        completeBody.revalidate();
    }

    private void appendLog(String line) {
        acquireLog.append(java.time.LocalTime.now().withNano(0) + "  " + line + "\n");
        acquireLog.setCaretPosition(acquireLog.getDocument().getLength());
    }

    // =====================================================================
    // Test driver hooks (AegisUiDriver). They set fields the way an operator
    // types them; buttons are still pressed through their real actions.
    // =====================================================================

    public void driverPrepareFile(Path source, String name, String number, boolean e01) {
        sourceFile.setSelected(true);
        ((java.awt.CardLayout) sourceCards.getLayout()).show(sourceCards, "file");
        filePath.setText(source.toString());
        evidenceName.setText(name);
        evidenceNumber.setText(number);
        description.setText("Disposable demo evidence image (synthetic, ground truth recorded)");
        if (destinationDir.getText().isBlank()) {
            destinationDir.setText(CaseWorkspace.evidenceDir().toString());
        }
        (e01 ? formatE01 : formatRaw).setSelected(true);
        syncImageName();
        for (int i = 0; i < 5; i++) {
            if (gate(step) == null && step < 5) {
                advance();
            }
        }
        evaluate();
    }

    /** "ready" | "running" | "verified" | "failed:<reason>" | "registered" | "gate:<reason>". */
    public String driverStatus() {
        if (cancel != null) {
            return "running";
        }
        if (dataSourceId >= 0) {
            return "registered";
        }
        if (acquisition != null) {
            return acquisition.succeeded() ? "verified" : "failed:" + acquisition.summary();
        }
        String g = gate(Math.min(step, 4));
        return g == null ? "ready" : "gate:" + g;
    }

    public String driverJob() {
        return acquisition == null ? "" : acquisition.operationId;
    }

    public Path driverImage() {
        return acquisition == null ? null : Path.of(acquisition.result.optString("image_path"));
    }

    // =====================================================================
    // helpers
    // =====================================================================

    private static String text(String s) {
        return s == null || s.isBlank() ? DetailList.NOT_AVAILABLE : s;
    }

    private static String joined(List<String> items) {
        return items.isEmpty() ? DetailList.NOT_AVAILABLE : String.join(", ", items);
    }

    private static String yesNo(Object o) {
        if (o instanceof Boolean b) {
            return b ? "Yes" : "No";
        }
        return DetailList.NOT_AVAILABLE;
    }

    private static String sectorText(AegisJsonObject d) {
        int l = d.optInt("logical_sector_size", 0);
        int p = d.optInt("physical_sector_size", 0);
        if (l <= 0) {
            return DetailList.NOT_AVAILABLE;
        }
        return l + " bytes" + (p > 0 && p != l ? " (physical " + p + ")" : "");
    }

    private static String rootMessage(Throwable error) {
        Throwable cause = error;
        while (cause.getCause() != null) {
            cause = cause.getCause();
        }
        return cause.getMessage() == null ? cause.getClass().getSimpleName() : cause.getMessage();
    }

    /** Lets a BoxLayout column track the viewport width inside a scroll pane. */
    static final class ScrollTrack extends JPanel implements javax.swing.Scrollable {

        ScrollTrack(JComponent content) {
            super(new BorderLayout());
            setOpaque(false);
            add(content, BorderLayout.NORTH);
        }

        @Override
        public Dimension getPreferredScrollableViewportSize() {
            return getPreferredSize();
        }

        @Override
        public int getScrollableUnitIncrement(java.awt.Rectangle r, int o, int d) {
            return 24;
        }

        @Override
        public int getScrollableBlockIncrement(java.awt.Rectangle r, int o, int d) {
            return r.height - 40;
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

    @SuppressWarnings("unused")
    private static JPanel flow() {
        return new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
    }
}
