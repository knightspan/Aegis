package org.sleuthkit.autopsy.aegis.ui.sanitization;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.GridLayout;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.function.Consumer;
import javax.swing.BorderFactory;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import javax.swing.Timer;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
import org.sleuthkit.autopsy.aegis.engine.AegisEngine;
import org.sleuthkit.autopsy.aegis.engine.CaseWorkspace;
import org.sleuthkit.autopsy.aegis.engine.EngineBridge;
import org.sleuthkit.autopsy.aegis.engine.EngineProgress;
import org.sleuthkit.autopsy.aegis.engine.EngineResult;
import org.sleuthkit.autopsy.aegis.sanitization.TargetType;
import org.sleuthkit.autopsy.aegis.ui.AegisNavigation;
import org.sleuthkit.autopsy.aegis.ui.AegisTokens;
import org.sleuthkit.autopsy.aegis.ui.kit.Badge;
import org.sleuthkit.autopsy.aegis.ui.kit.DetailList;
import org.sleuthkit.autopsy.aegis.ui.kit.Kit;
import org.sleuthkit.autopsy.aegis.ui.kit.KitCard;
import org.sleuthkit.autopsy.aegis.ui.kit.ProgressRing;
import org.sleuthkit.autopsy.aegis.ui.kit.Stepper;
import org.sleuthkit.autopsy.aegis.ui.kit.Tone;
import org.sleuthkit.autopsy.aegis.util.AegisJson.AegisJsonObject;

/**
 * Physical / removable device sanitization through the AEGIS Variant engine.
 *
 * <p>Methods are offered from the device's probed capabilities, never from a
 * fixed list; a method the engine cannot run on this device is shown with the
 * engine's own state and reason and cannot be selected. The destructive call
 * is gated here (identity, typed serial, acknowledgement, backup) and every
 * gate is re-checked by the engine immediately before the first write: the
 * system disk is refused by the backend, the write handle is bound to the disk
 * number, serial and size, and a changed identity aborts.
 */
public final class DeviceSanitizationView extends JPanel {

    private static final String[] STEPS = {"Target Selection", "Device Analysis", "Method Selection", "Deep Forensic Purge",
        "Execution", "Results"};
    private static final String[] CAPTIONS = {"Choose what to sanitize", "Inspect and verify", "Select sanitization method",
        "Secondary artifacts", "Sanitize with verification", "View report & audit"};

    private final Consumer<TargetType> switchToFiles;
    private final Stepper stepper = new Stepper(STEPS, CAPTIONS);
    private final DefaultTableModel model = new DefaultTableModel(new Object[]{"Device", "Type", "Model", "Serial Number",
        "Capacity", "Filesystem", "Status", "Eligible"}, 0) {
        @Override
        public boolean isCellEditable(int r, int c) {
            return false;
        }
    };
    private final JTable table = new JTable(model);
    private final List<AegisJsonObject> devices = new ArrayList<>();
    private AegisJsonObject selected;
    private final JLabel enumStatus = Kit.caption("");
    private final DetailList deviceInfo = new DetailList();
    private final Badge eligibleBadge = new Badge("", Tone.NEUTRAL);
    private final JPanel capabilityRows = Kit.column(0);
    private final JPanel methodRows = Kit.column(4);
    private final ButtonGroup methodGroup = new ButtonGroup();
    private final List<MethodOption> methods = new ArrayList<>();
    private final JCheckBox purgeTraces = new JCheckBox("Recent shortcuts, jump lists and Recycle Bin entries that name the device", true);
    private final JCheckBox purgeThumbs = new JCheckBox("Windows thumbnail cache (whole per-user cache; Restart Manager coordinated)", false);
    private final ProgressRing ring = new ProgressRing(130);
    private final DetailList execStats = new DetailList();
    private final JTextArea log = new JTextArea();
    private final JPanel verificationRows = Kit.column(0);
    private final JButton sanitize = Kit.danger("Sanitize Device…");
    private final JButton cancelButton = Kit.outline("Cancel", "stop");
    private final JButton reportButton = Kit.outline("Open Signed Report", "certificate");
    private EngineResult health;
    private EngineBridge.Cancel cancel;
    private Timer clock;
    private long startedAt;
    private EngineProgress last;
    private String lastJob = "";

    /** One selectable method row, built from the engine's capability resolution. */
    private record MethodOption(String title, String level, String overwrite, String capability, String state,
            String stateLabel, String reason, String assurance, JRadioButton radio) {

        boolean runnable() {
            return "VALIDATED_PHYSICAL".equals(state) || "IMPLEMENTED_NOT_PHYSICALLY_VALIDATED".equals(state)
                    || "READY_AFTER_PREPARE".equals(state);
        }
    }

    public DeviceSanitizationView(Consumer<TargetType> switchToFiles) {
        super(new BorderLayout());
        this.switchToFiles = switchToFiles;
        setBackground(AegisTokens.BACKGROUND);
        setOpaque(true);
        JPanel north = Kit.column(12, Kit.pageHeader("Data Sanitization", "Secure Data Sanitization & Verification",
                "Securely and permanently sanitize files, folders, volumes or physical devices with verification and audit logging."),
                stepper, targetTypeRow());
        north.setBorder(new EmptyBorder(20, 24, 8, 24));
        add(north, BorderLayout.NORTH);

        JPanel rowA = new JPanel(new BorderLayout(14, 0));
        rowA.setOpaque(false);
        rowA.add(deviceCard(), BorderLayout.CENTER);
        JComponent info = deviceInfoCard();
        info.setPreferredSize(new Dimension(400, 300));
        rowA.add(info, BorderLayout.EAST);

        JPanel rowB = new JPanel(new GridLayout(1, 3, 14, 0));
        rowB.setOpaque(false);
        rowB.add(capabilityCard());
        rowB.add(methodCard());
        rowB.add(purgeCard());

        JPanel rowC = new JPanel(new GridLayout(1, 3, 14, 0));
        rowC.setOpaque(false);
        rowC.add(executionCard());
        rowC.add(logCard());
        rowC.add(verificationCard());

        JPanel body = Kit.column(14, rowA, rowB, rowC);
        body.setBorder(new EmptyBorder(6, 24, 16, 24));
        add(Kit.scroll(new Track(body)), BorderLayout.CENTER);

        JButton back = Kit.outline("Back to File / Folder");
        back.addActionListener(e -> switchToFiles.accept(TargetType.FILE));
        sanitize.addActionListener(e -> authorize());
        cancelButton.setEnabled(false);
        cancelButton.addActionListener(e -> {
            if (cancel != null && JOptionPane.showConfirmDialog(this, "Cancel the running sanitization? The engine records the "
                    + "checkpoint it reached; the device will be partially overwritten.", "Cancel sanitization",
                    JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE) == JOptionPane.YES_OPTION) {
                cancel.request();
            }
        });
        reportButton.setEnabled(false);
        reportButton.addActionListener(e -> AegisNavigation.show(AegisNavigation.REPORTS));
        add(Kit.actionBar(back, Kit.row(10, reportButton, cancelButton, sanitize)), BorderLayout.SOUTH);
        stepper.setState(0, -1);
        resetExecution();
        evaluate();
    }

    public void refresh() {
        if (cancel == null) {
            enumerate();
        }
    }

    // =====================================================================
    // Cards
    // =====================================================================

    private JComponent targetTypeRow() {
        JPanel row = new JPanel(new GridLayout(1, 4, 10, 0));
        row.setOpaque(false);
        row.setMaximumSize(new Dimension(760, 40));
        row.setPreferredSize(new Dimension(720, 38));
        row.add(typeButton("File", "file", false, () -> switchToFiles.accept(TargetType.FILE)));
        row.add(typeButton("Folder", "folder", false, () -> switchToFiles.accept(TargetType.FOLDER)));
        row.add(typeButton("Volume", "device-usb", false, () -> switchToFiles.accept(TargetType.VOLUME)));
        row.add(typeButton("Physical Device", "disk", true, () -> { }));
        JPanel wrap = new JPanel(new BorderLayout());
        wrap.setOpaque(false);
        wrap.add(row, BorderLayout.WEST);
        return wrap;
    }

    private static JButton typeButton(String text, String icon, boolean active, Runnable action) {
        JButton b = active ? Kit.primary(text, icon) : Kit.outline(text, icon);
        b.addActionListener(e -> action.run());
        return b;
    }

    private KitCard deviceCard() {
        KitCard card = new KitCard("device-usb", "1. Select Target Device",
                "Only removable USB/SD media can be sanitized. Internal SSDs and disks are refused by the engine, not just disabled here.");
        JButton refresh = Kit.outline("Refresh Devices", "refresh");
        refresh.addActionListener(e -> enumerate());
        card.action(refresh);
        Kit.styleTable(table);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.getColumnModel().getColumn(6).setCellRenderer(Kit.badgeRenderer());
        table.getColumnModel().getColumn(7).setCellRenderer(Kit.badgeRenderer());
        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int r = table.getSelectedRow();
                selected = r >= 0 && r < devices.size() ? devices.get(r) : null;
                evaluate();
            }
        });
        JScrollPane sp = Kit.tableScroll(table);
        sp.setPreferredSize(new Dimension(600, 170));
        JPanel body = new JPanel(new BorderLayout(0, 6));
        body.setOpaque(false);
        body.add(sp, BorderLayout.CENTER);
        body.add(enumStatus, BorderLayout.SOUTH);
        return card.content(body);
    }

    private KitCard deviceInfoCard() {
        KitCard card = new KitCard("disk", "Selected Device Information", null);
        card.action(eligibleBadge);
        return card.content(deviceInfo);
    }

    private KitCard capabilityCard() {
        KitCard card = new KitCard("cpu", "2. Device Capability Analysis",
                "What the engine probed for this device. Firmware probes need an elevated process.");
        JButton rescan = Kit.outline("Re-scan");
        rescan.addActionListener(e -> enumerate());
        card.action(rescan);
        return card.content(capabilityRows);
    }

    private KitCard methodCard() {
        KitCard card = new KitCard("adjustments-horizontal", "3. Select Sanitization Method",
                "Offered from probed capability. A method that cannot run here is never substituted.");
        JPanel body = new JPanel(new BorderLayout(0, 8));
        body.setOpaque(false);
        body.add(methodRows, BorderLayout.CENTER);
        body.add(Kit.notice(Tone.INFO, "NIST SP 800-88 Rev. 2: an overwrite of the addressable range is a Clear. Purge needs a "
                + "device-executed sanitize or crypto erase. AEGIS is not NIST-certified; the report states the outcome achieved."),
                BorderLayout.SOUTH);
        return card.content(body);
    }

    private KitCard purgeCard() {
        KitCard card = new KitCard("eraser", "4. Deep Forensic Purge (Secondary Artifacts)",
                "Traces the host kept of files on this device, removed after the device is sanitized.");
        purgeTraces.setOpaque(false);
        purgeThumbs.setOpaque(false);
        purgeTraces.setFont(AegisTokens.BODY_SMALL);
        purgeThumbs.setFont(AegisTokens.BODY_SMALL);
        JPanel body = Kit.column(6, purgeTraces,
                Kit.caption("Only entries the engine ties to a path on this device on evidence are removed; others are reported."),
                purgeThumbs,
                Kit.caption("Thumbnails cannot be tied to one path; opting in clears the whole cache. Explorer is asked to close "
                        + "gracefully and is restarted; nothing is force-killed."),
                Kit.caption("Not searched on Windows: Windows Search index, application-private recent lists, shadow copies."));
        return card.content(body);
    }

    private KitCard executionCard() {
        KitCard card = new KitCard("activity", "5. Execution Progress", null);
        JPanel body = new JPanel(new BorderLayout(14, 0));
        body.setOpaque(false);
        ring.setUnknown();
        body.add(ring, BorderLayout.WEST);
        body.add(execStats, BorderLayout.CENTER);
        return card.content(body);
    }

    private KitCard logCard() {
        KitCard card = new KitCard("list", "Live Operation Log", null);
        log.setEditable(false);
        log.setFont(new java.awt.Font("Consolas", java.awt.Font.PLAIN, 11));
        log.setLineWrap(true);
        log.setWrapStyleWord(true);
        JScrollPane sp = new JScrollPane(log);
        sp.setBorder(BorderFactory.createLineBorder(AegisTokens.BORDER));
        sp.setPreferredSize(new Dimension(300, 200));
        return card.content(sp);
    }

    private KitCard verificationCard() {
        KitCard card = new KitCard("shield-check", "6. Verification Results", "Read back by the engine after the write.");
        return card.content(verificationRows);
    }

    // =====================================================================
    // Enumeration and evaluation
    // =====================================================================

    private void enumerate() {
        enumStatus.setText("Enumerating devices through the AEGIS engine…");
        new SwingWorker<EngineResult[], Void>() {
            @Override
            protected EngineResult[] doInBackground() {
                EngineResult h = EngineBridge.get().health();
                return new EngineResult[]{h, h.succeeded() ? AegisEngine.devices() : h};
            }

            @Override
            protected void done() {
                try {
                    EngineResult[] r = get();
                    health = r[0];
                    apply(r[1]);
                } catch (Exception ex) {
                    enumStatus.setText("Enumeration failed: " + ex.getMessage());
                }
            }
        }.execute();
    }

    private void apply(EngineResult r) {
        String keep = selected == null ? null : selected.optString("id");
        model.setRowCount(0);
        devices.clear();
        selected = null;
        if (!r.succeeded()) {
            enumStatus.setText("Device enumeration " + r.summary());
            enumStatus.setForeground(Tone.ERROR.fg);
            evaluate();
            return;
        }
        boolean elevated = r.result.object("discovery").optBoolean("elevated", false);
        for (AegisJsonObject d : r.result.array("devices").objects()) {
            devices.add(d);
            AegisJsonObject a = d.object("assessment");
            model.addRow(new Object[]{d.optString("model"), org.sleuthkit.autopsy.aegis.ui.diskimager.DiskImagerView.deviceTypeOf(d),
                d.optString("vendor"), d.optString("serial").trim(), Kit.bytes(d.optLong("capacity_bytes", -1)),
                d.optStringList("filesystems").isEmpty() ? DetailList.NOT_AVAILABLE : String.join(", ", d.optStringList("filesystems")),
                d.optBoolean("system_device", false) ? "SYSTEM DISK" : !d.object("sanitization").optBoolean("eligible", false)
                        ? "INTERNAL DRIVE" : a.optString("headline", a.optString("status")),
                eligible(d) ? "YES" : "NO"});
        }
        enumStatus.setText((elevated ? "Elevated process." : "Not elevated: firmware probes and writes need Run as administrator. ")
                + " " + devices.size() + " device(s) reported.");
        enumStatus.setForeground(elevated ? AegisTokens.TEXT_SECONDARY : Tone.WARNING.fg);
        for (int i = 0; keep != null && i < devices.size(); i++) {
            if (keep.equals(devices.get(i).optString("id"))) {
                table.setRowSelectionInterval(i, i);
            }
        }
        evaluate();
    }

    /** Eligible = not a system disk and at least one method is runnable now or after Prepare. */
    private boolean eligible(AegisJsonObject d) {
        // AEGIS policy, decided and enforced by the engine: removable USB/SD media only.
        // Internal drives (SSD, NVMe, SATA, HDD) are never eligible, system disk or not.
        if (!d.object("sanitization").optBoolean("eligible", false)) {
            return false;
        }
        if (d.optBoolean("system_device", false) || d.optString("serial").isBlank()) {
            return false;
        }
        for (AegisJsonObject cap : d.object("assessment").array("capabilities").objects()) {
            if (runnableState(d, cap)) {
                return true;
            }
        }
        return false;
    }

    private static boolean runnableState(AegisJsonObject d, AegisJsonObject cap) {
        String s = effectiveState(d, cap);
        return "VALIDATED_PHYSICAL".equals(s) || "IMPLEMENTED_NOT_PHYSICALLY_VALIDATED".equals(s) || "READY_AFTER_PREPARE".equals(s);
    }

    /**
     * The engine blocks a whole-drive Clear while a filesystem is mounted. When
     * that is the only restriction on a non-system disk, AEGIS takes the disk
     * offline (non-persistently, serial-gated) before the write, so the method
     * is shown as ready after that step rather than as blocked.
     */
    private static String effectiveState(AegisJsonObject d, AegisJsonObject cap) {
        String state = cap.optString("state");
        if ("BLOCKED_BY_SAFETY_POLICY".equals(state) && !d.optBoolean("system_device", false)) {
            List<String> restrictions = cap.optStringList("safety_restrictions");
            boolean onlyMounted = !restrictions.isEmpty() && restrictions.stream()
                    .allMatch(x -> x.toLowerCase(Locale.ROOT).contains("mounted"));
            if (onlyMounted) {
                return "READY_AFTER_PREPARE";
            }
        }
        return state;
    }

    private void evaluate() {
        deviceInfo.clear();
        capabilityRows.removeAll();
        methodRows.removeAll();
        methods.clear();
        for (var e = methodGroup.getElements(); e.hasMoreElements();) {
            methodGroup.remove(e.nextElement());
        }
        if (selected == null) {
            deviceInfo.put("Device", devices.isEmpty() ? "No devices listed" : "Select a device").done();
            eligibleBadge.set("", Tone.NEUTRAL);
            capabilityRows.add(Kit.caption("Select a device to see its probed capabilities."));
            methodRows.add(Kit.caption("Methods appear for the selected device."));
            sanitize.setEnabled(false);
            stepper.setState(0, -1);
            revalidate();
            repaint();
            return;
        }
        AegisJsonObject d = selected;
        AegisJsonObject a = d.object("assessment");
        deviceInfo.put("Model", d.optString("model")).put("Vendor", d.optString("vendor"))
                .put("Serial Number", d.optString("serial").trim()).put("Capacity", Kit.bytesExact(d.optLong("capacity_bytes", -1)))
                .put("Sector Size", d.optInt("logical_sector_size", 0) > 0 ? d.optInt("logical_sector_size", 0) + " bytes" : "")
                .put("Interface / media", d.optString("interface").toUpperCase(Locale.ROOT) + " / " + d.optString("media_type"))
                .put("Removable", d.opt("removable") instanceof Boolean b ? (b ? "Yes" : "No") : "")
                .put("System Disk", d.optBoolean("system_device", false) ? "Yes — protected" : "No")
                .put("Mounted", d.optBoolean("mounted", false) ? "Yes (" + String.join(", ", d.optStringList("mount_points")) + ")" : "No")
                .put("Physical Path", d.optString("path"))
                .put("AEGIS policy", d.object("sanitization").optString("reason", "Not reported by the engine: refused"))
                .put("Engine verdict", a.optString("headline") + (a.optString("reason").isBlank() ? "" : " — " + a.optString("reason")))
                .done();
        boolean ok = eligible(d);
        boolean internal = !d.object("sanitization").optBoolean("eligible", false);
        eligibleBadge.set(d.optBoolean("system_device", false) ? "Protected system disk"
                : internal ? "Internal drive — sanitization disabled" : ok ? "Eligible for Sanitization" : "Not eligible",
                d.optBoolean("system_device", false) || internal ? Tone.ERROR : ok ? Tone.SUCCESS : Tone.WARNING);

        for (AegisJsonObject check : a.array("safety_checks").objects()) {
            capabilityRows.add(Kit.check(check.optBoolean("passed", false) ? "SUCCESS" : "FAILED",
                    check.optString("label") + ": " + check.optString("detail")));
        }
        capabilityRows.add(javax.swing.Box.createVerticalStrut(6));
        for (AegisJsonObject cap : a.array("capabilities").objects()) {
            String eff = effectiveState(d, cap);
            JPanel row = new JPanel(new BorderLayout(8, 0));
            row.setOpaque(false);
            row.setBorder(new EmptyBorder(3, 2, 3, 2));
            JLabel l = Kit.label(cap.optString("label"), AegisTokens.BODY_SMALL, AegisTokens.TEXT);
            l.setToolTipText("<html><body style='width:380px'>" + Kit.escape(cap.optString("reason")) + "<br><br>"
                    + Kit.escape(cap.optString("mechanism")) + "</body></html>");
            row.add(l, BorderLayout.CENTER);
            row.add(new Badge("READY_AFTER_PREPARE".equals(eff) ? "AFTER PREPARE" : cap.optString("state_label", eff),
                    Tone.of(stateTone(eff))), BorderLayout.EAST);
            capabilityRows.add(row);
        }

        buildMethods(d);
        sanitize.setEnabled(cancel == null && ok && methods.stream().anyMatch(m -> m.radio().isSelected() && m.runnable()));
        stepper.setState(ok ? 2 : 1, ok ? 1 : 0);
        revalidate();
        repaint();
    }

    private static String stateTone(String state) {
        return switch (state) {
            case "VALIDATED_PHYSICAL", "IMPLEMENTED_NOT_PHYSICALLY_VALIDATED" -> "SUPPORTED";
            case "READY_AFTER_PREPARE", "IMPLEMENTED_DEVICE_DEPENDENT", "AVAILABLE_BUT_REQUIRES_PRIVILEGE" -> "WARNING";
            case "BLOCKED_BY_SAFETY_POLICY" -> "BLOCKED";
            default -> "NEUTRAL";
        };
    }

    private AegisJsonObject capability(AegisJsonObject d, String key) {
        for (AegisJsonObject cap : d.object("assessment").array("capabilities").objects()) {
            if (key.equals(cap.optString("capability"))) {
                return cap;
            }
        }
        return null;
    }

    private void buildMethods(AegisJsonObject d) {
        AegisJsonObject clear = capability(d, "whole_drive_clear");
        addMethod(d, "Zero-fill overwrite — single pass (Clear)", "CLEAR", "SINGLE_PASS_OVERWRITE", clear,
                "Every addressable sector written and read back. On flash the engine may substitute 0xA5 for 0x00 to defeat write elision.");
        addMethod(d, "Legacy DoD 5220.22-M profile — 3 passes (Clear)", "CLEAR", "DOD_5220_22_M_3PASS", clear,
                "Historical profile (0x00, 0xFF, 0x00). NIST SP 800-88 Rev. 2 does not require multiple passes; outcome is still Clear.");
        addFixed("Pseudorandom fill", "NOT IMPLEMENTED",
                "The engine verifies a known fill by read-back; a pseudorandom pass is not implemented, so it is not offered.");
        addFixed("Legacy Gutmann profile — 35 passes", "NOT APPLICABLE",
                "Designed for obsolete magnetic encodings; not implemented and not meaningful for modern flash or disks.");
        addMethod(d, "ATA SANITIZE — device executed (Purge)", "PURGE", "", capability(d, "ata_sanitize"), "");
        addMethod(d, "NVMe Sanitize — device executed (Purge)", "PURGE", "", capability(d, "nvme_sanitize"), "");
        addMethod(d, "Cryptographic erase (Purge)", "PURGE", "", capability(d, "crypto_erase"), "");
        AegisJsonObject ase = capability(d, "ata_security_erase");
        if (ase != null) {
            addMethod(d, "ATA SECURITY ERASE UNIT", "PURGE", "", ase, "");
        }
        MethodOption first = methods.stream().filter(MethodOption::runnable).findFirst().orElse(null);
        if (first != null) {
            first.radio().setSelected(true);
        }
    }

    private void addMethod(AegisJsonObject d, String title, String level, String overwrite, AegisJsonObject cap, String note) {
        if (cap == null) {
            addFixed(title, "NOT AVAILABLE", "The engine reported no capability row for this mechanism on this platform.");
            return;
        }
        String eff = effectiveState(d, cap);
        JRadioButton radio = new JRadioButton();
        MethodOption m = new MethodOption(title, level, overwrite, cap.optString("capability"), eff,
                "READY_AFTER_PREPARE".equals(eff) ? "READY AFTER PREPARE" : cap.optString("state_label", eff),
                cap.optString("reason"), cap.optString("assurance"), radio);
        radio.setEnabled(m.runnable());
        radio.setOpaque(false);
        radio.addActionListener(e -> evaluate2());
        methodGroup.add(radio);
        methods.add(m);
        methodRows.add(methodRow(radio, title, m.stateLabel(), note.isBlank() ? m.reason() : note + " " + m.reason()));
    }

    private void evaluate2() {
        boolean ok = selected != null && eligible(selected);
        sanitize.setEnabled(cancel == null && ok && methods.stream().anyMatch(m -> m.radio().isSelected() && m.runnable()));
    }

    private void addFixed(String title, String state, String why) {
        JRadioButton radio = new JRadioButton();
        radio.setEnabled(false);
        radio.setOpaque(false);
        methodRows.add(methodRow(radio, title, state, why));
    }

    private static JComponent methodRow(JRadioButton radio, String title, String state, String why) {
        JPanel p = new JPanel(new BorderLayout(6, 0));
        p.setOpaque(false);
        p.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, Kit.GRID), new EmptyBorder(4, 0, 4, 0)));
        p.add(radio, BorderLayout.WEST);
        JPanel text = new JPanel(new BorderLayout(0, 1));
        text.setOpaque(false);
        JLabel t = Kit.label(title, AegisTokens.BODY_SMALL, radio.isEnabled() ? AegisTokens.NAVY : AegisTokens.TEXT_SECONDARY);
        text.add(t, BorderLayout.NORTH);
        JLabel w = Kit.caption("<html><body style='width:230px'>" + Kit.escape(why) + "</body></html>");
        text.add(w, BorderLayout.CENTER);
        p.add(text, BorderLayout.CENTER);
        JPanel badge = new JPanel(new java.awt.FlowLayout(java.awt.FlowLayout.RIGHT, 0, 2));
        badge.setOpaque(false);
        badge.add(new Badge(state, Tone.of(stateWordTone(state))));
        p.add(badge, BorderLayout.EAST);
        return p;
    }

    private static String stateWordTone(String label) {
        String s = label.toUpperCase(Locale.ROOT);
        if (s.startsWith("SUPPORTED") || s.contains("IMPLEMENTED / UNVALIDATED") || s.contains("VALIDATED")) {
            return "SUPPORTED";
        }
        if (s.contains("PREPARE") || s.contains("DEVICE-DEPENDENT") || s.contains("PRIVILEGE")) {
            return "WARNING";
        }
        if (s.contains("BLOCKED")) {
            return "BLOCKED";
        }
        return "NEUTRAL";
    }

    // =====================================================================
    // Authorization and execution
    // =====================================================================

    private MethodOption chosen() {
        return methods.stream().filter(m -> m.radio().isSelected()).findFirst().orElse(null);
    }

    private void authorize() {
        AegisJsonObject d = selected;
        MethodOption m = chosen();
        if (d == null || m == null || !m.runnable()) {
            return;
        }
        List<String[]> backups = findBackups(d.optString("serial").trim());
        DeviceAuthorizationDialog dialog = new DeviceAuthorizationDialog(SwingUtilities.getWindowAncestor(this), d, m.title(),
                m.level(), backups, d.optBoolean("mounted", false));
        dialog.setVisible(true);
        if (!dialog.authorized()) {
            appendLog("Authorization not given; nothing was written.");
            return;
        }
        execute(d, m, dialog.typedSerial(), dialog.backupJob(), dialog.waiver());
    }

    /** Verified acquisitions of this serial recorded in the open case: {job, label}. */
    private static List<String[]> findBackups(String serial) {
        List<String[]> out = new ArrayList<>();
        Path jobs = CaseWorkspace.stateDir().resolve("jobs");
        if (!Files.isDirectory(jobs) || serial.isBlank()) {
            return out;
        }
        try (var stream = Files.newDirectoryStream(jobs, "acquire-*.json")) {
            for (Path j : stream) {
                AegisJsonObject job = AegisJsonObject.parseStrict(Files.readString(j, StandardCharsets.UTF_8));
                if ("SUCCESS".equals(job.optString("status")) && serial.equals(job.object("params").optString("expected_serial").trim())) {
                    out.add(new String[]{job.optString("job_id"), job.optString("job_id") + " — " + job.object("result").optString("image_path")
                        + " (SHA-256 " + Kit.shortHash(job.object("result").object("record").optString("sha256")) + ")"});
                }
            }
        } catch (Exception ignored) {
            // an unreadable job file is not a backup
        }
        return out;
    }

    private void execute(AegisJsonObject d, MethodOption m, String typedSerial, String backupJob, String waiver) {
        cancel = new EngineBridge.Cancel();
        sanitize.setEnabled(false);
        cancelButton.setEnabled(true);
        startedAt = System.currentTimeMillis();
        last = null;
        ring.setColor(Tone.ERROR.fg);
        ring.setValue(0);
        stepper.setState(4, 3);
        verificationRows.removeAll();
        verificationRows.add(Kit.check("PENDING", "Waiting for the engine's read-back verification"));
        appendLog("Authorized by " + CaseWorkspace.operator() + ": " + m.title() + " on " + d.optString("path") + " serial "
                + d.optString("serial").trim());
        clock = new Timer(1000, e -> updateStats());
        clock.start();
        final List<String> mounts = d.optStringList("mount_points");
        final boolean mounted = d.optBoolean("mounted", false);
        final boolean traces = purgeTraces.isSelected();
        final boolean thumbs = purgeThumbs.isSelected();
        final EngineBridge.Cancel token = cancel;
        new SwingWorker<EngineResult[], String>() {
            @Override
            protected EngineResult[] doInBackground() {
                EngineResult prepare = null;
                if (mounted) {
                    publish("Taking the disk offline (non-persistent) so no volume stays mounted…");
                    prepare = AegisEngine.prepareDevice(d.optString("id"), typedSerial);
                    publish("Prepare: " + prepare.summary());
                    if (!prepare.succeeded()) {
                        return new EngineResult[]{prepare, null, null, null, null};
                    }
                }
                AegisEngine.SanitizeRequest r = new AegisEngine.SanitizeRequest();
                r.deviceId = d.optString("id");
                r.typedSerial = typedSerial;
                r.expectedSerial = d.optString("serial").trim();
                r.expectedSize = d.optLong("capacity_bytes", 0);
                r.level = m.level();
                r.overwriteMethod = m.overwrite();
                r.backupJob = backupJob;
                r.waiveBackup = waiver;
                r.confirmDestructive = true;
                publish("Engine re-checks identity, serial, size, mounts and system-disk status before the first write.");
                EngineResult run = AegisEngine.sanitizeDevice(r, new EngineProgress.Listener() {
                    @Override
                    public void progress(EngineProgress p) {
                        SwingUtilities.invokeLater(() -> {
                            last = p;
                            ring.setValue(p.pct);
                            updateStats();
                        });
                    }

                    @Override
                    public void log(String level, String message) {
                        publish(level + ": " + message);
                    }
                }, token);
                publish("Sanitization: " + run.summary());
                EngineResult sweep = null;
                EngineResult thumb = null;
                EngineResult report = null;
                if (run.succeeded()) {
                    if (traces && !mounts.isEmpty()) {
                        publish("Deep Forensic Purge: sweeping traces of " + String.join(", ", mounts));
                        sweep = AegisEngine.traces(mounts.stream().map(Path::of).toList(), true, false, run.operationId, null);
                        publish("Trace sweep: " + sweep.summary());
                    }
                    if (thumbs) {
                        publish("Clearing the thumbnail cache through Restart Manager…");
                        thumb = AegisEngine.thumbcache(false);
                        publish("Thumbnail cache: " + thumb.summary());
                    }
                    report = AegisEngine.report(run.operationId);
                    publish("Signed report: " + report.summary());
                }
                return new EngineResult[]{prepare, run, sweep, thumb, report};
            }

            @Override
            protected void process(List<String> chunks) {
                chunks.forEach(DeviceSanitizationView.this::appendLog);
            }

            @Override
            protected void done() {
                clock.stop();
                cancel = null;
                cancelButton.setEnabled(false);
                try {
                    finish(get());
                } catch (Exception ex) {
                    appendLog("Failed: " + ex.getMessage());
                }
                evaluate2();
            }
        }.execute();
    }

    private void updateStats() {
        EngineProgress p = last;
        execStats.clear().put("Current stage", p == null ? "Preparing" : Kit.humanize(p.phase) + (p.message.isBlank() ? "" : " — " + p.message))
                .put("Elapsed time", Kit.duration((System.currentTimeMillis() - startedAt) / 1000))
                .put("Estimated time", p == null || p.etaSeconds <= 0 ? "" : Kit.duration(p.etaSeconds))
                .put("Speed", p == null ? "" : Kit.rate(p.throughput))
                .put("Bytes processed", p == null ? "" : Kit.bytes(p.bytesDone) + " / " + Kit.bytes(p.bytesTotal)).done();
    }

    private void resetExecution() {
        execStats.clear().put("Current stage", "Not started").put("Elapsed time", "").put("Estimated time", "").put("Speed", "")
                .put("Bytes processed", "").done();
        verificationRows.removeAll();
        verificationRows.add(Kit.check("PENDING", "Pattern verification (read-back)"));
        verificationRows.add(Kit.check("PENDING", "Residual risk assessment"));
        verificationRows.add(Kit.check("PENDING", "Secondary artifacts verification"));
    }

    private void finish(EngineResult[] r) {
        EngineResult prepare = r[0];
        EngineResult run = r[1];
        verificationRows.removeAll();
        if (run == null) {
            ring.setColor(Tone.ERROR.fg);
            stepper.setFailed(4);
            verificationRows.add(Kit.check("FAILED", "Not started: " + (prepare == null ? "" : prepare.summary())));
            JOptionPane.showMessageDialog(this, prepare == null ? "Not started." : prepare.summary() + "\n" + prepare.remediation,
                    "Sanitization not started", JOptionPane.WARNING_MESSAGE);
            return;
        }
        lastJob = run.operationId;
        if (!run.succeeded()) {
            ring.setColor(Tone.ERROR.fg);
            stepper.setFailed(4);
            verificationRows.add(Kit.check("FAILED", run.summary()));
            if (!run.remediation.isBlank()) {
                verificationRows.add(Kit.wrap(run.remediation));
            }
            JOptionPane.showMessageDialog(this, run.summary() + (run.remediation.isBlank() ? "" : "\n\n" + run.remediation),
                    "Sanitization " + Kit.humanize(run.status), JOptionPane.WARNING_MESSAGE);
            revalidate();
            return;
        }
        AegisJsonObject full = run.fullResult();
        AegisJsonObject v = full.object("verification");
        boolean passed = v.optBoolean("passed", false);
        ring.setColor(passed ? Tone.SUCCESS.fg : Tone.WARNING.fg);
        ring.setValue(100);
        verificationRows.add(Kit.check(passed ? "SUCCESS" : "FAILED", "Read-back verification (" + v.optString("strategy") + "): "
                + Kit.bytes(v.optLong("bytes_checked", 0)) + " checked, " + v.array("failed_offsets").length() + " mismatched"));
        if (!v.optString("probability_note").isBlank()) {
            verificationRows.add(Kit.wrap(v.optString("probability_note")));
        }
        verificationRows.add(Kit.check(full.optString("achieved_level").isBlank() ? "WARNING" : "SUCCESS",
                "Outcome achieved: " + (full.optString("achieved_level").isBlank() ? "not recorded" : full.optString("achieved_level"))
                + " (method " + full.optString("method") + ", " + full.optLong("passes", 0) + " pass(es))"));
        int unwritable = full.array("unwritable_ranges").length();
        verificationRows.add(Kit.check(unwritable == 0 ? "SUCCESS" : "WARNING", unwritable == 0 ? "No unwritable ranges"
                : unwritable + " unwritable range(s) recorded"));
        EngineResult sweep = r[2];
        if (sweep != null) {
            AegisJsonObject s = sweep.result.object("sweep");
            long removed = s.array("traces").objects().stream().filter(t -> t.optBoolean("removed", false)).count();
            long reportOnly = s.array("traces").objects().stream().filter(t -> t.optBoolean("report_only", false)).count();
            verificationRows.add(Kit.check(sweep.succeeded() ? "SUCCESS" : "FAILED", "Secondary artifacts: "
                    + s.array("traces").length() + " found, " + removed + " removed, " + reportOnly + " reported only, "
                    + s.array("searched").length() + " place(s) searched"));
        } else {
            verificationRows.add(Kit.check("PENDING", "Secondary artifacts: not run"));
        }
        if (r[3] != null) {
            verificationRows.add(Kit.check(r[3].succeeded() ? "SUCCESS" : "WARNING", "Thumbnail cache: " + r[3].result.optLong("cleared", 0)
                    + " cleared, " + r[3].result.optLong("failed", 0) + " not cleared"));
        }
        EngineResult report = r[4];
        if (report != null) {
            verificationRows.add(Kit.check(report.succeeded() ? "SUCCESS" : "FAILED", report.succeeded()
                    ? "Signed report " + Path.of(report.result.optString("json")).getFileName() : "Report: " + report.summary()));
            reportButton.setEnabled(report.succeeded());
        }
        for (String w : run.warnings) {
            appendLog("Limitation: " + w);
        }
        stepper.setState(5, 5);
        revalidate();
        repaint();
    }

    private void appendLog(String line) {
        log.append(LocalTime.now().withNano(0) + "  " + line + "\n");
        log.setCaretPosition(log.getDocument().getLength());
    }

    private static final class Track extends JPanel implements javax.swing.Scrollable {

        Track(JComponent content) {
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
}
