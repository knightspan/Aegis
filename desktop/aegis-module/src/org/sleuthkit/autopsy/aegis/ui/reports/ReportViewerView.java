package org.sleuthkit.autopsy.aegis.ui.reports;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Desktop;
import java.awt.Dimension;
import java.awt.GridLayout;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import javax.swing.BorderFactory;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.ListCellRenderer;
import javax.swing.SwingWorker;
import javax.swing.border.EmptyBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.DefaultTableModel;
import org.sleuthkit.autopsy.aegis.audit.ReportSigner;
import org.sleuthkit.autopsy.aegis.engine.AegisEngine;
import org.sleuthkit.autopsy.aegis.engine.CaseWorkspace;
import org.sleuthkit.autopsy.aegis.engine.EngineResult;
import org.sleuthkit.autopsy.aegis.ui.AegisIcons;
import org.sleuthkit.autopsy.aegis.ui.AegisTokens;
import org.sleuthkit.autopsy.aegis.ui.kit.Badge;
import org.sleuthkit.autopsy.aegis.ui.kit.DetailList;
import org.sleuthkit.autopsy.aegis.ui.kit.Kit;
import org.sleuthkit.autopsy.aegis.ui.kit.KitCard;
import org.sleuthkit.autopsy.aegis.ui.kit.Tone;
import org.sleuthkit.autopsy.aegis.util.AegisJson;
import org.sleuthkit.autopsy.aegis.util.AegisJson.AegisJsonArray;
import org.sleuthkit.autopsy.aegis.util.AegisJson.AegisJsonObject;
import org.sleuthkit.autopsy.casemodule.Case;

/**
 * AEGIS Report Viewer: the signed engine reports of the open case
 * (acquisition, recovery, device sanitization, trace sweep) and the case's
 * other registered reports. Every value shown is read from the signed JSON;
 * "Verify Signature" and "Verify Audit Chain" run the engine's independent
 * verifier and show its verdict, including a failure.
 */
public final class ReportViewerView extends JPanel {

    /** One report in the list. */
    private static final class Entry {

        String kind = "";
        String title = "";
        String subtitle = "";
        String jobId = "";
        Path json;
        Path pdf;
        Path html;
        String sha256 = "";
        String generated = "";
        AegisJsonObject report;
        String state = "";
    }

    private final DefaultListModel<Entry> listModel = new DefaultListModel<>();
    private final JList<Entry> list = new JList<>(listModel);
    private final List<Entry> all = new ArrayList<>();
    private final JTextField search = new JTextField();
    private final JPanel content = new JPanel(new BorderLayout());
    private final JTabbedPane tabs = new JTabbedPane();
    private Entry current;
    private final JLabel caseLine = Kit.caption("");

    public ReportViewerView() {
        super(new BorderLayout());
        setBackground(AegisTokens.BACKGROUND);
        setOpaque(true);
        JPanel north = new JPanel(new BorderLayout());
        north.setOpaque(false);
        north.add(Kit.pageHeader("Report Viewer", null,
                "Signed reports of acquisition, recovery and sanitization operations, with audit logs and cryptographic integrity."),
                BorderLayout.CENTER);
        JButton open = Kit.outline("Open in Browser", "external-link");
        open.addActionListener(e -> openExternal());
        JButton pdf = Kit.outline("Export PDF", "file-export");
        pdf.addActionListener(e -> export("pdf"));
        JButton html = Kit.primary("Export HTML", "file-export");
        html.addActionListener(e -> export("html"));
        JButton json = Kit.outline("Export JSON", "file-export");
        json.addActionListener(e -> export("json"));
        north.add(Kit.row(8, open, pdf, html, json), BorderLayout.EAST);
        north.setBorder(new EmptyBorder(20, 24, 10, 24));
        add(north, BorderLayout.NORTH);

        JPanel left = new JPanel(new BorderLayout(0, 8));
        left.setOpaque(false);
        KitCard listCard = new KitCard(null, "Reports", null);
        search.setFont(AegisTokens.BODY_SMALL);
        search.setToolTipText("Search reports");
        search.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                filter();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                filter();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
            }
        });
        list.setCellRenderer(new EntryRenderer());
        list.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting() && list.getSelectedValue() != null) {
                show(list.getSelectedValue());
            }
        });
        JPanel lb = new JPanel(new BorderLayout(0, 8));
        lb.setOpaque(false);
        lb.add(search, BorderLayout.NORTH);
        JScrollPane ls = new JScrollPane(list);
        ls.setBorder(BorderFactory.createEmptyBorder());
        lb.add(ls, BorderLayout.CENTER);
        lb.add(caseLine, BorderLayout.SOUTH);
        listCard.content(lb);
        left.add(listCard, BorderLayout.CENTER);
        left.setPreferredSize(new Dimension(270, 400));

        tabs.setFont(AegisTokens.BODY_SMALL);
        Kit.styleTabs(tabs);
        content.setOpaque(false);
        content.add(tabs, BorderLayout.CENTER);
        JPanel center = new JPanel(new BorderLayout(14, 0));
        center.setOpaque(false);
        center.setBorder(new EmptyBorder(0, 24, 20, 24));
        center.add(left, BorderLayout.WEST);
        center.add(content, BorderLayout.CENTER);
        add(center, BorderLayout.CENTER);
        showEmpty();
    }

    public void refresh() {
        caseLine.setText(CaseWorkspace.caseOpen() ? "Case " + CaseWorkspace.caseDisplayName() : "No case open");
        new SwingWorker<List<Entry>, Void>() {
            @Override
            protected List<Entry> doInBackground() {
                return load();
            }

            @Override
            protected void done() {
                try {
                    all.clear();
                    all.addAll(get());
                    filter();
                    if (!listModel.isEmpty() && list.getSelectedIndex() < 0) {
                        list.setSelectedIndex(0);
                    }
                    if (listModel.isEmpty()) {
                        showEmpty();
                    }
                } catch (Exception ex) {
                    showMessage("Reports could not be listed: " + ex.getMessage());
                }
            }
        }.execute();
    }

    // ------------------------------------------------------------------ loading

    private static List<Entry> load() {
        List<Entry> out = new ArrayList<>();
        Path reports = CaseWorkspace.stateDir().resolve("reports");
        if (Files.isDirectory(reports)) {
            try (var dirs = Files.newDirectoryStream(reports)) {
                for (Path dir : dirs) {
                    Path meta = dir.resolve("aegis-report.meta.json");
                    if (!Files.isRegularFile(meta)) {
                        continue;
                    }
                    try {
                        AegisJsonObject m = AegisJsonObject.parseStrict(Files.readString(meta, StandardCharsets.UTF_8));
                        Entry e = new Entry();
                        e.kind = m.optString("kind");
                        e.jobId = m.optString("job_id");
                        e.json = Path.of(m.optString("json"));
                        e.pdf = Path.of(m.optString("pdf"));
                        e.sha256 = m.optString("sha256");
                        e.generated = m.optString("generated_at");
                        e.report = Files.isRegularFile(e.json)
                                ? AegisJsonObject.parseStrict(Files.readString(e.json, StandardCharsets.UTF_8)) : null;
                        e.state = e.report == null ? "MISSING" : e.report.object("sections").object("case_identity").optString("job_state");
                        e.title = e.jobId;
                        e.subtitle = kindTitle(e.kind);
                        out.add(e);
                    } catch (Exception ignored) {
                        // an unreadable report is skipped from the list, never shown as valid
                    }
                }
            } catch (Exception ignored) {
                // no reports directory yet
            }
        }
        out.sort(Comparator.comparing((Entry e) -> e.generated).reversed());
        if (Case.isCaseOpen()) {
            try {
                for (org.sleuthkit.datamodel.Report r : Case.getCurrentCaseThrows().getAllReports()) {
                    Entry e = new Entry();
                    e.kind = "case";
                    e.title = r.getReportName();
                    e.subtitle = r.getSourceModuleName();
                    e.html = Path.of(r.getPath());
                    e.generated = Long.toString(r.getCreatedTime());
                    e.state = "";
                    out.add(e);
                }
            } catch (Exception ignored) {
                // case reports are optional
            }
        }
        return out;
    }

    static String kindTitle(String kind) {
        return switch (kind) {
            case "acquire" -> "Disk Image Acquisition";
            case "carve" -> "File Recovery Analysis";
            case "erase-drive" -> "Device Sanitization";
            case "traces" -> "Secondary Artifact Purge";
            case "case" -> "Case report";
            default -> Kit.humanize(kind);
        };
    }

    private void filter() {
        String q = search.getText().trim().toLowerCase(Locale.ROOT);
        Entry keep = list.getSelectedValue();
        listModel.clear();
        for (Entry e : all) {
            if (q.isEmpty() || (e.title + " " + e.subtitle + " " + e.kind).toLowerCase(Locale.ROOT).contains(q)) {
                listModel.addElement(e);
            }
        }
        if (keep != null && listModel.contains(keep)) {
            list.setSelectedValue(keep, true);
        }
    }

    private static final class EntryRenderer extends JPanel implements ListCellRenderer<Entry> {

        private final JLabel icon = new JLabel();
        private final JLabel title = new JLabel();
        private final JLabel sub = new JLabel();
        private final Badge badge = new Badge("", Tone.NEUTRAL);

        EntryRenderer() {
            super(new BorderLayout(8, 2));
            setBorder(BorderFactory.createCompoundBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, AegisTokens.BORDER),
                    new EmptyBorder(8, 8, 8, 8)));
            title.setFont(AegisTokens.TITLE);
            title.setForeground(AegisTokens.NAVY);
            sub.setFont(AegisTokens.CAPTION);
            sub.setForeground(AegisTokens.TEXT_SECONDARY);
            JPanel text = new JPanel(new GridLayout(3, 1));
            text.setOpaque(false);
            text.add(title);
            text.add(sub);
            JPanel b = new JPanel(new java.awt.FlowLayout(java.awt.FlowLayout.LEFT, 0, 0));
            b.setOpaque(false);
            b.add(badge);
            text.add(b);
            add(icon, BorderLayout.WEST);
            add(text, BorderLayout.CENTER);
        }

        @Override
        public Component getListCellRendererComponent(JList<? extends Entry> l, Entry e, int index, boolean selected,
                boolean focus) {
            icon.setIcon(AegisIcons.get("case".equals(e.kind) ? "file-text" : "report", AegisTokens.BLUE, 20));
            title.setText(e.title);
            sub.setText(e.subtitle + (e.generated.isBlank() || "case".equals(e.kind) ? "" : " · " + shortTime(e.generated)));
            if ("case".equals(e.kind)) {
                badge.set("Case report", Tone.NEUTRAL);
            } else {
                badge.set(Kit.humanize(e.state.isBlank() ? "UNKNOWN" : e.state), Tone.of(e.state));
            }
            setBackground(selected ? AegisTokens.SELECTION : AegisTokens.SURFACE);
            return this;
        }
    }

    private static String shortTime(String iso) {
        return iso.length() >= 16 ? iso.substring(0, 16).replace('T', ' ') : iso;
    }

    // ------------------------------------------------------------------ display

    private void showEmpty() {
        tabs.removeAll();
        JPanel p = Kit.column(10, Kit.notice(Tone.INFO, CaseWorkspace.caseOpen()
                ? "No signed AEGIS reports in this case yet. Reports are generated by Disk Imager (after registration), "
                + "Advanced Recovery (Signed Report) and device sanitization (automatically)."
                : "Open a case to see its reports."));
        p.setBorder(new EmptyBorder(16, 16, 16, 16));
        tabs.addTab("Overview", p);
    }

    private void showMessage(String message) {
        tabs.removeAll();
        tabs.addTab("Overview", Kit.notice(Tone.ERROR, message));
    }

    private void show(Entry e) {
        current = e;
        tabs.removeAll();
        if ("case".equals(e.kind)) {
            tabs.addTab("Overview", pad(caseReportOverview(e)));
            return;
        }
        if (e.report == null) {
            tabs.addTab("Overview", pad(Kit.notice(Tone.ERROR, "The report file " + e.json + " is missing or unreadable.")));
            return;
        }
        AegisJsonObject s = e.report.object("sections");
        tabs.addTab("Overview", scroll(overview(e, s)));
        tabs.addTab("Detailed Analysis", scroll(tree(s, List.of("audit_trail", "limitations"))));
        tabs.addTab("Verification Results", scroll(verificationTab(e, s)));
        tabs.addTab("Audit Trail", scroll(auditTab(e, s)));
        tabs.addTab("Secondary Artifacts", scroll(secondaryTab(e)));
        tabs.addTab("Technical Details", technicalTab(e));
        tabs.addTab("Warnings & Limitations", scroll(limitationsTab(s)));
        tabs.addTab("Cryptographic Integrity", scroll(cryptoTab(e)));
    }

    private JComponent overview(Entry e, AegisJsonObject s) {
        AegisJsonObject ci = s.object("case_identity");
        JPanel head = new JPanel(new BorderLayout(16, 0));
        head.setOpaque(false);
        JPanel title = Kit.column(2, Kit.label(kindTitle(e.kind) + " Report", Kit.PAGE_SUBTITLE, AegisTokens.NAVY),
                Kit.caption("AEGIS · Digital Forensics & Secure Data Sanitization"));
        head.add(new JLabel(AegisIcons.logo(30)), BorderLayout.WEST);
        head.add(title, BorderLayout.CENTER);
        String state = ci.optString("job_state");
        head.add(new DetailList().put("Report ID", e.jobId).put("Generated", ci.optString("generated_at"))
                .put("Tool Version", e.report.optString("tool_version")).put("Report Format", "Signed JSON (authoritative) + PDF").done(),
                BorderLayout.EAST);
        KitCard headCard = new KitCard(null, null, null);
        headCard.content(Kit.column(10, head, Kit.notice(Tone.of(state), "Operation " + Kit.humanize(state)
                + (verdictHint(e, s).isBlank() ? "" : " — " + verdictHint(e, s)))));

        JPanel tiles = new JPanel(new GridLayout(1, 4, 12, 0));
        tiles.setOpaque(false);
        for (String[] t : tiles(e, s)) {
            KitCard c = new KitCard(t[0], t[1], null);
            c.content(Kit.column(2, Kit.label(t[2], AegisTokens.TITLE, Tone.of(t[4]) == Tone.NEUTRAL ? AegisTokens.NAVY : Tone.of(t[4]).fg),
                    Kit.caption(t[3])));
            tiles.add(c);
        }
        KitCard details = new KitCard("file-description", "Operation Details", null).content(details(e, s));
        return Kit.column(14, headCard, tiles, details);
    }

    private static String verdictHint(Entry e, AegisJsonObject s) {
        return switch (e.kind) {
            case "erase-drive" -> s.object("method").optString("level_achieved").isBlank() ? ""
                    : "achieved " + s.object("method").optString("level_achieved");
            case "acquire" -> s.object("verification").optBoolean("passed", false) ? "image verified (SHA-256 + BLAKE3)" : "image NOT verified";
            case "carve" -> s.object("recovery").optLong("candidates", 0) + " object(s) recovered";
            default -> "";
        };
    }

    private static List<String[]> tiles(Entry e, AegisJsonObject s) {
        List<String[]> t = new ArrayList<>();
        AegisJsonObject audit = s.object("audit_trail");
        switch (e.kind) {
            case "acquire" -> {
                AegisJsonObject src = s.object("evidence_source");
                AegisJsonObject acq = s.object("acquisition");
                t.add(new String[]{"disk", "Source", src.optString("device_model", src.optString("source")),
                    Kit.bytes(src.optLong("size_bytes", -1)), ""});
                t.add(new String[]{"download", "Acquisition", String.valueOf(acq.optString("format")).toUpperCase(Locale.ROOT),
                    Kit.bytes(acq.optLong("bytes_read", -1)) + " read", ""});
                t.add(new String[]{"shield-check", "Verification", s.object("verification").optBoolean("passed", false) ? "Verified" : "Not verified",
                    "SHA-256 + BLAKE3 re-read", s.object("verification").optBoolean("passed", false) ? "VERIFIED" : "FAILED"});
            }
            case "carve" -> {
                AegisJsonObject rec = s.object("recovery");
                t.add(new String[]{"database", "Evidence", Path.of(s.object("evidence").optString("path", "-")).getFileName().toString(),
                    Kit.bytes(s.object("evidence").optLong("size_bytes", -1)), ""});
                t.add(new String[]{"photo-search", "Recovered", rec.optLong("candidates", 0) + " objects",
                    "by confidence " + s.object("confidence").object("by_bucket"), ""});
                t.add(new String[]{"puzzle", "Reassembled", rec.optLong("reassembled_from_fragments", 0) + " from fragments",
                    "joins proven by decoder", ""});
            }
            case "erase-drive" -> {
                AegisJsonObject dev = s.object("device_identity");
                AegisJsonObject v = s.object("verification");
                t.add(new String[]{"disk", "Target Device", dev.optString("model"), dev.optString("serial") + " · "
                    + Kit.bytes(dev.optLong("size_bytes", -1)), ""});
                t.add(new String[]{"settings", "Operation", s.object("method").optString("method"),
                    "requested " + s.object("method").optString("level_requested"), ""});
                t.add(new String[]{"shield-check", "Verification", v.optBoolean("passed", false) ? "Verified" : "Not verified",
                    v.optString("strategy") + " · " + Kit.bytes(v.optLong("bytes_checked", 0)), v.optBoolean("passed", false) ? "VERIFIED" : "FAILED"});
            }
            default -> t.add(new String[]{"report", "Report", kindTitle(e.kind), e.jobId, ""});
        }
        String chain = audit.optString("chain_status");
        t.add(new String[]{"lock-check", "Audit Integrity", "VALID".equals(chain) ? "Valid" : Kit.humanize(chain),
            "hash chain · Ed25519 signed", "VALID".equals(chain) ? "VALID" : "FAILED"});
        return t;
    }

    private static JComponent details(Entry e, AegisJsonObject s) {
        DetailList d = new DetailList();
        AegisJsonObject ci = s.object("case_identity");
        d.put("Case", ci.optString("case_id")).put("Operator", ci.optString("operator")).put("Job", e.jobId)
                .put("Job state", ci.optString("job_state"));
        switch (e.kind) {
            case "acquire" -> {
                AegisJsonObject acq = s.object("acquisition");
                AegisJsonObject src = s.object("evidence_source");
                d.put("Source", src.optString("source")).put("Device serial", src.optString("device_serial"))
                        .put("Image", acq.optString("image")).put("Started", acq.optString("started_at"))
                        .put("Finished", acq.optString("finished_at")).put("SHA-256", DetailList.mono(acq.optString("sha256")))
                        .put("BLAKE3", DetailList.mono(acq.optString("blake3")))
                        .put("Unreadable ranges", Integer.toString(s.object("unreadable_sectors").array("ranges").length()))
                        .put("Write block", acq.optBoolean("write_blocked", false) ? "Applied" : "Not available (read-only open)");
            }
            case "carve" -> {
                AegisJsonObject ev = s.object("evidence");
                d.put("Evidence", ev.optString("path")).put("Format", ev.optString("format"))
                        .put("Unallocated bytes", Kit.bytesExact(ev.optLong("unallocated_bytes", -1)))
                        .put("By source", s.object("recovery").object("by_source").toString())
                        .put("By category", s.object("recovery").object("by_category").toString())
                        .put("Objects written", Long.toString(s.object("acquisition_integrity").optLong("objects_written", 0)))
                        .put("PII (counts only)", s.object("pii_triage").object("identifiers_by_kind").toString());
            }
            case "erase-drive" -> {
                AegisJsonObject m = s.object("method");
                AegisJsonObject dev = s.object("device_identity");
                AegisJsonObject v = s.object("verification");
                d.put("Device", dev.optString("model")).put("Serial", dev.optString("serial"))
                        .put("Capacity", Kit.bytesExact(dev.optLong("size_bytes", -1))).put("Transport", dev.optString("transport"))
                        .put("Method", m.optString("method")).put("Level requested", m.optString("level_requested"))
                        .put("Level achieved", m.optString("level_achieved")).put("Justification", m.optString("justification"))
                        .put("Verification", v.optBoolean("passed", false) ? "PASSED" : "FAILED")
                        .put("Verification strategy", v.optString("strategy"))
                        .put("Bytes checked", Kit.bytesExact(v.optLong("bytes_checked", -1)))
                        .put("Residual risk", s.object("residual_risk").toString().length() > 300
                                ? s.object("residual_risk").optString("summary") : s.object("residual_risk").toString());
            }
            default -> {
            }
        }
        return d.done();
    }

    private JComponent verificationTab(Entry e, AegisJsonObject s) {
        JPanel col = Kit.column(10);
        AegisJsonObject v = s.object("verification");
        if (v.size() > 0) {
            col.add(new KitCard("shield-check", "Engine verification (recorded in the report)", null).content(tree(v, List.of())));
        }
        JButton verify = Kit.primary("Verify Signature & Chain", "shield-check");
        JPanel result = Kit.column(4);
        verify.addActionListener(ev -> runVerify(e, result));
        col.add(new KitCard("certificate", "Independent verification", "Runs the engine's report verifier on the signed JSON now.")
                .content(Kit.column(8, Kit.row(8, verify), result)));
        return col;
    }

    private void runVerify(Entry e, JPanel into) {
        into.removeAll();
        into.add(Kit.caption("Verifying…"));
        into.revalidate();
        new SwingWorker<EngineResult, Void>() {
            @Override
            protected EngineResult doInBackground() {
                return AegisEngine.verifyReport(e.json);
            }

            @Override
            protected void done() {
                into.removeAll();
                try {
                    EngineResult r = get();
                    AegisJsonObject res = r.result;
                    String verdict = res.optString("verdict", r.status);
                    into.add(Kit.notice(r.succeeded() ? (r.warnings.isEmpty() ? Tone.SUCCESS : Tone.WARNING) : Tone.ERROR,
                            "Verdict: " + verdict + (r.succeeded() ? "" : " — " + r.errorMessage)));
                    for (AegisJsonObject c : res.array("checks").objects()) {
                        into.add(Kit.check(c.optBoolean("passed", false) ? "SUCCESS" : "FAILED",
                                Kit.humanize(c.optString("name")) + ": " + c.optString("detail")));
                    }
                    for (String reason : res.optStringList("reasons")) {
                        into.add(Kit.wrap("• " + reason));
                    }
                    into.add(new DetailList().put("Signer fingerprint", DetailList.mono(res.optString("fingerprint")))
                            .put("Report SHA-256", DetailList.mono(res.optString("report_sha256"))).done());
                } catch (Exception ex) {
                    into.add(Kit.notice(Tone.ERROR, "Verification failed to run: " + ex.getMessage()));
                }
                into.revalidate();
                into.repaint();
            }
        }.execute();
    }

    private JComponent auditTab(Entry e, AegisJsonObject s) {
        AegisJsonObject audit = s.object("audit_trail");
        DefaultTableModel m = new DefaultTableModel(new Object[]{"Seq", "Time (UTC)", "Event", "Actor", "Entry hash (SHA-256)", "Previous"}, 0) {
            @Override
            public boolean isCellEditable(int r, int c) {
                return false;
            }
        };
        for (AegisJsonObject en : audit.array("entries").objects()) {
            m.addRow(new Object[]{en.optLong("seq", 0), en.optString("ts_utc"), en.optString("operation"), en.optString("actor"),
                Kit.shortHash(en.optString("entry_hash")), Kit.shortHash(en.optString("prev_entry_hash"))});
        }
        JTable t = new JTable(m);
        Kit.styleTable(t);
        JScrollPane sp = Kit.tableScroll(t);
        sp.setPreferredSize(new Dimension(600, 260));
        JPanel live = Kit.column(4);
        JButton verify = Kit.primary("Verify Audit Chain", "lock-check");
        verify.addActionListener(ev -> {
            live.removeAll();
            live.add(Kit.caption("Verifying the case ledger…"));
            live.revalidate();
            new SwingWorker<EngineResult, Void>() {
                @Override
                protected EngineResult doInBackground() {
                    return AegisEngine.ledgerVerify();
                }

                @Override
                protected void done() {
                    live.removeAll();
                    try {
                        EngineResult r = get();
                        live.add(Kit.notice(r.succeeded() ? Tone.SUCCESS : Tone.ERROR, (r.succeeded() ? "Hash chain VALID: " : "Hash chain INVALID: ")
                                + r.result.optString("explanation", r.errorMessage)));
                        live.add(new DetailList().put("Entries", r.result.optString("entry_count"))
                                .put("Verified through seq", r.result.optString("verified_through"))
                                .put("First bad seq", r.result.optString("first_bad_seq"))
                                .put("Failure kind", r.result.optString("failure_kind")).done());
                    } catch (Exception ex) {
                        live.add(Kit.notice(Tone.ERROR, ex.getMessage()));
                    }
                    live.revalidate();
                    live.repaint();
                }
            }.execute();
        });
        DetailList recorded = new DetailList().put("Chain status (at signing)", Badge.of(audit.optString("chain_status")))
                .put("Explanation", audit.optString("chain_explanation"))
                .put("Entries in chain", audit.optString("entry_count")).put("Excerpt entries", Integer.toString(audit.array("entries").length()))
                .put("Excerpt gaps", audit.array("excerpt_gaps").toString()).done();
        return Kit.column(12, new KitCard("history", "Audit Trail (hash chain excerpt)", "Entries of this job plus genesis, as signed.")
                .content(Kit.column(8, recorded, sp)),
                new KitCard("lock-check", "Live ledger check", "Re-verifies every entry and blob of the case ledger now.")
                        .content(Kit.column(8, Kit.row(8, verify), live)));
    }

    private JComponent secondaryTab(Entry e) {
        JPanel col = Kit.column(10);
        Path jobs = CaseWorkspace.stateDir().resolve("jobs");
        boolean any = false;
        if (Files.isDirectory(jobs)) {
            try (var stream = Files.newDirectoryStream(jobs, "traces-*.json")) {
                for (Path j : stream) {
                    AegisJsonObject job = AegisJsonObject.parseStrict(Files.readString(j, StandardCharsets.UTF_8));
                    if (!e.jobId.equals(job.object("params").optString("source_job")) && !"traces".equals(e.kind)) {
                        continue;
                    }
                    if ("traces".equals(e.kind) && !e.jobId.equals(job.optString("job_id"))) {
                        continue;
                    }
                    any = true;
                    col.add(traceCard(job));
                }
            } catch (Exception ignored) {
                // no secondary artifacts recorded
            }
        }
        if ("traces".equals(e.kind) || "erase-drive".equals(e.kind)) {
            AegisJsonObject sweep = e.report.object("sections").optJSONObject("trace_sweep");
            if (sweep != null && !any) {
                col.add(new KitCard("eraser", "Trace sweep (signed)", null).content(tree(sweep, List.of())));
                any = true;
            }
        }
        if (!any) {
            col.add(Kit.notice(Tone.NEUTRAL, "No secondary-artifact sweep is linked to this operation."));
        }
        return col;
    }

    private static JComponent traceCard(AegisJsonObject job) {
        AegisJsonObject sweep = job.object("result").object("trace_sweep");
        DefaultTableModel m = new DefaultTableModel(new Object[]{"Artifact Type", "Location", "Status", "Action"}, 0) {
            @Override
            public boolean isCellEditable(int r, int c) {
                return false;
            }
        };
        for (AegisJsonObject t : sweep.array("traces").objects()) {
            m.addRow(new Object[]{Kit.humanize(t.optString("kind")), t.optString("location"),
                t.optBoolean("removed", false) ? "REMOVED" : t.optBoolean("report_only", false) ? "REPORT ONLY" : "NOT REMOVED",
                t.optString("action")});
        }
        JTable table = new JTable(m);
        Kit.styleTable(table);
        table.getColumnModel().getColumn(2).setCellRenderer(Kit.badgeRenderer());
        JScrollPane sp = Kit.tableScroll(table);
        sp.setPreferredSize(new Dimension(500, 160));
        return new KitCard("eraser", "Secondary Artifacts — " + job.optString("job_id"), String.join("; ", job.object("params").optStringList("erased")))
                .content(Kit.column(8, sp, new DetailList().put("Searched", String.join("; ", sweep.optStringList("searched")))
                        .put("Not searched", String.join("; ", sweep.optStringList("not_searched"))).done()));
    }

    private static JComponent technicalTab(Entry e) {
        JTextArea area = new JTextArea(pretty(e.report, 0));
        area.setFont(AegisTokens.MONO);
        area.setEditable(false);
        area.setCaretPosition(0);
        return new JScrollPane(area);
    }

    private static JComponent limitationsTab(AegisJsonObject s) {
        JPanel col = Kit.column(6);
        List<String> items = s.object("limitations").optStringList("items");
        if (items.isEmpty()) {
            col.add(Kit.notice(Tone.NEUTRAL, "No limitations recorded."));
        }
        for (String i : items) {
            col.add(Kit.notice(Tone.WARNING, i));
        }
        return col;
    }

    private JComponent cryptoTab(Entry e) {
        AegisJsonObject sig = e.report.object("signature");
        DetailList d = new DetailList().put("Algorithm", sig.optString("alg"))
                .put("Signer fingerprint", DetailList.mono(sig.optString("pubkey_fingerprint")))
                .put("Public key (Base64)", DetailList.mono(Kit.shortHash(sig.optString("pubkey_b64"))))
                .put("Signature (Base64)", DetailList.mono(Kit.shortHash(sig.optString("sig_b64"))))
                .put("Signed at", sig.optString("signed_at")).put("Canonicalization", sig.optString("canon_version"))
                .put("Report SHA-256", DetailList.mono(e.sha256)).put("Authoritative file", e.json.toString())
                .put("Key storage", "Ed25519 key encrypted at rest; passphrase protected by Windows DPAPI for this account").done();
        JPanel result = Kit.column(4);
        JButton verify = Kit.primary("Verify Signature", "certificate");
        verify.addActionListener(ev -> runVerify(e, result));
        return Kit.column(12, new KitCard("certificate", "Cryptographic Integrity", "Ed25519 over the canonical report bytes.").content(d),
                new KitCard("shield-check", "Verify", null).content(Kit.column(8, Kit.row(8, verify), result)));
    }

    private JComponent caseReportOverview(Entry e) {
        DetailList d = new DetailList().put("Report", e.title).put("Module", e.subtitle).put("Path", e.html == null ? "" : e.html.toString()).done();
        JPanel result = Kit.column(4);
        JButton verify = Kit.primary("Verify Signature", "certificate");
        boolean html = e.html != null && e.html.toString().toLowerCase(Locale.ROOT).endsWith(".html");
        verify.setEnabled(html);
        verify.addActionListener(ev -> {
            result.removeAll();
            try {
                ReportSigner.Verification v = new ReportSigner().verifyHtmlReport(e.html);
                result.add(Kit.notice(v.valid ? Tone.SUCCESS : Tone.ERROR, (v.valid ? "VALID: " : "INVALID: ") + v.message));
                result.add(new DetailList().put("Fingerprint", v.keyFingerprint).put("Payload SHA-256", v.payloadSha256).done());
            } catch (Exception ex) {
                result.add(Kit.notice(Tone.ERROR, "INVALID: " + ex.getMessage()));
            }
            result.revalidate();
        });
        return Kit.column(10, d, Kit.caption(html ? "Signed HTML sanitization report (AEGIS file/folder sanitizer)."
                : "Case report registered by a module; it carries no AEGIS signature."), Kit.row(8, verify), result);
    }

    // ------------------------------------------------------------------ exports

    private void openExternal() {
        if (current == null) {
            return;
        }
        Path target = current.pdf != null && Files.isRegularFile(current.pdf) ? current.pdf : current.html;
        if (target == null || !Files.exists(target)) {
            JOptionPane.showMessageDialog(this, "No file to open for this report.");
            return;
        }
        try {
            Desktop.getDesktop().open(target.toFile());
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Could not open " + target + ": " + ex.getMessage());
        }
    }

    private void export(String what) {
        if (current == null || current.report == null) {
            JOptionPane.showMessageDialog(this, "Select a signed AEGIS report first.");
            return;
        }
        JFileChooser ch = new JFileChooser();
        String base = current.jobId + ".forensic";
        ch.setSelectedFile(new java.io.File(base + "." + what));
        if (ch.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        Path dest = ch.getSelectedFile().toPath();
        try {
            switch (what) {
                case "pdf" -> Files.copy(current.pdf, dest, StandardCopyOption.REPLACE_EXISTING);
                case "json" -> Files.copy(current.json, dest, StandardCopyOption.REPLACE_EXISTING);
                default -> Files.writeString(dest, html(current), StandardCharsets.UTF_8);
            }
            JOptionPane.showMessageDialog(this, "Exported " + dest + (what.equals("html")
                    ? "\nThe HTML is a readable rendering; the signed JSON remains the authoritative artifact." : ""));
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Export failed: " + ex.getMessage(), "Export", JOptionPane.ERROR_MESSAGE);
        }
    }

    private static String html(Entry e) {
        StringBuilder sb = new StringBuilder("<!doctype html><html><head><meta charset='utf-8'><title>AEGIS ")
                .append(Kit.escape(kindTitle(e.kind))).append(" Report ").append(Kit.escape(e.jobId))
                .append("</title><style>body{font-family:Segoe UI,Arial,sans-serif;color:#0F2747;margin:32px;background:#F8FAFC}")
                .append("h1{font-size:22px}h2{font-size:15px;margin-top:22px;border-bottom:1px solid #E5EAF0;padding-bottom:4px}")
                .append("table{border-collapse:collapse;width:100%;background:#fff}td{border:1px solid #E5EAF0;padding:4px 8px;font-size:12px;vertical-align:top}")
                .append("td.k{color:#64748B;width:28%}.note{background:#E7F0FF;padding:8px;border-radius:6px;font-size:12px}</style></head><body>")
                .append("<h1>AEGIS — ").append(Kit.escape(kindTitle(e.kind))).append(" Report</h1>")
                .append("<p class='note'>Readable rendering of the signed report <b>").append(Kit.escape(e.json.toString()))
                .append("</b> (SHA-256 ").append(Kit.escape(e.sha256)).append("). The signed JSON is the authoritative artifact; ")
                .append("verify it with the AEGIS verifier.</p>");
        AegisJsonObject sections = e.report.object("sections");
        for (String k : sections.keys()) {
            sb.append("<h2>").append(Kit.escape(Kit.humanize(k))).append("</h2><table>");
            Object v = sections.opt(k);
            if (v instanceof AegisJsonObject o) {
                for (String kk : o.keys()) {
                    sb.append("<tr><td class='k'>").append(Kit.escape(kk)).append("</td><td>")
                            .append(Kit.escape(abbreviate(AegisJson.toJson(o.opt(kk))))).append("</td></tr>");
                }
            } else {
                sb.append("<tr><td>").append(Kit.escape(abbreviate(AegisJson.toJson(v)))).append("</td></tr>");
            }
            sb.append("</table>");
        }
        sb.append("<h2>Signature</h2><table>");
        AegisJsonObject sig = e.report.object("signature");
        for (String k : sig.keys()) {
            sb.append("<tr><td class='k'>").append(Kit.escape(k)).append("</td><td>").append(Kit.escape(sig.optString(k))).append("</td></tr>");
        }
        return sb.append("</table></body></html>").toString();
    }

    private static String abbreviate(String s) {
        return s.length() > 4000 ? s.substring(0, 4000) + " … (" + s.length() + " chars; see the signed JSON)" : s;
    }

    // ------------------------------------------------------------------ helpers

    private static JComponent tree(AegisJsonObject o, List<String> skip) {
        JPanel col = Kit.column(6);
        for (String k : o.keys()) {
            if (skip.contains(k)) {
                continue;
            }
            Object v = o.opt(k);
            if (v instanceof AegisJsonObject child) {
                DetailList d = new DetailList().leftAligned();
                for (String kk : child.keys()) {
                    Object vv = child.opt(kk);
                    d.put(Kit.humanize(kk), vv == null ? "" : abbreviate(vv instanceof String str ? str : AegisJson.toJson(vv)));
                }
                col.add(new KitCard(null, Kit.humanize(k), null).content(d.done()));
            } else {
                col.add(new DetailList().leftAligned().put(Kit.humanize(k), v == null ? "" : abbreviate(String.valueOf(v))).done());
            }
        }
        return col;
    }

    private static String pretty(Object v, int indent) {
        StringBuilder sb = new StringBuilder();
        prettyTo(sb, v, indent);
        return sb.toString();
    }

    private static void prettyTo(StringBuilder sb, Object v, int indent) {
        String pad = "  ".repeat(indent);
        if (v instanceof AegisJsonObject o) {
            sb.append("{\n");
            int i = 0;
            for (String k : o.keys()) {
                sb.append(pad).append("  \"").append(k).append("\": ");
                prettyTo(sb, o.opt(k), indent + 1);
                sb.append(++i < o.size() ? ",\n" : "\n");
            }
            sb.append(pad).append('}');
        } else if (v instanceof AegisJsonArray a) {
            if (a.length() > 200) {
                sb.append("[ … ").append(a.length()).append(" items (see the signed JSON) ]");
                return;
            }
            sb.append("[\n");
            for (int i = 0; i < a.length(); i++) {
                sb.append(pad).append("  ");
                prettyTo(sb, a.get(i), indent + 1);
                sb.append(i + 1 < a.length() ? ",\n" : "\n");
            }
            sb.append(pad).append(']');
        } else {
            sb.append(AegisJson.toJson(v));
        }
    }

    private static JComponent scroll(JComponent c) {
        JPanel p = new JPanel(new BorderLayout());
        p.setBackground(AegisTokens.BACKGROUND);
        p.setBorder(new EmptyBorder(12, 12, 12, 12));
        p.add(c, BorderLayout.NORTH);
        JScrollPane sp = Kit.scroll(p);
        sp.getViewport().setOpaque(true);
        sp.getViewport().setBackground(AegisTokens.BACKGROUND);
        return sp;
    }

    private static JComponent pad(JComponent c) {
        JPanel p = new JPanel(new BorderLayout());
        p.setBackground(AegisTokens.BACKGROUND);
        p.setBorder(new EmptyBorder(16, 16, 16, 16));
        p.add(c, BorderLayout.NORTH);
        return p;
    }
}
