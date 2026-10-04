package org.sleuthkit.autopsy.aegis.ui.recovery;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.GridLayout;
import java.awt.Image;
import java.awt.RenderingHints;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import javax.imageio.ImageIO;
import javax.swing.BorderFactory;
import javax.swing.DefaultComboBoxModel;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
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
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableRowSorter;
import org.sleuthkit.autopsy.aegis.engine.AegisEngine;
import org.sleuthkit.autopsy.aegis.engine.CaseWorkspace;
import org.sleuthkit.autopsy.aegis.engine.EngineBridge;
import org.sleuthkit.autopsy.aegis.engine.EngineProgress;
import org.sleuthkit.autopsy.aegis.engine.EngineResult;
import org.sleuthkit.autopsy.aegis.ui.AegisNavigation;
import org.sleuthkit.autopsy.aegis.ui.AegisTokens;
import org.sleuthkit.autopsy.aegis.ui.kit.Badge;
import org.sleuthkit.autopsy.aegis.ui.kit.DetailList;
import org.sleuthkit.autopsy.aegis.ui.kit.Kit;
import org.sleuthkit.autopsy.aegis.ui.kit.KitCard;
import org.sleuthkit.autopsy.aegis.ui.kit.MediaMapBar;
import org.sleuthkit.autopsy.aegis.ui.kit.ProgressRing;
import org.sleuthkit.autopsy.aegis.ui.kit.Stepper;
import org.sleuthkit.autopsy.aegis.ui.kit.Tone;
import org.sleuthkit.autopsy.aegis.util.AegisJson;
import org.sleuthkit.autopsy.aegis.util.AegisJson.AegisJsonArray;
import org.sleuthkit.autopsy.aegis.util.AegisJson.AegisJsonObject;
import org.sleuthkit.autopsy.casemodule.Case;
import org.sleuthkit.datamodel.Content;


/**
 * AEGIS Advanced File Recovery over acquired evidence (RAW, split RAW, E01).
 *
 * <p>The scan is the AEGIS Variant recovery pipeline ({@code carve_generator}):
 * media map, filesystem-aware undelete (NTFS, FAT, exFAT, ext), signature and
 * structure carving, bifragment JPEG/PNG reassembly, decoder validation,
 * classification, PII counts and the evidence score. The engine refuses a live
 * device; recovered copies are written into the case's AEGIS folder, never next
 * to or into the evidence.
 */
public final class AdvancedRecoveryView extends JPanel {

    private static volatile AdvancedRecoveryView instance;

    private static final String[] STEPS = {"Select Source", "Scan Configuration", "Scanning", "Validation", "Analysis", "Results"};
    private static final String[] CAPTIONS = {"Choose evidence", "Set options", "File system & raw scan", "Structure & decode",
        "Fragments & scoring", "Review & recover"};

    private final Stepper stepper = new Stepper(STEPS, CAPTIONS);

    // Scan progress
    private final ProgressRing ring = new ProgressRing(120);
    private final DetailList progressList = new DetailList();
    private final JButton scanButton = Kit.primary("Start Scan", "play");
    private final JButton cancelButton = Kit.outline("Cancel", "stop");

    // Configuration
    private final JComboBox<Evidence> sourceBox = new JComboBox<>();
    private final JCheckBox optUndelete = new JCheckBox("Filesystem-aware undelete (NTFS, FAT, exFAT, ext)", true);
    private final JCheckBox optCarve = new JCheckBox("Signature + structure carving (24 signatures, 16 parsers)", true);
    private final JCheckBox optMap = new JCheckBox("Media map", true);
    private final JCheckBox optWrite = new JCheckBox("Write recovered copies to the case folder", true);
    private final DetailList configList = new DetailList();

    // Source info
    private final DetailList sourceList = new DetailList();

    // Media map
    private final MediaMapBar mediaMap = new MediaMapBar();
    private final JLabel mapTotal = Kit.label("", AegisTokens.TITLE, AegisTokens.NAVY);
    private final JLabel mapSelection = Kit.caption("Scroll to zoom, drag to pan, click a region to filter results by offset.");
    private long[] offsetFilter;

    // Results
    private final CandidateModel model = new CandidateModel();
    private final JTable table = new JTable(model) {
        @Override
        public boolean getScrollableTracksViewportWidth() {
            return getParent() == null || getPreferredSize().width < getParent().getWidth();
        }
    };
    private final TableRowSorter<CandidateModel> sorter = new TableRowSorter<>(model);
    private final JTextField search = new JTextField();
    private final JPanel filterPanel = Kit.column(2);
    private final Map<String, JCheckBox> categoryBoxes = new TreeMap<>();
    private final Map<String, JCheckBox> bucketBoxes = new LinkedHashMap<>();
    private final Map<String, JCheckBox> sourceBoxes = new LinkedHashMap<>();
    private final Map<String, JCheckBox> statusBoxes = new TreeMap<>();
    private final KitCard resultsCard = new KitCard("list", "Recovered Files", "Run a scan to list recovered objects.");

    // Preview
    private final JLabel previewImage = new JLabel("", JLabel.CENTER);
    private final DetailList previewFacts = new DetailList();
    private final DetailList metadataList = new DetailList();
    private final JPanel validationPanel = Kit.column(2);
    private final JPanel fragmentsPanel = Kit.column(2);
    private final JTextArea hexView = new JTextArea();
    private final JButton enhanceButton = Kit.outline("AI Enhance (derivative)", "sparkles");

    private EngineBridge.Cancel cancel;
    private Timer clock;
    private long startedAt;
    private EngineResult lastRun;
    private AegisJsonObject runResult;
    private String sourceJob = "";

    public AdvancedRecoveryView() {
        super(new BorderLayout());
        instance = this;
        setBackground(AegisTokens.BACKGROUND);
        setOpaque(true);

        JPanel north = Kit.column(12, Kit.pageHeader("Advanced File Recovery",
                "Filesystem-aware undelete · Structure carving · Bifragment reassembly",
                "Recover deleted files from acquired evidence using filesystem analysis and validated file carving. The evidence is only read."),
                stepper);
        north.setBorder(new EmptyBorder(20, 24, 8, 24));
        add(north, BorderLayout.NORTH);

        JPanel top = new JPanel(new GridLayout(1, 3, 14, 0));
        top.setOpaque(false);
        top.add(progressCard());
        top.add(configCard());
        top.add(sourceCard());

        JPanel bottom = new JPanel(new BorderLayout(14, 0));
        bottom.setOpaque(false);
        JComponent filters = filtersCard();
        filters.setPreferredSize(new Dimension(200, 440));
        bottom.add(filters, BorderLayout.WEST);
        bottom.add(resultsCard(), BorderLayout.CENTER);
        JComponent preview = previewCard();
        preview.setPreferredSize(new Dimension(380, 440));
        bottom.add(preview, BorderLayout.EAST);

        JPanel body = Kit.column(14, top, mapCard(), bottom);
        body.setBorder(new EmptyBorder(6, 24, 20, 24));
        add(Kit.scroll(new Track(body)), BorderLayout.CENTER);
        stepper.setState(0, -1);
        resetProgress();
    }

    /** Opens Recovery with an acquired image preselected (from Disk Imager). */
    public static void openWithImage(Path image, String acquisitionJob) {
        AegisNavigation.show(AegisNavigation.RECOVERY);
        SwingUtilities.invokeLater(() -> {
            AdvancedRecoveryView v = instance;
            if (v != null) {
                v.preselect(image, acquisitionJob);
            }
        });
    }

    public void refresh() {
        if (cancel != null) {
            return;
        }
        loadSources(null);
    }

    // =====================================================================
    // Cards
    // =====================================================================

    private KitCard progressCard() {
        KitCard card = new KitCard("radar", "Scan Progress", null);
        JPanel body = new JPanel(new BorderLayout(14, 8));
        body.setOpaque(false);
        ring.setUnknown();
        body.add(ring, BorderLayout.WEST);
        body.add(progressList, BorderLayout.CENTER);
        cancelButton.setEnabled(false);
        scanButton.addActionListener(e -> startScan());
        cancelButton.addActionListener(e -> {
            if (cancel != null) {
                cancel.request();
            }
        });
        body.add(Kit.row(8, scanButton, cancelButton), BorderLayout.SOUTH);
        return card.content(body);
    }

    private KitCard configCard() {
        KitCard card = new KitCard("adjustments-horizontal", "Scan Configuration", null);
        JButton browse = Kit.outline("Browse…", "folder-open");
        browse.addActionListener(e -> browseImage());
        card.action(browse);
        sourceBox.setFont(AegisTokens.BODY_SMALL);
        sourceBox.addActionListener(e -> updateSourceInfo());
        for (JCheckBox b : new JCheckBox[]{optUndelete, optCarve, optMap, optWrite}) {
            b.setOpaque(false);
            b.setFont(AegisTokens.BODY_SMALL);
        }
        configList.put("Validation", "Structure + decoder + SHA-256").put("Fragment recovery", "Bifragment JPEG/PNG, engine-proven joins only")
                .put("Hash algorithm", "SHA-256 per recovered object").put("Evidence access", "Read-only (live devices refused)").done();
        optWrite.setToolTipText("Off: list and score every candidate without writing copies (triage of very large images).");
        JPanel body = Kit.column(6, Kit.caption("Evidence image"), sourceBox, optUndelete, optCarve, optMap, optWrite, configList);
        return card.content(body);
    }

    private KitCard sourceCard() {
        KitCard card = new KitCard("database", "Source Information", null);
        return card.content(sourceList);
    }

    private KitCard mapCard() {
        KitCard card = new KitCard("map-2", "Media Map", "Regions classed by the engine from the evidence bytes; recovered objects marked below.");
        card.action(mapTotal);
        JButton zin = Kit.outline("", "zoom-in");
        zin.addActionListener(e -> mediaMap.zoom(0.5));
        JButton zout = Kit.outline("", "zoom-out");
        zout.addActionListener(e -> mediaMap.zoom(2));
        JButton fit = Kit.outline("Fit");
        fit.addActionListener(e -> {
            mediaMap.fit();
            offsetFilter = null;
            mapSelection.setText("Scroll to zoom, drag to pan, click a region to filter results by offset.");
            applyFilters();
        });
        mediaMap.onSelect(span -> {
            offsetFilter = new long[]{span.offset(), span.offset() + span.length()};
            mapSelection.setText("Filtering results to " + Kit.humanize(span.kind()) + " region at offset " + span.offset()
                    + " (" + Kit.bytes(span.length()) + ").  Click Fit to clear.");
            applyFilters();
        });
        JPanel legend = new JPanel(new FlowLayout(FlowLayout.LEFT, 14, 0));
        legend.setOpaque(false);
        legend.add(swatch(MediaMapBar.VOLUME, "Filesystem volume"));
        legend.add(swatch(MediaMapBar.UNALLOCATED_VOLUME, "Outside any volume"));
        for (Map.Entry<String, Color> e : MediaMapBar.KIND_COLORS.entrySet()) {
            legend.add(swatch(e.getValue(), Kit.humanize(e.getKey())));
        }
        legend.add(swatch(MediaMapBar.RECOVERED, "Recovered object"));
        legend.add(swatch(MediaMapBar.FRAGMENT, "Reassembled fragment run"));
        JPanel south = new JPanel(new BorderLayout());
        south.setOpaque(false);
        south.add(legend, BorderLayout.CENTER);
        south.add(Kit.row(6, zin, zout, fit), BorderLayout.EAST);
        JPanel body = new JPanel(new BorderLayout(0, 8));
        body.setOpaque(false);
        body.add(mediaMap, BorderLayout.CENTER);
        body.add(Kit.column(4, south, mapSelection), BorderLayout.SOUTH);
        return card.content(body);
    }

    private static JComponent swatch(Color c, String label) {
        JLabel l = new JLabel(label + " ");
        l.setFont(AegisTokens.CAPTION);
        l.setForeground(AegisTokens.TEXT_SECONDARY);
        l.setBorder(new EmptyBorder(0, 0, 0, 6));
        l.setIcon(new javax.swing.Icon() {
            @Override
            public void paintIcon(Component comp, Graphics g, int x, int y) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(c);
                g2.fillOval(x, y + 1, 10, 10);
                g2.dispose();
            }

            @Override
            public int getIconWidth() {
                return 12;
            }

            @Override
            public int getIconHeight() {
                return 12;
            }
        });
        return l;
    }

    private KitCard filtersCard() {
        KitCard card = new KitCard(null, "Filters", null);
        search.setFont(AegisTokens.BODY_SMALL);
        search.setToolTipText("Search file name, extension, type or SHA-256");
        search.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                applyFilters();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                applyFilters();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
            }
        });
        JPanel body = new JPanel(new BorderLayout(0, 8));
        body.setOpaque(false);
        body.add(search, BorderLayout.NORTH);
        JScrollPane sp = Kit.scroll(filterPanel);
        body.add(sp, BorderLayout.CENTER);
        filterPanel.add(Kit.caption("Filters appear after a scan."));
        return card.content(body);
    }

    private KitCard resultsCard() {
        Kit.styleTable(table);
        table.setRowSorter(sorter);
        table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        table.getColumnModel().getColumn(6).setCellRenderer(Kit.badgeRenderer());
        table.getColumnModel().getColumn(5).setCellRenderer(new ScoreRenderer());
        int[] widths = {230, 56, 72, 150, 150, 90, 90, 150};
        for (int i = 0; i < widths.length; i++) {
            table.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);
        }
        table.setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS);
        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                showSelected();
            }
        });
        JButton export = Kit.outline("Export Selected", "file-export");
        export.addActionListener(e -> exportSelected());
        JButton addCase = Kit.primary("Add to Case", "database-plus");
        addCase.addActionListener(e -> addToCase());
        JButton report = Kit.outline("Signed Report", "certificate");
        report.addActionListener(e -> generateReport());
        JScrollPane sp = Kit.tableScroll(table);
        sp.setPreferredSize(new Dimension(500, 370));
        JPanel body = new JPanel(new BorderLayout(0, 8));
        body.setOpaque(false);
        body.add(Kit.row(8, export, report, addCase), BorderLayout.NORTH);
        body.add(sp, BorderLayout.CENTER);
        return resultsCard.content(body);
    }

    private KitCard previewCard() {
        KitCard card = new KitCard("photo-search", "File Preview & Analysis", null);
        JTabbedPane tabs = new JTabbedPane();
        Kit.styleTabs(tabs);
        tabs.setFont(AegisTokens.BODY_SMALL);
        JPanel prev = new JPanel(new BorderLayout(10, 8));
        prev.setOpaque(false);
        previewImage.setPreferredSize(new Dimension(170, 150));
        previewImage.setBorder(BorderFactory.createLineBorder(AegisTokens.BORDER));
        prev.add(previewImage, BorderLayout.WEST);
        prev.add(previewFacts, BorderLayout.CENTER);
        enhanceButton.setEnabled(false);
        enhanceButton.addActionListener(e -> enhanceSelected());
        prev.add(Kit.row(6, enhanceButton), BorderLayout.SOUTH);
        tabs.addTab("Preview", pad(prev));
        tabs.addTab("Metadata", pad(Kit.scroll(metadataList)));
        tabs.addTab("Validation", pad(Kit.scroll(validationPanel)));
        tabs.addTab("Fragments", pad(Kit.scroll(fragmentsPanel)));
        hexView.setFont(new java.awt.Font("Consolas", java.awt.Font.PLAIN, 11));
        hexView.setEditable(false);
        tabs.addTab("Hex View", new JScrollPane(hexView));
        return card.content(tabs);
    }

    private static JComponent pad(JComponent c) {
        JPanel p = new JPanel(new BorderLayout());
        p.setBackground(AegisTokens.SURFACE);
        p.setBorder(new EmptyBorder(10, 8, 8, 8));
        p.add(c, BorderLayout.CENTER);
        return p;
    }

    // =====================================================================
    // Sources
    // =====================================================================

    /** One selectable evidence image. */
    private static final class Evidence {

        final Path path;
        final String label;
        final String job;

        Evidence(Path path, String label, String job) {
            this.path = path;
            this.label = label;
            this.job = job == null ? "" : job;
        }

        @Override
        public String toString() {
            return label;
        }
    }

    /** Image path (case-insensitive, normalized) to the AEGIS acquisition job that wrote it. */
    private volatile java.util.Map<String, String> knownJobs = java.util.Map.of();

    private static String pathKey(Path p) {
        return p.toAbsolutePath().normalize().toString().toLowerCase(java.util.Locale.ROOT);
    }

    private void loadSources(Path select) {
        new SwingWorker<List<Evidence>, Void>() {
            @Override
            protected List<Evidence> doInBackground() {
                List<Evidence> out = new ArrayList<>();
                if (Case.isCaseOpen()) {
                    // Successful AEGIS acquisitions of this case, by image path, so a registered image
                    // keeps the link to the job that produced it (provenance in the recovery report).
                    java.util.Map<String, String> acquired = new java.util.LinkedHashMap<>();
                    java.util.Map<String, Path> acquiredPaths = new java.util.LinkedHashMap<>();
                    Path jobs = CaseWorkspace.stateDir().resolve("jobs");
                    if (Files.isDirectory(jobs)) {
                        try (var stream = Files.newDirectoryStream(jobs, "acquire-*.json")) {
                            for (Path j : stream) {
                                AegisJsonObject job = AegisJsonObject.parseStrict(Files.readString(j, StandardCharsets.UTF_8));
                                if ("SUCCESS".equals(job.optString("status"))) {
                                    Path img = Path.of(job.object("result").optString("image_path"));
                                    if (Files.isRegularFile(img)) {
                                        acquired.put(pathKey(img), job.optString("job_id"));
                                        acquiredPaths.put(pathKey(img), img);
                                    }
                                }
                            }
                        } catch (Exception ignored) {
                            // unreadable job files are skipped
                        }
                    }
                    knownJobs = acquired;
                    try {
                        for (Content c : Case.getCurrentCaseThrows().getDataSources()) {
                            if (c instanceof org.sleuthkit.datamodel.Image img && img.getPaths() != null && img.getPaths().length > 0) {
                                Path p = Path.of(img.getPaths()[0]);
                                if (Files.isRegularFile(p)) {
                                    String job = acquired.getOrDefault(pathKey(p), "");
                                    out.add(new Evidence(p, "Case data source: " + img.getName(), job));
                                    acquiredPaths.remove(pathKey(p));
                                }
                            }
                        }
                    } catch (Exception ignored) {
                        // listed sources are best effort; browsing still works
                    }
                    for (var entry : acquiredPaths.entrySet()) {
                        out.add(new Evidence(entry.getValue(), "AEGIS acquisition: " + entry.getValue().getFileName(),
                                acquired.get(entry.getKey())));
                    }
                }
                return out;
            }

            @Override
            protected void done() {
                try {
                    List<Evidence> list = get();
                    Evidence current = (Evidence) sourceBox.getSelectedItem();
                    DefaultComboBoxModel<Evidence> m = new DefaultComboBoxModel<>();
                    for (Evidence e : list) {
                        m.addElement(e);
                    }
                    if (current != null && list.stream().noneMatch(e -> e.path.equals(current.path))) {
                        m.addElement(current);
                    }
                    sourceBox.setModel(m);
                    Path want = select != null ? select : current == null ? null : current.path;
                    for (int i = 0; i < m.getSize(); i++) {
                        if (m.getElementAt(i).path.equals(want)) {
                            sourceBox.setSelectedIndex(i);
                        }
                    }
                    updateSourceInfo();
                } catch (Exception ignored) {
                    // keep the previous list
                }
            }
        }.execute();
    }

    private void preselect(Path image, String job) {
        DefaultComboBoxModel<Evidence> m = (DefaultComboBoxModel<Evidence>) sourceBox.getModel();
        Evidence e = new Evidence(image, "AEGIS acquisition: " + image.getFileName(), job);
        m.addElement(e);
        sourceBox.setSelectedItem(e);
        loadSources(image);
    }

    private void browseImage() {
        JFileChooser ch = new JFileChooser();
        ch.setDialogTitle("Select an evidence image (RAW, DD, split RAW .001, E01)");
        if (ch.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            Path p = ch.getSelectedFile().toPath();
            Evidence e = new Evidence(p, "Image file: " + p.getFileName(), knownJobs.getOrDefault(pathKey(p), ""));
            ((DefaultComboBoxModel<Evidence>) sourceBox.getModel()).addElement(e);
            sourceBox.setSelectedItem(e);
        }
    }

    private void updateSourceInfo() {
        Evidence e = (Evidence) sourceBox.getSelectedItem();
        sourceList.clear();
        if (e == null) {
            sourceList.put("Evidence", "Select or browse to an acquired image").done();
            scanButton.setEnabled(false);
            stepper.setState(0, -1);
            return;
        }
        long size = -1;
        try {
            size = Files.size(e.path);
        } catch (Exception ignored) {
            // shown as not available
        }
        String name = e.path.getFileName().toString().toLowerCase(Locale.ROOT);
        String fmt = name.endsWith(".e01") ? "E01 (Expert Witness Format)" : name.matches(".*\\.\\d{3}$") ? "Split RAW" : "RAW / DD";
        sourceList.put("Evidence", e.path.getFileName().toString()).put("Format", fmt)
                .put("File size", Kit.bytesExact(size)).put("Location", e.path.getParent() == null ? "" : e.path.getParent().toString())
                .put("Acquisition job", e.job.isBlank() ? "Not acquired by AEGIS in this case" : e.job)
                .put("Case", CaseWorkspace.caseOpen() ? CaseWorkspace.caseDisplayName() : "No case open");
        if (runResult != null) {
            AegisJsonObject ev = runResult.object("evidence");
            sourceList.put("Engine format", ev.optString("format")).put("Image size", Kit.bytesExact(ev.optLong("size_bytes", -1)))
                    .put("Identity digest", DetailList.mono(Kit.shortHash(ev.object("identity").optString("sha256"))));
            StringBuilder fs = new StringBuilder();
            for (AegisJsonObject p : runResult.array("partitions").objects()) {
                if (!p.optString("fs_type").isBlank()) {
                    fs.append(p.optString("fs_type").toUpperCase(Locale.ROOT)).append(" @").append(p.optLong("offset", 0))
                            .append(" (cluster ").append(p.optLong("cluster_bytes", 0)).append(" B)  ");
                }
            }
            sourceList.put("Filesystems", fs.toString().trim());
        }
        sourceList.done();
        scanButton.setEnabled(cancel == null);
        stepper.setState(runResult == null ? 1 : 5, runResult == null ? 0 : 5);
    }

    // =====================================================================
    // Scan
    // =====================================================================

    private void resetProgress() {
        progressList.clear().put("Current stage", "Not started").put("Elapsed time", "").put("Phase detail", "")
                .put("Candidates", "").done();
    }

    private void startScan() {
        Evidence e = (Evidence) sourceBox.getSelectedItem();
        if (e == null) {
            return;
        }
        if (!CaseWorkspace.caseOpen() && JOptionPane.showConfirmDialog(this,
                "No case is open. Recovered files and the ledger entry will go to the per-user AEGIS folder instead of a case. Continue?",
                "No case open", JOptionPane.OK_CANCEL_OPTION) != JOptionPane.OK_OPTION) {
            return;
        }
        cancel = new EngineBridge.Cancel();
        scanButton.setEnabled(false);
        cancelButton.setEnabled(true);
        ring.setColor(AegisTokens.BLUE);
        ring.setValue(0);
        startedAt = System.currentTimeMillis();
        stepper.setState(2, 1);
        clock = new Timer(1000, ev -> progressList.put("Elapsed time", Kit.duration((System.currentTimeMillis() - startedAt) / 1000)).done());
        clock.start();
        sourceJob = e.job;
        final boolean u = optUndelete.isSelected();
        final boolean c = optCarve.isSelected();
        final boolean m = optMap.isSelected();
        final boolean w = optWrite.isSelected();
        final EngineBridge.Cancel token = cancel;
        new SwingWorker<EngineResult, Void>() {
            @Override
            protected EngineResult doInBackground() {
                return AegisEngine.recover(e.path, e.job, u, c, m, w, p -> SwingUtilities.invokeLater(() -> {
                    ring.setValue(p.pct);
                    progressList.put("Current stage", phaseName(p.phase)).put("Phase detail", p.message).done();
                    stepper.setState(switch (p.phase) {
                        case "validate" -> 3;
                        case "score", "write" -> 4;
                        default -> 2;
                    }, 1);
                }), token);
            }

            @Override
            protected void done() {
                clock.stop();
                cancel = null;
                cancelButton.setEnabled(false);
                scanButton.setEnabled(true);
                try {
                    lastRun = get();
                } catch (Exception ex) {
                    lastRun = new EngineResult();
                    lastRun.status = "FAILED";
                    lastRun.errorMessage = ex.getMessage();
                }
                onScanFinished();
            }
        }.execute();
    }

    private static String phaseName(String phase) {
        return switch (phase) {
            case "open" -> "Opening evidence";
            case "map" -> "Mapping media";
            case "undelete" -> "Filesystem metadata (undelete)";
            case "signatures" -> "Signature & structure carving";
            case "validate" -> "Validating (decoders)";
            case "score" -> "Scoring & dedupe";
            case "write" -> "Writing recovered copies";
            default -> Kit.humanize(phase);
        };
    }

    private void onScanFinished() {
        EngineResult r = lastRun;
        if (!r.succeeded()) {
            ring.setColor(Tone.ERROR.fg);
            stepper.setFailed(stepper.current());
            progressList.put("Current stage", r.status).put("Phase detail", r.errorMessage).done();
            JOptionPane.showMessageDialog(this, r.summary() + (r.remediation.isBlank() ? "" : "\n\n" + r.remediation),
                    "Recovery " + Kit.humanize(r.status), JOptionPane.WARNING_MESSAGE);
            return;
        }
        ring.setValue(100);
        ring.setColor(Tone.SUCCESS.fg);
        runResult = r.fullResult();
        AegisJsonArray candidates = runResult.array("candidates");
        progressList.put("Current stage", "Complete").put("Phase detail", r.result.optLong("written", 0) + " object(s) written to the case folder")
                .put("Candidates", candidates.length() + "  (" + bucketText(r.result.object("by_bucket")) + ")").done();
        model.set(candidates.objects());
        resultsCard.setTitle("Recovered Files (" + candidates.length() + ")");
        resultsCard.setSubtitle("Engine job " + r.operationId + " · " + runResult.optString("out_dir"));
        buildFilters();
        buildMediaMap();
        updateSourceInfo();
        stepper.setState(5, 5);
        if (!r.warnings.isEmpty()) {
            progressList.put("Limitations", r.warnings.size() + " recorded (see Validation tab)").done();
        }
    }

    private static String bucketText(AegisJsonObject buckets) {
        StringBuilder sb = new StringBuilder();
        for (String k : new String[]{"HIGH", "MEDIUM", "LOW"}) {
            if (buckets.has(k)) {
                sb.append(k).append(' ').append(buckets.optLong(k, 0)).append("  ");
            }
        }
        return sb.toString().trim();
    }

    private void buildMediaMap() {
        AegisJsonObject mm = runResult.optJSONObject("media_map");
        long total = runResult.object("evidence").optLong("size_bytes", 0);
        List<MediaMapBar.Span> regions = new ArrayList<>();
        if (mm != null) {
            for (AegisJsonObject reg : mm.array("regions").objects()) {
                String kind = reg.optBoolean("substituted", false) ? "UNREADABLE" : reg.optString("kind");
                regions.add(new MediaMapBar.Span(reg.optLong("offset", 0), reg.optLong("length", 0), kind,
                        "entropy " + reg.optLong("entropy_mb", 0) / 1000.0 + " bits/byte; headers " + reg.object("headers")));
            }
        }
        List<MediaMapBar.Span> volumes = new ArrayList<>();
        for (AegisJsonObject p : runResult.array("partitions").objects()) {
            if (!p.optString("fs_type").isBlank()) {
                volumes.add(new MediaMapBar.Span(p.optLong("offset", 0), p.optLong("length", 0), "VOLUME",
                        p.optString("fs_type").toUpperCase(Locale.ROOT)));
            }
        }
        List<MediaMapBar.Span> rec = new ArrayList<>();
        for (AegisJsonObject c : runResult.array("candidates").objects()) {
            AegisJsonArray frags = c.array("fragments");
            if (frags.length() > 0) {
                for (AegisJsonObject f : frags.objects()) {
                    rec.add(new MediaMapBar.Span(f.optLong("offset", 0), f.optLong("length", 0), "FRAGMENT", c.optString("ext")));
                }
            } else {
                rec.add(new MediaMapBar.Span(c.optLong("offset", 0), c.optLong("length", 0), "RECOVERED", c.optString("ext")));
            }
        }
        mediaMap.setData(total, regions, volumes, rec);
        mapTotal.setText(Kit.bytes(total) + (mm != null && mm.optBoolean("sampled", false) ? "  (sampled)" : ""));
    }

    // =====================================================================
    // Filters
    // =====================================================================

    private void buildFilters() {
        filterPanel.removeAll();
        categoryBoxes.clear();
        bucketBoxes.clear();
        sourceBoxes.clear();
        statusBoxes.clear();
        Map<String, Integer> cats = new TreeMap<>();
        Map<String, Integer> buckets = new LinkedHashMap<>();
        buckets.put("HIGH", 0);
        buckets.put("MEDIUM", 0);
        buckets.put("LOW", 0);
        Map<String, Integer> sources = new LinkedHashMap<>();
        Map<String, Integer> statuses = new TreeMap<>();
        for (AegisJsonObject c : model.rows) {
            cats.merge(Kit.humanize(c.optString("category", "unknown")), 1, Integer::sum);
            buckets.merge(c.optString("bucket"), 1, Integer::sum);
            sources.merge(sourceName(c.optString("source")), 1, Integer::sum);
            statuses.merge(c.optString("validation", "unknown"), 1, Integer::sum);
        }
        filterPanel.add(Kit.label("File Type", AegisTokens.TITLE, AegisTokens.NAVY));
        cats.forEach((k, v) -> filterPanel.add(box(categoryBoxes, k, k + " (" + v + ")")));
        filterPanel.add(javax.swing.Box.createVerticalStrut(8));
        filterPanel.add(Kit.label("Evidence Score", AegisTokens.TITLE, AegisTokens.NAVY));
        buckets.forEach((k, v) -> filterPanel.add(box(bucketBoxes, k, bucketLabel(k) + " (" + v + ")")));
        filterPanel.add(javax.swing.Box.createVerticalStrut(8));
        filterPanel.add(Kit.label("Recovered By", AegisTokens.TITLE, AegisTokens.NAVY));
        sources.forEach((k, v) -> filterPanel.add(box(sourceBoxes, k, k + " (" + v + ")")));
        filterPanel.add(javax.swing.Box.createVerticalStrut(8));
        filterPanel.add(Kit.label("Validation", AegisTokens.TITLE, AegisTokens.NAVY));
        statuses.forEach((k, v) -> filterPanel.add(box(statusBoxes, k, Kit.humanize(k) + " (" + v + ")")));
        filterPanel.revalidate();
        filterPanel.repaint();
        applyFilters();
    }

    private static String bucketLabel(String b) {
        return switch (b) {
            case "HIGH" -> "High (≥ 80%)";
            case "MEDIUM" -> "Medium (50–79%)";
            case "LOW" -> "Low (< 50%)";
            default -> b;
        };
    }

    private JCheckBox box(Map<String, JCheckBox> group, String key, String label) {
        JCheckBox b = new JCheckBox(label, true);
        b.setOpaque(false);
        b.setFont(AegisTokens.BODY_SMALL);
        b.addActionListener(e -> applyFilters());
        group.put(key, b);
        return b;
    }

    private static boolean allowed(Map<String, JCheckBox> group, String key) {
        JCheckBox b = group.get(key);
        return b == null || b.isSelected();
    }

    private void applyFilters() {
        String q = search.getText().trim().toLowerCase(Locale.ROOT);
        sorter.setRowFilter(new javax.swing.RowFilter<CandidateModel, Integer>() {
            @Override
            public boolean include(Entry<? extends CandidateModel, ? extends Integer> entry) {
                AegisJsonObject c = model.rows.get(entry.getIdentifier());
                if (!allowed(categoryBoxes, Kit.humanize(c.optString("category", "unknown")))
                        || !allowed(bucketBoxes, c.optString("bucket"))
                        || !allowed(sourceBoxes, sourceName(c.optString("source")))
                        || !allowed(statusBoxes, c.optString("validation", "unknown"))) {
                    return false;
                }
                if (offsetFilter != null) {
                    long o = c.optLong("offset", 0);
                    long end = o + c.optLong("length", 0);
                    if (end < offsetFilter[0] || o > offsetFilter[1]) {
                        return false;
                    }
                }
                if (q.isEmpty()) {
                    return true;
                }
                return (displayName(c) + " " + c.optString("ext") + " " + c.optString("mime") + " " + c.optString("sha256"))
                        .toLowerCase(Locale.ROOT).contains(q);
            }
        });
    }

    static String sourceName(String source) {
        return switch (source) {
            case "fs_metadata" -> "Filesystem metadata";
            case "structure" -> "Structure carving";
            case "signature" -> "Signature carving";
            default -> Kit.humanize(source);
        };
    }

    static String displayName(AegisJsonObject c) {
        String n = c.optString("original_name");
        if (!n.isBlank()) {
            return n;
        }
        String out = c.optString("output_path");
        if (!out.isBlank()) {
            return Path.of(out).getFileName().toString();
        }
        return String.format("carved_%012d.%s", c.optLong("offset", 0), c.optString("ext", "bin"));
    }

    // =====================================================================
    // Selection detail
    // =====================================================================

    private List<AegisJsonObject> selectedRows() {
        List<AegisJsonObject> out = new ArrayList<>();
        for (int v : table.getSelectedRows()) {
            out.add(model.rows.get(table.convertRowIndexToModel(v)));
        }
        return out;
    }

    private void showSelected() {
        List<AegisJsonObject> sel = selectedRows();
        AegisJsonObject c = sel.isEmpty() ? null : sel.get(0);
        previewFacts.clear();
        metadataList.clear();
        validationPanel.removeAll();
        fragmentsPanel.removeAll();
        hexView.setText("");
        previewImage.setIcon(null);
        previewImage.setText("");
        enhanceButton.setEnabled(false);
        if (c == null) {
            previewFacts.done();
            metadataList.done();
            return;
        }
        String out = c.optString("output_path");
        previewFacts.put("File", displayName(c)).put("Type", c.optString("ext").toUpperCase(Locale.ROOT) + " · " + c.optString("mime"))
                .put("Size", Kit.bytesExact(c.optLong("length", -1)))
                .put("Offset", c.optLong("offset", 0) + " (sector " + c.optLong("offset", 0) / 512 + ")")
                .put("Evidence score", String.format(Locale.ROOT, "%.2f%% (%s)", c.optLong("confidence_bp", 0) / 100.0, c.optString("bucket")))
                .put("Status", Badge.of(c.optString("validation")))
                .put("SHA-256", DetailList.mono(Kit.shortHash(c.optString("sha256")))).done();
        if (!out.isBlank() && Files.isRegularFile(Path.of(out))) {
            loadPreview(Path.of(out), c);
        } else {
            previewImage.setText("<html><center>No recovered copy<br>was written</center></html>");
        }

        AegisJsonObject mac = c.optJSONObject("mac");
        metadataList.put("Original name", c.optString("original_name")).put("Recovered by", sourceName(c.optString("source")))
                .put("Filesystem", c.optString("fs_type")).put("Category", Kit.humanize(c.optString("category")))
                .put("MIME", c.optString("mime"))
                .put("Modified", mac == null ? "" : mac.optString("modified")).put("Accessed", mac == null ? "" : mac.optString("accessed"))
                .put("Created", mac == null ? "" : mac.optString("created")).put("Changed", mac == null ? "" : mac.optString("changed"))
                .put("Contiguity assumed", c.optBoolean("contiguity_assumed", false) ? "Yes (layout inferred)" : "No")
                .put("Possibly fragmented", c.optBoolean("possibly_fragmented", false) ? "Yes" : "No")
                .put("Duplicates at", c.array("duplicate_offsets").toString())
                .put("PII (counts only)", c.object("pii").object("counts").size() == 0 ? (c.object("pii").optBoolean("inspected", false)
                        ? "None found" : "Not inspected") : c.object("pii").object("counts").toString())
                .put("Recovered copy", out).put("Copy SHA-256", DetailList.mono(Kit.shortHash(c.optString("output_sha256"))))
                .put("Source evidence", runResult == null ? "" : runResult.object("evidence").optString("path"))
                .put("Engine job", lastRun == null ? "" : lastRun.operationId).done();

        String v = c.optString("validation");
        validationPanel.add(Kit.label("Validation Details", AegisTokens.TITLE, AegisTokens.NAVY));
        validationPanel.add(Kit.check(v, "Decoder verdict: " + Kit.humanize(v)));
        if (!c.optString("validation_detail").isBlank()) {
            validationPanel.add(Kit.wrap(c.optString("validation_detail")));
        }
        validationPanel.add(javax.swing.Box.createVerticalStrut(8));
        validationPanel.add(Kit.label("Evidence Score Components", AegisTokens.TITLE, AegisTokens.NAVY));
        AegisJsonObject comps = c.object("score_components");
        for (String k : comps.keys()) {
            validationPanel.add(componentBar(k, comps.optLong(k, 0)));
        }
        validationPanel.add(Kit.caption("Sum = " + c.optLong("confidence_bp", 0) + " basis points. An evidence score, not a probability."));
        if (c.optBoolean("contiguity_contradicted", false)) {
            validationPanel.add(Kit.notice(Tone.WARNING, "Contiguity contradicted: the bytes after the start do not continue this object."));
        }
        AegisJsonArray frags = c.array("fragments");
        if (frags.length() == 0) {
            fragmentsPanel.add(Kit.check("SUCCESS", "Single contiguous run (no reassembly)"));
            fragmentsPanel.add(new DetailList().put("Run", c.optLong("offset", 0) + " .. " + (c.optLong("offset", 0) + c.optLong("length", 0)))
                    .put("Length", Kit.bytesExact(c.optLong("length", -1))).done());
        } else {
            fragmentsPanel.add(Kit.check("WARNING", "Reassembled from " + frags.length() + " runs; the join was proven by the decoder"));
            int i = 1;
            long prevEnd = -1;
            for (AegisJsonObject f : frags.objects()) {
                long o = f.optLong("offset", 0);
                long l = f.optLong("length", 0);
                DetailList d = new DetailList().put("Fragment " + i, o + " .. " + (o + l) + "  (" + Kit.bytes(l) + ")");
                if (prevEnd >= 0) {
                    d.put("Gap before", Kit.bytesExact(o - prevEnd));
                }
                fragmentsPanel.add(d.done());
                prevEnd = o + l;
                i++;
            }
            fragmentsPanel.add(new DetailList().put("Join validation", c.optString("validation"))
                    .put("Reassembly component", Long.toString(comps.optLong("reassembly", 0)))
                    .put("Result SHA-256", DetailList.mono(c.optString("sha256"))).done());
            fragmentsPanel.add(Kit.caption("Scored below HIGH by design: where the gap was is inferred."));
        }
        if (lastRun != null && !lastRun.warnings.isEmpty()) {
            validationPanel.add(javax.swing.Box.createVerticalStrut(8));
            validationPanel.add(Kit.label("Run Limitations", AegisTokens.TITLE, AegisTokens.NAVY));
            for (String w : lastRun.warnings) {
                validationPanel.add(Kit.wrap("• " + w));
            }
        }
        validationPanel.revalidate();
        fragmentsPanel.revalidate();
    }

    private static JComponent componentBar(String name, long value) {
        JPanel p = new JPanel(new BorderLayout(8, 0));
        p.setOpaque(false);
        JLabel l = Kit.label(Kit.humanize(name), AegisTokens.BODY_SMALL, AegisTokens.TEXT);
        l.setPreferredSize(new Dimension(110, 20));
        p.add(l, BorderLayout.WEST);
        JProgressBar bar = new JProgressBar(0, 4000);
        bar.setValue((int) Math.max(0, Math.min(4000, Math.abs(value))));
        bar.setForeground(value < 0 ? Tone.WARNING.fg : value == 0 ? AegisTokens.BORDER : Tone.SUCCESS.fg);
        bar.setBorderPainted(false);
        bar.setPreferredSize(new Dimension(120, 8));
        p.add(bar, BorderLayout.CENTER);
        JLabel v = Kit.label((value > 0 ? "+" : "") + value, AegisTokens.MONO, value < 0 ? Tone.WARNING.fg : AegisTokens.NAVY);
        v.setPreferredSize(new Dimension(52, 20));
        p.add(v, BorderLayout.EAST);
        p.setBorder(new EmptyBorder(2, 0, 2, 0));
        return p;
    }

    private void loadPreview(Path file, AegisJsonObject c) {
        new SwingWorker<Object[], Void>() {
            @Override
            protected Object[] doInBackground() throws Exception {
                byte[] head;
                try (RandomAccessFile raf = new RandomAccessFile(file.toFile(), "r")) {
                    head = new byte[(int) Math.min(1024, raf.length())];
                    raf.readFully(head);
                }
                BufferedImage img = null;
                if ("image".equalsIgnoreCase(c.optString("category")) || file.toString().matches("(?i).*\\.(jpg|jpeg|png|gif|bmp)$")) {
                    try {
                        img = ImageIO.read(file.toFile());
                    } catch (Exception ignored) {
                        // not decodable by ImageIO: no thumbnail
                    }
                }
                return new Object[]{head, img};
            }

            @Override
            protected void done() {
                try {
                    Object[] r = get();
                    hexView.setText(hex((byte[]) r[0]));
                    hexView.setCaretPosition(0);
                    BufferedImage img = (BufferedImage) r[1];
                    if (img != null) {
                        double s = Math.min(168.0 / img.getWidth(), 148.0 / img.getHeight());
                        previewImage.setIcon(new ImageIcon(img.getScaledInstance(Math.max(1, (int) (img.getWidth() * s)),
                                Math.max(1, (int) (img.getHeight() * s)), Image.SCALE_SMOOTH)));
                        previewImage.setText("");
                        enhanceButton.setEnabled(true);
                    } else {
                        previewImage.setText("<html><center>" + c.optString("ext").toUpperCase(Locale.ROOT) + "<br>no image preview</center></html>");
                    }
                } catch (Exception ex) {
                    previewImage.setText("Preview unavailable");
                }
            }
        }.execute();
    }

    private static String hex(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < data.length; i += 16) {
            sb.append(String.format("%08x  ", i));
            StringBuilder ascii = new StringBuilder();
            for (int j = 0; j < 16; j++) {
                if (i + j < data.length) {
                    int b = data[i + j] & 0xff;
                    sb.append(String.format("%02x ", b));
                    ascii.append(b >= 32 && b < 127 ? (char) b : '.');
                } else {
                    sb.append("   ");
                }
            }
            sb.append(' ').append(ascii).append('\n');
        }
        return sb.toString();
    }

    // =====================================================================
    // Actions
    // =====================================================================

    private List<Path> selectedOutputs() {
        List<Path> out = new ArrayList<>();
        for (AegisJsonObject c : selectedRows()) {
            String p = c.optString("output_path");
            if (!p.isBlank() && Files.isRegularFile(Path.of(p))) {
                out.add(Path.of(p));
            }
        }
        return out;
    }

    private void exportSelected() {
        List<Path> files = selectedOutputs();
        if (files.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Select recovered objects that have a written copy.");
            return;
        }
        JFileChooser ch = new JFileChooser();
        ch.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        ch.setDialogTitle("Export recovered copies to");
        if (ch.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        Path dir = ch.getSelectedFile().toPath();
        new SwingWorker<String, Void>() {
            @Override
            protected String doInBackground() throws Exception {
                int n = 0;
                for (Path f : files) {
                    Files.copy(f, dir.resolve(f.getFileName()), StandardCopyOption.COPY_ATTRIBUTES);
                    n++;
                }
                AegisEngine.record("aegis.desktop.recovery.exported", new AegisJsonObject().put("job_id", lastRun.operationId)
                        .put("destination", dir.toString()).put("files", files.stream().map(Path::toString).toList()), new AegisJsonObject().put("count", n));
                return n + " file(s) exported to " + dir;
            }

            @Override
            protected void done() {
                try {
                    JOptionPane.showMessageDialog(AdvancedRecoveryView.this, get());
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(AdvancedRecoveryView.this, "Export failed: " + ex.getMessage(), "Export", JOptionPane.ERROR_MESSAGE);
                }
            }
        }.execute();
    }

    private void addToCase() {
        if (!Case.isCaseOpen() || lastRun == null || runResult == null) {
            JOptionPane.showMessageDialog(this, "Run a scan with a case open first.");
            return;
        }
        List<Path> files = selectedOutputs();
        if (files.isEmpty()) {
            for (AegisJsonObject c : model.rows) {
                String p = c.optString("output_path");
                if (!p.isBlank() && Files.isRegularFile(Path.of(p))) {
                    files.add(Path.of(p));
                }
            }
        }
        if (files.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No recovered copies were written by this run.");
            return;
        }
        final List<Path> chosen = files;
        final String job = lastRun.operationId;
        new SwingWorker<String, Void>() {
            @Override
            protected String doInBackground() throws Exception {
                Case c = Case.getCurrentCaseThrows();
                List<String> paths = chosen.stream().map(Path::toString).toList();
                var ds = c.getServices().getFileManager().addLocalFilesDataSource("aegis-recovery-" + job,
                        "AEGIS Recovery " + job, java.util.TimeZone.getDefault().getID(), paths, null);
                AegisEngine.record("aegis.desktop.recovery.registered", new AegisJsonObject().put("job_id", job)
                        .put("data_source_id", ds.getId()).put("files", paths)
                        .put("source_evidence", runResult.object("evidence").optString("path")),
                        new AegisJsonObject().put("count", paths.size()));
                return chosen.size() + " recovered file(s) added to the case as data source \"AEGIS Recovery " + job
                        + "\" (id " + ds.getId() + "). Run ingest on it to index and analyse the files.";
            }

            @Override
            protected void done() {
                try {
                    JOptionPane.showMessageDialog(AdvancedRecoveryView.this, get(), "Added to case", JOptionPane.INFORMATION_MESSAGE);
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(AdvancedRecoveryView.this, "Could not add to case: " + ex.getMessage(), "Add to case",
                            JOptionPane.ERROR_MESSAGE);
                }
            }
        }.execute();
    }

    private void generateReport() {
        if (lastRun == null || !lastRun.succeeded()) {
            JOptionPane.showMessageDialog(this, "Run a scan first.");
            return;
        }
        final String job = lastRun.operationId;
        new SwingWorker<EngineResult, Void>() {
            @Override
            protected EngineResult doInBackground() {
                return AegisEngine.report(job);
            }

            @Override
            protected void done() {
                try {
                    EngineResult r = get();
                    JOptionPane.showMessageDialog(AdvancedRecoveryView.this, r.succeeded() ? "Signed recovery report written:\n"
                            + r.result.optString("pdf") + "\nSHA-256 " + r.result.optString("sha256") + "\nOpen it from Reports."
                            : r.summary(), "Recovery report", r.succeeded() ? JOptionPane.INFORMATION_MESSAGE : JOptionPane.ERROR_MESSAGE);
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(AdvancedRecoveryView.this, ex.getMessage());
                }
            }
        }.execute();
    }

    private void enhanceSelected() {
        List<Path> files = selectedOutputs();
        if (files.isEmpty()) {
            return;
        }
        EnhancementDialog.open(this, files.get(0));
    }

    // =====================================================================
    // Test driver hooks (AegisUiDriver)
    // =====================================================================

    public void driverSelectImage(Path image, String job) {
        preselect(image, job);
    }

    /** "idle" | "running" | "done:<n>" | "failed:<reason>". */
    public String driverStatus() {
        if (cancel != null) {
            return "running";
        }
        if (lastRun == null) {
            return "idle";
        }
        return lastRun.succeeded() ? "done:" + model.rows.size() : "failed:" + lastRun.summary();
    }

    /** Selects the first reassembled object, else the highest-scoring image; returns its recovered copy. */
    public Path driverSelectShowcase() {
        int pick = -1;
        for (int i = 0; i < model.rows.size() && pick < 0; i++) {
            if (model.rows.get(i).array("fragments").length() > 0) {
                pick = i;
            }
        }
        for (int i = 0; i < model.rows.size() && pick < 0; i++) {
            if ("fs_metadata".equals(model.rows.get(i).optString("source"))) {
                pick = i;
            }
        }
        if (pick < 0 && !model.rows.isEmpty()) {
            pick = 0;
        }
        if (pick < 0) {
            return null;
        }
        int view = table.convertRowIndexToView(pick);
        table.setRowSelectionInterval(view, view);
        table.scrollRectToVisible(table.getCellRect(view, 0, true));
        String out = model.rows.get(pick).optString("output_path");
        return out.isBlank() ? null : Path.of(out);
    }

    /** The recovered copy of the first decodable JPEG/PNG photo, for the enhancement step. */
    public Path driverPhoto() {
        for (AegisJsonObject c : model.rows) {
            String out = c.optString("output_path");
            if (!out.isBlank() && "valid".equals(c.optString("validation")) && out.toLowerCase(Locale.ROOT).matches(".*\\.(jpg|jpeg)$")
                    && c.array("fragments").length() == 0) {
                return Path.of(out);
            }
        }
        return null;
    }

    // =====================================================================
    // Table model and renderers
    // =====================================================================

    private static final class CandidateModel extends AbstractTableModel {

        private static final String[] COLS = {"File Name", "Type", "Size", "Offset (Sector)", "Recovered By", "Evidence Score", "Status", "SHA-256"};
        final List<AegisJsonObject> rows = new ArrayList<>();

        void set(List<AegisJsonObject> list) {
            rows.clear();
            rows.addAll(list);
            fireTableDataChanged();
        }

        @Override
        public int getRowCount() {
            return rows.size();
        }

        @Override
        public int getColumnCount() {
            return COLS.length;
        }

        @Override
        public String getColumnName(int c) {
            return COLS[c];
        }

        @Override
        public Class<?> getColumnClass(int c) {
            return c == 5 ? Long.class : c == 2 ? SizeValue.class : String.class;
        }

        @Override
        public Object getValueAt(int r, int c) {
            AegisJsonObject o = rows.get(r);
            return switch (c) {
                case 0 -> displayName(o);
                case 1 -> o.optString("ext").toUpperCase(Locale.ROOT);
                case 2 -> new SizeValue(o.optLong("length", 0));
                case 3 -> String.format("0x%X (%d)", o.optLong("offset", 0), o.optLong("offset", 0) / 512);
                case 4 -> sourceName(o.optString("source")) + (o.array("fragments").length() > 0 ? " · reassembled" : "");
                case 5 -> o.optLong("confidence_bp", 0);
                case 6 -> o.optString("validation").toUpperCase(Locale.ROOT);
                default -> Kit.shortHash(o.optString("sha256"));
            };
        }
    }

    /** Size that sorts numerically and displays human-readably. */
    private record SizeValue(long bytes) implements Comparable<SizeValue> {

        @Override
        public int compareTo(SizeValue o) {
            return Long.compare(bytes, o.bytes);
        }

        @Override
        public String toString() {
            return Kit.bytes(bytes);
        }
    }

    private static final class ScoreRenderer extends javax.swing.table.DefaultTableCellRenderer {

        @Override
        public Component getTableCellRendererComponent(JTable t, Object v, boolean s, boolean f, int r, int c) {
            JLabel l = (JLabel) super.getTableCellRendererComponent(t, v, s, false, r, c);
            long bp = v instanceof Long x ? x : 0;
            l.setText(String.format(Locale.ROOT, "%.0f%%", bp / 100.0));
            l.setForeground(bp >= 8000 ? Tone.SUCCESS.fg : bp >= 5000 ? Tone.WARNING.fg : Tone.ERROR.fg);
            l.setFont(AegisTokens.TITLE);
            l.setBorder(new EmptyBorder(0, 10, 0, 10));
            if (!s) {
                l.setBackground(AegisTokens.SURFACE);
            }
            return l;
        }
    }

    /** Lets the page track the viewport width. */
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

    @SuppressWarnings("unused")
    private static String json(Object o) {
        return AegisJson.toJson(o);
    }

    @SuppressWarnings("unused")
    private static File file(Path p) {
        return p.toFile();
    }
}
