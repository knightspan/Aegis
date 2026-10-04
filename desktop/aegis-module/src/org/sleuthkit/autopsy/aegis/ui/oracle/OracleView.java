package org.sleuthkit.autopsy.aegis.ui.oracle;

import java.awt.BorderLayout;
import java.awt.Desktop;
import java.awt.Dimension;
import java.awt.GridLayout;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.SwingWorker;
import javax.swing.border.EmptyBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import org.sleuthkit.autopsy.aegis.oracle.OracleService;
import org.sleuthkit.autopsy.aegis.ui.AegisIcons;
import org.sleuthkit.autopsy.aegis.ui.AegisTokens;
import org.sleuthkit.autopsy.aegis.ui.kit.Badge;
import org.sleuthkit.autopsy.aegis.ui.kit.DetailList;
import org.sleuthkit.autopsy.aegis.ui.kit.Kit;
import org.sleuthkit.autopsy.aegis.ui.kit.KitCard;
import org.sleuthkit.autopsy.aegis.ui.kit.Tone;

/**
 * ORACLE: forensic ontology and knowledge graph of the open case. Built in the
 * background from the case database, the AEGIS job records and the case ledger;
 * every edge shown can be traced to the record it came from.
 */
public final class OracleView extends JPanel {

    private final OracleService service = new OracleService();
    private OracleService.GraphModel model;
    private final OracleGraphPanel graph = new OracleGraphPanel();
    private final JLabel statEntities = stat();
    private final JLabel statRelationships = stat();
    private final JLabel statSources = stat();
    private final JLabel statProvenance = stat();
    private final JLabel status = Kit.caption("");
    private final JTextField search = new JTextField();
    private final JPanel typeFilters = Kit.column(0);
    private final Map<String, JCheckBox> typeBoxes = new TreeMap<>();
    private final JPanel sourcesList = Kit.column(2);
    private final DefaultTableModel focusEvents = table("Time", "Event Type", "Description", "Source");
    private final DefaultTableModel allEvents = table("Time", "Event Type", "Description", "Source", "Related Entity");
    private final DefaultTableModel explorer = table("Type", "Name", "Hash (SHA-256)", "Degree", "Provenance");
    private final List<String> explorerIds = new ArrayList<>();
    private final List<String> eventIds = new ArrayList<>();
    private final TableRowSorter<DefaultTableModel> explorerSorter = new TableRowSorter<>(explorer);
    private final TableRowSorter<DefaultTableModel> eventSorter = new TableRowSorter<>(allEvents);
    private final JPanel pathsPanel = Kit.column(8);
    private final JPanel insightsPanel = Kit.column(8);
    private final JPanel analyticsPanel = Kit.column(8);
    private final JPanel inspector = new JPanel(new BorderLayout());
    private final JTabbedPane tabs = new JTabbedPane();
    private String inspected;
    private boolean building;

    public OracleView() {
        super(new BorderLayout());
        setBackground(AegisTokens.BACKGROUND);
        setOpaque(true);

        JPanel north = new JPanel(new BorderLayout(16, 0));
        north.setOpaque(false);
        north.add(Kit.pageHeader("ORACLE", "Forensic Ontology & Knowledge Graph",
                "Correlate evidence, artifacts, operations and events of the case in a provenance-aware knowledge graph."), BorderLayout.CENTER);
        JPanel stats = new JPanel(new GridLayout(1, 4, 10, 0));
        stats.setOpaque(false);
        stats.add(statTile("list", statEntities, "Entities"));
        stats.add(statTile("affiliate", statRelationships, "Relationships"));
        stats.add(statTile("database", statSources, "Data Sources"));
        stats.add(statTile("shield-check", statProvenance, "Provenance Coverage"));
        north.add(stats, BorderLayout.EAST);
        north.setBorder(new EmptyBorder(20, 24, 10, 24));
        add(north, BorderLayout.NORTH);

        tabs.setFont(AegisTokens.BODY);
        Kit.styleTabs(tabs);
        tabs.addTab("Knowledge Graph", graphTab());
        tabs.addTab("Timeline Correlation", timelineTab());
        tabs.addTab("Entity Explorer", explorerTab());
        tabs.addTab("Evidence Paths", Kit.scroll(pad(pathsPanel)));
        tabs.addTab("Case Insights", Kit.scroll(pad(insightsPanel)));
        tabs.addTab("Graph Analytics", Kit.scroll(pad(analyticsPanel)));
        JPanel center = new JPanel(new BorderLayout(14, 0));
        center.setOpaque(false);
        center.setBorder(new EmptyBorder(0, 24, 16, 24));
        center.add(tabs, BorderLayout.CENTER);
        inspector.setOpaque(false);
        inspector.setPreferredSize(new Dimension(360, 400));
        center.add(inspector, BorderLayout.EAST);
        add(center, BorderLayout.CENTER);
        graph.onSelect(this::inspect);
        showInspectorEmpty();
    }

    public void refresh() {
        if (building) {
            return;
        }
        building = true;
        status.setText("Building the graph from the case database, AEGIS jobs and the case ledger…");
        new SwingWorker<OracleService.GraphModel, Void>() {
            @Override
            protected OracleService.GraphModel doInBackground() {
                return service.buildFromOpenCase();
            }

            @Override
            protected void done() {
                building = false;
                try {
                    render(get());
                } catch (Exception ex) {
                    status.setText("Graph build failed: " + ex.getMessage());
                }
            }
        }.execute();
    }

    // ------------------------------------------------------------------ layout

    private JComponent graphTab() {
        JPanel controls = new JPanel(new BorderLayout(0, 8));
        controls.setOpaque(false);
        KitCard card = new KitCard(null, "Graph Controls", null);
        search.setFont(AegisTokens.BODY_SMALL);
        search.setToolTipText("Search entities, files, hashes");
        search.addActionListener(e -> searchAndFocus());
        JButton rebuild = Kit.outline("Rebuild", "refresh");
        rebuild.addActionListener(e -> refresh());
        JPanel body = Kit.column(8, search, Kit.label("Entity Types", AegisTokens.TITLE, AegisTokens.NAVY), typeFilters,
                Kit.label("Data Sources", AegisTokens.TITLE, AegisTokens.NAVY), sourcesList, Kit.row(6, rebuild));
        card.content(Kit.scroll(body));
        controls.add(card, BorderLayout.CENTER);
        controls.setPreferredSize(new Dimension(240, 400));

        KitCard graphCard = new KitCard("affiliate", "Knowledge Graph", "Click to inspect · double-click to centre on an entity");
        JButton reset = Kit.outline("Reset View", "refresh");
        reset.addActionListener(e -> {
            if (model != null) {
                focusDefault();
            }
        });
        graphCard.action(reset);
        JPanel legend = new JPanel(new java.awt.FlowLayout(java.awt.FlowLayout.LEFT, 8, 2));
        legend.setOpaque(false);
        for (Map.Entry<String, java.awt.Color> e : OracleGraphPanel.TYPE_COLORS.entrySet()) {
            JLabel l = new JLabel(e.getKey(), AegisIcons.get(OracleGraphPanel.TYPE_ICONS.get(e.getKey()), e.getValue(), 12), JLabel.LEFT);
            l.setFont(AegisTokens.CAPTION);
            l.setForeground(AegisTokens.TEXT_SECONDARY);
            legend.add(l);
        }
        JPanel gbody = new JPanel(new BorderLayout(0, 6));
        gbody.setOpaque(false);
        gbody.add(legend, BorderLayout.NORTH);
        graph.setBorder(BorderFactory.createLineBorder(AegisTokens.BORDER));
        gbody.add(graph, BorderLayout.CENTER);
        gbody.add(status, BorderLayout.SOUTH);
        graphCard.content(gbody);

        JTable t = new JTable(focusEvents);
        Kit.styleTable(t);
        JScrollPane sp = Kit.tableScroll(t);
        sp.setPreferredSize(new Dimension(500, 110));
        KitCard tl = new KitCard("timeline", "Timeline Correlation", "Recorded events of the selected entity");
        tl.content(sp);

        JPanel center = new JPanel(new BorderLayout(0, 12));
        center.setOpaque(false);
        center.add(graphCard, BorderLayout.CENTER);
        center.add(tl, BorderLayout.SOUTH);

        JPanel root = new JPanel(new BorderLayout(12, 0));
        root.setBackground(AegisTokens.BACKGROUND);
        root.setBorder(new EmptyBorder(10, 0, 0, 0));
        root.add(controls, BorderLayout.WEST);
        root.add(center, BorderLayout.CENTER);
        return root;
    }

    private JComponent timelineTab() {
        JTable t = new JTable(allEvents);
        Kit.styleTable(t);
        t.setRowSorter(eventSorter);
        t.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        t.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting() && t.getSelectedRow() >= 0) {
                String id = eventIds.get(t.convertRowIndexToModel(t.getSelectedRow()));
                if (!id.isBlank()) {
                    inspect(id);
                }
            }
        });
        JTextField filter = new JTextField();
        filter.setToolTipText("Filter events");
        filter.getDocument().addDocumentListener(simple(() -> eventSorter.setRowFilter(
                javax.swing.RowFilter.regexFilter("(?i)" + java.util.regex.Pattern.quote(filter.getText().trim())))));
        JPanel p = new JPanel(new BorderLayout(0, 8));
        p.setBackground(AegisTokens.BACKGROUND);
        p.setBorder(new EmptyBorder(10, 0, 0, 0));
        p.add(Kit.row(8, Kit.caption("Filter"), sized(filter, 300)), BorderLayout.NORTH);
        p.add(Kit.tableScroll(t), BorderLayout.CENTER);
        return p;
    }

    private JComponent explorerTab() {
        JTable t = new JTable(explorer);
        Kit.styleTable(t);
        t.setRowSorter(explorerSorter);
        t.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        t.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting() && t.getSelectedRow() >= 0) {
                inspect(explorerIds.get(t.convertRowIndexToModel(t.getSelectedRow())));
            }
        });
        JTextField filter = new JTextField();
        filter.getDocument().addDocumentListener(simple(() -> explorerSorter.setRowFilter(
                javax.swing.RowFilter.regexFilter("(?i)" + java.util.regex.Pattern.quote(filter.getText().trim())))));
        JPanel p = new JPanel(new BorderLayout(0, 8));
        p.setBackground(AegisTokens.BACKGROUND);
        p.setBorder(new EmptyBorder(10, 0, 0, 0));
        p.add(Kit.row(8, Kit.caption("Search"), sized(filter, 300)), BorderLayout.NORTH);
        p.add(Kit.tableScroll(t), BorderLayout.CENTER);
        return p;
    }

    // ------------------------------------------------------------------ rendering

    private void render(OracleService.GraphModel m) {
        model = m;
        status.setText(m.status);
        statEntities.setText(Integer.toString(m.entities.size()));
        statRelationships.setText(Integer.toString(m.relationships.size()));
        long ds = m.entities.stream().filter(e -> "Evidence".equals(e.type) || "Recovery Set".equals(e.type)).count();
        statSources.setText(Long.toString(ds));
        long withProv = m.relationships.stream().filter(r -> r.provenance != null && !r.provenance.isBlank()).count();
        statProvenance.setText(m.relationships.isEmpty() ? "—" : Math.round(100.0 * withProv / m.relationships.size()) + "%");

        Map<String, Integer> counts = new TreeMap<>();
        for (OracleService.Entity e : m.entities) {
            counts.merge(e.type, 1, Integer::sum);
        }
        typeFilters.removeAll();
        typeBoxes.clear();
        counts.forEach((type, n) -> {
            JCheckBox b = new JCheckBox(type + " (" + n + ")", true);
            b.setOpaque(false);
            b.setFont(AegisTokens.BODY_SMALL);
            b.addActionListener(e -> applyTypeFilter());
            typeBoxes.put(type, b);
            typeFilters.add(b);
        });
        sourcesList.removeAll();
        for (String s : m.sources) {
            sourcesList.add(Kit.wrap("• " + s));
        }
        typeFilters.revalidate();
        sourcesList.revalidate();

        allEvents.setRowCount(0);
        eventIds.clear();
        for (OracleService.Event e : m.events) {
            OracleService.Entity en = m.byId.get(e.entityId);
            allEvents.addRow(new Object[]{e.when, e.type, e.label, e.source, en == null ? "" : en.label});
            eventIds.add(e.entityId);
        }
        explorer.setRowCount(0);
        explorerIds.clear();
        for (OracleService.Entity e : m.entities) {
            explorer.addRow(new Object[]{e.type, e.label, e.hash.isBlank() ? "" : Kit.shortHash(e.hash), m.edgesOf(e.id).size(), e.provenance});
            explorerIds.add(e.id);
        }
        insightsPanel.removeAll();
        if (!m.grounded) {
            insightsPanel.add(Kit.notice(Tone.INFO, m.status));
        }
        for (String s : m.insights) {
            insightsPanel.add(Kit.notice(Tone.NEUTRAL, s));
        }
        insightsPanel.add(new KitCard("database", "Sources used", null).content(Kit.column(4,
                m.sources.stream().map(s -> (JComponent) Kit.wrap("• " + s)).toArray(JComponent[]::new))));
        insightsPanel.revalidate();
        analytics(m);
        focusDefault();
    }

    private void focusDefault() {
        if (model == null || model.entities.isEmpty()) {
            graph.setModel(model, null);
            showInspectorEmpty();
            return;
        }
        // The most connected recovered file, else the most connected entity.
        OracleService.Entity best = model.entities.stream().filter(e -> "Recovered File".equals(e.type))
                .max(Comparator.comparingInt(e -> model.edgesOf(e.id).size())).orElse(null);
        if (best == null) {
            best = model.entities.stream().max(Comparator.comparingInt(e -> model.edgesOf(e.id).size())).orElse(model.entities.get(0));
        }
        graph.setModel(model, best.id);
        applyTypeFilter();
        inspect(best.id);
    }

    private void applyTypeFilter() {
        Set<String> hidden = new LinkedHashSet<>();
        typeBoxes.forEach((t, b) -> {
            if (!b.isSelected()) {
                hidden.add(t);
            }
        });
        graph.setHiddenTypes(hidden);
    }

    private void searchAndFocus() {
        if (model == null) {
            return;
        }
        String q = search.getText().trim().toLowerCase(Locale.ROOT);
        for (OracleService.Entity e : model.entities) {
            if (e.label.toLowerCase(Locale.ROOT).contains(q) || e.hash.toLowerCase(Locale.ROOT).startsWith(q)) {
                graph.setFocus(e.id);
                inspect(e.id);
                return;
            }
        }
        status.setText("No entity matches “" + search.getText().trim() + "”.");
    }

    private void inspect(String id) {
        if (model == null || !model.byId.containsKey(id)) {
            return;
        }
        inspected = id;
        OracleService.Entity e = model.byId.get(id);
        focusEvents.setRowCount(0);
        for (OracleService.Event ev : model.eventsOf(id)) {
            focusEvents.addRow(new Object[]{ev.when, ev.type, ev.label, ev.source});
        }
        inspector.removeAll();
        KitCard card = new KitCard(OracleGraphPanel.TYPE_ICONS.getOrDefault(e.type, "info"), "Entity Details", null);
        JPanel head = Kit.column(4, Kit.label(e.label, AegisTokens.H3, AegisTokens.NAVY), new Badge(e.type, Tone.INFO));
        JTabbedPane t = new JTabbedPane();
        Kit.styleTabs(t);
        t.setFont(AegisTokens.CAPTION);
        DetailList details = new DetailList().put("Type", e.type).put("Name", e.label)
                .put("Hash (SHA-256)", e.hash.isBlank() ? "" : e.hash).put("Time", e.time);
        e.meta.entrySet().stream().limit(10).forEach(m -> details.put(m.getKey(), m.getValue()));
        t.addTab("Details", Kit.scroll(pad(details.done())));
        JPanel rels = Kit.column(4);
        for (OracleService.Relationship r : model.edgesOf(id)) {
            boolean out = r.fromId.equals(id);
            OracleService.Entity other = model.byId.get(out ? r.toId : r.fromId);
            JLabel l = new JLabel("<html><b>" + (out ? "" : "← ") + Kit.escape(r.type.toUpperCase(Locale.ROOT)) + (out ? " →" : "")
                    + "</b> " + Kit.escape(other == null ? "?" : other.label) + " <span style='color:#64748B'>(" + Kit.escape(other == null ? "" : other.type)
                    + ")</span><br><span style='color:#94A3B8;font-size:9px'>" + Kit.escape(r.provenance) + "</span></html>");
            l.setFont(AegisTokens.BODY_SMALL);
            l.setCursor(java.awt.Cursor.getPredefinedCursor(java.awt.Cursor.HAND_CURSOR));
            final String target = other == null ? null : other.id;
            l.addMouseListener(new java.awt.event.MouseAdapter() {
                @Override
                public void mouseClicked(java.awt.event.MouseEvent ev) {
                    if (target != null) {
                        graph.setFocus(target);
                        inspect(target);
                    }
                }
            });
            rels.add(l);
        }
        t.addTab("Relationships (" + model.edgesOf(id).size() + ")", Kit.scroll(pad(rels)));
        JPanel tl = Kit.column(4);
        for (OracleService.Event ev : model.eventsOf(id)) {
            tl.add(Kit.wrap(ev.when + "  " + ev.type + " — " + ev.label));
        }
        if (model.eventsOf(id).isEmpty()) {
            tl.add(Kit.caption("No recorded events for this entity."));
        }
        t.addTab("Timeline", Kit.scroll(pad(tl)));
        JPanel prov = Kit.column(6, Kit.label("Entity source", AegisTokens.TITLE, AegisTokens.NAVY), Kit.wrap(e.provenance),
                Kit.label("Edge sources", AegisTokens.TITLE, AegisTokens.NAVY));
        for (OracleService.Relationship r : model.edgesOf(id)) {
            prov.add(Kit.wrap(r.type + ": " + r.provenance));
        }
        t.addTab("Provenance", Kit.scroll(pad(prov)));
        DetailList meta = new DetailList();
        e.meta.forEach(meta::put);
        t.addTab("Metadata", Kit.scroll(pad(meta.done())));
        JButton center = Kit.outline("Focus Graph", "target");
        center.addActionListener(ev -> {
            graph.setFocus(id);
            tabs.setSelectedIndex(0);
        });
        String path = e.meta.getOrDefault("Recovered copy", e.meta.getOrDefault("Path", e.meta.getOrDefault("JSON", "")));
        JButton open = Kit.outline("Open File", "external-link");
        open.setEnabled(!path.isBlank() && Files.isRegularFile(Path.of(path)));
        open.addActionListener(ev -> {
            try {
                Desktop.getDesktop().open(Path.of(path).toFile());
            } catch (Exception ex) {
                status.setText("Could not open " + path + ": " + ex.getMessage());
            }
        });
        JButton copy = Kit.outline("Copy Provenance", "copy");
        copy.addActionListener(ev -> {
            StringBuilder sb = new StringBuilder(e.type + " " + e.label + "\nSource: " + e.provenance + "\n");
            for (OracleService.Relationship r : model.edgesOf(id)) {
                sb.append(r.fromId).append(" ").append(r.type).append(" ").append(r.toId).append(" :: ").append(r.provenance).append('\n');
            }
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(sb.toString()), null);
        });
        JPanel body = new JPanel(new BorderLayout(0, 8));
        body.setOpaque(false);
        body.add(head, BorderLayout.NORTH);
        body.add(t, BorderLayout.CENTER);
        body.add(Kit.column(6, Kit.row(6, center, open), Kit.row(6, copy)), BorderLayout.SOUTH);
        card.content(body);
        inspector.add(card, BorderLayout.CENTER);
        inspector.revalidate();
        inspector.repaint();
        paths(id);
    }

    private void showInspectorEmpty() {
        inspector.removeAll();
        inspector.add(new KitCard("info", "Entity Details", null).content(Kit.notice(Tone.NEUTRAL,
                "Open a case. The graph is built from its evidence, the AEGIS operations recorded for it and the case ledger.")),
                BorderLayout.CENTER);
        inspector.revalidate();
    }

    /** Shortest recorded paths from the entity to every Evidence and Device, and to the Case. */
    private void paths(String from) {
        pathsPanel.removeAll();
        OracleService.Entity src = model.byId.get(from);
        pathsPanel.add(Kit.label("Evidence paths from " + src.label + " (" + src.type + ")", AegisTokens.H3, AegisTokens.NAVY));
        Map<String, String> prev = new LinkedHashMap<>();
        Map<String, OracleService.Relationship> via = new LinkedHashMap<>();
        Deque<String> q = new ArrayDeque<>();
        prev.put(from, null);
        q.add(from);
        while (!q.isEmpty()) {
            String id = q.poll();
            for (OracleService.Relationship r : model.edgesOf(id)) {
                String o = r.fromId.equals(id) ? r.toId : r.fromId;
                if (!prev.containsKey(o)) {
                    prev.put(o, id);
                    via.put(o, r);
                    q.add(o);
                }
            }
        }
        int shown = 0;
        for (OracleService.Entity target : model.entities) {
            if (target.id.equals(from) || !prev.containsKey(target.id)
                    || !List.of("Evidence", "Device", "Case", "Report", "Sanitization Operation").contains(target.type)) {
                continue;
            }
            List<String> hops = new ArrayList<>();
            String cur = target.id;
            while (prev.get(cur) != null) {
                OracleService.Relationship r = via.get(cur);
                OracleService.Entity a = model.byId.get(prev.get(cur));
                OracleService.Entity b = model.byId.get(cur);
                hops.add(0, a.label + " —" + r.type.toUpperCase(Locale.ROOT) + "→ " + b.label + "   [" + r.provenance + "]");
                cur = prev.get(cur);
            }
            KitCard c = new KitCard(OracleGraphPanel.TYPE_ICONS.getOrDefault(target.type, "info"), "To " + target.type + ": " + target.label,
                    hops.size() + " hop(s)");
            c.content(Kit.column(3, hops.stream().map(h -> (JComponent) Kit.wrap(h)).toArray(JComponent[]::new)));
            pathsPanel.add(c);
            shown++;
        }
        if (shown == 0) {
            pathsPanel.add(Kit.notice(Tone.NEUTRAL, "No recorded path connects this entity to evidence, a device or the case."));
        }
        pathsPanel.revalidate();
    }

    private void analytics(OracleService.GraphModel m) {
        analyticsPanel.removeAll();
        Map<String, Integer> relTypes = new TreeMap<>();
        for (OracleService.Relationship r : m.relationships) {
            relTypes.merge(r.type, 1, Integer::sum);
        }
        DetailList rel = new DetailList();
        relTypes.forEach((k, v) -> rel.put(k, Integer.toString(v)));
        analyticsPanel.add(new KitCard("affiliate", "Relationships by type", null).content(rel.done()));
        DetailList top = new DetailList();
        m.entities.stream().sorted(Comparator.comparingInt((OracleService.Entity e) -> m.edgesOf(e.id).size()).reversed()).limit(10)
                .forEach(e -> top.put(e.label + " (" + e.type + ")", m.edgesOf(e.id).size() + " edges"));
        analyticsPanel.add(new KitCard("chart-bar", "Most connected entities (degree)", null).content(top.done()));
        // Connected components
        Map<String, String> comp = new LinkedHashMap<>();
        int components = 0;
        for (OracleService.Entity e : m.entities) {
            if (comp.containsKey(e.id)) {
                continue;
            }
            components++;
            Deque<String> q = new ArrayDeque<>();
            q.add(e.id);
            comp.put(e.id, e.id);
            while (!q.isEmpty()) {
                String id = q.poll();
                for (OracleService.Relationship r : m.edgesOf(id)) {
                    String o = r.fromId.equals(id) ? r.toId : r.fromId;
                    if (!comp.containsKey(o)) {
                        comp.put(o, e.id);
                        q.add(o);
                    }
                }
            }
        }
        long withProv = m.relationships.stream().filter(r -> !r.provenance.isBlank()).count();
        analyticsPanel.add(new KitCard("chart-dots-3", "Graph", null).content(new DetailList()
                .put("Entities", Integer.toString(m.entities.size())).put("Relationships", Integer.toString(m.relationships.size()))
                .put("Connected components", Integer.toString(components))
                .put("Edges with provenance", withProv + " / " + m.relationships.size())
                .put("Events in timeline", Integer.toString(m.events.size())).done()));
        analyticsPanel.revalidate();
    }

    // ------------------------------------------------------------------ helpers

    private static JLabel stat() {
        JLabel l = new JLabel("—");
        l.setFont(new java.awt.Font("Segoe UI", java.awt.Font.BOLD, 20));
        l.setForeground(AegisTokens.NAVY);
        return l;
    }

    private static JComponent statTile(String icon, JLabel value, String caption) {
        KitCard c = new KitCard(icon, null, null);
        c.setBorder(new EmptyBorder(10, 14, 10, 14));
        JPanel p = new JPanel(new BorderLayout(10, 0));
        p.setOpaque(false);
        p.add(new JLabel(AegisIcons.get(icon, AegisTokens.BLUE, 24)), BorderLayout.WEST);
        p.add(Kit.column(0, value, Kit.caption(caption)), BorderLayout.CENTER);
        c.content(p);
        c.setPreferredSize(new Dimension(150, 64));
        return c;
    }

    private static DefaultTableModel table(String... cols) {
        return new DefaultTableModel(cols, 0) {
            @Override
            public boolean isCellEditable(int r, int c) {
                return false;
            }
        };
    }

    private static JComponent pad(JComponent c) {
        JPanel p = new JPanel(new BorderLayout());
        p.setBackground(AegisTokens.SURFACE);
        p.setBorder(new EmptyBorder(10, 10, 10, 10));
        p.add(c, BorderLayout.NORTH);
        return p;
    }

    private static JComponent sized(JComponent c, int w) {
        c.setPreferredSize(new Dimension(w, 30));
        return c;
    }

    private static DocumentListener simple(Runnable r) {
        return new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                r.run();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                r.run();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
            }
        };
    }
}
