package org.sleuthkit.autopsy.aegis.ui.oracle;

import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.Rectangle;
import java.awt.RenderingHints;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import javax.swing.JPanel;
import org.sleuthkit.autopsy.aegis.oracle.OracleService;
import org.sleuthkit.autopsy.aegis.ui.AegisIcons;
import org.sleuthkit.autopsy.aegis.ui.AegisTokens;

/**
 * Ego graph around the focused entity: the focus in the centre, its direct
 * relationships on the inner ring, their neighbours on the outer ring. Only
 * entities and edges present in the model are drawn; every edge is labelled
 * with its relationship type.
 */
final class OracleGraphPanel extends JPanel {

    static final Map<String, Color> TYPE_COLORS = new LinkedHashMap<>();
    static final Map<String, String> TYPE_ICONS = new LinkedHashMap<>();

    static {
        put("Case", new Color(0x0F2747), "folder");
        put("Evidence", new Color(0x2D6CDF), "database");
        put("Device", new Color(0x0F9F6E), "device-usb");
        put("File", new Color(0x3B82F6), "file");
        put("Deleted File", new Color(0xDC2626), "file");
        put("Recovered File", new Color(0x2563EB), "photo-search");
        put("Recovery Set", new Color(0x2563EB), "folders");
        put("Artifact", new Color(0x7C3AED), "fingerprint");
        put("Registry Entry", new Color(0x9333EA), "registry");
        put("User", new Color(0x1D4ED8), "user");
        put("Event", new Color(0xF59E0B), "clock");
        put("Communication", new Color(0xEA580C), "mail");
        put("Process", new Color(0xDB2777), "terminal-2");
        put("Location", new Color(0x0891B2), "map-pin");
        put("Report", new Color(0x475569), "report");
        put("Acquisition", new Color(0x0D9488), "download");
        put("Recovery", new Color(0x2563EB), "restore");
        put("Sanitization Operation", new Color(0xB91C1C), "shield-check");
        put("Verification", new Color(0x059669), "circle-check");
        put("Derivative", new Color(0x7C3AED), "sparkles");
    }

    private static void put(String type, Color c, String icon) {
        TYPE_COLORS.put(type, c);
        TYPE_ICONS.put(type, icon);
    }

    private OracleService.GraphModel model;
    private String focus;
    private final Set<String> hiddenTypes = new LinkedHashSet<>();
    private final Map<String, Rectangle> boxes = new LinkedHashMap<>();
    private final List<OracleService.Relationship> drawn = new ArrayList<>();
    private Consumer<String> onSelect;
    private String selected;

    OracleGraphPanel() {
        setBackground(AegisTokens.SURFACE);
        setPreferredSize(new Dimension(760, 470));
        addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                for (Map.Entry<String, Rectangle> b : boxes.entrySet()) {
                    if (b.getValue().contains(e.getPoint())) {
                        selected = b.getKey();
                        if (e.getClickCount() >= 2) {
                            focus = b.getKey();
                        }
                        repaint();
                        if (onSelect != null) {
                            onSelect.accept(b.getKey());
                        }
                        return;
                    }
                }
            }
        });
    }

    void onSelect(Consumer<String> listener) {
        this.onSelect = listener;
    }

    void setModel(OracleService.GraphModel model, String focus) {
        this.model = model;
        this.focus = focus;
        this.selected = focus;
        repaint();
    }

    void setFocus(String id) {
        this.focus = id;
        this.selected = id;
        repaint();
    }

    void setHiddenTypes(Set<String> types) {
        hiddenTypes.clear();
        hiddenTypes.addAll(types);
        repaint();
    }

    String focus() {
        return focus;
    }

    @Override
    protected void paintComponent(Graphics graphics) {
        super.paintComponent(graphics);
        Graphics2D g = (Graphics2D) graphics.create();
        g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_LCD_HRGB);
        boxes.clear();
        drawn.clear();
        if (model == null || focus == null || !model.byId.containsKey(focus)) {
            g.setColor(AegisTokens.TEXT_SECONDARY);
            g.setFont(AegisTokens.BODY);
            g.drawString(model == null ? "Building the graph from the case…" : "No entity selected. Open a case and build the graph.", 20, 30);
            g.dispose();
            return;
        }
        // Breadth-first ego network, depth 2, capped.
        Map<String, Integer> depth = new LinkedHashMap<>();
        Map<String, String> parent = new LinkedHashMap<>();
        Deque<String> queue = new ArrayDeque<>();
        depth.put(focus, 0);
        queue.add(focus);
        while (!queue.isEmpty() && depth.size() < 24) {
            String id = queue.poll();
            int d = depth.get(id);
            if (d >= 2) {
                continue;
            }
            int perNode = 0;
            for (OracleService.Relationship r : model.edgesOf(id)) {
                String other = r.fromId.equals(id) ? r.toId : r.fromId;
                OracleService.Entity oe = model.byId.get(other);
                if (oe == null || hiddenTypes.contains(oe.type) || depth.containsKey(other)) {
                    continue;
                }
                if ((d == 0 && ++perNode > 8) || (d == 1 && ++perNode > 2)) {
                    break;
                }
                depth.put(other, d + 1);
                parent.put(other, id);
                queue.add(other);
                if (depth.size() >= 24) {
                    break;
                }
            }
        }
        int w = getWidth();
        int h = getHeight();
        int cx = w / 2;
        int cy = h / 2;
        List<String> ring1 = new ArrayList<>();
        List<String> ring2 = new ArrayList<>();
        depth.forEach((id, d) -> {
            if (d == 1) {
                ring1.add(id);
            } else if (d == 2) {
                ring2.add(id);
            }
        });
        Map<String, double[]> pos = new LinkedHashMap<>();
        pos.put(focus, new double[]{cx, cy});
        double r1x = Math.min(w * 0.28, 330);
        double r1y = Math.min(h * 0.27, 170);
        Map<String, Double> angle = new LinkedHashMap<>();
        for (int i = 0; i < ring1.size(); i++) {
            double a = -Math.PI / 2 + 2 * Math.PI * i / Math.max(1, ring1.size());
            angle.put(ring1.get(i), a);
            pos.put(ring1.get(i), new double[]{cx + r1x * Math.cos(a), cy + r1y * Math.sin(a)});
        }
        double r2x = Math.min(w * 0.45, 520);
        double r2y = Math.min(h * 0.42, 230);
        Map<String, Integer> siblings = new LinkedHashMap<>();
        Map<String, Integer> index = new LinkedHashMap<>();
        for (String id : ring2) {
            String p = parent.get(id);
            index.put(id, siblings.merge(p, 1, Integer::sum) - 1);
        }
        for (String id : ring2) {
            String p = parent.get(id);
            int n = siblings.get(p);
            double spread = 0.36;
            double a = angle.getOrDefault(p, 0.0) + (index.get(id) - (n - 1) / 2.0) * spread;
            pos.put(id, new double[]{cx + r2x * Math.cos(a), cy + r2y * Math.sin(a)});
        }
        // Edges
        g.setFont(new Font("Segoe UI", Font.PLAIN, 10));
        for (OracleService.Relationship r : model.relationships) {
            double[] a = pos.get(r.fromId);
            double[] b = pos.get(r.toId);
            if (a == null || b == null) {
                continue;
            }
            drawn.add(r);
            boolean hot = r.fromId.equals(selected) || r.toId.equals(selected);
            g.setColor(hot ? AegisTokens.BLUE : new Color(0x9FB3CC));
            g.setStroke(new BasicStroke(hot ? 1.6f : 1f));
            g.drawLine((int) a[0], (int) a[1], (int) b[0], (int) b[1]);
            arrow(g, a, b);
            String label = r.type.toUpperCase(java.util.Locale.ROOT);
            FontMetrics fm = g.getFontMetrics();
            int lx = (int) ((a[0] + b[0]) / 2) - fm.stringWidth(label) / 2;
            int ly = (int) ((a[1] + b[1]) / 2);
            g.setColor(new Color(255, 255, 255, 220));
            g.fillRect(lx - 2, ly - fm.getAscent() + 1, fm.stringWidth(label) + 4, fm.getHeight() - 2);
            g.setColor(AegisTokens.TEXT_SECONDARY);
            g.drawString(label, lx, ly);
        }
        // Nodes (outer first so the focus is on top)
        List<String> order = new ArrayList<>(ring2);
        order.addAll(ring1);
        order.add(focus);
        for (String id : order) {
            OracleService.Entity e = model.byId.get(id);
            double[] p = pos.get(id);
            drawNode(g, e, (int) p[0], (int) p[1], id.equals(focus), id.equals(selected));
        }
        g.dispose();
    }

    private static void arrow(Graphics2D g, double[] a, double[] b) {
        double dx = b[0] - a[0];
        double dy = b[1] - a[1];
        double len = Math.hypot(dx, dy);
        if (len < 60) {
            return;
        }
        double ux = dx / len;
        double uy = dy / len;
        double tx = b[0] - ux * 52;
        double ty = b[1] - uy * 26;
        int[] xs = {(int) tx, (int) (tx - ux * 7 - uy * 4), (int) (tx - ux * 7 + uy * 4)};
        int[] ys = {(int) ty, (int) (ty - uy * 7 + ux * 4), (int) (ty - uy * 7 - ux * 4)};
        g.fillPolygon(xs, ys, 3);
    }

    private void drawNode(Graphics2D g, OracleService.Entity e, int x, int y, boolean isFocus, boolean isSelected) {
        Color c = TYPE_COLORS.getOrDefault(e.type, AegisTokens.TEXT_SECONDARY);
        Font title = isFocus ? new Font("Segoe UI Semibold", Font.PLAIN, 13) : new Font("Segoe UI Semibold", Font.PLAIN, 11);
        Font sub = new Font("Segoe UI", Font.PLAIN, 10);
        String label = e.label.length() > 22 ? e.label.substring(0, 21) + "…" : e.label;
        FontMetrics fm = g.getFontMetrics(title);
        int bw = Math.max(fm.stringWidth(label), g.getFontMetrics(sub).stringWidth(e.type)) + 44;
        int bh = isFocus ? 48 : 38;
        Rectangle box = new Rectangle(x - bw / 2, y - bh / 2, bw, bh);
        boxes.put(e.id, box);
        g.setColor(new Color(c.getRed(), c.getGreen(), c.getBlue(), isFocus ? 36 : 18));
        g.fillRoundRect(box.x, box.y, box.width, box.height, 14, 14);
        g.setColor(isSelected ? AegisTokens.BLUE : new Color(c.getRed(), c.getGreen(), c.getBlue(), 120));
        g.setStroke(new BasicStroke(isSelected ? 2f : 1f));
        g.drawRoundRect(box.x, box.y, box.width, box.height, 14, 14);
        javax.swing.Icon icon = AegisIcons.get(TYPE_ICONS.getOrDefault(e.type, "circle"), c, 16);
        icon.paintIcon(this, g, box.x + 8, y - 8);
        g.setFont(title);
        g.setColor(AegisTokens.NAVY);
        g.drawString(label, box.x + 30, y - 2);
        g.setFont(sub);
        g.setColor(AegisTokens.TEXT_SECONDARY);
        g.drawString(e.type, box.x + 30, y + 11);
    }
}
