package org.sleuthkit.autopsy.aegis.ui.kit;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.MouseWheelEvent;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import javax.swing.JComponent;
import org.sleuthkit.autopsy.aegis.ui.AegisTokens;

/**
 * The evidence media map. Three bands, all from engine output:
 * volumes (partition table), byte-class regions (the Variant media map:
 * ZERO, FILL, TEXT, STRUCTURED, HIGH_ENTROPY, and unreadable/substituted), and
 * the spans of recovered objects. Mouse wheel zooms, drag pans, click selects.
 */
public final class MediaMapBar extends JComponent {

    public static final Map<String, Color> KIND_COLORS = new LinkedHashMap<>();

    static {
        KIND_COLORS.put("STRUCTURED", new Color(0x4F86E8));
        KIND_COLORS.put("HIGH_ENTROPY", new Color(0x7C6FD6));
        KIND_COLORS.put("TEXT", new Color(0x22B8CF));
        KIND_COLORS.put("FILL", new Color(0xC9D3DF));
        KIND_COLORS.put("ZERO", new Color(0x94A3B8));
        KIND_COLORS.put("UNREADABLE", new Color(0xEF4444));
    }

    public static final Color VOLUME = new Color(0x2D6CDF);
    public static final Color UNALLOCATED_VOLUME = new Color(0xDCE3EC);
    public static final Color RECOVERED = new Color(0x10B981);
    public static final Color FRAGMENT = new Color(0xF59E0B);

    public record Span(long offset, long length, String kind, String label) {
    }

    private final List<Span> regions = new ArrayList<>();
    private final List<Span> volumes = new ArrayList<>();
    private final List<Span> recovered = new ArrayList<>();
    private long total;
    private double viewStart;
    private double viewEnd;
    private Span selected;
    private Consumer<Span> onSelect;
    private int dragX = -1;

    public MediaMapBar() {
        setPreferredSize(new Dimension(800, 78));
        setMinimumSize(new Dimension(300, 70));
        setOpaque(false);
        MouseAdapter mouse = new MouseAdapter() {
            @Override
            public void mouseWheelMoved(MouseWheelEvent e) {
                if (total <= 0) {
                    return;
                }
                double at = toOffset(e.getX());
                double factor = e.getWheelRotation() < 0 ? 0.75 : 1.33;
                double span = Math.max(4096, Math.min(total, (viewEnd - viewStart) * factor));
                double left = at - (at - viewStart) * span / (viewEnd - viewStart);
                setView(left, left + span);
            }

            @Override
            public void mousePressed(MouseEvent e) {
                dragX = e.getX();
            }

            @Override
            public void mouseDragged(MouseEvent e) {
                if (dragX < 0 || total <= 0) {
                    return;
                }
                double perPx = (viewEnd - viewStart) / Math.max(1, getWidth());
                double shift = (dragX - e.getX()) * perPx;
                dragX = e.getX();
                setView(viewStart + shift, viewEnd + shift);
            }

            @Override
            public void mouseClicked(MouseEvent e) {
                long at = (long) toOffset(e.getX());
                Span hit = null;
                List<Span> band = e.getY() > getHeight() - 20 ? recovered : e.getY() < 16 ? volumes : regions;
                for (Span s : band) {
                    if (at >= s.offset && at < s.offset + Math.max(s.length, (long) ((viewEnd - viewStart) / getWidth() * 3))) {
                        hit = s;
                        break;
                    }
                }
                selected = hit;
                repaint();
                if (hit != null && onSelect != null) {
                    onSelect.accept(hit);
                }
            }

            @Override
            public void mouseMoved(MouseEvent e) {
                long at = (long) toOffset(e.getX());
                for (Span s : regions) {
                    if (at >= s.offset && at < s.offset + s.length) {
                        setToolTipText("<html><b>" + Kit.humanize(s.kind) + "</b><br>offset " + at + " (sector "
                                + at / 512 + ")<br>" + Kit.bytes(s.length) + " region" + (s.label == null || s.label.isBlank()
                                ? "" : "<br>" + Kit.escape(s.label)) + "</html>");
                        return;
                    }
                }
                setToolTipText(null);
            }
        };
        addMouseListener(mouse);
        addMouseMotionListener(mouse);
        addMouseWheelListener(mouse);
    }

    public void onSelect(Consumer<Span> listener) {
        this.onSelect = listener;
    }

    public void setData(long totalBytes, List<Span> regions, List<Span> volumes, List<Span> recovered) {
        this.total = Math.max(0, totalBytes);
        this.regions.clear();
        this.regions.addAll(regions);
        this.volumes.clear();
        this.volumes.addAll(volumes);
        this.recovered.clear();
        this.recovered.addAll(recovered);
        fit();
    }

    public void clear() {
        setData(0, List.of(), List.of(), List.of());
    }

    public void fit() {
        viewStart = 0;
        viewEnd = Math.max(1, total);
        repaint();
    }

    public void zoom(double factor) {
        if (total <= 0) {
            return;
        }
        double mid = (viewStart + viewEnd) / 2;
        double span = Math.max(4096, Math.min(total, (viewEnd - viewStart) * factor));
        setView(mid - span / 2, mid + span / 2);
    }

    public long total() {
        return total;
    }

    private void setView(double start, double end) {
        double span = end - start;
        if (start < 0) {
            start = 0;
            end = span;
        }
        if (end > total) {
            end = total;
            start = Math.max(0, end - span);
        }
        viewStart = start;
        viewEnd = Math.max(start + 1, end);
        repaint();
    }

    private double toOffset(int x) {
        return viewStart + (viewEnd - viewStart) * x / Math.max(1.0, getWidth());
    }

    private int toX(double offset) {
        return (int) Math.round((offset - viewStart) / (viewEnd - viewStart) * getWidth());
    }

    @Override
    protected void paintComponent(Graphics g) {
        Graphics2D g2 = (Graphics2D) g.create();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        int w = getWidth();
        int volTop = 0;
        int volH = 12;
        int top = 16;
        int h = getHeight() - top - 20;
        int recTop = top + h + 4;
        g2.setColor(new Color(0xF1F5F9));
        g2.fillRoundRect(0, top, w, h, 6, 6);
        if (total <= 0) {
            g2.setColor(AegisTokens.TEXT_MUTED);
            g2.setFont(AegisTokens.BODY_SMALL);
            String msg = "No media map yet. Run a scan to map the evidence.";
            FontMetrics fm = g2.getFontMetrics();
            g2.drawString(msg, (w - fm.stringWidth(msg)) / 2, top + h / 2 + fm.getAscent() / 2);
            g2.dispose();
            return;
        }
        g2.setColor(UNALLOCATED_VOLUME);
        g2.fillRect(0, volTop, w, volH);
        for (Span v : volumes) {
            int x1 = Math.max(0, toX(v.offset));
            int x2 = Math.min(w, toX(v.offset + v.length));
            if (x2 < 0 || x1 > w) {
                continue;
            }
            g2.setColor(VOLUME);
            g2.fillRect(x1, volTop, Math.max(1, x2 - x1), volH);
            g2.setColor(Color.WHITE);
            g2.setFont(AegisTokens.CAPTION);
            String label = v.label == null ? "" : v.label;
            if (x2 - x1 > g2.getFontMetrics().stringWidth(label) + 8) {
                g2.drawString(label, x1 + 4, volTop + 10);
            }
        }
        for (Span r : regions) {
            int x1 = toX(r.offset);
            int x2 = toX(r.offset + r.length);
            if (x2 < 0 || x1 > w) {
                continue;
            }
            Color c = KIND_COLORS.getOrDefault(r.kind, new Color(0xCBD5E1));
            g2.setColor(c);
            g2.fillRect(Math.max(0, x1), top, Math.max("ZERO".equals(r.kind) ? 1 : 2, Math.min(w, x2) - Math.max(0, x1)), h);
        }
        for (Span r : recovered) {
            int x1 = toX(r.offset);
            int x2 = toX(r.offset + r.length);
            if (x2 < 0 || x1 > w) {
                continue;
            }
            g2.setColor("FRAGMENT".equals(r.kind) ? FRAGMENT : RECOVERED);
            g2.fillRect(Math.max(0, x1), recTop, Math.max(2, Math.min(w, x2) - Math.max(0, x1)), 10);
        }
        if (selected != null) {
            int x1 = Math.max(0, toX(selected.offset));
            int x2 = Math.min(w, toX(selected.offset + selected.length));
            g2.setColor(AegisTokens.NAVY);
            g2.drawRect(x1, top - 1, Math.max(2, x2 - x1), h + 1);
        }
        g2.dispose();
    }
}
