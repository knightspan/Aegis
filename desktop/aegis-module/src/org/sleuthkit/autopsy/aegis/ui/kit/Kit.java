package org.sleuthkit.autopsy.aegis.ui.kit;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.util.Locale;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.ScrollPaneConstants;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.JTableHeader;
import javax.swing.table.TableCellRenderer;
import org.sleuthkit.autopsy.aegis.ui.AegisIcons;
import org.sleuthkit.autopsy.aegis.ui.AegisTokens;

/** Factories for the AEGIS reference visual language. */
public final class Kit {

    public static final Font PAGE_TITLE = new Font("Segoe UI", Font.BOLD, 24);
    public static final Font PAGE_SUBTITLE = new Font("Segoe UI Semibold", Font.PLAIN, 16);
    public static final Font CARD_TITLE = new Font("Segoe UI Semibold", Font.PLAIN, 15);
    public static final Color TABLE_HEADER = new Color(0xF6F8FB);
    public static final Color GRID = new Color(0xEDF1F6);

    private Kit() {
    }

    // ------------------------------------------------------------------ header

    /** Page header: AEGIS mark, title, blue subtitle, grey description. */
    public static JComponent pageHeader(String title, String subtitle, String description) {
        JPanel header = new JPanel(new BorderLayout(16, 0));
        header.setOpaque(false);
        JLabel mark = new JLabel(AegisIcons.monoMark(46));
        mark.setVerticalAlignment(JLabel.TOP);
        header.add(mark, BorderLayout.WEST);
        JPanel text = new JPanel();
        text.setOpaque(false);
        text.setLayout(new BoxLayout(text, BoxLayout.Y_AXIS));
        JLabel t = new JLabel(title);
        t.setFont(PAGE_TITLE);
        t.setForeground(AegisTokens.NAVY);
        text.add(t);
        if (subtitle != null && !subtitle.isBlank()) {
            JLabel s = new JLabel(subtitle);
            s.setFont(PAGE_SUBTITLE);
            s.setForeground(AegisTokens.BLUE);
            text.add(Box.createVerticalStrut(2));
            text.add(s);
        }
        if (description != null && !description.isBlank()) {
            JLabel d = new JLabel(description);
            d.setFont(AegisTokens.BODY);
            d.setForeground(AegisTokens.TEXT_SECONDARY);
            text.add(Box.createVerticalStrut(4));
            text.add(d);
        }
        header.add(text, BorderLayout.CENTER);
        return header;
    }

    // ------------------------------------------------------------------ buttons

    public static JButton primary(String text) {
        return new RoundButton(text, AegisTokens.BLUE, Color.WHITE, null);
    }

    public static JButton danger(String text) {
        return new RoundButton(text, Tone.ERROR.fg, Color.WHITE, null);
    }

    public static JButton outline(String text) {
        return new RoundButton(text, AegisTokens.SURFACE, AegisTokens.NAVY, AegisTokens.BORDER);
    }

    public static JButton outline(String text, String icon) {
        JButton b = outline(text);
        b.setIcon(AegisIcons.get(icon, AegisTokens.BLUE, 15));
        b.setIconTextGap(6);
        return b;
    }

    public static JButton primary(String text, String icon) {
        JButton b = primary(text);
        b.setIcon(AegisIcons.get(icon, Color.WHITE, 15));
        b.setIconTextGap(6);
        return b;
    }

    /** Flat rounded button that keeps its colours under the Windows look and feel. */
    static final class RoundButton extends JButton {

        private final Color fill;
        private final Color line;

        RoundButton(String text, Color fill, Color fg, Color line) {
            super(text);
            this.fill = fill;
            this.line = line;
            setFont(AegisTokens.BUTTON);
            setForeground(fg);
            setFocusPainted(false);
            setContentAreaFilled(false);
            setBorderPainted(false);
            setOpaque(false);
            setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
            setBorder(new EmptyBorder(8, 16, 8, 16));
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            Color f = fill;
            if (!isEnabled()) {
                f = line == null ? new Color(fill.getRed(), fill.getGreen(), fill.getBlue(), 110) : new Color(0xF4F6F9);
            } else if (getModel().isPressed()) {
                f = fill.darker();
            } else if (getModel().isRollover()) {
                f = line == null ? fill.brighter() : new Color(0xF4F7FB);
            }
            g2.setColor(f);
            g2.fillRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 8, 8);
            if (line != null) {
                g2.setColor(line);
                g2.drawRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 8, 8);
            }
            g2.dispose();
            super.paintComponent(g);
        }
    }

    // ------------------------------------------------------------------ layout helpers

    /** A vertically stacked column of full-width components. */
    public static JPanel column(int gap, Component... parts) {
        JPanel p = new JPanel();
        p.setOpaque(false);
        p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
        boolean first = true;
        for (Component c : parts) {
            if (!first && gap > 0) {
                p.add(Box.createVerticalStrut(gap));
            }
            first = false;
            if (c instanceof JComponent jc) {
                jc.setAlignmentX(Component.LEFT_ALIGNMENT);
            }
            p.add(c);
        }
        return p;
    }

    public static JPanel row(int gap, Component... parts) {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, gap, 0));
        p.setOpaque(false);
        for (Component c : parts) {
            p.add(c);
        }
        return p;
    }

    /** Scrolls a page body vertically with a sensible wheel speed and no horizontal bar. */
    public static JScrollPane scroll(Component body) {
        JScrollPane sp = new JScrollPane(body instanceof javax.swing.Scrollable ? body : new WidthTracker(body));
        sp.setBorder(BorderFactory.createEmptyBorder());
        sp.setOpaque(false);
        sp.getViewport().setOpaque(false);
        sp.getVerticalScrollBar().setUnitIncrement(24);
        sp.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        return sp;
    }

    /** Makes scrolled content follow the viewport width (no clipped right-aligned values). */
    static final class WidthTracker extends JPanel implements javax.swing.Scrollable {

        WidthTracker(Component content) {
            super(new BorderLayout());
            setOpaque(false);
            add(content, BorderLayout.CENTER);
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
            return Math.max(24, r.height - 40);
        }

        @Override
        public boolean getScrollableTracksViewportWidth() {
            return true;
        }

        @Override
        public boolean getScrollableTracksViewportHeight() {
            return getParent() != null && getParent().getHeight() > getPreferredSize().height;
        }
    }

    /** A bottom action bar: left and right groups above a hairline. */
    public static JPanel actionBar(JComponent left, JComponent right) {
        JPanel bar = new JPanel(new BorderLayout());
        bar.setBackground(AegisTokens.SURFACE);
        bar.setOpaque(true);
        bar.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 0, 0, 0, AegisTokens.BORDER),
                new EmptyBorder(10, 20, 10, 20)));
        if (left != null) {
            bar.add(left, BorderLayout.WEST);
        }
        if (right != null) {
            bar.add(right, BorderLayout.EAST);
        }
        return bar;
    }

    public static JLabel label(String text, Font font, Color color) {
        JLabel l = new JLabel(text);
        l.setFont(font);
        l.setForeground(color);
        return l;
    }

    public static JLabel caption(String text) {
        return label(text, AegisTokens.CAPTION, AegisTokens.TEXT_SECONDARY);
    }

    /** Wrapped body text. */
    public static JTextArea wrap(String text) {
        JTextArea a = new JTextArea(text == null ? "" : text);
        a.setLineWrap(true);
        a.setWrapStyleWord(true);
        a.setEditable(false);
        a.setOpaque(false);
        a.setFont(AegisTokens.BODY_SMALL);
        a.setForeground(AegisTokens.TEXT_SECONDARY);
        a.setBorder(null);
        return a;
    }

    /** An inline notice box (info/warning/error) with an icon. */
    public static JPanel notice(Tone tone, String text) {
        JPanel p = new JPanel(new BorderLayout(10, 0)) {
            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(tone.bg);
                g2.fillRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 8, 8);
                g2.setColor(new Color(tone.fg.getRed(), tone.fg.getGreen(), tone.fg.getBlue(), 60));
                g2.drawRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 8, 8);
                g2.dispose();
            }
        };
        p.setOpaque(false);
        p.setBorder(new EmptyBorder(9, 12, 9, 12));
        String icon = switch (tone) {
            case ERROR -> "error";
            case WARNING -> "warning";
            case SUCCESS -> "success";
            default -> "info";
        };
        JLabel i = new JLabel(AegisIcons.get(icon, tone.fg, 16));
        i.setVerticalAlignment(JLabel.TOP);
        p.add(i, BorderLayout.WEST);
        JTextArea t = wrap(text);
        t.setForeground(tone == Tone.NEUTRAL ? AegisTokens.TEXT_SECONDARY : tone.fg.darker());
        p.add(t, BorderLayout.CENTER);
        return p;
    }

    /** A check row: green tick, red cross, amber dot or grey pending marker, plus text. */
    public static JPanel check(String state, String text) {
        JPanel p = new JPanel(new BorderLayout(10, 0));
        p.setOpaque(false);
        p.setBorder(new EmptyBorder(5, 4, 5, 4));
        Tone tone = Tone.of(state);
        String icon = switch (tone) {
            case SUCCESS -> "success";
            case ERROR -> "error";
            case WARNING -> "warning";
            default -> "clock";
        };
        p.add(new JLabel(AegisIcons.get(icon, tone.fg, 17)), BorderLayout.WEST);
        JLabel l = new JLabel("<html>" + escape(text) + "</html>");
        l.setFont(AegisTokens.BODY_SMALL);
        l.setForeground(AegisTokens.TEXT);
        p.add(l, BorderLayout.CENTER);
        return p;
    }

    // ------------------------------------------------------------------ tabs

    /** Flat underline tabs as in the reference screens: blue text and a 2px underline on the active tab. */
    public static void styleTabs(javax.swing.JTabbedPane tabs) {
        tabs.setFont(AegisTokens.BODY);
        tabs.setOpaque(false);
        tabs.setUI(new javax.swing.plaf.basic.BasicTabbedPaneUI() {
            @Override
            protected void installDefaults() {
                super.installDefaults();
                tabInsets = new java.awt.Insets(8, 16, 9, 16);
                selectedTabPadInsets = new java.awt.Insets(0, 0, 0, 0);
                contentBorderInsets = new java.awt.Insets(1, 0, 0, 0);
                tabAreaInsets = new java.awt.Insets(0, 0, 0, 0);
            }

            @Override
            protected void paintTabBackground(Graphics g, int placement, int index, int x, int y, int w, int h, boolean selected) {
            }

            @Override
            protected void paintTabBorder(Graphics g, int placement, int index, int x, int y, int w, int h, boolean selected) {
                if (selected) {
                    g.setColor(AegisTokens.BLUE);
                    g.fillRect(x + 6, y + h - 2, w - 12, 2);
                }
            }

            @Override
            protected void paintFocusIndicator(Graphics g, int placement, java.awt.Rectangle[] rects, int index,
                    java.awt.Rectangle iconRect, java.awt.Rectangle textRect, boolean selected) {
            }

            @Override
            protected void paintContentBorder(Graphics g, int placement, int selectedIndex) {
                int y = calculateTabAreaHeight(placement, runCount, maxTabHeight);
                g.setColor(AegisTokens.BORDER);
                g.fillRect(0, y, tabPane.getWidth(), 1);
            }

            @Override
            protected void paintText(Graphics g, int placement, java.awt.Font font, java.awt.FontMetrics metrics, int index,
                    String title, java.awt.Rectangle textRect, boolean selected) {
                Graphics2D g2 = (Graphics2D) g;
                g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_LCD_HRGB);
                g2.setFont(selected ? AegisTokens.TITLE : font);
                g2.setColor(selected ? AegisTokens.BLUE : AegisTokens.TEXT_SECONDARY);
                g2.drawString(title, textRect.x, textRect.y + metrics.getAscent());
            }
        });
    }

    // ------------------------------------------------------------------ tables

    /** Applies the reference table style: light header, 34px rows, hairline grid, blue selection. */
    public static void styleTable(JTable table) {
        table.setRowHeight(34);
        table.setFont(AegisTokens.BODY_SMALL);
        table.setForeground(AegisTokens.TEXT);
        table.setShowVerticalLines(false);
        table.setShowHorizontalLines(true);
        table.setGridColor(GRID);
        table.setIntercellSpacing(new Dimension(0, 1));
        table.setSelectionBackground(AegisTokens.SELECTION);
        table.setSelectionForeground(AegisTokens.NAVY);
        table.setFillsViewportHeight(true);
        table.setBackground(AegisTokens.SURFACE);
        JTableHeader header = table.getTableHeader();
        header.setReorderingAllowed(false);
        header.setPreferredSize(new Dimension(header.getPreferredSize().width, 34));
        DefaultTableCellRenderer hr = new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable t, Object v, boolean s, boolean f, int r, int c) {
                JLabel l = (JLabel) super.getTableCellRendererComponent(t, v, false, false, r, c);
                l.setFont(new Font("Segoe UI Semibold", Font.PLAIN, 12));
                l.setForeground(AegisTokens.NAVY);
                l.setBackground(TABLE_HEADER);
                l.setOpaque(true);
                l.setBorder(BorderFactory.createCompoundBorder(
                        BorderFactory.createMatteBorder(0, 0, 1, 0, AegisTokens.BORDER),
                        new EmptyBorder(0, 10, 0, 10)));
                return l;
            }
        };
        header.setDefaultRenderer(hr);
        DefaultTableCellRenderer cell = new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable t, Object v, boolean s, boolean f, int r, int c) {
                JLabel l = (JLabel) super.getTableCellRendererComponent(t, v, s, false, r, c);
                l.setBorder(new EmptyBorder(0, 10, 0, 10));
                l.setFont(AegisTokens.BODY_SMALL);
                if (!s) {
                    l.setBackground(AegisTokens.SURFACE);
                    l.setForeground(AegisTokens.TEXT);
                }
                if (v != null && DetailList.NOT_AVAILABLE.equals(v.toString()) && !s) {
                    l.setForeground(AegisTokens.TEXT_MUTED);
                }
                l.setToolTipText(v == null ? null : v.toString());
                return l;
            }
        };
        table.setDefaultRenderer(Object.class, cell);
    }

    /** Renders a column as status pills. */
    public static TableCellRenderer badgeRenderer() {
        return (table, value, isSelected, hasFocus, row, column) -> {
            JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 6));
            p.setBackground(isSelected ? AegisTokens.SELECTION : AegisTokens.SURFACE);
            String text = value == null ? "" : value.toString();
            if (!text.isEmpty()) {
                p.add(new Badge(humanize(text), Tone.of(text)));
            }
            return p;
        };
    }

    public static JScrollPane tableScroll(JTable table) {
        JScrollPane sp = new JScrollPane(table);
        sp.setBorder(BorderFactory.createLineBorder(AegisTokens.BORDER));
        sp.getViewport().setBackground(AegisTokens.SURFACE);
        return sp;
    }

    // ------------------------------------------------------------------ formatting

    public static String bytes(long n) {
        if (n < 0) {
            return DetailList.NOT_AVAILABLE;
        }
        if (n < 1024) {
            return n + " B";
        }
        String[] units = {"KB", "MB", "GB", "TB"};
        double v = n;
        int u = -1;
        while (v >= 1000 && u < units.length - 1) {
            v /= 1000;
            u++;
        }
        return String.format(Locale.ROOT, v >= 100 ? "%.0f %s" : "%.1f %s", v, units[u]);
    }

    public static String bytesExact(long n) {
        return n < 0 ? DetailList.NOT_AVAILABLE : bytes(n) + " (" + String.format(Locale.ROOT, "%,d", n) + " bytes)";
    }

    public static String duration(long seconds) {
        if (seconds < 0) {
            return DetailList.NOT_AVAILABLE;
        }
        return String.format(Locale.ROOT, "%02d:%02d:%02d", seconds / 3600, (seconds % 3600) / 60, seconds % 60);
    }

    public static String rate(long bytesPerSecond) {
        return bytesPerSecond <= 0 ? DetailList.NOT_AVAILABLE : bytes(bytesPerSecond) + "/s";
    }

    /** "SUCCESS_WITH_WARNINGS" -> "Success with warnings"; acronyms kept. */
    public static String humanize(String s) {
        if (s == null || s.isBlank()) {
            return "";
        }
        String t = s.replace('_', ' ').trim();
        if (t.length() <= 4 && t.equals(t.toUpperCase(Locale.ROOT))) {
            return t;
        }
        t = t.toLowerCase(Locale.ROOT);
        return Character.toUpperCase(t.charAt(0)) + t.substring(1);
    }

    public static String escape(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    public static String shortHash(String h) {
        if (h == null || h.isBlank()) {
            return DetailList.NOT_AVAILABLE;
        }
        return h.length() > 20 ? h.substring(0, 16) + "…" + h.substring(h.length() - 4) : h;
    }
}
