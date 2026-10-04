package org.sleuthkit.autopsy.aegis.ui.kit;

import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import javax.swing.JComponent;
import org.sleuthkit.autopsy.aegis.ui.AegisTokens;

/**
 * Numbered horizontal workflow stepper (Disk Imager 9 steps, Recovery 6,
 * Sanitization 6). Completed steps are blue, the active step is blue and bold,
 * a failed step is red, and later steps are grey. Steps are display-only: the
 * state comes from the workflow, never from the stepper.
 */
public final class Stepper extends JComponent {

    private final String[] titles;
    private final String[] captions;
    private int current;
    private int completedThrough = -1;
    private int failed = -1;

    public Stepper(String[] titles, String[] captions) {
        this.titles = titles.clone();
        this.captions = captions.clone();
        setOpaque(false);
        setPreferredSize(new Dimension(900, 62));
        setMinimumSize(new Dimension(400, 58));
    }

    public void setState(int current, int completedThrough) {
        this.current = Math.max(0, Math.min(titles.length - 1, current));
        this.completedThrough = completedThrough;
        this.failed = -1;
        repaint();
    }

    public void setFailed(int step) {
        this.failed = step;
        repaint();
    }

    public int current() {
        return current;
    }

    @Override
    public Dimension getMaximumSize() {
        return new Dimension(Integer.MAX_VALUE, 66);
    }

    @Override
    protected void paintComponent(Graphics g) {
        Graphics2D g2 = (Graphics2D) g.create();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_LCD_HRGB);
        int n = titles.length;
        float slot = getWidth() / (float) n;
        int cy = 13;
        int r = 11;
        g2.setStroke(new BasicStroke(1.4f));
        for (int i = 0; i < n - 1; i++) {
            int x1 = Math.round(slot * i + slot / 2f + r + 4);
            int x2 = Math.round(slot * (i + 1) + slot / 2f - r - 4);
            g2.setColor(i < current || i <= completedThrough - 1 ? AegisTokens.BLUE : AegisTokens.BORDER);
            g2.drawLine(x1, cy, x2, cy);
        }
        for (int i = 0; i < n; i++) {
            int cx = Math.round(slot * i + slot / 2f);
            boolean active = i == current;
            boolean done = i <= completedThrough && !active;
            boolean bad = i == failed;
            Color fill = bad ? Tone.ERROR.fg : (active || done) ? AegisTokens.BLUE : new Color(0xE8EDF3);
            g2.setColor(fill);
            g2.fillOval(cx - r, cy - r, r * 2, r * 2);
            if (active && !bad) {
                g2.setColor(new Color(45, 108, 223, 50));
                g2.setStroke(new BasicStroke(3f));
                g2.drawOval(cx - r - 3, cy - r - 3, r * 2 + 6, r * 2 + 6);
                g2.setStroke(new BasicStroke(1.4f));
            }
            g2.setColor(active || done || bad ? Color.WHITE : AegisTokens.TEXT_SECONDARY);
            g2.setFont(new Font("Segoe UI Semibold", Font.PLAIN, 11));
            FontMetrics fm = g2.getFontMetrics();
            if (done && !bad) {
                g2.setStroke(new BasicStroke(2f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
                g2.drawPolyline(new int[]{cx - 5, cx - 1, cx + 5}, new int[]{cy, cy + 4, cy - 4}, 3);
                g2.setStroke(new BasicStroke(1.4f));
            } else {
                String num = Integer.toString(i + 1);
                g2.drawString(num, cx - fm.stringWidth(num) / 2, cy + fm.getAscent() / 2 - 1);
            }
            g2.setFont(active ? new Font("Segoe UI Semibold", Font.PLAIN, 12) : AegisTokens.BODY_SMALL);
            g2.setColor(bad ? Tone.ERROR.fg : active ? AegisTokens.BLUE : AegisTokens.TEXT);
            fm = g2.getFontMetrics();
            String t = fit(titles[i], fm, (int) slot - 4);
            g2.drawString(t, cx - fm.stringWidth(t) / 2, cy + r + 16);
            g2.setFont(AegisTokens.CAPTION);
            g2.setColor(active ? AegisTokens.BLUE : AegisTokens.TEXT_MUTED);
            fm = g2.getFontMetrics();
            String c = fit(captions[i], fm, (int) slot - 4);
            g2.drawString(c, cx - fm.stringWidth(c) / 2, cy + r + 31);
        }
        g2.dispose();
    }

    private static String fit(String s, FontMetrics fm, int width) {
        if (fm.stringWidth(s) <= width) {
            return s;
        }
        String out = s;
        while (out.length() > 1 && fm.stringWidth(out + "…") > width) {
            out = out.substring(0, out.length() - 1);
        }
        return out + "…";
    }
}
