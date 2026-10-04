package org.sleuthkit.autopsy.aegis.ui.kit;

import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.geom.Arc2D;
import javax.swing.JComponent;
import org.sleuthkit.autopsy.aegis.ui.AegisTokens;

/**
 * Donut progress indicator. It only ever shows a value the engine reported:
 * {@link #setUnknown()} draws an empty ring with "—" rather than inventing one.
 */
public final class ProgressRing extends JComponent {

    private double pct = -1;
    private Color color = AegisTokens.BLUE;
    private String caption = "";

    public ProgressRing(int size) {
        setPreferredSize(new Dimension(size, size));
        setMinimumSize(new Dimension(size, size));
        setOpaque(false);
    }

    public void setValue(double pct) {
        this.pct = Math.max(0, Math.min(100, pct));
        repaint();
    }

    public void setUnknown() {
        this.pct = -1;
        repaint();
    }

    public void setColor(Color c) {
        this.color = c;
        repaint();
    }

    public void setCaption(String caption) {
        this.caption = caption == null ? "" : caption;
        repaint();
    }

    @Override
    protected void paintComponent(Graphics g) {
        Graphics2D g2 = (Graphics2D) g.create();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_LCD_HRGB);
        int size = Math.min(getWidth(), getHeight());
        float stroke = Math.max(8f, size / 9f);
        int pad = (int) Math.ceil(stroke / 2) + 2;
        int d = size - pad * 2;
        int x = (getWidth() - size) / 2 + pad;
        int y = (getHeight() - size) / 2 + pad;
        g2.setStroke(new BasicStroke(stroke, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
        g2.setColor(new Color(0xE8EDF3));
        g2.drawOval(x, y, d, d);
        if (pct > 0) {
            g2.setColor(color);
            g2.draw(new Arc2D.Double(x, y, d, d, 90, -360 * pct / 100.0, Arc2D.OPEN));
        }
        String text = pct < 0 ? "—" : (pct >= 99.95 ? "100%" : String.format("%.0f%%", Math.floor(pct)));
        g2.setFont(new Font("Segoe UI", Font.BOLD, Math.max(16, size / 5)));
        g2.setColor(AegisTokens.NAVY);
        FontMetrics fm = g2.getFontMetrics();
        int ty = getHeight() / 2 + fm.getAscent() / 2 - (caption.isEmpty() ? 2 : 8);
        g2.drawString(text, (getWidth() - fm.stringWidth(text)) / 2, ty);
        if (!caption.isEmpty()) {
            g2.setFont(AegisTokens.CAPTION);
            g2.setColor(AegisTokens.TEXT_SECONDARY);
            FontMetrics cm = g2.getFontMetrics();
            g2.drawString(caption, (getWidth() - cm.stringWidth(caption)) / 2, ty + cm.getHeight());
        }
        g2.dispose();
    }
}
