package org.sleuthkit.autopsy.aegis.ui.kit;

import java.awt.Dimension;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import javax.swing.JComponent;
import org.sleuthkit.autopsy.aegis.ui.AegisTokens;

/** Rounded status pill: tinted background, coloured text. */
public final class Badge extends JComponent {

    private String text;
    private Tone tone;

    public Badge(String text, Tone tone) {
        this.text = text == null ? "" : text;
        this.tone = tone == null ? Tone.NEUTRAL : tone;
        setFont(AegisTokens.LABEL);
        setOpaque(false);
    }

    public static Badge of(String status) {
        return new Badge(Kit.humanize(status), Tone.of(status));
    }

    public void set(String text, Tone tone) {
        this.text = text == null ? "" : text;
        this.tone = tone == null ? Tone.NEUTRAL : tone;
        revalidate();
        repaint();
    }

    public void setStatus(String status) {
        set(Kit.humanize(status), Tone.of(status));
    }

    public String text() {
        return text;
    }

    @Override
    public Dimension getPreferredSize() {
        FontMetrics fm = getFontMetrics(getFont());
        return new Dimension(fm.stringWidth(text) + 20, fm.getHeight() + 6);
    }

    @Override
    public Dimension getMaximumSize() {
        return getPreferredSize();
    }

    @Override
    protected void paintComponent(Graphics g) {
        if (text.isEmpty()) {
            return;
        }
        Graphics2D g2 = (Graphics2D) g.create();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_LCD_HRGB);
        Dimension d = getPreferredSize();
        int h = Math.min(getHeight(), d.height);
        int y = (getHeight() - h) / 2;
        int w = Math.min(getWidth(), d.width);
        g2.setColor(tone.bg);
        g2.fillRoundRect(0, y, w, h, h, h);
        g2.setColor(tone.fg);
        g2.setFont(getFont());
        FontMetrics fm = g2.getFontMetrics();
        g2.drawString(text, (w - fm.stringWidth(text)) / 2, y + (h + fm.getAscent() - fm.getDescent()) / 2);
        g2.dispose();
    }
}
