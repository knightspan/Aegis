package org.sleuthkit.autopsy.aegis.ui.sanitization;

import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import javax.swing.JComponent;
import org.sleuthkit.autopsy.aegis.sanitization.SanitizationUIState;
import org.sleuthkit.autopsy.aegis.ui.AegisTokens;

/**
 * Compact six-step workflow indicator for AEGIS Sanitization.
 */
public final class SanitizationStepper extends JComponent {

    private SanitizationUIState.Step current = SanitizationUIState.Step.TARGET;
    private int highestCompleted = -1;

    public SanitizationStepper() {
        setOpaque(false);
        setPreferredSize(new Dimension(100, 64));
        setMinimumSize(new Dimension(480, 56));
        setMaximumSize(new Dimension(Integer.MAX_VALUE, 72));
    }

    public void setProgress(SanitizationUIState.Step current, int highestCompleted) {
        this.current = current == null ? SanitizationUIState.Step.TARGET : current;
        this.highestCompleted = highestCompleted;
        repaint();
    }

    @Override
    protected void paintComponent(Graphics g) {
        Graphics2D g2 = (Graphics2D) g.create();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
        SanitizationUIState.Step[] steps = SanitizationUIState.Step.values();
        int n = steps.length;
        int pad = 4;
        int usable = Math.max(1, getWidth() - pad * 2);
        float slot = usable / (float) n;
        int cy = 14;
        int radius = 10;

        for (int i = 0; i < n - 1; i++) {
            float x1 = pad + slot * i + slot / 2f + radius + 2;
            float x2 = pad + slot * (i + 1) + slot / 2f - radius - 2;
            boolean done = i < current.index() || i < highestCompleted;
            g2.setColor(done ? AegisTokens.BLUE : AegisTokens.BORDER);
            g2.setStroke(new BasicStroke(1.5f));
            g2.drawLine(Math.round(x1), cy, Math.round(x2), cy);
        }

        for (int i = 0; i < n; i++) {
            SanitizationUIState.Step step = steps[i];
            int cx = Math.round(pad + slot * i + slot / 2f);
            boolean active = step == current;
            boolean complete = step.index() < current.index() || step.index() <= highestCompleted;
            if (active || complete) {
                g2.setColor(AegisTokens.BLUE);
                g2.fillOval(cx - radius, cy - radius, radius * 2, radius * 2);
                g2.setColor(Color.WHITE);
            } else {
                g2.setColor(new Color(0xE8EDF3));
                g2.fillOval(cx - radius, cy - radius, radius * 2, radius * 2);
                g2.setColor(AegisTokens.TEXT_SECONDARY);
            }
            g2.setFont(new Font("Segoe UI Semibold", Font.PLAIN, 11));
            String num = Integer.toString(i + 1);
            FontMetrics fm = g2.getFontMetrics();
            g2.drawString(num, cx - fm.stringWidth(num) / 2, cy + fm.getAscent() / 2 - 1);

            g2.setFont(active ? AegisTokens.TITLE : AegisTokens.CAPTION);
            g2.setColor(active ? AegisTokens.BLUE : AegisTokens.TEXT_SECONDARY);
            String title = step.title();
            g2.drawString(title, cx - g2.getFontMetrics().stringWidth(title) / 2, cy + radius + 13);

            g2.setFont(AegisTokens.CAPTION);
            g2.setColor(active ? AegisTokens.BLUE : AegisTokens.TEXT_MUTED);
            String caption = step.caption();
            g2.drawString(caption, cx - g2.getFontMetrics().stringWidth(caption) / 2, cy + radius + 26);
        }
        g2.dispose();
    }
}
