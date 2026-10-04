package org.sleuthkit.autopsy.aegis.ui.kit;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;
import org.sleuthkit.autopsy.aegis.ui.AegisIcons;
import org.sleuthkit.autopsy.aegis.ui.AegisTokens;

/**
 * White rounded card with an icon, a title, a subtitle and an optional
 * right-hand header action, matching the AEGIS reference cards.
 */
public class KitCard extends JPanel {

    private final JPanel body = new JPanel(new BorderLayout());
    private final JPanel headerRight = new JPanel(new java.awt.FlowLayout(java.awt.FlowLayout.RIGHT, 6, 0));
    private final JLabel titleLabel = new JLabel();
    private final JLabel subtitleLabel = new JLabel();

    public KitCard(String icon, String title, String subtitle) {
        super(new BorderLayout(0, 12));
        setOpaque(false);
        setBorder(new EmptyBorder(16, 18, 16, 18));
        JPanel header = new JPanel(new BorderLayout(12, 0));
        header.setOpaque(false);
        if (icon != null) {
            JLabel mark = new JLabel(AegisIcons.get(icon, AegisTokens.BLUE, 22));
            mark.setVerticalAlignment(JLabel.TOP);
            header.add(mark, BorderLayout.WEST);
        }
        JPanel text = new JPanel();
        text.setOpaque(false);
        text.setLayout(new BoxLayout(text, BoxLayout.Y_AXIS));
        titleLabel.setText(title);
        titleLabel.setFont(Kit.CARD_TITLE);
        titleLabel.setForeground(AegisTokens.NAVY);
        text.add(titleLabel);
        if (subtitle != null && !subtitle.isBlank()) {
            subtitleLabel.setText(subtitle);
            subtitleLabel.setFont(AegisTokens.BODY_SMALL);
            subtitleLabel.setForeground(AegisTokens.TEXT_SECONDARY);
            text.add(Box.createVerticalStrut(3));
            text.add(subtitleLabel);
        }
        header.add(text, BorderLayout.CENTER);
        headerRight.setOpaque(false);
        header.add(headerRight, BorderLayout.EAST);
        if (title != null) {
            add(header, BorderLayout.NORTH);
        }
        body.setOpaque(false);
        add(body, BorderLayout.CENTER);
    }

    public JPanel body() {
        return body;
    }

    public KitCard content(Component c) {
        body.removeAll();
        body.add(c, BorderLayout.CENTER);
        body.revalidate();
        return this;
    }

    public KitCard action(JComponent c) {
        headerRight.add(c);
        return this;
    }

    public void setTitle(String title) {
        titleLabel.setText(title);
    }

    public void setSubtitle(String subtitle) {
        subtitleLabel.setText(subtitle);
    }

    @Override
    public Dimension getMaximumSize() {
        return new Dimension(Integer.MAX_VALUE, getPreferredSize().height);
    }

    @Override
    protected void paintComponent(Graphics g) {
        Graphics2D g2 = (Graphics2D) g.create();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g2.setColor(new java.awt.Color(15, 39, 71, 10));
        g2.fillRoundRect(1, 2, getWidth() - 2, getHeight() - 2, 12, 12);
        g2.setColor(AegisTokens.SURFACE);
        g2.fillRoundRect(0, 0, getWidth() - 1, getHeight() - 2, 12, 12);
        g2.setColor(AegisTokens.BORDER);
        g2.drawRoundRect(0, 0, getWidth() - 1, getHeight() - 2, 12, 12);
        g2.dispose();
        super.paintComponent(g);
    }
}
