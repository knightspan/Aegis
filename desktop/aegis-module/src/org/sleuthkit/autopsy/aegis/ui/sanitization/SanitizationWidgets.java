package org.sleuthkit.autopsy.aegis.ui.sanitization;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.GridLayout;
import java.awt.RenderingHints;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;
import org.sleuthkit.autopsy.aegis.sanitization.DeviceEligibilityService;
import org.sleuthkit.autopsy.aegis.sanitization.TargetType;
import org.sleuthkit.autopsy.aegis.ui.AegisIcons;
import org.sleuthkit.autopsy.aegis.ui.AegisTokens;

final class TargetTypeTile extends JPanel {

    interface Listener {
        void onSelect(TargetType type);

        void onInfo(TargetType type);
    }

    private final TargetType type;
    private boolean selected;
    private boolean enabledTile = true;

    TargetTypeTile(TargetType type, Listener listener) {
        this.type = type;
        setOpaque(false);
        setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        setPreferredSize(new Dimension(0, 76));
        setMinimumSize(new Dimension(100, 70));
        setBorder(new EmptyBorder(8, 10, 8, 10));
        setLayout(new BorderLayout(6, 4));

        JPanel top = new JPanel(new BorderLayout());
        top.setOpaque(false);
        JLabel icon = new JLabel(AegisIcons.get(iconName(type), AegisTokens.TEXT_SECONDARY, 22));
        top.add(icon, BorderLayout.WEST);
        if (type.requiresRemovableMedia()) {
            JLabel info = new JLabel(AegisIcons.get("info", AegisTokens.BLUE, 14));
            info.setToolTipText(DeviceEligibilityService.usbOnlyMessage());
            info.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
            info.addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent e) {
                    listener.onInfo(type);
                }
            });
            top.add(info, BorderLayout.EAST);
        }
        JLabel title = new JLabel(type.label());
        title.setFont(AegisTokens.TITLE);
        title.setForeground(AegisTokens.TEXT);
        JLabel hint = new JLabel(type.hint());
        hint.setFont(AegisTokens.CAPTION);
        hint.setForeground(AegisTokens.TEXT_SECONDARY);

        JPanel text = new JPanel();
        text.setOpaque(false);
        text.setLayout(new BoxLayout(text, BoxLayout.Y_AXIS));
        title.setAlignmentX(LEFT_ALIGNMENT);
        hint.setAlignmentX(LEFT_ALIGNMENT);
        text.setAlignmentX(LEFT_ALIGNMENT);
        text.add(title);
        text.add(Box.createVerticalStrut(2));
        text.add(hint);

        add(top, BorderLayout.NORTH);
        add(text, BorderLayout.CENTER);

        addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (enabledTile) {
                    listener.onSelect(type);
                }
            }
        });
    }

    void setSelected(boolean selected) {
        this.selected = selected;
        repaint();
    }

    void setTileEnabled(boolean enabled) {
        this.enabledTile = enabled;
        setEnabled(enabled);
        setCursor(enabled ? Cursor.getPredefinedCursor(Cursor.HAND_CURSOR)
                : Cursor.getDefaultCursor());
        repaint();
    }

    TargetType type() {
        return type;
    }

    @Override
    protected void paintComponent(Graphics g) {
        Graphics2D g2 = (Graphics2D) g.create();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        Color fill = AegisTokens.SURFACE;
        Color border = AegisTokens.BORDER;
        if (!enabledTile) {
            fill = new Color(0xF8FAFC);
            border = new Color(0xE5EAF0);
            g2.setComposite(java.awt.AlphaComposite.getInstance(java.awt.AlphaComposite.SRC_OVER, 0.7f));
        } else if (selected) {
            fill = AegisTokens.SELECTION;
            border = AegisTokens.BLUE;
        }
        g2.setColor(fill);
        g2.fillRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 10, 10);
        g2.setColor(border);
        g2.drawRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 10, 10);
        g2.dispose();
        super.paintComponent(g);
    }

    private static String iconName(TargetType type) {
        return switch (type) {
            case FILE -> "file";
            case FOLDER -> "folder";
            case VOLUME -> "device-usb";
            case PHYSICAL_DISK -> "disk";
        };
    }
}

class SanitizationCard extends JPanel {

    SanitizationCard() {
        super(new BorderLayout(8, 8));
        setOpaque(false);
        setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(AegisTokens.BORDER),
                new EmptyBorder(14, 14, 14, 14)));
        setBackground(AegisTokens.SURFACE);
    }

    @Override
    protected void paintComponent(Graphics g) {
        Graphics2D g2 = (Graphics2D) g.create();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g2.setColor(AegisTokens.SURFACE);
        g2.fillRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 10, 10);
        g2.setColor(AegisTokens.BORDER);
        g2.drawRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 10, 10);
        g2.dispose();
    }
}

final class UiButtons {
    private UiButtons() {
    }

    static javax.swing.JButton primary(String text) {
        javax.swing.JButton button = new javax.swing.JButton(text);
        button.setFont(AegisTokens.BUTTON);
        button.setFocusPainted(false);
        button.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        button.setBackground(AegisTokens.BLUE);
        button.setForeground(Color.WHITE);
        button.setOpaque(true);
        button.setBorderPainted(false);
        button.setBorder(new EmptyBorder(8, 18, 8, 18));
        return button;
    }

    static javax.swing.JButton outline(String text) {
        javax.swing.JButton button = new javax.swing.JButton(text);
        button.setFont(AegisTokens.BUTTON);
        button.setFocusPainted(false);
        button.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        button.setBackground(AegisTokens.SURFACE);
        button.setForeground(AegisTokens.NAVY);
        button.setOpaque(true);
        button.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(AegisTokens.BORDER),
                new EmptyBorder(7, 16, 7, 16)));
        return button;
    }

    static javax.swing.JButton danger(String text) {
        javax.swing.JButton button = primary(text);
        button.setBackground(AegisTokens.ERROR);
        return button;
    }
}

final class CardHeader extends JPanel {
    CardHeader(String icon, String title, String subtitle) {
        super(new BorderLayout(10, 2));
        setOpaque(false);
        setAlignmentX(LEFT_ALIGNMENT);
        setMaximumSize(new Dimension(Integer.MAX_VALUE, 64));
        JLabel mark = new JLabel(AegisIcons.get(icon, AegisTokens.BLUE, 18));
        JPanel text = new JPanel();
        text.setOpaque(false);
        text.setLayout(new BoxLayout(text, BoxLayout.Y_AXIS));
        JLabel heading = new JLabel(title);
        heading.setFont(AegisTokens.H3);
        heading.setForeground(AegisTokens.NAVY);
        heading.setAlignmentX(LEFT_ALIGNMENT);
        JLabel sub = new JLabel(subtitle);
        sub.setFont(AegisTokens.BODY_SMALL);
        sub.setForeground(AegisTokens.TEXT_SECONDARY);
        sub.setAlignmentX(LEFT_ALIGNMENT);
        text.add(heading);
        text.add(Box.createVerticalStrut(2));
        text.add(sub);
        add(mark, BorderLayout.WEST);
        add(text, BorderLayout.CENTER);
        this.sub = sub;
    }

    private final JLabel sub;

    void setSubtitle(String subtitle) {
        sub.setText(subtitle);
    }
}

final class TargetTypeGrid extends JPanel {
    private final TargetTypeTile[] tiles;

    TargetTypeGrid(TargetTypeTile.Listener listener) {
        super(new GridLayout(1, 4, 10, 0));
        setOpaque(false);
        setAlignmentX(LEFT_ALIGNMENT);
        // Grow to card width (BoxLayout); keep a modest preferred width for measuring.
        setPreferredSize(new Dimension(480, 82));
        setMaximumSize(new Dimension(Integer.MAX_VALUE, 86));
        setMinimumSize(new Dimension(320, 76));
        TargetType[] types = TargetType.values();
        tiles = new TargetTypeTile[types.length];
        for (int i = 0; i < types.length; i++) {
            tiles[i] = new TargetTypeTile(types[i], listener);
            add(tiles[i]);
        }
    }

    void sync(TargetType selected, boolean volumeDiskEligible) {
        for (TargetTypeTile tile : tiles) {
            boolean removable = tile.type().requiresRemovableMedia();
            tile.setTileEnabled(!removable || volumeDiskEligible);
            tile.setSelected(tile.type() == selected);
        }
    }
}
