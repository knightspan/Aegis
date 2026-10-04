package org.sleuthkit.autopsy.aegis.ui;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.GridLayout;
import java.awt.RenderingHints;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.Icon;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.border.EmptyBorder;

final class AegisButton extends JButton {

    enum Kind {
        PRIMARY, SECONDARY, OUTLINE, GHOST, DANGER
    }

    AegisButton(String text, Kind kind) {
        super(text);
        setDefaultCapable(kind == Kind.PRIMARY);
        setFont(AegisTokens.BUTTON);
        setFocusPainted(false);
        setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        setBorder(new EmptyBorder(8, 16, 8, 16));
        switch (kind) {
            case PRIMARY -> {
                setBackground(AegisTokens.BLUE);
                setForeground(Color.WHITE);
                setOpaque(true);
                setBorderPainted(false);
            }
            case DANGER -> {
                setBackground(AegisTokens.ERROR);
                setForeground(Color.WHITE);
                setOpaque(true);
                setBorderPainted(false);
            }
            case SECONDARY -> {
                setBackground(AegisTokens.SURFACE_ALT);
                setForeground(AegisTokens.NAVY);
                setOpaque(true);
                setBorderPainted(false);
            }
            case OUTLINE -> {
                setBackground(AegisTokens.SURFACE);
                setForeground(AegisTokens.NAVY);
                setOpaque(true);
                setBorder(BorderFactory.createCompoundBorder(
                        BorderFactory.createLineBorder(AegisTokens.BORDER),
                        new EmptyBorder(7, 15, 7, 15)));
            }
            case GHOST -> {
                setBackground(AegisTokens.NAVY);
                setForeground(Color.WHITE);
                setOpaque(false);
                setContentAreaFilled(false);
                setBorderPainted(false);
            }
        }
    }
}

class AegisCard extends JPanel {

    AegisCard() {
        this(new BorderLayout(8, 8));
    }

    AegisCard(java.awt.LayoutManager layout) {
        super(layout);
        setBackground(AegisTokens.SURFACE);
        setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(AegisTokens.BORDER),
                new EmptyBorder(16, 16, 16, 16)));
    }
}

/**
 * Search field: Tabler icon + native JLabel placeholder (crisp on Windows HiDPI).
 * The field background is not painted so the label stays sharp underneath.
 */
final class AegisSearchField extends JPanel {

    private final JTextField field = new JTextField();
    private final JLabel prompt;
    private final String placeholder;

    AegisSearchField(String placeholder) {
        this.placeholder = placeholder;
        setLayout(new BorderLayout(8, 0));
        setOpaque(true);
        setBackground(AegisTokens.SURFACE);
        setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(AegisTokens.BORDER),
                new EmptyBorder(0, 10, 0, 12)));

        JLabel icon = new JLabel(AegisIcons.get("search", AegisTokens.TEXT_MUTED, 16));
        prompt = new JLabel(placeholder);
        prompt.setFont(AegisTokens.BODY);
        prompt.setForeground(AegisTokens.TEXT_MUTED);

        // Size to the full placeholder so it is never clipped to "Search cases...".
        java.awt.FontMetrics metrics = prompt.getFontMetrics(AegisTokens.BODY);
        int textWidth = metrics.stringWidth(placeholder) + 8;
        Dimension size = new Dimension(Math.max(420, textWidth + 48), 34);
        setPreferredSize(size);
        setMinimumSize(new Dimension(Math.max(320, textWidth + 48), 34));
        setMaximumSize(new Dimension(560, 34));

        field.setBorder(null);
        field.setOpaque(false);
        field.setFont(AegisTokens.BODY);
        field.setForeground(AegisTokens.TEXT);
        field.setCaretColor(AegisTokens.BLUE);
        field.setToolTipText(placeholder);
        field.setBackground(new Color(0, 0, 0, 0));
        // Avoid Windows L&F filling an opaque background over the crisp label.
        field.setUI(new javax.swing.plaf.basic.BasicTextFieldUI());

        field.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            @Override public void insertUpdate(javax.swing.event.DocumentEvent e) { syncPrompt(); }
            @Override public void removeUpdate(javax.swing.event.DocumentEvent e) { syncPrompt(); }
            @Override public void changedUpdate(javax.swing.event.DocumentEvent e) { syncPrompt(); }
        });

        JPanel stack = new JPanel(new GridBagLayout());
        stack.setOpaque(false);
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.weightx = 1;
        gbc.weighty = 1;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.anchor = GridBagConstraints.WEST;
        stack.add(prompt, gbc);
        stack.add(field, gbc);

        add(icon, BorderLayout.WEST);
        add(stack, BorderLayout.CENTER);
        syncPrompt();
    }

    private void syncPrompt() {
        prompt.setVisible(field.getText().isEmpty());
        repaint();
    }

    String getText() {
        return field.getText();
    }

    void setText(String text) {
        field.setText(text);
        syncPrompt();
    }

    void addActionListener(java.awt.event.ActionListener listener) {
        field.addActionListener(listener);
    }

    @Override
    public synchronized void addKeyListener(java.awt.event.KeyListener listener) {
        field.addKeyListener(listener);
    }

    @Override
    public synchronized void removeKeyListener(java.awt.event.KeyListener listener) {
        field.removeKeyListener(listener);
    }

    @Override
    public void requestFocus() {
        field.requestFocus();
    }

    @Override
    public boolean requestFocusInWindow() {
        return field.requestFocusInWindow();
    }
}

final class AegisEmptyState extends JPanel {

    AegisEmptyState(String icon, String title, String body) {
        super();
        setOpaque(false);
        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
        JLabel mark = new JLabel(AegisIcons.get(icon, AegisTokens.TEXT_MUTED));
        mark.setAlignmentX(LEFT_ALIGNMENT);
        JLabel heading = new JLabel(title);
        heading.setFont(AegisTokens.H2);
        heading.setForeground(AegisTokens.NAVY);
        heading.setAlignmentX(LEFT_ALIGNMENT);
        JLabel text = new JLabel("<html><body style='width:360px'>" + body + "</body></html>");
        text.setFont(AegisTokens.BODY);
        text.setForeground(AegisTokens.TEXT_SECONDARY);
        text.setAlignmentX(LEFT_ALIGNMENT);
        add(mark);
        add(Box.createVerticalStrut(12));
        add(heading);
        add(Box.createVerticalStrut(8));
        add(text);
    }
}

final class AegisStatusBadge extends JLabel {

    AegisStatusBadge(String text, Color color) {
        super("  " + text + "  ");
        setFont(AegisTokens.CAPTION);
        setForeground(color);
        setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(color),
                new EmptyBorder(2, 6, 2, 6)));
        setOpaque(false);
    }
}

final class AegisSectionHeader extends JPanel {

    AegisSectionHeader(String title) {
        super(new BorderLayout());
        setOpaque(false);
        JLabel label = new JLabel(title);
        label.setFont(AegisTokens.LABEL);
        label.setForeground(AegisTokens.TEXT_SECONDARY);
        add(label, BorderLayout.WEST);
    }
}

final class AegisSidebarItem extends JPanel {

    private boolean selected;
    private boolean hover;
    private final String page;
    private final String iconName;
    private final JLabel iconLabel;
    private final JLabel text;

    AegisSidebarItem(String page, String icon, String label) {
        this.page = page;
        setLayout(new BorderLayout(10, 0));
        setOpaque(false);
        setBackground(AegisTokens.SIDEBAR);
        setBorder(new EmptyBorder(6, 22, 6, 12));
        setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        setToolTipText(label);
        getAccessibleContext().setAccessibleName(label);
        getAccessibleContext().setAccessibleDescription(label);
        this.iconName = icon;
        iconLabel = new JLabel(AegisIcons.get(icon, AegisTokens.TEXT_SECONDARY));
        text = new JLabel(label);
        text.setFont(AegisTokens.BODY);
        text.setForeground(AegisTokens.TEXT);
        add(iconLabel, BorderLayout.WEST);
        add(text, BorderLayout.CENTER);
        addMouseListener(new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent e) {
                hover = true;
                repaint();
            }

            @Override
            public void mouseExited(MouseEvent e) {
                hover = false;
                repaint();
            }
        });
    }

    @Override
    protected void paintComponent(Graphics g) {
        Graphics2D g2 = (Graphics2D) g.create();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        if (selected || hover) {
            g2.setColor(selected ? AegisTokens.SELECTION : AegisTokens.SIDEBAR_HOVER);
            g2.fillRoundRect(10, 1, getWidth() - 18, getHeight() - 2, 10, 10);
            if (selected) {
                g2.setColor(AegisTokens.BLUE);
                g2.fillRoundRect(4, 4, 3, getHeight() - 8, 2, 2);
            }
        }
        g2.dispose();
        super.paintComponent(g);
    }

    String page() {
        return page;
    }

    void setSelected(boolean value) {
        selected = value;
        text.setForeground(value ? AegisTokens.BLUE : AegisTokens.TEXT);
        text.setFont(value ? AegisTokens.TITLE : AegisTokens.BODY);
        iconLabel.setIcon(AegisIcons.get(iconName, value ? AegisTokens.BLUE : AegisTokens.TEXT_SECONDARY));
        repaint();
    }
}

final class AegisMarkPanel extends JPanel {

    AegisMarkPanel() {
        setOpaque(false);
        setLayout(new BorderLayout());
        add(new JLabel(AegisIcons.logo(28)), BorderLayout.CENTER);
    }
}

final class AegisActionRow extends JPanel {

    AegisActionRow() {
        super(new FlowLayout(FlowLayout.LEFT, 8, 0));
        setOpaque(false);
    }
}

final class AegisStatCard extends AegisCard {

    AegisStatCard(String value, String label) {
        super(new GridLayout(2, 1, 0, 4));
        JLabel number = new JLabel(value);
        number.setFont(new Font("Segoe UI", Font.BOLD, 22));
        number.setForeground(AegisTokens.NAVY);
        JLabel caption = new JLabel(label);
        caption.setFont(AegisTokens.CAPTION);
        caption.setForeground(AegisTokens.TEXT_SECONDARY);
        add(number);
        add(caption);
    }

    void setValue(String value) {
        ((JLabel) getComponent(0)).setText(value);
    }
}
