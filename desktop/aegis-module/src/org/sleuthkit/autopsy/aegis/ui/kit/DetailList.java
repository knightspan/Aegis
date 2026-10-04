package org.sleuthkit.autopsy.aegis.ui.kit;

import java.awt.Color;
import java.awt.Component;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import org.sleuthkit.autopsy.aegis.ui.AegisTokens;

/**
 * Two-column key/value list: grey keys on the left, navy values right-aligned,
 * as in the reference "Device Information" panels. A value that was not
 * reported is shown as "Not available", never as an invented default.
 */
public final class DetailList extends JPanel {

    public static final String NOT_AVAILABLE = "Not available";

    private final Map<String, Object> rows = new LinkedHashMap<>();
    private boolean rightAlign = true;

    public DetailList() {
        super(new GridBagLayout());
        setOpaque(false);
    }

    public DetailList leftAligned() {
        rightAlign = false;
        return this;
    }

    public DetailList clear() {
        rows.clear();
        rebuild();
        return this;
    }

    public DetailList put(String key, String value) {
        rows.put(key, value == null || value.isBlank() ? NOT_AVAILABLE : value);
        return this;
    }

    public DetailList put(String key, JComponent value) {
        rows.put(key, value);
        return this;
    }

    public DetailList done() {
        rebuild();
        return this;
    }

    private void rebuild() {
        removeAll();
        GridBagConstraints c = new GridBagConstraints();
        c.gridy = 0;
        c.insets = new Insets(3, 0, 3, 0);
        for (Map.Entry<String, Object> e : rows.entrySet()) {
            c.gridx = 0;
            c.weightx = 0;
            c.anchor = GridBagConstraints.NORTHWEST;
            c.fill = GridBagConstraints.NONE;
            JLabel key = new JLabel(e.getKey());
            key.setFont(AegisTokens.BODY_SMALL);
            key.setForeground(AegisTokens.TEXT_SECONDARY);
            add(key, c);
            c.gridx = 1;
            c.weightx = 1;
            c.fill = GridBagConstraints.HORIZONTAL;
            c.anchor = rightAlign ? GridBagConstraints.NORTHEAST : GridBagConstraints.NORTHWEST;
            c.insets = new Insets(3, 14, 3, 0);
            Component value;
            if (e.getValue() instanceof JComponent comp) {
                JPanel holder = new JPanel(new java.awt.FlowLayout(rightAlign ? java.awt.FlowLayout.RIGHT
                        : java.awt.FlowLayout.LEFT, 0, 0));
                holder.setOpaque(false);
                holder.add(comp);
                value = holder;
            } else {
                String text = String.valueOf(e.getValue());
                JLabel v = new JLabel("<html><div style='text-align:" + (rightAlign ? "right" : "left") + "'>"
                        + Kit.escape(text) + "</div></html>");
                v.setHorizontalAlignment(rightAlign ? JLabel.RIGHT : JLabel.LEFT);
                v.setFont(AegisTokens.BODY_SMALL);
                v.setForeground(NOT_AVAILABLE.equals(text) ? AegisTokens.TEXT_MUTED : AegisTokens.NAVY);
                v.setToolTipText(text);
                value = v;
            }
            add(value, c);
            c.insets = new Insets(3, 0, 3, 0);
            c.gridy++;
        }
        revalidate();
        repaint();
    }

    public static JLabel mono(String text) {
        String shown = text == null || text.isBlank() ? NOT_AVAILABLE : text;
        if (shown.length() > 40 && !shown.contains(" ")) {
            // Long digests and keys wrap at 32 characters instead of being clipped.
            StringBuilder sb = new StringBuilder("<html>");
            for (int i = 0; i < shown.length(); i += 32) {
                sb.append(Kit.escape(shown.substring(i, Math.min(shown.length(), i + 32))));
                if (i + 32 < shown.length()) {
                    sb.append("<br>");
                }
            }
            shown = sb.append("</html>").toString();
        }
        JLabel l = new JLabel(shown);
        l.setFont(AegisTokens.MONO);
        l.setForeground(text == null || text.isBlank() ? AegisTokens.TEXT_MUTED : new Color(0x0F2747));
        l.setToolTipText(text);
        return l;
    }
}
