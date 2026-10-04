package org.sleuthkit.autopsy.aegis.ui;

import java.awt.BorderLayout;
import java.awt.Dimension;
import javax.swing.border.EmptyBorder;
import org.sleuthkit.autopsy.aegis.ui.sanitization.SanitizationView;

/**
 * Host page for {@link SanitizationView}. Fills the workspace card; does not
 * inflate preferred height to the scrollable sanitization content.
 */
final class AegisSanitizationWorkspace extends AegisPage {

    private final SanitizationView view = new SanitizationView();
    private final java.awt.CardLayout cards = new java.awt.CardLayout();
    private final javax.swing.JPanel stack = new javax.swing.JPanel(cards);
    private final org.sleuthkit.autopsy.aegis.ui.sanitization.DeviceSanitizationView device;

    AegisSanitizationWorkspace() {
        setBorder(new EmptyBorder(0, 0, 0, 0));
        setLayout(new BorderLayout());
        setBackground(AegisTokens.BACKGROUND);
        setOpaque(true);
        device = new org.sleuthkit.autopsy.aegis.ui.sanitization.DeviceSanitizationView(type -> {
            cards.show(stack, "files");
            view.selectTargetType(type);
        });
        view.setPhysicalDeviceHandler(this::showDevice);
        stack.setOpaque(false);
        stack.add(view, "files");
        stack.add(device, "device");
        add(stack, BorderLayout.CENTER);
    }

    void showDevice() {
        cards.show(stack, "device");
        device.refresh();
    }

    SanitizationView view() {
        return view;
    }

    @Override
    public Dimension getPreferredSize() {
        java.awt.Container parent = getParent();
        if (parent != null && parent.getWidth() > 0 && parent.getHeight() > 0) {
            return new Dimension(parent.getWidth(), parent.getHeight());
        }
        return new Dimension(960, 640);
    }

    @Override
    public Dimension getMinimumSize() {
        return new Dimension(720, 480);
    }

    @Override
    public Dimension getMaximumSize() {
        return new Dimension(Integer.MAX_VALUE, Integer.MAX_VALUE);
    }
}
