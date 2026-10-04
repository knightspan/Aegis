package org.sleuthkit.autopsy.core;

import java.awt.Color;
import java.awt.Font;
import java.awt.GraphicsEnvironment;
import java.awt.Image;
import java.awt.Window;
import java.util.ArrayList;
import java.util.List;
import javax.swing.UIManager;
import javax.swing.plaf.FontUIResource;
import org.openide.windows.WindowManager;

/**
 * Applies the AEGIS palette and window icon to the existing Swing shell.
 */
public final class AegisTheme {

    private static final Color NAVY = new Color(0x0F2747);
    private static final Color BLUE = new Color(0x2D6CDF);
    private static final Color BACKGROUND = new Color(0xF8FAFC);
    private static final Color SURFACE = Color.WHITE;
    private static final Color TEXT = new Color(0x1F2937);
    private static final Color MUTED = new Color(0x64748B);
    private static final Color SELECTION = new Color(0xE7F0FF);

    private AegisTheme() {
    }

    public static void install() {
        if (GraphicsEnvironment.isHeadless()) {
            return;
        }
        applyColors();
        applyFonts();
        try {
            WindowManager.getDefault().invokeWhenUIReady(AegisTheme::applyWindowIcon);
        } catch (IllegalStateException ex) {
            applyWindowIcon();
        }
    }

    private static void applyColors() {
        UIManager.put("control", SURFACE);
        UIManager.put("Panel.background", BACKGROUND);
        UIManager.put("Viewport.background", SURFACE);
        UIManager.put("OptionPane.background", SURFACE);
        UIManager.put("OptionPane.messageForeground", TEXT);
        UIManager.put("Label.foreground", TEXT);
        UIManager.put("Button.background", SURFACE);
        UIManager.put("Button.foreground", NAVY);
        UIManager.put("Button.focus", BLUE);
        UIManager.put("ToggleButton.background", SURFACE);
        UIManager.put("TextField.background", SURFACE);
        UIManager.put("TextField.foreground", TEXT);
        UIManager.put("TextField.caretForeground", NAVY);
        UIManager.put("TextArea.background", SURFACE);
        UIManager.put("TextArea.foreground", TEXT);
        UIManager.put("ComboBox.background", SURFACE);
        UIManager.put("Table.background", SURFACE);
        UIManager.put("Table.foreground", TEXT);
        UIManager.put("Table.selectionBackground", SELECTION);
        UIManager.put("Table.selectionForeground", NAVY);
        UIManager.put("Table.gridColor", new Color(0xE5EAF0));
        UIManager.put("TableHeader.background", BACKGROUND);
        UIManager.put("TableHeader.foreground", MUTED);
        UIManager.put("Tree.background", SURFACE);
        UIManager.put("Tree.foreground", TEXT);
        UIManager.put("Tree.selectionBackground", SELECTION);
        UIManager.put("Tree.selectionForeground", NAVY);
        UIManager.put("List.background", SURFACE);
        UIManager.put("List.selectionBackground", SELECTION);
        UIManager.put("List.selectionForeground", NAVY);
        UIManager.put("ProgressBar.foreground", BLUE);
        UIManager.put("ProgressBar.background", new Color(0xE5EAF0));
        UIManager.put("TabbedPane.foreground", TEXT);
        UIManager.put("TabbedPane.selected", SURFACE);
        UIManager.put("TabbedPane.focus", BLUE);
        UIManager.put("Menu.foreground", TEXT);
        UIManager.put("MenuItem.foreground", TEXT);
        UIManager.put("MenuBar.background", SURFACE);
        UIManager.put("ToolTip.background", SURFACE);
        UIManager.put("ToolTip.foreground", TEXT);
        UIManager.put("TitledBorder.titleColor", NAVY);
    }

    private static void applyFonts() {
        Font ui = new Font("Segoe UI", Font.PLAIN, 13);
        String[] keys = {
            "Label.font", "Button.font", "ToggleButton.font", "CheckBox.font", "RadioButton.font",
            "Menu.font", "MenuItem.font", "MenuBar.font", "Table.font", "TableHeader.font",
            "Tree.font", "List.font", "TextField.font", "TextArea.font", "ComboBox.font",
            "TabbedPane.font", "TitledBorder.font", "OptionPane.messageFont", "ToolTip.font"
        };
        FontUIResource resource = new FontUIResource(ui);
        for (String key : keys) {
            UIManager.put(key, resource);
        }
    }

    private static void applyWindowIcon() {
        List<Image> icons = new ArrayList<>();
        for (String name : new String[]{"aegis-16.png", "aegis-32.png", "aegis-48.png", "aegis-256.png"}) {
            try (java.io.InputStream in = AegisTheme.class.getResourceAsStream("/org/sleuthkit/autopsy/images/" + name)) {
                if (in != null) {
                    icons.add(javax.imageio.ImageIO.read(in));
                }
            } catch (java.io.IOException ex) {
                // Keep the branding icon if a size cannot be read.
            }
        }
        if (icons.isEmpty()) {
            return;
        }
        Window window = WindowManager.getDefault().getMainWindow();
        if (window != null) {
            window.setIconImages(icons);
        }
    }
}
