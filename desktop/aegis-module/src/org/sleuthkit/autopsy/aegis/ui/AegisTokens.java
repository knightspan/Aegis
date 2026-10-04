package org.sleuthkit.autopsy.aegis.ui;

import java.awt.Color;
import java.awt.Font;

/**
 * AEGIS design tokens. Used by every AEGIS-owned Swing surface.
 */
public final class AegisTokens {

    public static final Color NAVY = new Color(0x0F2747);
    public static final Color BLUE = new Color(0x2D6CDF);
    public static final Color ACCENT = new Color(0x5A9BF5);
    public static final Color BACKGROUND = new Color(0xF8FAFC);
    public static final Color SURFACE = Color.WHITE;
    public static final Color SURFACE_ALT = new Color(0xF1F5F9);
    public static final Color BORDER = new Color(0xE5EAF0);
    public static final Color TEXT = new Color(0x1F2937);
    public static final Color TEXT_SECONDARY = new Color(0x64748B);
    public static final Color TEXT_MUTED = new Color(0x94A3B8);
    public static final Color SUCCESS = new Color(0x10B981);
    public static final Color WARNING = new Color(0xF59E0B);
    public static final Color ERROR = new Color(0xEF4444);
    public static final Color INFO = new Color(0x3B82F6);
    public static final Color SELECTION = new Color(0xE7F0FF);
    public static final Color SIDEBAR = new Color(0xF8FAFC);
    public static final Color SIDEBAR_HOVER = new Color(0xE7F0FF);
    public static final Color SIDEBAR_SELECTED = new Color(0xE7F0FF);

    public static final Font DISPLAY = new Font("Segoe UI", Font.BOLD, 32);
    public static final Font H1 = new Font("Segoe UI", Font.BOLD, 22);
    public static final Font H2 = new Font("Segoe UI", Font.BOLD, 16);
    public static final Font H3 = new Font("Segoe UI", Font.BOLD, 14);
    public static final Font TITLE = new Font("Segoe UI", Font.BOLD, 13);
    public static final Font BODY = new Font("Segoe UI", Font.PLAIN, 13);
    public static final Font BODY_SMALL = new Font("Segoe UI", Font.PLAIN, 12);
    public static final Font CAPTION = new Font("Segoe UI", Font.PLAIN, 11);
    public static final Font LABEL = new Font("Segoe UI Semibold", Font.PLAIN, 11);
    public static final Font BUTTON = new Font("Segoe UI Semibold", Font.PLAIN, 13);
    public static final Font MONO = new Font("Consolas", Font.PLAIN, 12);

    public static final int SPACE_4 = 4;
    public static final int SPACE_8 = 8;
    public static final int SPACE_12 = 12;
    public static final int SPACE_16 = 16;
    public static final int SPACE_20 = 20;
    public static final int SPACE_24 = 24;
    public static final int SPACE_32 = 32;
    public static final int RADIUS = 8;

    public static final String PRODUCT = "AEGIS";
    public static final String DESCRIPTOR = "DIGITAL FORENSICS & SECURE DATA SANITIZATION";
    public static final String TAGLINE = "INVESTIGATE. UNDERSTAND. PROTECT.";
    public static final String VERSION = "1.0.0";

    private AegisTokens() {
    }
}
