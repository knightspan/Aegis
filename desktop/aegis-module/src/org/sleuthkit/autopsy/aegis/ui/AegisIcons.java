package org.sleuthkit.autopsy.aegis.ui;

import java.awt.Color;
import java.awt.Graphics2D;
import java.awt.GraphicsConfiguration;
import java.awt.GraphicsEnvironment;
import java.awt.Image;
import java.awt.RenderingHints;
import java.awt.geom.AffineTransform;
import java.awt.image.BaseMultiResolutionImage;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import javax.imageio.ImageIO;
import javax.swing.Icon;
import javax.swing.ImageIcon;

/**
 * Loads the supplied AEGIS logo, banner, and Tabler icons. Drawn stand-ins are
 * not used.
 */
public final class AegisIcons {

    private static final int NAV = 20;
    private static final Map<String, Icon> CACHE = new HashMap<>();
    private static final Properties MAP = new Properties();
    private static BufferedImage logo;
    private static BufferedImage banner;
    private static BufferedImage sanitizeMark;

    static {
        try (InputStream input = AegisIcons.class.getResourceAsStream("assets/icon-map.properties")) {
            if (input != null) {
                MAP.load(input);
            }
        } catch (IOException ex) {
            MAP.clear();
        }
    }

    private AegisIcons() {
    }

    public static Icon get(String name) {
        return get(name, AegisTokens.TEXT_SECONDARY);
    }

    public static Icon get(String name, Color color) {
        return get(name, color, NAV);
    }

    public static Icon get(String name, Color color, int size) {
        String key = name + "#" + color.getRGB() + "#" + size;
        return CACHE.computeIfAbsent(key, ignored -> load(name, color, size));
    }

    public static ImageIcon logo(int height) {
        BufferedImage source = logo();
        if (source == null || height <= 0) {
            return new ImageIcon();
        }
        int width = Math.max(1, (int) Math.round(height * (source.getWidth() / (double) source.getHeight())));
        return new ImageIcon(sharp(source, width, height));
    }

    /**
     * Black AEGIS mono mark for the Sanitization workspace header only.
     * Uses the supplied "logo 2 for sanatize page" asset.
     */
    public static ImageIcon monoMark(int height) {
        if (height <= 0) {
            return new ImageIcon();
        }
        BufferedImage source = sanitizeMark();
        if (source == null) {
            return new ImageIcon();
        }
        int width = Math.max(1, (int) Math.round(height * (source.getWidth() / (double) source.getHeight())));
        return new ImageIcon(sharp(source, width, height));
    }

    private static BufferedImage sanitizeMark() {
        if (sanitizeMark == null) {
            sanitizeMark = trim(readImage("assets/aegis-sanitize-mark.png"));
            if (sanitizeMark != null) {
                sanitizeMark = markOnly(sanitizeMark);
            }
        }
        return sanitizeMark;
    }

    /**
     * Square window icons cut from the supplied mark, not the wordmark.
     */
    public static List<Image> windowIcons() {
        List<Image> icons = new ArrayList<>();
        BufferedImage mark = markOnly(logo());
        if (mark == null) {
            return icons;
        }
        for (int size : new int[]{16, 32, 48, 256}) {
            icons.add(sharp(mark, size, size));
        }
        return icons;
    }

    public static BufferedImage banner() {
        if (banner == null) {
            banner = readImage("assets/aegis-banner.png");
        }
        return banner;
    }

    private static Icon load(String name, Color color, int size) {
        String file = MAP.getProperty(name, name + ".svg");
        String svg = readText("assets/icons/" + file);
        if (svg == null) {
            svg = readText("assets/icons/" + name + ".svg");
        }
        if (svg == null) {
            return new ImageIcon();
        }
        return AegisSvg.icon(svg, size, color);
    }

    private static BufferedImage logo() {
        if (logo == null) {
            logo = trim(readImage("assets/aegis-logo.png"));
        }
        return logo;
    }

    private static BufferedImage readImage(String resource) {
        try (InputStream input = AegisIcons.class.getResourceAsStream(resource)) {
            return input == null ? null : ImageIO.read(input);
        } catch (IOException ex) {
            return null;
        }
    }

    private static String readText(String resource) {
        try (InputStream input = AegisIcons.class.getResourceAsStream(resource)) {
            if (input == null) {
                return null;
            }
            return new String(input.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException ex) {
            return null;
        }
    }

    private static BufferedImage trim(BufferedImage image) {
        if (image == null) {
            return null;
        }
        int width = image.getWidth();
        int height = image.getHeight();
        int minX = width;
        int minY = height;
        int maxX = -1;
        int maxY = -1;
        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                int pixel = image.getRGB(x, y);
                int red = (pixel >> 16) & 0xFF;
                int green = (pixel >> 8) & 0xFF;
                int blue = pixel & 0xFF;
                if (red < 248 || green < 248 || blue < 248) {
                    minX = Math.min(minX, x);
                    minY = Math.min(minY, y);
                    maxX = Math.max(maxX, x);
                    maxY = Math.max(maxY, y);
                }
            }
        }
        if (maxX < minX || maxY < minY) {
            return image;
        }
        BufferedImage cropped = image.getSubimage(minX, minY, maxX - minX + 1, maxY - minY + 1);
        return unmatteWhite(cropped);
    }

    /**
     * Removes the white page behind the supplied logo and keeps the soft edge
     * pixels, so the mark does not turn into a staircase when it is reduced.
     */
    private static BufferedImage unmatteWhite(BufferedImage cropped) {
        int width = cropped.getWidth();
        int height = cropped.getHeight();
        BufferedImage clear = new BufferedImage(width, height, BufferedImage.TYPE_INT_ARGB);
        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                int pixel = cropped.getRGB(x, y);
                int red = (pixel >> 16) & 0xFF;
                int green = (pixel >> 8) & 0xFF;
                int blue = pixel & 0xFF;
                int alpha = 255 - Math.min(red, Math.min(green, blue));
                if (alpha < 8) {
                    continue;
                }
                float coverage = alpha / 255f;
                int outRed = clamp((int) Math.round((red - 255 * (1 - coverage)) / coverage));
                int outGreen = clamp((int) Math.round((green - 255 * (1 - coverage)) / coverage));
                int outBlue = clamp((int) Math.round((blue - 255 * (1 - coverage)) / coverage));
                clear.setRGB(x, y, (alpha << 24) | (outRed << 16) | (outGreen << 8) | outBlue);
            }
        }
        return clear;
    }

    private static BufferedImage markOnly(BufferedImage lockup) {
        if (lockup == null) {
            return null;
        }
        int width = lockup.getWidth();
        int height = lockup.getHeight();
        boolean[] ink = new boolean[width];
        for (int x = 0; x < width; x++) {
            for (int y = 0; y < height; y++) {
                if (((lockup.getRGB(x, y) >>> 24) & 0xFF) > 16) {
                    ink[x] = true;
                    break;
                }
            }
        }
        int start = 0;
        while (start < width && !ink[start]) {
            start++;
        }
        int gap = start;
        boolean seen = false;
        int empty = 0;
        for (int x = start; x < width; x++) {
            if (ink[x]) {
                if (seen && empty > height / 8) {
                    gap = x - empty;
                    break;
                }
                seen = true;
                empty = 0;
                gap = x + 1;
            } else if (seen) {
                empty++;
            }
        }
        int top = height;
        int bottom = -1;
        for (int y = 0; y < height; y++) {
            for (int x = start; x < gap; x++) {
                if (((lockup.getRGB(x, y) >>> 24) & 0xFF) > 16) {
                    top = Math.min(top, y);
                    bottom = Math.max(bottom, y);
                    break;
                }
            }
        }
        if (bottom < top || gap <= start) {
            return lockup;
        }
        int contentW = gap - start;
        int contentH = bottom - top + 1;
        int box = Math.max(contentW, contentH);
        int pad = Math.max(2, box / 16);
        int canvas = box + pad * 2;
        int drawW = Math.max(1, contentW * box / Math.max(contentW, contentH));
        int drawH = Math.max(1, contentH * box / Math.max(contentW, contentH));
        BufferedImage square = new BufferedImage(canvas, canvas, BufferedImage.TYPE_INT_ARGB);
        Graphics2D g = square.createGraphics();
        hints(g);
        int x = (canvas - drawW) / 2;
        int y = (canvas - drawH) / 2;
        g.drawImage(lockup, x, y, x + drawW, y + drawH, start, top, gap, bottom + 1, null);
        g.dispose();
        return square;
    }

    private static Image sharp(BufferedImage source, int width, int height) {
        BufferedImage base = downscale(source, width, height);
        double device = deviceScale();
        if (device <= 1.05) {
            return base;
        }
        BufferedImage hi = downscale(source, Math.max(width + 1, (int) Math.round(width * device)),
                Math.max(height + 1, (int) Math.round(height * device)));
        return new BaseMultiResolutionImage(base, hi);
    }

    private static double deviceScale() {
        if (GraphicsEnvironment.isHeadless()) {
            return 1;
        }
        GraphicsConfiguration config = GraphicsEnvironment.getLocalGraphicsEnvironment()
                .getDefaultScreenDevice().getDefaultConfiguration();
        AffineTransform transform = config.getDefaultTransform();
        return Math.max(transform.getScaleX(), transform.getScaleY());
    }

    private static BufferedImage downscale(BufferedImage source, int width, int height) {
        BufferedImage current = source;
        int w = source.getWidth();
        int h = source.getHeight();
        while (w / 2 >= width && h / 2 >= height) {
            w = Math.max(width, w / 2);
            h = Math.max(height, h / 2);
            current = blit(current, w, h);
        }
        return blit(current, width, height);
    }

    private static BufferedImage blit(BufferedImage source, int width, int height) {
        BufferedImage image = new BufferedImage(width, height, BufferedImage.TYPE_INT_ARGB);
        Graphics2D g = image.createGraphics();
        hints(g);
        g.drawImage(source, 0, 0, width, height, null);
        g.dispose();
        return image;
    }

    private static void hints(Graphics2D g) {
        g.setRenderingHint(RenderingHints.KEY_INTERPOLATION, RenderingHints.VALUE_INTERPOLATION_BICUBIC);
        g.setRenderingHint(RenderingHints.KEY_RENDERING, RenderingHints.VALUE_RENDER_QUALITY);
        g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g.setRenderingHint(RenderingHints.KEY_ALPHA_INTERPOLATION, RenderingHints.VALUE_ALPHA_INTERPOLATION_QUALITY);
    }

    private static int clamp(int channel) {
        return Math.max(0, Math.min(255, channel));
    }
}
