package org.sleuthkit.autopsy.aegis.ui;

import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Component;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.geom.GeneralPath;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import javax.swing.Icon;

/**
 * Draws the supplied Tabler outline SVGs. Tabler icons are stroke paths in a
 * 24x24 view box, so this covers that subset and keeps the vectors sharp at
 * any Windows scale.
 */
final class AegisSvg {

    private AegisSvg() {
    }

    static Icon icon(String svg, int size, Color color) {
        float stroke = strokeWidth(svg);
        List<GeneralPath> paths = paths(svg);
        return new Icon() {
            @Override
            public int getIconWidth() {
                return size;
            }

            @Override
            public int getIconHeight() {
                return size;
            }

            @Override
            public void paintIcon(Component c, Graphics g, int x, int y) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setRenderingHint(RenderingHints.KEY_STROKE_CONTROL, RenderingHints.VALUE_STROKE_PURE);
                g2.translate(x, y);
                g2.scale(size / 24.0, size / 24.0);
                g2.setColor(color);
                g2.setStroke(new BasicStroke(stroke, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
                for (GeneralPath path : paths) {
                    g2.draw(path);
                }
                g2.dispose();
            }
        };
    }

    private static float strokeWidth(String svg) {
        int mark = svg.indexOf("stroke-width=\"");
        if (mark < 0) {
            return 2f;
        }
        int start = mark + "stroke-width=\"".length();
        int end = svg.indexOf('"', start);
        try {
            return Float.parseFloat(svg.substring(start, end));
        } catch (RuntimeException ex) {
            return 2f;
        }
    }

    private static List<GeneralPath> paths(String svg) {
        List<GeneralPath> paths = new ArrayList<>();
        int cursor = 0;
        while (true) {
            int path = svg.indexOf("<path", cursor);
            int circle = svg.indexOf("<circle", cursor);
            int line = svg.indexOf("<line", cursor);
            int next = earliest(path, earliest(circle, line));
            if (next < 0) {
                break;
            }
            int end = svg.indexOf('>', next);
            if (end < 0) {
                break;
            }
            String tag = svg.substring(next, end);
            if (next == path) {
                String data = attr(tag, "d");
                if (data != null) {
                    paths.add(parsePath(data));
                }
            } else if (next == circle) {
                paths.add(circle(attr(tag, "cx"), attr(tag, "cy"), attr(tag, "r")));
            } else {
                paths.add(line(attr(tag, "x1"), attr(tag, "y1"), attr(tag, "x2"), attr(tag, "y2")));
            }
            cursor = end + 1;
        }
        return paths;
    }

    private static int earliest(int left, int right) {
        if (left < 0) {
            return right;
        }
        if (right < 0) {
            return left;
        }
        return Math.min(left, right);
    }

    private static String attr(String tag, String name) {
        String key = name + "=\"";
        int start = tag.indexOf(key);
        if (start < 0) {
            return null;
        }
        start += key.length();
        int end = tag.indexOf('"', start);
        return end < 0 ? null : tag.substring(start, end);
    }

    private static GeneralPath circle(String cx, String cy, String r) {
        GeneralPath path = new GeneralPath();
        double x = num(cx);
        double y = num(cy);
        double radius = num(r);
        path.moveTo(x + radius, y);
        path.append(new java.awt.geom.Ellipse2D.Double(x - radius, y - radius, radius * 2, radius * 2), false);
        return path;
    }

    private static GeneralPath line(String x1, String y1, String x2, String y2) {
        GeneralPath path = new GeneralPath();
        path.moveTo(num(x1), num(y1));
        path.lineTo(num(x2), num(y2));
        return path;
    }

    private static double num(String text) {
        return text == null ? 0 : Double.parseDouble(text);
    }

    static GeneralPath parsePath(String data) {
        GeneralPath path = new GeneralPath();
        Parser parser = new Parser(data);
        double cx = 0;
        double cy = 0;
        double sx = 0;
        double sy = 0;
        double lastCubicX = 0;
        double lastCubicY = 0;
        double lastQuadX = 0;
        double lastQuadY = 0;
        char command = 0;
        char previous = 0;
        while (parser.hasNext()) {
            if (parser.hasCommand()) {
                command = parser.command();
            } else if (command == 0) {
                break;
            }
            boolean relative = Character.isLowerCase(command);
            char op = Character.toUpperCase(command);
            switch (op) {
                case 'M' -> {
                    double x = parser.number();
                    double y = parser.number();
                    if (relative) {
                        x += cx;
                        y += cy;
                    }
                    path.moveTo(x, y);
                    cx = x;
                    cy = y;
                    sx = x;
                    sy = y;
                    command = relative ? 'l' : 'L';
                }
                case 'L' -> {
                    double x = parser.number();
                    double y = parser.number();
                    if (relative) {
                        x += cx;
                        y += cy;
                    }
                    path.lineTo(x, y);
                    cx = x;
                    cy = y;
                }
                case 'H' -> {
                    double x = parser.number();
                    if (relative) {
                        x += cx;
                    }
                    path.lineTo(x, cy);
                    cx = x;
                }
                case 'V' -> {
                    double y = parser.number();
                    if (relative) {
                        y += cy;
                    }
                    path.lineTo(cx, y);
                    cy = y;
                }
                case 'C' -> {
                    double x1 = parser.number();
                    double y1 = parser.number();
                    double x2 = parser.number();
                    double y2 = parser.number();
                    double x = parser.number();
                    double y = parser.number();
                    if (relative) {
                        x1 += cx;
                        y1 += cy;
                        x2 += cx;
                        y2 += cy;
                        x += cx;
                        y += cy;
                    }
                    path.curveTo(x1, y1, x2, y2, x, y);
                    lastCubicX = x2;
                    lastCubicY = y2;
                    cx = x;
                    cy = y;
                }
                case 'S' -> {
                    double x2 = parser.number();
                    double y2 = parser.number();
                    double x = parser.number();
                    double y = parser.number();
                    if (relative) {
                        x2 += cx;
                        y2 += cy;
                        x += cx;
                        y += cy;
                    }
                    double x1 = cx;
                    double y1 = cy;
                    if (previous == 'C' || previous == 'S') {
                        x1 = 2 * cx - lastCubicX;
                        y1 = 2 * cy - lastCubicY;
                    }
                    path.curveTo(x1, y1, x2, y2, x, y);
                    lastCubicX = x2;
                    lastCubicY = y2;
                    cx = x;
                    cy = y;
                }
                case 'Q' -> {
                    double x1 = parser.number();
                    double y1 = parser.number();
                    double x = parser.number();
                    double y = parser.number();
                    if (relative) {
                        x1 += cx;
                        y1 += cy;
                        x += cx;
                        y += cy;
                    }
                    path.quadTo(x1, y1, x, y);
                    lastQuadX = x1;
                    lastQuadY = y1;
                    cx = x;
                    cy = y;
                }
                case 'A' -> {
                    double rx = parser.number();
                    double ry = parser.number();
                    double rotation = parser.number();
                    boolean large = parser.number() != 0;
                    boolean sweep = parser.number() != 0;
                    double x = parser.number();
                    double y = parser.number();
                    if (relative) {
                        x += cx;
                        y += cy;
                    }
                    arcTo(path, cx, cy, rx, ry, rotation, large, sweep, x, y);
                    cx = x;
                    cy = y;
                }
                case 'Z' -> {
                    path.closePath();
                    cx = sx;
                    cy = sy;
                }
                default -> {
                    return path;
                }
            }
            previous = op == 'M' ? 'L' : op;
        }
        return path;
    }

    private static void arcTo(GeneralPath path, double x1, double y1, double rx, double ry,
            double rotation, boolean large, boolean sweep, double x2, double y2) {
        if (rx == 0 || ry == 0 || (x1 == x2 && y1 == y2)) {
            path.lineTo(x2, y2);
            return;
        }
        double phi = Math.toRadians(rotation);
        double cos = Math.cos(phi);
        double sin = Math.sin(phi);
        double dx = (x1 - x2) / 2;
        double dy = (y1 - y2) / 2;
        double x1p = cos * dx + sin * dy;
        double y1p = -sin * dx + cos * dy;
        rx = Math.abs(rx);
        ry = Math.abs(ry);
        double lambda = (x1p * x1p) / (rx * rx) + (y1p * y1p) / (ry * ry);
        if (lambda > 1) {
            double scale = Math.sqrt(lambda);
            rx *= scale;
            ry *= scale;
        }
        double sign = (large == sweep) ? -1 : 1;
        double rx2 = rx * rx;
        double ry2 = ry * ry;
        double num = rx2 * ry2 - rx2 * y1p * y1p - ry2 * x1p * x1p;
        double den = rx2 * y1p * y1p + ry2 * x1p * x1p;
        double coef = sign * Math.sqrt(Math.max(0, num / den));
        double cxp = coef * rx * y1p / ry;
        double cyp = coef * -ry * x1p / rx;
        double cx = cos * cxp - sin * cyp + (x1 + x2) / 2;
        double cy = sin * cxp + cos * cyp + (y1 + y2) / 2;
        double theta1 = angle(1, 0, (x1p - cxp) / rx, (y1p - cyp) / ry);
        double delta = angle((x1p - cxp) / rx, (y1p - cyp) / ry, (-x1p - cxp) / rx, (-y1p - cyp) / ry);
        if (!sweep && delta > 0) {
            delta -= 2 * Math.PI;
        } else if (sweep && delta < 0) {
            delta += 2 * Math.PI;
        }
        int segments = Math.max(1, (int) Math.ceil(Math.abs(delta) / (Math.PI / 2)));
        double step = delta / segments;
        double t = theta1;
        for (int i = 0; i < segments; i++) {
            double t2 = t + step;
            double alpha = Math.tan(step / 4) * 4 / 3;
            double cos1 = Math.cos(t);
            double sin1 = Math.sin(t);
            double cos2 = Math.cos(t2);
            double sin2 = Math.sin(t2);
            double e1x = cx + rx * cos * cos1 - ry * sin * sin1;
            double e1y = cy + rx * sin * cos1 + ry * cos * sin1;
            double e2x = cx + rx * cos * cos2 - ry * sin * sin2;
            double e2y = cy + rx * sin * cos2 + ry * cos * sin2;
            double c1x = e1x + alpha * (-rx * cos * sin1 - ry * sin * cos1);
            double c1y = e1y + alpha * (-rx * sin * sin1 + ry * cos * cos1);
            double c2x = e2x - alpha * (-rx * cos * sin2 - ry * sin * cos2);
            double c2y = e2y - alpha * (-rx * sin * sin2 + ry * cos * cos2);
            path.curveTo(c1x, c1y, c2x, c2y, e2x, e2y);
            t = t2;
        }
    }

    private static double angle(double ux, double uy, double vx, double vy) {
        double dot = ux * vx + uy * vy;
        double len = Math.hypot(ux, uy) * Math.hypot(vx, vy);
        double ang = Math.acos(Math.max(-1, Math.min(1, dot / len)));
        if (ux * vy - uy * vx < 0) {
            ang = -ang;
        }
        return ang;
    }

    private static final class Parser {
        private final String data;
        private int index;

        Parser(String data) {
            this.data = data;
        }

        boolean hasNext() {
            skipSeparators();
            return index < data.length();
        }

        boolean hasCommand() {
            skipSeparators();
            return index < data.length() && Character.isLetter(data.charAt(index));
        }

        char command() {
            return data.charAt(index++);
        }

        double number() {
            skipSeparators();
            int start = index;
            if (index < data.length() && (data.charAt(index) == '+' || data.charAt(index) == '-')) {
                index++;
            }
            boolean dot = false;
            while (index < data.length()) {
                char ch = data.charAt(index);
                if (ch >= '0' && ch <= '9') {
                    index++;
                } else if (ch == '.' && !dot) {
                    dot = true;
                    index++;
                } else {
                    break;
                }
            }
            if (index < data.length() && (data.charAt(index) == 'e' || data.charAt(index) == 'E')) {
                index++;
                if (index < data.length() && (data.charAt(index) == '+' || data.charAt(index) == '-')) {
                    index++;
                }
                while (index < data.length() && data.charAt(index) >= '0' && data.charAt(index) <= '9') {
                    index++;
                }
            }
            return Double.parseDouble(data.substring(start, index).toLowerCase(Locale.ROOT));
        }

        private void skipSeparators() {
            while (index < data.length()) {
                char ch = data.charAt(index);
                if (ch == ' ' || ch == ',' || ch == '\n' || ch == '\r' || ch == '\t') {
                    index++;
                } else {
                    break;
                }
            }
        }
    }
}
