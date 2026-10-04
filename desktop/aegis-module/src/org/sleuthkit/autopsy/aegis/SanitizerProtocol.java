package org.sleuthkit.autopsy.aegis;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Parses one stdout line from aegis_cli. Human-readable banners are ignored.
 */
public final class SanitizerProtocol {

    public enum Kind {
        PROGRESS,
        RESULT,
        IGNORED
    }

    private final Kind kind;
    private final Map<String, String> fields;

    private SanitizerProtocol(Kind kind, Map<String, String> fields) {
        this.kind = kind;
        this.fields = fields;
    }

    public Kind getKind() {
        return kind;
    }

    public String get(String name) {
        return fields.get(name);
    }

    public static SanitizerProtocol parse(String line) {
        if (line == null) {
            return new SanitizerProtocol(Kind.IGNORED, Map.of());
        }
        String trimmed = line.trim();
        if (!trimmed.startsWith("AEGIS_EVENT ")) {
            return new SanitizerProtocol(Kind.IGNORED, Map.of());
        }
        String json = trimmed.substring("AEGIS_EVENT ".length()).trim();
        Map<String, String> fields = readFlatObject(json);
        String type = fields.getOrDefault("type", "");
        Kind kind = "progress".equals(type) ? Kind.PROGRESS : "result".equals(type) ? Kind.RESULT : Kind.IGNORED;
        return new SanitizerProtocol(kind, fields);
    }

    public static boolean isSuccessfulStatus(String status) {
        return "SUCCESS".equals(status) || "SUCCESS_WITH_WARNINGS".equals(status);
    }

    /**
     * A zero exit code is success only when the structured status also says so.
     */
    public static boolean acceptExit(int exitCode, String status) {
        if (status == null || status.isBlank()) {
            return false;
        }
        if (!isSuccessfulStatus(status)) {
            return false;
        }
        return exitCode == 0;
    }

    static Map<String, String> readFlatObject(String json) {
        Map<String, String> values = new LinkedHashMap<>();
        if (json == null || json.length() < 2 || json.charAt(0) != '{') {
            return values;
        }
        int i = 1;
        while (i < json.length()) {
            while (i < json.length() && (json.charAt(i) == ' ' || json.charAt(i) == ',' || json.charAt(i) == '\n')) {
                i++;
            }
            if (i >= json.length() || json.charAt(i) == '}') {
                break;
            }
            if (json.charAt(i) != '"') {
                break;
            }
            String key = readString(json, i);
            i = stringEnd(json, i);
            while (i < json.length() && (json.charAt(i) == ' ' || json.charAt(i) == ':')) {
                i++;
            }
            if (i >= json.length()) {
                break;
            }
            String value;
            if (json.charAt(i) == '"') {
                value = readString(json, i);
                i = stringEnd(json, i);
            } else if (json.charAt(i) == '{') {
                int depth = 0;
                int start = i;
                do {
                    if (json.charAt(i) == '{') {
                        depth++;
                    } else if (json.charAt(i) == '}') {
                        depth--;
                    }
                    i++;
                } while (i < json.length() && depth > 0);
                value = json.substring(start, i);
            } else {
                int start = i;
                while (i < json.length() && json.charAt(i) != ',' && json.charAt(i) != '}') {
                    i++;
                }
                value = json.substring(start, i).trim();
            }
            values.put(key, value);
        }
        return values;
    }

    private static String readString(String json, int quoteIndex) {
        StringBuilder out = new StringBuilder();
        for (int i = quoteIndex + 1; i < json.length(); i++) {
            char c = json.charAt(i);
            if (c == '\\' && i + 1 < json.length()) {
                char n = json.charAt(++i);
                switch (n) {
                    case '"':
                    case '\\':
                    case '/':
                        out.append(n);
                        break;
                    case 'n':
                        out.append('\n');
                        break;
                    case 'r':
                        out.append('\r');
                        break;
                    case 't':
                        out.append('\t');
                        break;
                    case 'u':
                        if (i + 4 < json.length()) {
                            String hex = json.substring(i + 1, i + 5);
                            out.append((char) Integer.parseInt(hex, 16));
                            i += 4;
                        }
                        break;
                    default:
                        out.append(n);
                        break;
                }
            } else if (c == '"') {
                break;
            } else {
                out.append(c);
            }
        }
        return out.toString();
    }

    private static int stringEnd(String json, int quoteIndex) {
        for (int i = quoteIndex + 1; i < json.length(); i++) {
            if (json.charAt(i) == '\\') {
                i++;
            } else if (json.charAt(i) == '"') {
                return i + 1;
            }
        }
        return json.length();
    }
}
