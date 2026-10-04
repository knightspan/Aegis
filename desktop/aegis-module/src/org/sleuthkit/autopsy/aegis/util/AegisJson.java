package org.sleuthkit.autopsy.aegis.util;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Zero-dependency JSON for the AEGIS module: a strict recursive-descent parser
 * (RFC 8259: strings with escapes, nested values, numbers, true/false/null)
 * and a serializer. Engine bridge results are parsed here, so a brace inside a
 * string, an escaped quote or a null must never be misread.
 */
public final class AegisJson {

    private AegisJson() {
    }

    /** Parses any JSON value: AegisJsonObject, AegisJsonArray, String, Long, Double, Boolean or null. */
    public static Object parse(String text) {
        if (text == null) {
            throw new IllegalArgumentException("null JSON text");
        }
        Parser p = new Parser(text);
        p.ws();
        Object value = p.value();
        p.ws();
        if (p.i != text.length()) {
            throw new IllegalArgumentException("Trailing data at offset " + p.i);
        }
        return value;
    }

    public static String toJson(Object value) {
        StringBuilder sb = new StringBuilder();
        write(sb, value);
        return sb.toString();
    }

    private static void write(StringBuilder sb, Object v) {
        if (v == null) {
            sb.append("null");
        } else if (v instanceof AegisJsonObject o) {
            sb.append('{');
            boolean first = true;
            for (Map.Entry<String, Object> e : o.map.entrySet()) {
                if (!first) {
                    sb.append(',');
                }
                first = false;
                quote(sb, e.getKey());
                sb.append(':');
                write(sb, e.getValue());
            }
            sb.append('}');
        } else if (v instanceof AegisJsonArray a) {
            sb.append('[');
            for (int i = 0; i < a.list.size(); i++) {
                if (i > 0) {
                    sb.append(',');
                }
                write(sb, a.list.get(i));
            }
            sb.append(']');
        } else if (v instanceof Map<?, ?> m) {
            AegisJsonObject o = new AegisJsonObject();
            m.forEach((k, val) -> o.put(String.valueOf(k), val));
            write(sb, o);
        } else if (v instanceof List<?> l) {
            AegisJsonArray a = new AegisJsonArray();
            l.forEach(a::add);
            write(sb, a);
        } else if (v instanceof Number || v instanceof Boolean) {
            sb.append(v);
        } else {
            quote(sb, String.valueOf(v));
        }
    }

    private static void quote(StringBuilder sb, String s) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        sb.append('"');
    }

    private static final class Parser {

        private final String s;
        private int i;

        Parser(String s) {
            this.s = s;
        }

        void ws() {
            while (i < s.length()) {
                char c = s.charAt(i);
                if (c == ' ' || c == '\n' || c == '\r' || c == '\t') {
                    i++;
                } else {
                    break;
                }
            }
        }

        Object value() {
            if (i >= s.length()) {
                throw err("Unexpected end of JSON");
            }
            char c = s.charAt(i);
            return switch (c) {
                case '{' -> object();
                case '[' -> array();
                case '"' -> string();
                case 't' -> literal("true", Boolean.TRUE);
                case 'f' -> literal("false", Boolean.FALSE);
                case 'n' -> literal("null", null);
                default -> number();
            };
        }

        AegisJsonObject object() {
            AegisJsonObject o = new AegisJsonObject();
            i++;
            ws();
            if (peek() == '}') {
                i++;
                return o;
            }
            while (true) {
                ws();
                if (peek() != '"') {
                    throw err("Expected object key");
                }
                String key = string();
                ws();
                expect(':');
                ws();
                o.map.put(key, value());
                ws();
                char c = next();
                if (c == '}') {
                    return o;
                }
                if (c != ',') {
                    throw err("Expected , or }");
                }
            }
        }

        AegisJsonArray array() {
            AegisJsonArray a = new AegisJsonArray();
            i++;
            ws();
            if (peek() == ']') {
                i++;
                return a;
            }
            while (true) {
                ws();
                a.list.add(value());
                ws();
                char c = next();
                if (c == ']') {
                    return a;
                }
                if (c != ',') {
                    throw err("Expected , or ]");
                }
            }
        }

        String string() {
            expect('"');
            StringBuilder sb = new StringBuilder();
            while (true) {
                if (i >= s.length()) {
                    throw err("Unterminated string");
                }
                char c = s.charAt(i++);
                if (c == '"') {
                    return sb.toString();
                }
                if (c == '\\') {
                    char e = next();
                    switch (e) {
                        case '"', '\\', '/' -> sb.append(e);
                        case 'b' -> sb.append('\b');
                        case 'f' -> sb.append('\f');
                        case 'n' -> sb.append('\n');
                        case 'r' -> sb.append('\r');
                        case 't' -> sb.append('\t');
                        case 'u' -> {
                            if (i + 4 > s.length()) {
                                throw err("Bad unicode escape");
                            }
                            sb.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                            i += 4;
                        }
                        default -> throw err("Bad escape \\" + e);
                    }
                } else {
                    sb.append(c);
                }
            }
        }

        Object number() {
            int start = i;
            if (peek() == '-') {
                i++;
            }
            boolean fraction = false;
            while (i < s.length()) {
                char c = s.charAt(i);
                if (c >= '0' && c <= '9') {
                    i++;
                } else if (c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-') {
                    fraction = true;
                    i++;
                } else {
                    break;
                }
            }
            String text = s.substring(start, i);
            if (text.isEmpty() || "-".equals(text)) {
                throw err("Invalid value");
            }
            try {
                if (!fraction) {
                    return Long.parseLong(text);
                }
                return Double.parseDouble(text);
            } catch (NumberFormatException ex) {
                return Double.parseDouble(text);
            }
        }

        Object literal(String word, Object value) {
            if (!s.startsWith(word, i)) {
                throw err("Invalid literal");
            }
            i += word.length();
            return value;
        }

        char peek() {
            return i < s.length() ? s.charAt(i) : '\0';
        }

        char next() {
            if (i >= s.length()) {
                throw err("Unexpected end of JSON");
            }
            return s.charAt(i++);
        }

        void expect(char c) {
            if (next() != c) {
                throw err("Expected '" + c + "'");
            }
        }

        IllegalArgumentException err(String message) {
            return new IllegalArgumentException(message + " at offset " + i);
        }
    }

    public static final class AegisJsonObject {

        private final Map<String, Object> map = new LinkedHashMap<>();

        public AegisJsonObject() {
        }

        /** Parses an object. Invalid or non-object text yields an empty object. */
        public AegisJsonObject(String jsonText) {
            parse(jsonText);
        }

        public void parse(String json) {
            if (json == null || json.isBlank()) {
                return;
            }
            Object v = AegisJson.parse(json);
            if (v instanceof AegisJsonObject o) {
                map.putAll(o.map);
            }
        }

        public static AegisJsonObject parseStrict(String json) {
            Object v = AegisJson.parse(json);
            if (v instanceof AegisJsonObject o) {
                return o;
            }
            throw new IllegalArgumentException("JSON is not an object");
        }

        public AegisJsonObject put(String key, Object value) {
            map.put(key, value);
            return this;
        }

        public boolean has(String key) {
            return map.containsKey(key);
        }

        public boolean isNull(String key) {
            return map.get(key) == null;
        }

        public Object opt(String key) {
            return map.get(key);
        }

        public Set<String> keys() {
            return Collections.unmodifiableSet(map.keySet());
        }

        public String optString(String key, String fallback) {
            Object val = map.get(key);
            if (val == null) {
                return fallback;
            }
            if (val instanceof Double d && d == Math.rint(d) && !Double.isInfinite(d)) {
                return String.valueOf(d.longValue());
            }
            return String.valueOf(val);
        }

        public String optString(String key) {
            return optString(key, "");
        }

        public boolean optBoolean(String key, boolean fallback) {
            Object val = map.get(key);
            if (val instanceof Boolean b) {
                return b;
            }
            if (val instanceof String str) {
                return "true".equalsIgnoreCase(str) ? true : ("false".equalsIgnoreCase(str) ? false : fallback);
            }
            return fallback;
        }

        public int optInt(String key, int fallback) {
            return (int) optLong(key, fallback);
        }

        public long optLong(String key, long fallback) {
            Object val = map.get(key);
            if (val instanceof Number n) {
                return n.longValue();
            }
            if (val instanceof String str) {
                try {
                    return Long.parseLong(str.trim());
                } catch (NumberFormatException ignored) {
                    return fallback;
                }
            }
            return fallback;
        }

        public double optDouble(String key, double fallback) {
            Object val = map.get(key);
            if (val instanceof Number n) {
                return n.doubleValue();
            }
            if (val instanceof String str) {
                try {
                    return Double.parseDouble(str.trim());
                } catch (NumberFormatException ignored) {
                    return fallback;
                }
            }
            return fallback;
        }

        public AegisJsonArray optJSONArray(String key) {
            Object val = map.get(key);
            return val instanceof AegisJsonArray arr ? arr : null;
        }

        public AegisJsonArray array(String key) {
            AegisJsonArray a = optJSONArray(key);
            return a == null ? new AegisJsonArray() : a;
        }

        public AegisJsonObject optJSONObject(String key) {
            Object val = map.get(key);
            return val instanceof AegisJsonObject obj ? obj : null;
        }

        public AegisJsonObject object(String key) {
            AegisJsonObject o = optJSONObject(key);
            return o == null ? new AegisJsonObject() : o;
        }

        public List<String> optStringList(String key) {
            List<String> out = new ArrayList<>();
            AegisJsonArray a = optJSONArray(key);
            if (a != null) {
                for (int k = 0; k < a.length(); k++) {
                    Object v = a.get(k);
                    if (v != null) {
                        out.add(String.valueOf(v));
                    }
                }
            }
            return out;
        }

        public int size() {
            return map.size();
        }

        @Override
        public String toString() {
            return toJson(this);
        }
    }

    public static final class AegisJsonArray {

        private final List<Object> list = new ArrayList<>();

        public AegisJsonArray() {
        }

        public AegisJsonArray(String jsonText) {
            parse(jsonText);
        }

        public void parse(String json) {
            if (json == null || json.isBlank()) {
                return;
            }
            Object v = AegisJson.parse(json);
            if (v instanceof AegisJsonArray a) {
                list.addAll(a.list);
            }
        }

        public AegisJsonArray add(Object value) {
            list.add(value);
            return this;
        }

        public int length() {
            return list.size();
        }

        public Object get(int index) {
            return list.get(index);
        }

        public AegisJsonObject getJSONObject(int index) {
            Object obj = list.get(index);
            return obj instanceof AegisJsonObject o ? o : new AegisJsonObject();
        }

        public String optString(int index, String fallback) {
            Object v = index < list.size() ? list.get(index) : null;
            return v == null ? fallback : String.valueOf(v);
        }

        public long optLong(int index, long fallback) {
            Object v = index < list.size() ? list.get(index) : null;
            return v instanceof Number n ? n.longValue() : fallback;
        }

        public List<AegisJsonObject> objects() {
            List<AegisJsonObject> out = new ArrayList<>();
            for (Object o : list) {
                if (o instanceof AegisJsonObject j) {
                    out.add(j);
                }
            }
            return out;
        }

        @Override
        public String toString() {
            return toJson(this);
        }
    }
}
