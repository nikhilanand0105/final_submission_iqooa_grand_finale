package dev.guardianai.util;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal, dependency-free JSON reader/writer used by the pure-Java core
 * (provider responses, bundled lesson content, model output validation).
 * Parses into Map / List / String / Double / Boolean / null.
 * Enforces depth and size limits because inputs may be untrusted.
 */
public final class Json {

    public static final int MAX_DEPTH = 64;
    public static final int MAX_LENGTH = 4 * 1024 * 1024;

    private final String s;
    private int i;

    private Json(String s) {
        this.s = s;
    }

    public static class ParseException extends Exception {
        public ParseException(String msg) {
            super(msg);
        }
    }

    public static Object parse(String text) throws ParseException {
        if (text == null) throw new ParseException("null input");
        if (text.length() > MAX_LENGTH) throw new ParseException("input too large");
        Json p = new Json(text);
        p.ws();
        Object v = p.value(0);
        p.ws();
        if (p.i != p.s.length()) throw new ParseException("trailing data at " + p.i);
        return v;
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> parseObject(String text) throws ParseException {
        Object v = parse(text);
        if (!(v instanceof Map)) throw new ParseException("expected JSON object");
        return (Map<String, Object>) v;
    }

    private Object value(int depth) throws ParseException {
        if (depth > MAX_DEPTH) throw new ParseException("nesting too deep");
        if (i >= s.length()) throw new ParseException("unexpected end");
        char c = s.charAt(i);
        switch (c) {
            case '{': return object(depth);
            case '[': return array(depth);
            case '"': return string();
            case 't': lit("true"); return Boolean.TRUE;
            case 'f': lit("false"); return Boolean.FALSE;
            case 'n': lit("null"); return null;
            default:
                if (c == '-' || (c >= '0' && c <= '9')) return number();
                throw new ParseException("unexpected '" + c + "' at " + i);
        }
    }

    private Map<String, Object> object(int depth) throws ParseException {
        Map<String, Object> m = new LinkedHashMap<>();
        i++;
        ws();
        if (peek('}')) { i++; return m; }
        while (true) {
            ws();
            if (!peek('"')) throw new ParseException("expected key at " + i);
            String k = string();
            ws();
            expect(':');
            ws();
            m.put(k, value(depth + 1));
            ws();
            if (peek(',')) { i++; continue; }
            expect('}');
            return m;
        }
    }

    private List<Object> array(int depth) throws ParseException {
        List<Object> l = new ArrayList<>();
        i++;
        ws();
        if (peek(']')) { i++; return l; }
        while (true) {
            ws();
            l.add(value(depth + 1));
            ws();
            if (peek(',')) { i++; continue; }
            expect(']');
            return l;
        }
    }

    private String string() throws ParseException {
        expect('"');
        StringBuilder b = new StringBuilder();
        while (true) {
            if (i >= s.length()) throw new ParseException("unterminated string");
            char c = s.charAt(i++);
            if (c == '"') return b.toString();
            if (c < 0x20) throw new ParseException("control char in string");
            if (c != '\\') { b.append(c); continue; }
            if (i >= s.length()) throw new ParseException("bad escape");
            char e = s.charAt(i++);
            switch (e) {
                case '"': b.append('"'); break;
                case '\\': b.append('\\'); break;
                case '/': b.append('/'); break;
                case 'b': b.append('\b'); break;
                case 'f': b.append('\f'); break;
                case 'n': b.append('\n'); break;
                case 'r': b.append('\r'); break;
                case 't': b.append('\t'); break;
                case 'u':
                    if (i + 4 > s.length()) throw new ParseException("bad unicode escape");
                    try {
                        b.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                    } catch (NumberFormatException ex) {
                        throw new ParseException("bad unicode escape");
                    }
                    i += 4;
                    break;
                default: throw new ParseException("bad escape \\" + e);
            }
        }
    }

    private Double number() throws ParseException {
        int st = i;
        if (peek('-')) i++;
        while (i < s.length() && "0123456789.eE+-".indexOf(s.charAt(i)) >= 0) i++;
        try {
            return Double.parseDouble(s.substring(st, i));
        } catch (NumberFormatException e) {
            throw new ParseException("bad number at " + st);
        }
    }

    private void lit(String w) throws ParseException {
        if (!s.startsWith(w, i)) throw new ParseException("expected " + w + " at " + i);
        i += w.length();
    }

    private void ws() {
        while (i < s.length() && Character.isWhitespace(s.charAt(i))) i++;
    }

    private boolean peek(char c) {
        return i < s.length() && s.charAt(i) == c;
    }

    private void expect(char c) throws ParseException {
        if (!peek(c)) throw new ParseException("expected '" + c + "' at " + i);
        i++;
    }

    // ---- typed accessors -------------------------------------------------

    public static String str(Map<String, Object> m, String k) {
        Object v = m == null ? null : m.get(k);
        return v instanceof String ? (String) v : null;
    }

    public static Long lng(Map<String, Object> m, String k) {
        Object v = m == null ? null : m.get(k);
        return v instanceof Double ? Long.valueOf(((Double) v).longValue()) : null;
    }

    public static Boolean bool(Map<String, Object> m, String k) {
        Object v = m == null ? null : m.get(k);
        return v instanceof Boolean ? (Boolean) v : null;
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> obj(Map<String, Object> m, String k) {
        Object v = m == null ? null : m.get(k);
        return v instanceof Map ? (Map<String, Object>) v : null;
    }

    @SuppressWarnings("unchecked")
    public static List<Object> arr(Map<String, Object> m, String k) {
        Object v = m == null ? null : m.get(k);
        return v instanceof List ? (List<Object>) v : null;
    }

    /** Returns the list of strings at k, or null if absent or any element is not a string. */
    public static List<String> strList(Map<String, Object> m, String k) {
        List<Object> a = arr(m, k);
        if (a == null) return null;
        List<String> out = new ArrayList<>();
        for (Object o : a) {
            if (!(o instanceof String)) return null;
            out.add((String) o);
        }
        return out;
    }

    // ---- writer ----------------------------------------------------------

    public static String write(Object v) {
        StringBuilder b = new StringBuilder();
        write(b, v);
        return b.toString();
    }

    @SuppressWarnings("unchecked")
    private static void write(StringBuilder b, Object v) {
        if (v == null) {
            b.append("null");
        } else if (v instanceof String) {
            quote(b, (String) v);
        } else if (v instanceof Number || v instanceof Boolean) {
            if (v instanceof Double && ((Double) v) == Math.rint((Double) v) && !Double.isInfinite((Double) v)) {
                b.append(((Double) v).longValue());
            } else {
                b.append(v);
            }
        } else if (v instanceof Map) {
            b.append('{');
            boolean first = true;
            for (Map.Entry<String, Object> e : ((Map<String, Object>) v).entrySet()) {
                if (!first) b.append(',');
                first = false;
                quote(b, e.getKey());
                b.append(':');
                write(b, e.getValue());
            }
            b.append('}');
        } else if (v instanceof Iterable) {
            b.append('[');
            boolean first = true;
            for (Object o : (Iterable<Object>) v) {
                if (!first) b.append(',');
                first = false;
                write(b, o);
            }
            b.append(']');
        } else {
            quote(b, v.toString());
        }
    }

    public static String quote(String str) {
        StringBuilder b = new StringBuilder();
        quote(b, str);
        return b.toString();
    }

    private static void quote(StringBuilder b, String str) {
        b.append('"');
        for (int k = 0; k < str.length(); k++) {
            char c = str.charAt(k);
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
                    else b.append(c);
            }
        }
        b.append('"');
    }

    /** Convenience builder for small JSON objects. */
    public static Map<String, Object> map(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int k = 0; k + 1 < kv.length; k += 2) m.put((String) kv[k], kv[k + 1]);
        return m;
    }
}
