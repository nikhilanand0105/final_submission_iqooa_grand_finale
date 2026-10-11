package dev.guardianai.shield.url;

import java.net.IDN;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Parses untrusted URL text into a {@link ParsedUrl}. Never throws; malformed input yields an invalid result
 * with a human-readable reason. Parsing is done by hand (not java.net.URI) so that browser-tolerated but
 * deceptive forms (backslashes, user-info, encoded hosts, numeric IP variants) are observed rather than rejected.
 */
public class UrlParser {

    public static final int MAX_INPUT_LENGTH = 8192;
    public static final String NOTE_BACKSLASH = "BACKSLASH";
    public static final String NOTE_ENCODED_HOST = "ENCODED_HOST";
    public static final String NOTE_TRAILING_DOT = "TRAILING_DOT";

    private static final Pattern SCHEME = Pattern.compile("^[a-zA-Z][a-zA-Z0-9+.-]{0,31}$");
    private static final Pattern IPV4_DOTTED = Pattern.compile("^(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}$");
    private static final Pattern NUMERIC_PART = Pattern.compile("^(0[xX][0-9a-fA-F]*|0[0-7]*|[1-9]\\d*)$");
    private static final Pattern IPV6 = Pattern.compile("^[0-9a-fA-F:.]+(%[0-9a-zA-Z]+)?$");
    private static final Pattern ASCII_LABEL = Pattern.compile("^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$");

    private static final String[] BLOCKED_SCHEMES = {"javascript", "data", "vbscript", "file", "blob", "intent", "content", "about"};

    public ParsedUrl parse(String input) {
        try {
            return doParse(input);
        } catch (RuntimeException e) {
            // Defensive: any unexpected parser defect must surface as "invalid", never as a crash or clean result.
            return ParsedUrl.invalid(input, "The address could not be read");
        }
    }

    private ParsedUrl doParse(String input) {
        if (input == null || input.trim().isEmpty()) {
            return ParsedUrl.invalid(input, "No address was entered");
        }
        if (input.length() > MAX_INPUT_LENGTH) {
            return ParsedUrl.invalid(input, "The address is too long to check (" + input.length() + " characters)");
        }
        String s = input.trim();
        for (int k = 0; k < s.length(); k++) {
            char c = s.charAt(k);
            if (Character.isWhitespace(c) || Character.isISOControl(c)) {
                return ParsedUrl.invalid(input, "The address contains spaces or hidden control characters");
            }
        }

        List<String> notes = new ArrayList<>();
        String scheme = "https";
        boolean explicit = false;
        String rest = s;

        int colon = s.indexOf(':');
        if (colon > 0) {
            String cand = s.substring(0, colon);
            String after = s.substring(colon + 1);
            boolean looksLikePort = after.matches("^\\d{1,5}([/?#].*)?$");
            if (SCHEME.matcher(cand).matches() && !looksLikePort) {
                String lc = cand.toLowerCase(Locale.ROOT);
                for (String b : BLOCKED_SCHEMES) {
                    if (b.equals(lc)) {
                        return ParsedUrl.invalid(input, "This is not a web address (" + lc + ": links can run code or open files)");
                    }
                }
                if (!lc.equals("http") && !lc.equals("https")) {
                    return ParsedUrl.invalid(input, "Only web addresses (http or https) can be checked, not '" + lc + ":'");
                }
                scheme = lc;
                explicit = true;
                rest = after;
                if (rest.contains("\\")) notes.add(NOTE_BACKSLASH);
                rest = rest.replace('\\', '/');
                if (!rest.startsWith("//")) {
                    return ParsedUrl.invalid(input, "The address is missing '//' after '" + lc + ":'");
                }
                rest = rest.substring(2);
            }
        }
        if (!explicit) {
            if (rest.contains("\\")) notes.add(NOTE_BACKSLASH);
            rest = rest.replace('\\', '/');
            if (rest.startsWith("//")) rest = rest.substring(2);
        }

        // Split authority / path / query / fragment
        String fragment = "";
        int h = rest.indexOf('#');
        if (h >= 0) { fragment = rest.substring(h + 1); rest = rest.substring(0, h); }
        String query = "";
        int q = rest.indexOf('?');
        if (q >= 0) { query = rest.substring(q + 1); rest = rest.substring(0, q); }
        String authority = rest;
        String path = "";
        int sl = rest.indexOf('/');
        if (sl >= 0) { authority = rest.substring(0, sl); path = rest.substring(sl); }

        String userInfo = "";
        int at = authority.lastIndexOf('@');
        if (at >= 0) { userInfo = authority.substring(0, at); authority = authority.substring(at + 1); }
        if (authority.isEmpty()) {
            return ParsedUrl.invalid(input, "The address has no website name");
        }

        // Host and port
        String host;
        int port = -1;
        boolean bracketed = false;
        if (authority.startsWith("[")) {
            int close = authority.indexOf(']');
            if (close < 0) return ParsedUrl.invalid(input, "The address has a broken IPv6 host");
            host = authority.substring(1, close);
            String tail = authority.substring(close + 1);
            if (!tail.isEmpty()) {
                if (!tail.startsWith(":")) return ParsedUrl.invalid(input, "Unexpected text after the host");
                port = parsePort(tail.substring(1));
                if (port < 0) return ParsedUrl.invalid(input, "The port number is not valid");
            }
            bracketed = true;
        } else {
            int pc = authority.lastIndexOf(':');
            if (pc >= 0) {
                port = parsePort(authority.substring(pc + 1));
                if (port < 0) return ParsedUrl.invalid(input, "The port number is not valid");
                host = authority.substring(0, pc);
            } else {
                host = authority;
            }
        }
        if (host.isEmpty()) return ParsedUrl.invalid(input, "The address has no website name");
        String rawHost = host;

        if (host.indexOf('%') >= 0 && !bracketed) {
            String dec = percentDecode(host);
            if (dec == null) return ParsedUrl.invalid(input, "The website name has broken %-encoding");
            notes.add(NOTE_ENCODED_HOST);
            host = dec;
        }
        if (host.endsWith(".") && host.length() > 1) {
            notes.add(NOTE_TRAILING_DOT);
            host = host.substring(0, host.length() - 1);
        }

        if (bracketed) {
            if (!IPV6.matcher(host).matches() || host.indexOf(':') < 0) {
                return ParsedUrl.invalid(input, "The IPv6 address is not valid");
            }
            String lc = host.toLowerCase(Locale.ROOT);
            return new ParsedUrl(input, true, "", scheme, explicit, userInfo, rawHost, lc, lc,
                    ParsedUrl.HostKind.IPV6, port, path, query, fragment, notes);
        }

        String lower = host.toLowerCase(Locale.ROOT);
        if (IPV4_DOTTED.matcher(lower).matches()) {
            return new ParsedUrl(input, true, "", scheme, explicit, userInfo, rawHost, lower, lower,
                    ParsedUrl.HostKind.IPV4, port, path, query, fragment, notes);
        }
        if (isNonStandardIpv4(lower)) {
            return new ParsedUrl(input, true, "", scheme, explicit, userInfo, rawHost, lower, lower,
                    ParsedUrl.HostKind.IPV4_NONSTANDARD, port, path, query, fragment, notes);
        }

        String ascii;
        String unicode;
        try {
            ascii = IDN.toASCII(host, IDN.ALLOW_UNASSIGNED).toLowerCase(Locale.ROOT);
            unicode = IDN.toUnicode(ascii, IDN.ALLOW_UNASSIGNED).toLowerCase(Locale.ROOT);
        } catch (IllegalArgumentException e) {
            return ParsedUrl.invalid(input, "The website name contains characters that cannot form a real domain");
        }
        if (ascii.length() > 253) return ParsedUrl.invalid(input, "The website name is too long");
        String[] labels = ascii.split("\\.", -1);
        for (String l : labels) {
            if (l.isEmpty()) return ParsedUrl.invalid(input, "The website name has an empty part (two dots in a row)");
            if (!ASCII_LABEL.matcher(l).matches()) {
                return ParsedUrl.invalid(input, "The website name contains characters that are not allowed");
            }
        }
        if (labels.length < 2 && !ascii.equals("localhost")) {
            return ParsedUrl.invalid(input, "The website name is incomplete (for example, it needs '.com' or '.in')");
        }
        String tld = labels[labels.length - 1];
        if (labels.length >= 2 && tld.matches("^\\d+$")) {
            return ParsedUrl.invalid(input, "The website name ending is not valid");
        }
        return new ParsedUrl(input, true, "", scheme, explicit, userInfo, rawHost, ascii, unicode,
                ParsedUrl.HostKind.DOMAIN, port, path, query, fragment, notes);
    }

    private static int parsePort(String p) {
        if (p.isEmpty() || p.length() > 5 || !p.matches("^\\d+$")) return -1;
        int v = Integer.parseInt(p);
        return (v >= 1 && v <= 65535) ? v : -1;
    }

    /**
     * Browsers accept IPv4 hosts written as a single integer, hex or octal parts, or fewer than four parts
     * (e.g. 3232235777, 0xC0A80101, 0300.0250.1.1, 192.168.257). These are flagged as non-standard IPs.
     */
    static boolean isNonStandardIpv4(String host) {
        String[] parts = host.split("\\.", -1);
        if (parts.length < 1 || parts.length > 4) return false;
        boolean anyNonDecimal = false;
        for (String p : parts) {
            if (p.isEmpty() || !NUMERIC_PART.matcher(p).matches()) return false;
            if (p.length() > 1 && (p.startsWith("0"))) anyNonDecimal = true;
        }
        return parts.length != 4 || anyNonDecimal || !IPV4_DOTTED.matcher(host).matches();
    }

    /** Strict UTF-8 percent decoding; returns null on malformed sequences. */
    static String percentDecode(String s) {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        for (int k = 0; k < s.length(); k++) {
            char c = s.charAt(k);
            if (c == '%') {
                if (k + 2 >= s.length()) return null;
                int hi = Character.digit(s.charAt(k + 1), 16);
                int lo = Character.digit(s.charAt(k + 2), 16);
                if (hi < 0 || lo < 0) return null;
                out.write((hi << 4) | lo);
                k += 2;
            } else {
                int end = k;
                while (end < s.length() && s.charAt(end) != '%') end++;
                byte[] b = s.substring(k, end).getBytes(java.nio.charset.StandardCharsets.UTF_8);
                out.write(b, 0, b.length);
                k = end - 1;
            }
        }
        java.nio.charset.CharsetDecoder d = java.nio.charset.StandardCharsets.UTF_8.newDecoder();
        try {
            return d.decode(java.nio.ByteBuffer.wrap(out.toByteArray())).toString();
        } catch (java.nio.charset.CharacterCodingException e) {
            return null;
        }
    }
}
