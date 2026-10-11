package dev.guardianai.shield.network.url;

import java.net.IDN;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Dedicated URL parser and normaliser.
 * Rejects empty or invalid inputs with clear explanations, normalises whitespace, scheme,
 * host, IDN/punycode, and separates scheme, host, port, path, and query components.
 */
public final class UrlParser {

    private static final int MAX_URL_LENGTH = 4096;

    // Dangerous non-web schemes
    private static final Set<String> DANGEROUS_SCHEMES = new HashSet<>(Arrays.asList(
            "javascript", "data", "file", "blob", "vbscript", "intent", "content", "about"
    ));

    // Regex for standard IPv4 dotted decimal
    private static final Pattern IPV4_PATTERN = Pattern.compile(
            "^(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})$"
    );

    // Regex for IPv6 literal: [::1], [2001:db8::1], etc.
    private static final Pattern IPV6_PATTERN = Pattern.compile(
            "^\\[[0-9a-fA-F:]+\\]$"
    );

    // Regex for single dword/integer or hex/octal IP formats (e.g. 2130706433, 0x7f000001, 017700000001)
    private static final Pattern OBFUSCATED_NUMERIC_IP_PATTERN = Pattern.compile(
            "^(?:0x[0-9a-fA-F]+|0[0-7]+|\\d{8,11})$"
    );

    // Regex for dotted hex/octal mixed IP (e.g. 0x7f.0.0.1, 0177.0.0.1)
    private static final Pattern DOTTED_HEX_OCTAL_PATTERN = Pattern.compile(
            "^(?:0x[0-9a-fA-F]+|0[0-7]+|\\d+)\\.(?:0x[0-9a-fA-F]+|0[0-7]+|\\d+)\\.(?:0x[0-9a-fA-F]+|0[0-7]+|\\d+)\\.(?:0x[0-9a-fA-F]+|0[0-7]+|\\d+)$"
    );

    // Look for double percent-encoding or control-character percent-encoding
    private static final Pattern EXCESSIVE_ENCODING_PATTERN = Pattern.compile(
            "(?i)(%25|%00|%2e%2e|%2f%2f|%5c)"
    );

    private UrlParser() {}

    /**
     * Parses and normalises a raw URL string entered by the user.
     *
     * @param rawInput Raw string entered or pasted by the user.
     * @return Fully parsed and normalised {@link ParsedUrl}.
     * @throws UrlParseException if input is empty, too long, or malformed.
     */
    public static ParsedUrl parse(String rawInput) throws UrlParseException {
        if (rawInput == null) {
            throw new UrlParseException(UrlParseException.ErrorCode.EMPTY_INPUT);
        }

        // 1. Whitespace and length handling
        String input = rawInput.trim();
        if (input.isEmpty()) {
            throw new UrlParseException(UrlParseException.ErrorCode.EMPTY_INPUT);
        }

        if (input.length() > MAX_URL_LENGTH) {
            throw new UrlParseException(UrlParseException.ErrorCode.INPUT_TOO_LONG);
        }

        // Check for embedded line breaks/tabs that might be used for bypasses
        input = input.replace("\r", "").replace("\n", "").replace("\t", "");

        // 2. Unicode safety & normalization
        String normalizedInput;
        try {
            normalizedInput = Normalizer.normalize(input, Normalizer.Form.NFC);
        } catch (Exception e) {
            throw new UrlParseException(UrlParseException.ErrorCode.MALFORMED_UNICODE, "Invalid Unicode sequence detected.");
        }

        // 3. Scheme extraction & validation
        String scheme;
        String remaining;
        boolean schemeImplicit = false;

        int schemeSep = normalizedInput.indexOf("://");
        if (schemeSep > 0) {
            scheme = normalizedInput.substring(0, schemeSep).toLowerCase(Locale.ROOT);
            remaining = normalizedInput.substring(schemeSep + 3);

            if (DANGEROUS_SCHEMES.contains(scheme)) {
                throw new UrlParseException(
                        UrlParseException.ErrorCode.DANGEROUS_SCHEME,
                        "Dangerous scheme '" + scheme + ":' is not a valid web URL."
                );
            }

            if (!scheme.equals("http") && !scheme.equals("https")) {
                throw new UrlParseException(
                        UrlParseException.ErrorCode.INVALID_SCHEME,
                        "Unsupported scheme '" + scheme + "://'. GuardianAi supports HTTP and HTTPS web addresses."
                );
            }
        } else {
            // Check if user entered "scheme:something" without "//"
            int colonIdx = normalizedInput.indexOf(':');
            if (colonIdx > 0 && colonIdx < 16 && !normalizedInput.substring(0, colonIdx).contains("/")) {
                String candidateScheme = normalizedInput.substring(0, colonIdx).toLowerCase(Locale.ROOT);
                if (DANGEROUS_SCHEMES.contains(candidateScheme)) {
                    throw new UrlParseException(
                            UrlParseException.ErrorCode.DANGEROUS_SCHEME,
                            "Dangerous scheme '" + candidateScheme + ":' is not a valid web URL."
                    );
                }
            }

            // Implicit scheme defaults to https
            scheme = "https";
            remaining = normalizedInput;
            schemeImplicit = true;
        }

        // 4. Authority extraction (userInfo, host, port) vs Path/Query
        // Authority ends at the first '/', '?', or '#'
        int pathStart = -1;
        for (int i = 0; i < remaining.length(); i++) {
            char c = remaining.charAt(i);
            if (c == '/' || c == '?' || c == '#') {
                pathStart = i;
                break;
            }
        }

        String authority;
        String pathAndBeyond;
        if (pathStart >= 0) {
            authority = remaining.substring(0, pathStart);
            pathAndBeyond = remaining.substring(pathStart);
        } else {
            authority = remaining;
            pathAndBeyond = "/";
        }

        if (authority.isEmpty()) {
            throw new UrlParseException(UrlParseException.ErrorCode.MISSING_HOST);
        }

        // 5. User-Info extraction (e.g. user:pass@host or bank@evil.com)
        String userInfo = "";
        String hostAndPort = authority;
        boolean hasUserInfo = false;

        int atIdx = authority.lastIndexOf('@');
        if (atIdx >= 0) {
            userInfo = authority.substring(0, atIdx);
            hostAndPort = authority.substring(atIdx + 1);
            hasUserInfo = true;

            if (hostAndPort.isEmpty()) {
                throw new UrlParseException(
                        UrlParseException.ErrorCode.MISSING_HOST,
                        "Deceptive user-info prefix '@' without a destination host."
                );
            }
        }

        // 6. Host and Port extraction
        String rawHost;
        int port = -1;
        boolean isNonStandardPort = false;

        if (hostAndPort.startsWith("[")) {
            // IPv6 literal: [2001:db8::1]:8080
            int closingBracket = hostAndPort.indexOf(']');
            if (closingBracket < 0) {
                throw new UrlParseException(
                        UrlParseException.ErrorCode.MALFORMED_HOST,
                        "Malformed IPv6 address: missing closing bracket."
                );
            }
            rawHost = hostAndPort.substring(0, closingBracket + 1);
            String portPart = hostAndPort.substring(closingBracket + 1);
            if (portPart.startsWith(":")) {
                port = parsePort(portPart.substring(1));
            }
        } else {
            int colonIdx = hostAndPort.lastIndexOf(':');
            if (colonIdx >= 0) {
                rawHost = hostAndPort.substring(0, colonIdx);
                port = parsePort(hostAndPort.substring(colonIdx + 1));
            } else {
                rawHost = hostAndPort;
            }
        }

        if (rawHost.isEmpty()) {
            throw new UrlParseException(UrlParseException.ErrorCode.MISSING_HOST);
        }

        // Determine if port is non-standard
        if (port != -1) {
            if ((scheme.equals("http") && port != 80) || (scheme.equals("https") && port != 443)) {
                isNonStandardPort = true;
            }
        } else {
            port = scheme.equals("https") ? 443 : 80;
        }

        // 7. Host analysis (IP address detection vs Domain IDN/Punycode)
        boolean isIpAddress = false;
        String ipAddressType = null;
        String asciiHost;
        String unicodeHost;
        boolean isPunycode = false;
        boolean containsNonAscii = false;

        // Check for non-ASCII characters
        for (int i = 0; i < rawHost.length(); i++) {
            if (rawHost.charAt(i) > 127) {
                containsNonAscii = true;
                break;
            }
        }

        if (IPV4_PATTERN.matcher(rawHost).matches()) {
            validateIpv4Octets(rawHost);
            isIpAddress = true;
            ipAddressType = "IPV4";
            asciiHost = rawHost.toLowerCase(Locale.ROOT);
            unicodeHost = asciiHost;
        } else if (IPV6_PATTERN.matcher(rawHost).matches()) {
            isIpAddress = true;
            ipAddressType = "IPV6";
            asciiHost = rawHost.toLowerCase(Locale.ROOT);
            unicodeHost = asciiHost;
        } else if (OBFUSCATED_NUMERIC_IP_PATTERN.matcher(rawHost).matches()) {
            isIpAddress = true;
            ipAddressType = "OBFUSCATED_NUMERIC";
            asciiHost = rawHost.toLowerCase(Locale.ROOT);
            unicodeHost = asciiHost;
        } else if (DOTTED_HEX_OCTAL_PATTERN.matcher(rawHost).matches()) {
            isIpAddress = true;
            ipAddressType = "OBFUSCATED_NUMERIC";
            asciiHost = rawHost.toLowerCase(Locale.ROOT);
            unicodeHost = asciiHost;
        } else {
            // Internationalised Domain Name (IDN) / Punycode resolution
            try {
                // Convert Unicode domain to Punycode ASCII
                asciiHost = IDN.toASCII(rawHost, IDN.ALLOW_UNASSIGNED).toLowerCase(Locale.ROOT);
                // Convert Punycode domain to Unicode
                unicodeHost = IDN.toUnicode(rawHost).toLowerCase(Locale.ROOT);
            } catch (Exception e) {
                throw new UrlParseException(
                        UrlParseException.ErrorCode.MALFORMED_HOST,
                        "Could not resolve internationalised domain name: " + e.getMessage()
                );
            }

            if (asciiHost.contains("xn--")) {
                isPunycode = true;
            }

            // Validate domain label constraints
            validateDomainLabels(asciiHost);
        }

        // 8. Path, Query, Fragment extraction
        String path = "/";
        String query = "";
        Map<String, List<String>> queryParams = new LinkedHashMap<>();
        String fragment = "";

        int hashIdx = pathAndBeyond.indexOf('#');
        String pathAndQuery = (hashIdx >= 0) ? pathAndBeyond.substring(0, hashIdx) : pathAndBeyond;
        if (hashIdx >= 0) {
            fragment = pathAndBeyond.substring(hashIdx + 1);
        }

        int qIdx = pathAndQuery.indexOf('?');
        if (qIdx >= 0) {
            path = pathAndQuery.substring(0, qIdx);
            query = pathAndQuery.substring(qIdx + 1);
            queryParams = parseQueryParams(query);
        } else {
            path = pathAndQuery;
        }

        if (path.isEmpty()) {
            path = "/";
        }

        // Normalise path (handle backslashes, consecutive slashes if not leading)
        path = path.replace('\\', '/');

        // Check for excessive or obfuscated encoding (%25, %00, etc.)
        boolean hasExcessiveEncoding = EXCESSIVE_ENCODING_PATTERN.matcher(input).find();

        // 9. Construct canonical normalised URL
        StringBuilder normSb = new StringBuilder();
        normSb.append(scheme).append("://");
        if (hasUserInfo && !userInfo.isEmpty()) {
            normSb.append(userInfo).append("@");
        }
        normSb.append(asciiHost);
        if (isNonStandardPort) {
            normSb.append(":").append(port);
        }
        normSb.append(path);
        if (!query.isEmpty()) {
            normSb.append("?").append(query);
        }
        if (!fragment.isEmpty()) {
            normSb.append("#").append(fragment);
        }
        String normalizedUrl = normSb.toString();

        return new ParsedUrl(
                rawInput,
                normalizedUrl,
                scheme,
                rawHost,
                asciiHost,
                unicodeHost,
                port,
                path,
                query,
                queryParams,
                fragment,
                userInfo,
                isIpAddress,
                ipAddressType,
                hasUserInfo,
                isPunycode,
                containsNonAscii,
                hasExcessiveEncoding,
                isNonStandardPort,
                schemeImplicit
        );
    }

    private static int parsePort(String portStr) throws UrlParseException {
        if (portStr == null || portStr.isEmpty()) {
            throw new UrlParseException(UrlParseException.ErrorCode.INVALID_PORT, "Port specified without a number.");
        }
        try {
            int port = Integer.parseInt(portStr);
            if (port < 1 || port > 65535) {
                throw new UrlParseException(
                        UrlParseException.ErrorCode.INVALID_PORT,
                        "Port '" + port + "' is outside the valid network port range (1-65535)."
                );
            }
            return port;
        } catch (NumberFormatException e) {
            throw new UrlParseException(
                    UrlParseException.ErrorCode.INVALID_PORT,
                    "Invalid port string '" + portStr + "'. Port must be a number between 1 and 65535."
            );
        }
    }

    private static void validateIpv4Octets(String ip) throws UrlParseException {
        String[] octets = ip.split("\\.");
        for (String octet : octets) {
            try {
                int val = Integer.parseInt(octet);
                if (val < 0 || val > 255) {
                    throw new UrlParseException(
                            UrlParseException.ErrorCode.MALFORMED_HOST,
                            "Invalid IPv4 octet value '" + val + "'. Must be between 0 and 255."
                    );
                }
            } catch (NumberFormatException e) {
                throw new UrlParseException(
                        UrlParseException.ErrorCode.MALFORMED_HOST,
                        "Invalid IPv4 address format: " + ip
                );
            }
        }
    }

    private static void validateDomainLabels(String asciiHost) throws UrlParseException {
        if (asciiHost.length() > 253) {
            throw new UrlParseException(
                    UrlParseException.ErrorCode.MALFORMED_HOST,
                    "Hostname length exceeds 253 characters."
            );
        }

        String[] labels = asciiHost.split("\\.", -1);
        for (String label : labels) {
            if (label.isEmpty()) {
                throw new UrlParseException(
                        UrlParseException.ErrorCode.MALFORMED_HOST,
                        "Hostname contains empty label or consecutive dots."
                );
            }
            if (label.length() > 63) {
                throw new UrlParseException(
                        UrlParseException.ErrorCode.MALFORMED_HOST,
                        "Domain label '" + label.substring(0, 20) + "...' exceeds 63 characters."
                );
            }
            if (label.startsWith("-") || label.endsWith("-")) {
                throw new UrlParseException(
                        UrlParseException.ErrorCode.MALFORMED_HOST,
                        "Domain label '" + label + "' cannot start or end with a hyphen."
                );
            }
            // Check label characters (must be alphanumeric or hyphen)
            for (int i = 0; i < label.length(); i++) {
                char c = label.charAt(i);
                if (!Character.isLetterOrDigit(c) && c != '-') {
                    throw new UrlParseException(
                            UrlParseException.ErrorCode.MALFORMED_HOST,
                            "Domain label contains illegal character '" + c + "'."
                    );
                }
            }
        }
    }

    private static Map<String, List<String>> parseQueryParams(String query) {
        Map<String, List<String>> map = new LinkedHashMap<>();
        if (query == null || query.isEmpty()) return map;

        String[] pairs = query.split("&");
        for (String pair : pairs) {
            if (pair.isEmpty()) continue;
            int eqIdx = pair.indexOf('=');
            String key;
            String val = "";
            if (eqIdx >= 0) {
                key = safeUrlDecode(pair.substring(0, eqIdx));
                val = safeUrlDecode(pair.substring(eqIdx + 1));
            } else {
                key = safeUrlDecode(pair);
            }
            map.computeIfAbsent(key, k -> new ArrayList<>()).add(val);
        }
        return map;
    }

    private static String safeUrlDecode(String s) {
        try {
            return URLDecoder.decode(s, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return s; // Fallback to raw string without throwing
        }
    }
}
