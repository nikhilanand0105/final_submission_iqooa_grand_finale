package dev.guardianai.shield.network.url;

import java.util.*;

/**
 * Immutable representation of a parsed and normalised URL.
 * Preserves the original input for display while providing normalised components
 * and structural properties for forensic analysis.
 */
public class ParsedUrl {

    private final String originalInput;
    private final String normalizedUrl;
    private final String scheme;
    private final String rawHost;
    private final String asciiHost;
    private final String unicodeHost;
    private final int port;
    private final String path;
    private final String query;
    private final Map<String, List<String>> queryParams;
    private final String fragment;
    private final String userInfo;

    // Structural properties
    private final boolean isIpAddress;
    private final String ipAddressType; // "IPV4", "IPV6", "OBFUSCATED_NUMERIC", or null
    private final boolean hasUserInfo;
    private final boolean isPunycode;
    private final boolean containsNonAscii;
    private final boolean hasExcessiveEncoding;
    private final boolean isNonStandardPort;
    private final boolean schemeImplicitlyAdded;

    public ParsedUrl(
            String originalInput,
            String normalizedUrl,
            String scheme,
            String rawHost,
            String asciiHost,
            String unicodeHost,
            int port,
            String path,
            String query,
            Map<String, List<String>> queryParams,
            String fragment,
            String userInfo,
            boolean isIpAddress,
            String ipAddressType,
            boolean hasUserInfo,
            boolean isPunycode,
            boolean containsNonAscii,
            boolean hasExcessiveEncoding,
            boolean isNonStandardPort,
            boolean schemeImplicitlyAdded) {
        this.originalInput = Objects.requireNonNull(originalInput, "originalInput cannot be null");
        this.normalizedUrl = Objects.requireNonNull(normalizedUrl, "normalizedUrl cannot be null");
        this.scheme = scheme != null ? scheme.toLowerCase(Locale.ROOT) : "";
        this.rawHost = rawHost != null ? rawHost : "";
        this.asciiHost = asciiHost != null ? asciiHost.toLowerCase(Locale.ROOT) : "";
        this.unicodeHost = unicodeHost != null ? unicodeHost.toLowerCase(Locale.ROOT) : "";
        this.port = port;
        this.path = path != null ? path : "/";
        this.query = query != null ? query : "";
        this.queryParams = queryParams != null ? Collections.unmodifiableMap(queryParams) : Collections.emptyMap();
        this.fragment = fragment != null ? fragment : "";
        this.userInfo = userInfo != null ? userInfo : "";
        this.isIpAddress = isIpAddress;
        this.ipAddressType = ipAddressType;
        this.hasUserInfo = hasUserInfo;
        this.isPunycode = isPunycode;
        this.containsNonAscii = containsNonAscii;
        this.hasExcessiveEncoding = hasExcessiveEncoding;
        this.isNonStandardPort = isNonStandardPort;
        this.schemeImplicitlyAdded = schemeImplicitlyAdded;
    }

    public String getOriginalInput() {
        return originalInput;
    }

    public String getNormalizedUrl() {
        return normalizedUrl;
    }

    public String getScheme() {
        return scheme;
    }

    public String getRawHost() {
        return rawHost;
    }

    public String getAsciiHost() {
        return asciiHost;
    }

    public String getUnicodeHost() {
        return unicodeHost;
    }

    public int getPort() {
        return port;
    }

    public String getPath() {
        return path;
    }

    public String getQuery() {
        return query;
    }

    public Map<String, List<String>> getQueryParams() {
        return queryParams;
    }

    public String getFragment() {
        return fragment;
    }

    public String getUserInfo() {
        return userInfo;
    }

    public boolean isIpAddress() {
        return isIpAddress;
    }

    public String getIpAddressType() {
        return ipAddressType;
    }

    public boolean hasUserInfo() {
        return hasUserInfo;
    }

    public boolean isPunycode() {
        return isPunycode;
    }

    public boolean containsNonAscii() {
        return containsNonAscii;
    }

    public boolean hasExcessiveEncoding() {
        return hasExcessiveEncoding;
    }

    public boolean isNonStandardPort() {
        return isNonStandardPort;
    }

    public boolean isSchemeImplicitlyAdded() {
        return schemeImplicitlyAdded;
    }

    public List<String> getHostLabels() {
        if (asciiHost.isEmpty()) return Collections.emptyList();
        return Arrays.asList(asciiHost.split("\\."));
    }

    public String getTopLevelDomain() {
        if (asciiHost.isEmpty() || isIpAddress) return "";
        int lastDot = asciiHost.lastIndexOf('.');
        if (lastDot >= 0 && lastDot < asciiHost.length() - 1) {
            return asciiHost.substring(lastDot);
        }
        return "";
    }

    /**
     * Returns the registrable domain (e.g. "example.com" from "sub.example.com" or "bank.co.in").
     */
    public String getRegistrableDomain() {
        if (asciiHost.isEmpty() || isIpAddress) return asciiHost;
        String[] labels = asciiHost.split("\\.");
        if (labels.length <= 2) return asciiHost;

        // Check common two-part ccTLDs (.co.in, .gov.in, .org.in, .co.uk, etc.)
        int n = labels.length;
        String lastTwo = labels[n - 2] + "." + labels[n - 1];
        if ((labels[n - 1].length() == 2 && (labels[n - 2].equals("co") || labels[n - 2].equals("com")
                || labels[n - 2].equals("gov") || labels[n - 2].equals("org") || labels[n - 2].equals("edu")
                || labels[n - 2].equals("net") || labels[n - 2].equals("ac"))) && n >= 3) {
            return labels[n - 3] + "." + lastTwo;
        }

        return labels[n - 2] + "." + labels[n - 1];
    }

    @Override
    public String toString() {
        return normalizedUrl;
    }
}
