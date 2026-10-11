package dev.saathi.shield.url;

import java.util.Collections;
import java.util.List;

/**
 * Immutable, decomposed URL. The original input is kept verbatim for display;
 * normalised components are used for analysis. Instances are only created by {@link UrlParser}.
 */
public final class ParsedUrl {

    public enum HostKind { DOMAIN, IPV4, IPV6, IPV4_NONSTANDARD, NONE }

    private final String originalInput;
    private final boolean valid;
    private final String error;

    private final String scheme;
    private final boolean schemeExplicit;
    private final String userInfo;
    private final String rawHost;      // host text exactly as typed (before decoding / IDN)
    private final String asciiHost;    // lower-case, punycode (ACE) form
    private final String unicodeHost;  // lower-case, Unicode form for display
    private final HostKind hostKind;
    private final int port;            // -1 when not explicit
    private final String path;
    private final String query;
    private final String fragment;
    private final List<String> parseNotes; // structural oddities found while parsing (e.g. backslashes, encoded host)

    ParsedUrl(String originalInput, boolean valid, String error, String scheme, boolean schemeExplicit,
              String userInfo, String rawHost, String asciiHost, String unicodeHost, HostKind hostKind,
              int port, String path, String query, String fragment, List<String> parseNotes) {
        this.originalInput = originalInput == null ? "" : originalInput;
        this.valid = valid;
        this.error = error == null ? "" : error;
        this.scheme = nz(scheme);
        this.schemeExplicit = schemeExplicit;
        this.userInfo = nz(userInfo);
        this.rawHost = nz(rawHost);
        this.asciiHost = nz(asciiHost);
        this.unicodeHost = nz(unicodeHost);
        this.hostKind = hostKind == null ? HostKind.NONE : hostKind;
        this.port = port;
        this.path = nz(path);
        this.query = nz(query);
        this.fragment = nz(fragment);
        this.parseNotes = parseNotes == null ? Collections.<String>emptyList() : Collections.unmodifiableList(parseNotes);
    }

    static ParsedUrl invalid(String original, String error) {
        return new ParsedUrl(original, false, error, "", false, "", "", "", "", HostKind.NONE, -1, "", "", "", null);
    }

    private static String nz(String s) {
        return s == null ? "" : s;
    }

    public String getOriginalInput() { return originalInput; }
    public boolean isValid() { return valid; }
    public String getValidationError() { return error; }
    public String getScheme() { return scheme; }
    public boolean isSchemeExplicit() { return schemeExplicit; }
    public String getUserInfo() { return userInfo; }
    public boolean hasUserInfo() { return !userInfo.isEmpty(); }
    public String getRawHost() { return rawHost; }
    public String getAsciiHost() { return asciiHost; }
    public String getUnicodeHost() { return unicodeHost; }
    public HostKind getHostKind() { return hostKind; }
    public int getPort() { return port; }
    public String getPath() { return path; }
    public String getQuery() { return query; }
    public String getFragment() { return fragment; }
    public List<String> getParseNotes() { return parseNotes; }

    public boolean isIpLiteral() {
        return hostKind == HostKind.IPV4 || hostKind == HostKind.IPV6 || hostKind == HostKind.IPV4_NONSTANDARD;
    }

    public boolean isPunycode() {
        return asciiHost.startsWith("xn--") || asciiHost.contains(".xn--");
    }

    /**
     * scheme://host[:port]/path with user-info, query and fragment removed.
     * This is the only form that may leave the device (reputation lookup) or be persisted.
     */
    public String getSanitizedUrl() {
        if (!valid) return "";
        StringBuilder b = new StringBuilder(scheme).append("://");
        b.append(hostKind == HostKind.IPV6 ? "[" + asciiHost + "]" : asciiHost);
        if (port > 0) b.append(':').append(port);
        b.append(path.isEmpty() ? "/" : path);
        return b.toString();
    }

    /** Host only — the most privacy-preserving form, used for local history. */
    public String getDisplayHost() {
        return unicodeHost.isEmpty() ? asciiHost : unicodeHost;
    }

    @Override
    public String toString() {
        return valid ? getSanitizedUrl() : "<invalid url>";
    }
}
