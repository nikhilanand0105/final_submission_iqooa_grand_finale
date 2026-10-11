package dev.saathi.shield.network.url;

import java.util.regex.Pattern;

/**
 * Utility to sanitize URLs for logging and display, stripping authentication tokens,
 * passwords, and sensitive query parameters to prevent telemetry leaks.
 */
public final class UrlSanitizer {

    private static final Pattern SENSITIVE_PARAM_PATTERN = Pattern.compile(
            "(?i)(token|auth|key|secret|password|pwd|api[_-]?key|access[_-]?token|session|jwt|code|otp|pin|bearer)"
    );

    private UrlSanitizer() {}

    /**
     * Sanitizes a URL for secure logging by:
     * 1. Removing user credentials in user-info (e.g., http://user:pass@host -> http://***@host)
     * 2. Masking sensitive query parameter values while preserving non-sensitive parameters and path.
     */
    public static String sanitizeForLog(ParsedUrl parsedUrl) {
        if (parsedUrl == null) return "<null>";
        StringBuilder sb = new StringBuilder();
        sb.append(parsedUrl.getScheme()).append("://");

        if (parsedUrl.hasUserInfo()) {
            sb.append("***@");
        }

        sb.append(parsedUrl.getAsciiHost());

        if (parsedUrl.isNonStandardPort()) {
            sb.append(":").append(parsedUrl.getPort());
        }

        sb.append(parsedUrl.getPath());

        if (!parsedUrl.getQueryParams().isEmpty()) {
            sb.append("?");
            boolean first = true;
            for (var entry : parsedUrl.getQueryParams().entrySet()) {
                String paramName = entry.getKey();
                if (!first) sb.append("&");
                first = false;
                sb.append(paramName).append("=");
                if (SENSITIVE_PARAM_PATTERN.matcher(paramName).find()) {
                    sb.append("[REDACTED]");
                } else {
                    sb.append("[VALUE]");
                }
            }
        }

        return sb.toString();
    }

    public static String sanitizeForLog(String rawUrl) {
        if (rawUrl == null || rawUrl.isBlank()) return "<empty>";
        try {
            ParsedUrl parsed = UrlParser.parse(rawUrl);
            return sanitizeForLog(parsed);
        } catch (Exception e) {
            // If it cannot be parsed, truncate and mask query part
            int qIdx = rawUrl.indexOf('?');
            if (qIdx >= 0) {
                return rawUrl.substring(0, qIdx) + "?[REDACTED_QUERY]";
            }
            return rawUrl.length() > 64 ? rawUrl.substring(0, 64) + "..." : rawUrl;
        }
    }
}
