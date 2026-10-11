package dev.guardianai.shield.url;

/**
 * Online URL reputation lookup. Implementations must:
 * - only send {@link ParsedUrl#getSanitizedUrl()} (no user-info, query or fragment);
 * - use HTTPS with a bounded timeout;
 * - map every failure to UNAVAILABLE or TIMEOUT_OR_NETWORK, never to NO_MATCH;
 * - never hold provider secrets on the device.
 */
public interface UrlReputationProvider {

    ReputationResult check(ParsedUrl url);

    /** True when an endpoint is configured; false means lookups will return NOT_CHECKED. */
    boolean isConfigured();

    /** Human-readable provider name for the result screen, e.g. "Google Web Risk (via GuardianAi server)". */
    String getName();

    /** What will be sent and to whom, shown to the child before the first online check. */
    String getDisclosure();

    /** Default provider used when nothing is configured: performs no network access. */
    UrlReputationProvider NONE = new UrlReputationProvider() {
        @Override public ReputationResult check(ParsedUrl url) { return ReputationResult.notChecked("No online safety service is set up in this build"); }
        @Override public boolean isConfigured() { return false; }
        @Override public String getName() { return "Not configured"; }
        @Override public String getDisclosure() { return ""; }
    };
}
