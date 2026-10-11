package dev.saathi.shield.network.url;

/**
 * Explicit outcomes from an online URL threat-reputation service.
 */
public enum ReputationState {
    /**
     * Threat match confirmed by online reputation database (malicious / phishing / malware).
     */
    THREAT_MATCH("Threat Match Confirmed"),

    /**
     * No threat record found in the provider's database.
     */
    NO_KNOWN_THREAT_MATCH("No Known Threat Match"),

    /**
     * The reputation service is unavailable, returned an HTTP error (500/503), or is unconfigured.
     */
    PROVIDER_UNAVAILABLE("Provider Unavailable"),

    /**
     * Network communication timed out or encountered a connection failure.
     * Note: A timeout must NEVER produce a clean result.
     */
    TIMEOUT_NETWORK_ERROR("Timeout / Network Error"),

    /**
     * Live reputation was not checked (e.g. offline mode, unconfigured provider, or disabled).
     */
    NOT_CHECKED("Not Checked"),

    /**
     * Input was malformed, incomplete, or rejected by the reputation service.
     */
    INVALID_INPUT("Invalid Input");

    private final String displayName;

    ReputationState(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }
}
