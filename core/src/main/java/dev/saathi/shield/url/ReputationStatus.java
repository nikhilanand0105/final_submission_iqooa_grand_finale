package dev.saathi.shield.url;

/**
 * Overall reputation/validity status of a URL check. Keeps online reputation outcomes strictly separate from
 * local structural findings, and keeps every failure mode distinct from "no known threat".
 */
public enum ReputationStatus {
    /** The configured provider reported the URL as a known threat. */
    THREAT_MATCH("Known threat found", "The online safety service lists this address as dangerous."),
    /** The configured provider checked the URL and has no listing for it. Not a guarantee of safety. */
    NO_KNOWN_THREAT("No known threat found", "The online safety service has no warning listed for this address right now."),
    /** Online reputation was not checked, and the local check found warning signs. */
    LOCAL_WARNINGS_ONLY("Warning signs found on this phone", "Only the address structure was checked on this phone. The online safety list was not checked."),
    /** Online reputation was not checked (not configured or not allowed), and no local warning signs were found. */
    LIVE_NOT_CHECKED("Online safety list not checked", "Only the address structure was checked on this phone. The online safety list was not checked."),
    /** The provider is configured but returned an error or an unreadable answer. */
    PROVIDER_UNAVAILABLE("Online check unavailable", "The online safety service didn't give a usable answer, so we can't say what it knows."),
    /** The provider did not answer in time, or there was no network. Never treated as clean. */
    TIMEOUT_OR_NETWORK_ERROR("Online check didn't finish", "The online check timed out or there was no internet, so it didn't finish."),
    /** The input is not a valid web address. */
    INVALID_INPUT("Not a valid web address", "This doesn't look like a complete web address, so it couldn't be checked.");

    private final String title;
    private final String description;

    ReputationStatus(String title, String description) {
        this.title = title;
        this.description = description;
    }

    public String getTitle() { return title; }
    public String getDescription() { return description; }

    /** True only for outcomes where the online provider actually completed a lookup. */
    public boolean isLiveLookupCompleted() {
        return this == THREAT_MATCH || this == NO_KNOWN_THREAT;
    }
}
