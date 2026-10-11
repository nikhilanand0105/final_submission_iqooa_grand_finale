package dev.saathi.shield.apk;

/**
 * Optional lookup of a file's SHA-256 in a real threat-intelligence service. Only a configured provider may
 * produce {@link ApkRiskVerdict#KNOWN_THREAT_MATCH}. No embedded hash lists are used.
 */
public interface FileHashReputationProvider {

    enum Outcome { KNOWN_MALICIOUS, NOT_KNOWN, NOT_CHECKED, UNAVAILABLE }

    Outcome check(String sha256Hex);

    boolean isConfigured();

    String getName();

    FileHashReputationProvider NONE = new FileHashReputationProvider() {
        @Override public Outcome check(String sha256Hex) { return Outcome.NOT_CHECKED; }
        @Override public boolean isConfigured() { return false; }
        @Override public String getName() { return "Not configured"; }
    };
}
