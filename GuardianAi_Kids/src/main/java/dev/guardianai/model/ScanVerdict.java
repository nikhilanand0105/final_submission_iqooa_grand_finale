package dev.guardianai.model;

/**
 * The 5 canonical verdict categories defined in the GuardianAi product specification.
 * GuardianAi must never claim an APK is "100% safe" - clean scans are classified as NO_KNOWN_THREAT_DETECTED.
 */
public enum ScanVerdict {
    KNOWN_MALICIOUS(
        "Known Malicious",
        "Matches a sufficiently reliable known threat indicator or signature."
    ),
    HIGH_RISK(
        "High Risk",
        "Multiple strong indicators of harmful, deceptive, or abusive behaviour detected."
    ),
    CAUTION(
        "Caution",
        "Suspicious, atypical, or unexplained behaviour that requires user review before proceeding."
    ),
    NO_KNOWN_THREAT_DETECTED(
        "No Known Threat Detected",
        "Static checks completed without identifying known malicious patterns. Runtime behaviour cannot be guaranteed."
    ),
    UNABLE_TO_DETERMINE(
        "Unable to Determine",
        "The file is unsupported, encrypted, incomplete, or could not be sufficiently analysed."
    );

    private final String displayName;
    private final String definition;

    ScanVerdict(String displayName, String definition) {
        this.displayName = displayName;
        this.definition = definition;
    }

    public String getDisplayName() {
        return displayName;
    }

    public String getDefinition() {
        return definition;
    }
}
