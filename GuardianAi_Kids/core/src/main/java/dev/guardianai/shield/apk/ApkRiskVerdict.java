package dev.guardianai.shield.apk;

/** File-check verdicts. None of these means "malware-free" or "100% safe". */
public enum ApkRiskVerdict {
    /** The file could not be analysed at all (empty, not an APK, corrupt, too big, unreadable, cancelled). */
    CANNOT_ANALYSE("Couldn't check this file"),
    /** The file was partly analysed; important parts could not be read. */
    ANALYSIS_INCOMPLETE("Check is incomplete"),
    /** Static indicators were found in the file. Indicators are not proof of malware. */
    STATIC_INDICATORS_FOUND("Warning signs found in this app"),
    /** A configured threat-intelligence provider recognised this exact file. */
    KNOWN_THREAT_MATCH("Known harmful app"),
    /** The static checks that ran found nothing suspicious. */
    NO_SUSPICIOUS_STATIC_INDICATORS("No warning signs found by these checks");

    private final String label;

    ApkRiskVerdict(String label) {
        this.label = label;
    }

    public String getLabel() { return label; }
}
