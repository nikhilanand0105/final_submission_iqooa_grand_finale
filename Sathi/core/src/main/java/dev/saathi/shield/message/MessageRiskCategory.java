package dev.saathi.shield.message;

/**
 * Categorical safety assessment for user-submitted message content.
 * Strictly describes observable risk levels without making moral judgements
 * about individuals or declaring guilt.
 */
public enum MessageRiskCategory {
    /**
     * Multiple corroborated scam indicators, credential/OTP harvesting,
     * or high-danger coercion patterns observed.
     */
    HIGH_RISK,

    /**
     * Notable threat indicators (unverified links, urgency, suspension lures)
     * detected that warrant heightened caution.
     */
    SUSPICIOUS,

    /**
     * Sensitive terminology or financial keywords present in conversational
     * context with incomplete evidence of malicious intent.
     */
    AMBIGUOUS,

    /**
     * Everyday conversation or legitimate informational notification with
     * no observable threat indicators.
     */
    LOW_RISK,

    /**
     * Input is blank, whitespace-only, or too brief to meaningfully evaluate.
     */
    INSUFFICIENT_INPUT;

    public dev.saathi.model.ScanVerdict toScanVerdict() {
        switch (this) {
            case HIGH_RISK:
                return dev.saathi.model.ScanVerdict.KNOWN_MALICIOUS;
            case SUSPICIOUS:
                return dev.saathi.model.ScanVerdict.HIGH_RISK;
            case AMBIGUOUS:
                return dev.saathi.model.ScanVerdict.CAUTION;
            case LOW_RISK:
            case INSUFFICIENT_INPUT:
            default:
                return dev.saathi.model.ScanVerdict.NO_KNOWN_THREAT_DETECTED;
        }
    }
}
