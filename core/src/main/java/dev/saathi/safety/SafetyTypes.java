package dev.saathi.safety;

/** Enumerations shared by the safety classification pipeline. Model output must map onto these exactly. */
public final class SafetyTypes {

    private SafetyTypes() {}

    /** Where analysed content came from. */
    public enum SourceType {
        NOTIFICATION, MANUAL_MESSAGE, MANUAL_LINK, BROWSER_URL, BROWSER_SEARCH, BROWSER_PAGE
    }

    /** Threatening / coercive behaviour (feeds the Threats flag). */
    public enum ThreatKind {
        NONE, BLACKMAIL, HARM_THREAT, EXPOSURE_THREAT, PAYMENT_COERCION, CREDENTIAL_DEMAND, INTIMIDATION
    }

    /** Self-harm related content (feeds the Suicide/Self-harm flag only for personal-risk kinds). */
    public enum SelfHarmKind {
        NONE,
        /** First-person statement of intent or plan. */
        PERSONAL_INTENT,
        /** First-person thoughts/wishes without a stated plan. */
        PERSONAL_IDEATION,
        /** Asking for help with self-harm feelings. */
        HELP_SEEKING,
        /** Education, school work, research. */
        INFORMATIONAL,
        /** News, prevention or awareness material. */
        NEWS_OR_PREVENTION,
        /** Mentions self-harm but the context can't be determined. */
        AMBIGUOUS;

        public boolean isPersonalRisk() {
            return this == PERSONAL_INTENT || this == PERSONAL_IDEATION || this == HELP_SEEKING;
        }
    }

    public enum ScamKind { NONE, PRIZE_OR_REWARD, CREDENTIAL_PHISHING, PAYMENT_REQUEST, IMPERSONATION, GROOMING_OR_SECRECY }

    public enum WebsiteConcern { NONE, SUSPECTED_SPOOF, KNOWN_HARMFUL, SUSPICIOUS_STRUCTURE, UNKNOWN }

    public enum AgeConcern { NONE, EXPLICIT_CONTENT, GAMBLING, VIOLENCE, SELF_HARM_MATERIAL, UNKNOWN }

    public enum Severity {
        NONE(0), LOW(1), MEDIUM(2), HIGH(3), IMMINENT(4);
        public final int rank;
        Severity(int r) { rank = r; }
        public static Severity max(Severity a, Severity b) { return a.rank >= b.rank ? a : b; }
    }

    public enum Confidence { LOW, MEDIUM, HIGH }

    /** Truthful state of the analysis itself. NEEDS_REVIEW / UNAVAILABLE are never "safe". */
    public enum Status { COMPLETE, NEEDS_REVIEW, PENDING, UNAVAILABLE, CONTENT_UNAVAILABLE }

    /** Who produced the final result. */
    public enum Source {
        GEMMA, GEMMA_WITH_GUARD, RULES_FALLBACK, RULES_WITH_GUARD, TECHNICAL_CHECKS, COMBINED, NONE;

        public boolean usedModel() {
            return this == GEMMA || this == GEMMA_WITH_GUARD || this == COMBINED;
        }

        public String label() {
            switch (this) {
                case GEMMA: return "On-device Gemma model";
                case GEMMA_WITH_GUARD: return "On-device Gemma model + Saathi safety rules";
                case RULES_FALLBACK: return "Saathi safety rules (AI model not used)";
                case RULES_WITH_GUARD: return "Saathi safety rules (AI model not used)";
                case TECHNICAL_CHECKS: return "Technical address checks";
                case COMBINED: return "On-device Gemma model + technical checks";
                default: return "Not analysed";
            }
        }
    }
}
