package dev.guardianai.shield.message;

/**
 * Dedicated interface for message risk analysis.
 * Analyzes the actual message content entered by the user rather than
 * picking prewritten results from sample templates.
 */
public interface MessageRiskAnalyzer {

    /**
     * Evaluates user-supplied message text for scam patterns, fraud lures,
     * credential demands, coercion, and social engineering signals.
     *
     * @param rawMessage the exact text entered or pasted by the user.
     * @return explainable assessment contract containing indicators and next steps.
     */
    MessageRiskAssessment analyze(String rawMessage);

    /**
     * Unique identifier for this analysis engine implementation.
     */
    String getEngineId();

    /**
     * Semantic or calendar version for the active rules catalogue.
     */
    String getRulesVersion();
}
