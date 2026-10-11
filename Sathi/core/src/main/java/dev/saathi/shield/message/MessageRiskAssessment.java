package dev.saathi.shield.message;

import dev.saathi.model.ThreatSeverity;

import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Result contract for message risk analysis.
 * Contains actionable guidance, verifiable evidence excerpts,
 * and explicit limitations and uncertainty disclosures.
 */
public final class MessageRiskAssessment {
    private final MessageRiskCategory category;
    private final ThreatSeverity severity;
    private final List<MessageIndicator> indicators;
    private final String overallSummary;
    private final List<String> suggestedActions;
    private final String limitations;
    private final String engineId;
    private final String rulesVersion;
    private final int inputLength;
    private final long analyzedAt;

    public MessageRiskAssessment(
            MessageRiskCategory category,
            ThreatSeverity severity,
            List<MessageIndicator> indicators,
            String overallSummary,
            List<String> suggestedActions,
            String limitations,
            String engineId,
            String rulesVersion,
            int inputLength,
            long analyzedAt) {
        this.category = Objects.requireNonNull(category, "category cannot be null");
        this.severity = Objects.requireNonNull(severity, "severity cannot be null");
        this.indicators = indicators != null ? Collections.unmodifiableList(indicators) : Collections.emptyList();
        this.overallSummary = overallSummary != null ? overallSummary : "";
        this.suggestedActions = suggestedActions != null ? Collections.unmodifiableList(suggestedActions) : Collections.emptyList();
        this.limitations = limitations != null ? limitations : "";
        this.engineId = engineId != null ? engineId : "";
        this.rulesVersion = rulesVersion != null ? rulesVersion : "";
        this.inputLength = inputLength;
        this.analyzedAt = analyzedAt;
    }

    public MessageRiskCategory getCategory() {
        return category;
    }

    public ThreatSeverity getSeverity() {
        return severity;
    }

    public List<MessageIndicator> getIndicators() {
        return indicators;
    }

    public String getOverallSummary() {
        return overallSummary;
    }

    public List<String> getSuggestedActions() {
        return suggestedActions;
    }

    public String getLimitations() {
        return limitations;
    }

    public String getEngineId() {
        return engineId;
    }

    public String getRulesVersion() {
        return rulesVersion;
    }

    public int getInputLength() {
        return inputLength;
    }

    public long getAnalyzedAt() {
        return analyzedAt;
    }

    public boolean isThreat() {
        return category == MessageRiskCategory.HIGH_RISK || category == MessageRiskCategory.SUSPICIOUS;
    }

    public boolean isAmbiguous() {
        return category == MessageRiskCategory.AMBIGUOUS;
    }

    public int getIndicatorCount() {
        return indicators.size();
    }
}
