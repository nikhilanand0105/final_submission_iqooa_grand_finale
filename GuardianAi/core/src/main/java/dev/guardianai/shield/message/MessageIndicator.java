package dev.guardianai.shield.message;

import dev.guardianai.model.ThreatSeverity;

import java.util.Objects;

/**
 * An observable forensic or behavioural signal identified in message content.
 */
public final class MessageIndicator {
    private final String indicatorId;
    private final MessageIndicatorType type;
    private final ThreatSeverity severity;
    private final String title;
    private final String plainLanguageExplanation;
    private final EvidenceSpan evidenceSpan;

    public MessageIndicator(
            String indicatorId,
            MessageIndicatorType type,
            ThreatSeverity severity,
            String title,
            String plainLanguageExplanation,
            EvidenceSpan evidenceSpan) {
        this.indicatorId = Objects.requireNonNull(indicatorId, "indicatorId cannot be null");
        this.type = Objects.requireNonNull(type, "type cannot be null");
        this.severity = Objects.requireNonNull(severity, "severity cannot be null");
        this.title = Objects.requireNonNull(title, "title cannot be null");
        this.plainLanguageExplanation = Objects.requireNonNull(plainLanguageExplanation, "plainLanguageExplanation cannot be null");
        this.evidenceSpan = evidenceSpan;
    }

    public String getIndicatorId() {
        return indicatorId;
    }

    public MessageIndicatorType getType() {
        return type;
    }

    public ThreatSeverity getSeverity() {
        return severity;
    }

    public String getTitle() {
        return title;
    }

    public String getPlainLanguageExplanation() {
        return plainLanguageExplanation;
    }

    public EvidenceSpan getEvidenceSpan() {
        return evidenceSpan;
    }

    public String getEvidenceText() {
        return evidenceSpan != null ? evidenceSpan.getMatchedText() : "";
    }

    @Override
    public String toString() {
        return "MessageIndicator{" +
                "id='" + indicatorId + '\'' +
                ", type=" + type +
                ", severity=" + severity +
                ", title='" + title + '\'' +
                ", evidence=" + (evidenceSpan != null ? evidenceSpan.getMatchedText() : "none") +
                '}';
    }
}
