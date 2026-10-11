package dev.guardianai.shield.network.url;

import dev.guardianai.model.ThreatSeverity;

import java.util.Objects;

/**
 * An observable forensic indicator derived from structural or heuristic analysis of a URL.
 * Contains detectable condition, observed evidence, plain-language explanation, and severity rationale.
 */
public class UrlIndicator {

    private final String id;
    private final String category;
    private final String title;
    private final String condition;
    private final String evidence;
    private final String explanation;
    private final String severityRationale;
    private final ThreatSeverity severity;

    public UrlIndicator(
            String id,
            String category,
            String title,
            String condition,
            String evidence,
            String explanation,
            String severityRationale,
            ThreatSeverity severity) {
        this.id = Objects.requireNonNull(id, "id cannot be null");
        this.category = Objects.requireNonNull(category, "category cannot be null");
        this.title = Objects.requireNonNull(title, "title cannot be null");
        this.condition = Objects.requireNonNull(condition, "condition cannot be null");
        this.evidence = Objects.requireNonNull(evidence, "evidence cannot be null");
        this.explanation = Objects.requireNonNull(explanation, "explanation cannot be null");
        this.severityRationale = Objects.requireNonNull(severityRationale, "severityRationale cannot be null");
        this.severity = Objects.requireNonNull(severity, "severity cannot be null");
    }

    public String getId() {
        return id;
    }

    public String getCategory() {
        return category;
    }

    public String getTitle() {
        return title;
    }

    public String getCondition() {
        return condition;
    }

    public String getEvidence() {
        return evidence;
    }

    public String getExplanation() {
        return explanation;
    }

    public String getSeverityRationale() {
        return severityRationale;
    }

    public ThreatSeverity getSeverity() {
        return severity;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        UrlIndicator that = (UrlIndicator) o;
        return id.equals(that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }

    @Override
    public String toString() {
        return String.format("[%s] %s: %s (Evidence: %s)", severity, title, explanation, evidence);
    }
}
