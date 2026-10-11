package dev.guardianai.sense.analyzer;

import java.util.Objects;

/**
 * An individual observable safety pattern detected within a message.
 */
public class SafetyIndicator {
    private final String id;
    private final SafetyIndicatorCategory category;
    private final String name;
    private final String description;
    private final String evidenceExcerpt;
    private final IndicatorSeverity severity;

    public SafetyIndicator(
            String id,
            SafetyIndicatorCategory category,
            String name,
            String description,
            String evidenceExcerpt,
            IndicatorSeverity severity) {
        this.id = id;
        this.category = category;
        this.name = name;
        this.description = description;
        this.evidenceExcerpt = evidenceExcerpt != null ? evidenceExcerpt : "";
        this.severity = severity;
    }

    public String getId() {
        return id;
    }

    public SafetyIndicatorCategory getCategory() {
        return category;
    }

    public String getName() {
        return name;
    }

    public String getDescription() {
        return description;
    }

    public String getEvidenceExcerpt() {
        return evidenceExcerpt;
    }

    public IndicatorSeverity getSeverity() {
        return severity;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SafetyIndicator that = (SafetyIndicator) o;
        return Objects.equals(id, that.id) &&
                Objects.equals(evidenceExcerpt, that.evidenceExcerpt);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, evidenceExcerpt);
    }

    @Override
    public String toString() {
        return "[" + category + "] " + name + " (Evidence: '" + evidenceExcerpt + "')";
    }
}
