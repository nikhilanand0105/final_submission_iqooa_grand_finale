package dev.guardianai.shield.url;

import dev.guardianai.model.ThreatSeverity;

import java.util.Objects;

/**
 * An individual observable structural warning sign detected in a URL.
 */
public class UrlStructuralIndicator {

    private final String id;
    private final String name;
    private final String description;
    private final String evidenceExcerpt;
    private final ThreatSeverity severity;

    public UrlStructuralIndicator(
            String id,
            String name,
            String description,
            String evidenceExcerpt,
            ThreatSeverity severity) {
        this.id = id;
        this.name = name;
        this.description = description;
        this.evidenceExcerpt = evidenceExcerpt != null ? evidenceExcerpt : "";
        this.severity = severity != null ? severity : ThreatSeverity.INFO;
    }

    public String getId() {
        return id;
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

    public ThreatSeverity getSeverity() {
        return severity;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        UrlStructuralIndicator that = (UrlStructuralIndicator) o;
        return Objects.equals(id, that.id) && Objects.equals(evidenceExcerpt, that.evidenceExcerpt);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, evidenceExcerpt);
    }

    @Override
    public String toString() {
        return "[" + severity + "] " + name + ": " + description + " (Excerpt: '" + evidenceExcerpt + "')";
    }
}
