package dev.guardianai.model;

import java.util.Objects;

/**
 * A concrete piece of security evidence extracted during static reverse engineering.
 */
public class ThreatIndicator {
    private final String id;
    private final String title;
    private final String description;
    private final ThreatSeverity severity;
    private final String category; // e.g., "PERMISSIONS", "BYTECODE", "SIGNATURE", "ASSETS"

    public ThreatIndicator(String id, String title, String description, ThreatSeverity severity, String category) {
        this.id = id;
        this.title = title;
        this.description = description;
        this.severity = severity;
        this.category = category;
    }

    public String getId() {
        return id;
    }

    public String getTitle() {
        return title;
    }

    public String getDescription() {
        return description;
    }

    public ThreatSeverity getSeverity() {
        return severity;
    }

    public String getCategory() {
        return category;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ThreatIndicator)) return false;
        ThreatIndicator that = (ThreatIndicator) o;
        return Objects.equals(id, that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }

    @Override
    public String toString() {
        return String.format("[%s] %s: %s (%s)", severity, title, description, category);
    }
}
