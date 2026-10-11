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
    private final String evidenceSource;
    private final String riskRationale;
    private final boolean isDirectFact;

    public ThreatIndicator(String id, String title, String description, ThreatSeverity severity, String category) {
        this(id, title, description, severity, category, null, null,
                "SIGNATURE".equalsIgnoreCase(category) || "PERMISSIONS".equalsIgnoreCase(category) || "CONTAINER".equalsIgnoreCase(category));
    }

    public ThreatIndicator(String id, String title, String description, ThreatSeverity severity, String category,
                           String evidenceSource, String riskRationale, boolean isDirectFact) {
        this.id = id;
        this.title = title;
        this.description = description;
        this.severity = severity;
        this.category = category;
        this.evidenceSource = evidenceSource;
        this.riskRationale = riskRationale;
        this.isDirectFact = isDirectFact;
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

    public String getEvidenceSource() {
        if (evidenceSource != null && !evidenceSource.isEmpty()) {
            return evidenceSource;
        }
        if ("PERMISSIONS".equalsIgnoreCase(category)) return "AndroidManifest.xml";
        if ("BYTECODE".equalsIgnoreCase(category)) return "DEX Bytecode (classes.dex)";
        if ("SIGNATURE".equalsIgnoreCase(category)) return "META-INF Signature Block";
        if ("CONTAINER".equalsIgnoreCase(category)) return "APK Archive Container";
        if ("REPUTATION".equalsIgnoreCase(category)) return "Threat Intelligence Hash Registry";
        if ("ASSETS".equalsIgnoreCase(category)) return "APK Assets Directory";
        return "Static Analysis Engine";
    }

    public String getRiskRationale() {
        if (riskRationale != null && !riskRationale.isEmpty()) {
            return riskRationale;
        }
        return description;
    }

    public boolean isDirectFact() {
        return isDirectFact;
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
