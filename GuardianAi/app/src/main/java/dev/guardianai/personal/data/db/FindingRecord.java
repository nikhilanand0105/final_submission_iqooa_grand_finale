package dev.guardianai.personal.data.db;

import java.util.Objects;

/**
 * Immutable entity representing a single forensic finding or indicator discovered during a scan.
 * Linked to a parent {@link ScanRecord} via foreign key scanId.
 */
public class FindingRecord {

    private final String id;
    private final String scanId;
    private final String indicatorType;
    private final String severity;
    private final String explanation;
    private final String recommendedAction;

    public FindingRecord(
            String id,
            String scanId,
            String indicatorType,
            String severity,
            String explanation,
            String recommendedAction) {
        this.id = Objects.requireNonNull(id, "id cannot be null");
        this.scanId = Objects.requireNonNull(scanId, "scanId cannot be null");
        this.indicatorType = indicatorType != null ? indicatorType : "UNKNOWN";
        this.severity = severity != null ? severity : "INFO";
        this.explanation = explanation != null ? explanation : "";
        this.recommendedAction = recommendedAction != null ? recommendedAction : "";
    }

    public String getId() {
        return id;
    }

    public String getScanId() {
        return scanId;
    }

    public String getIndicatorType() {
        return indicatorType;
    }

    public String getSeverity() {
        return severity;
    }

    public String getExplanation() {
        return explanation;
    }

    public String getRecommendedAction() {
        return recommendedAction;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        FindingRecord that = (FindingRecord) o;
        return id.equals(that.id) &&
                scanId.equals(that.scanId) &&
                indicatorType.equals(that.indicatorType) &&
                severity.equals(that.severity) &&
                explanation.equals(that.explanation) &&
                recommendedAction.equals(that.recommendedAction);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, scanId, indicatorType, severity, explanation, recommendedAction);
    }

    @Override
    public String toString() {
        return "FindingRecord{" +
                "id='" + id + '\'' +
                ", scanId='" + scanId + '\'' +
                ", indicatorType='" + indicatorType + '\'' +
                ", severity='" + severity + '\'' +
                ", explanation='" + explanation + '\'' +
                ", recommendedAction='" + recommendedAction + '\'' +
                '}';
    }
}
