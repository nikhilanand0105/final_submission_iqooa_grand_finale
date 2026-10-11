package dev.guardianai.personal.data.db;

import java.util.Objects;

/**
 * Immutable entity representing a security scan execution.
 * Tracks source, operation type, verdict, severity, and forensic outcome.
 */
public class ScanRecord {

    private final String id;
    private final String operationType;
    private final long timestamp;
    private final String processingStatus;
    private final String summary;
    private final String source;
    private final String analysisVersion;
    private final boolean isConclusive;
    private final String verdict;
    private final String severity;
    private final String actionTaken;

    public ScanRecord(
            String id,
            String operationType,
            long timestamp,
            String processingStatus,
            String summary,
            String source,
            String analysisVersion,
            boolean isConclusive,
            String verdict,
            String severity,
            String actionTaken) {
        this.id = Objects.requireNonNull(id, "id cannot be null");
        this.operationType = Objects.requireNonNull(operationType, "operationType cannot be null");
        this.timestamp = timestamp;
        this.processingStatus = processingStatus != null ? processingStatus : "COMPLETED";
        this.summary = summary != null ? summary : "";
        this.source = source != null ? source : "";
        this.analysisVersion = analysisVersion != null ? analysisVersion : "1.0.0";
        this.isConclusive = isConclusive;
        this.verdict = verdict != null ? verdict : "UNKNOWN";
        this.severity = severity != null ? severity : "INFO";
        this.actionTaken = actionTaken != null ? actionTaken : "";
    }

    public String getId() {
        return id;
    }

    public String getOperationType() {
        return operationType;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public String getProcessingStatus() {
        return processingStatus;
    }

    public String getSummary() {
        return summary;
    }

    public String getSource() {
        return source;
    }

    public String getAnalysisVersion() {
        return analysisVersion;
    }

    public boolean isConclusive() {
        return isConclusive;
    }

    public String getVerdict() {
        return verdict;
    }

    public String getSeverity() {
        return severity;
    }

    public String getActionTaken() {
        return actionTaken;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ScanRecord that = (ScanRecord) o;
        return timestamp == that.timestamp &&
                isConclusive == that.isConclusive &&
                id.equals(that.id) &&
                operationType.equals(that.operationType) &&
                processingStatus.equals(that.processingStatus) &&
                summary.equals(that.summary) &&
                source.equals(that.source) &&
                analysisVersion.equals(that.analysisVersion) &&
                verdict.equals(that.verdict) &&
                severity.equals(that.severity) &&
                actionTaken.equals(that.actionTaken);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, operationType, timestamp, processingStatus, summary, source, analysisVersion, isConclusive, verdict, severity, actionTaken);
    }

    @Override
    public String toString() {
        return "ScanRecord{" +
                "id='" + id + '\'' +
                ", operationType='" + operationType + '\'' +
                ", timestamp=" + timestamp +
                ", processingStatus='" + processingStatus + '\'' +
                ", summary='" + summary + '\'' +
                ", source='" + source + '\'' +
                ", analysisVersion='" + analysisVersion + '\'' +
                ", isConclusive=" + isConclusive +
                ", verdict='" + verdict + '\'' +
                ", severity='" + severity + '\'' +
                ", actionTaken='" + actionTaken + '\'' +
                '}';
    }
}
