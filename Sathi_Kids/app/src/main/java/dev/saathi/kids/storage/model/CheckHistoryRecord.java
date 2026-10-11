package dev.saathi.kids.storage.model;

/**
 * Minimized on-device audit record for safety checks.
 * In accordance with strict child privacy requirements, raw message text,
 * URLs, and file payloads are NEVER stored by default. Only inspection metadata is retained.
 */
public class CheckHistoryRecord {
    private final String recordId;
    private final String checkType; // "MESSAGE", "LINK", "FILE"
    private final long timestamp;
    private final String engineIdentifier;
    private final String resultCategory; // e.g., "LOOKS_OKAY", "WARNING_SIGNS", "BE_CAREFUL", "CANNOT_TELL"
    private final String summary;
    private final String indicatorsSummary; // Formatted non-sensitive warning cues
    private final String status; // "EVALUATED", "FAILED"

    public CheckHistoryRecord(
            String recordId,
            String checkType,
            long timestamp,
            String engineIdentifier,
            String resultCategory,
            String summary,
            String indicatorsSummary,
            String status) {
        this.recordId = recordId;
        this.checkType = checkType;
        this.timestamp = timestamp;
        this.engineIdentifier = engineIdentifier;
        this.resultCategory = resultCategory;
        this.summary = summary;
        this.indicatorsSummary = indicatorsSummary != null ? indicatorsSummary : "";
        this.status = status;
    }

    public String getRecordId() {
        return recordId;
    }

    public String getCheckType() {
        return checkType;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public String getEngineIdentifier() {
        return engineIdentifier;
    }

    public String getResultCategory() {
        return resultCategory;
    }

    public String getSummary() {
        return summary;
    }

    public String getIndicatorsSummary() {
        return indicatorsSummary;
    }

    public String getStatus() {
        return status;
    }
}
