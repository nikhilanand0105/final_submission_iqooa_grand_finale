package dev.guardianai.storage;

import dev.guardianai.model.ScanVerdict;

import java.util.Date;

/**
 * Minimized on-device audit record of an APK or file scan.
 * Under GuardianAi's privacy policy, the raw APK file is never stored—only the cryptographic hash and verdict metadata.
 */
public class ScanHistoryRecord {
    private final String scanId;
    private final Date timestamp;
    private final String fileName;
    private final String sha256Checksum;
    private final ScanVerdict verdict;
    private final int threatCount;
    private String userActionTaken; // e.g., "CANCELLED_INSTALL", "DELETED_FILE", "SYSTEM_INSTALL_PROCEEDED"

    public ScanHistoryRecord(
            String scanId,
            Date timestamp,
            String fileName,
            String sha256Checksum,
            ScanVerdict verdict,
            int threatCount,
            String userActionTaken) {
        this.scanId = scanId;
        this.timestamp = timestamp != null ? timestamp : new Date();
        this.fileName = fileName;
        this.sha256Checksum = sha256Checksum;
        this.verdict = verdict;
        this.threatCount = threatCount;
        this.userActionTaken = userActionTaken;
    }

    public String getScanId() {
        return scanId;
    }

    public Date getTimestamp() {
        return timestamp;
    }

    public String getFileName() {
        return fileName;
    }

    public String getSha256Checksum() {
        return sha256Checksum;
    }

    public ScanVerdict getVerdict() {
        return verdict;
    }

    public int getThreatCount() {
        return threatCount;
    }

    public String getUserActionTaken() {
        return userActionTaken;
    }

    public void setUserActionTaken(String action) {
        this.userActionTaken = action;
    }
}
