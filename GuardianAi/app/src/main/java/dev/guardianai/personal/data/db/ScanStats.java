package dev.guardianai.personal.data.db;

import java.util.Objects;

/**
 * Aggregated statistics across all historical security scans.
 */
public class ScanStats {

    private final int totalScans;
    private final int safeCount;
    private final int suspiciousCount;
    private final int maliciousCount;
    private final int unknownCount;

    public ScanStats(int totalScans, int safeCount, int suspiciousCount, int maliciousCount, int unknownCount) {
        this.totalScans = totalScans;
        this.safeCount = safeCount;
        this.suspiciousCount = suspiciousCount;
        this.maliciousCount = maliciousCount;
        this.unknownCount = unknownCount;
    }

    public static ScanStats empty() {
        return new ScanStats(0, 0, 0, 0, 0);
    }

    public int getTotalScans() {
        return totalScans;
    }

    public int getSafeCount() {
        return safeCount;
    }

    public int getSuspiciousCount() {
        return suspiciousCount;
    }

    public int getMaliciousCount() {
        return maliciousCount;
    }

    public int getUnknownCount() {
        return unknownCount;
    }

    /**
     * Calculates clean protection rate percentage (0 - 100).
     * If no scans have been performed yet, returns 100 (clean baseline).
     */
    public int getCleanRate() {
        if (totalScans == 0) return 100;
        return Math.max(0, Math.min(100, (safeCount * 100) / totalScans));
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ScanStats scanStats = (ScanStats) o;
        return totalScans == scanStats.totalScans &&
                safeCount == scanStats.safeCount &&
                suspiciousCount == scanStats.suspiciousCount &&
                maliciousCount == scanStats.maliciousCount &&
                unknownCount == scanStats.unknownCount;
    }

    @Override
    public int hashCode() {
        return Objects.hash(totalScans, safeCount, suspiciousCount, maliciousCount, unknownCount);
    }

    @Override
    public String toString() {
        return "ScanStats{" +
                "totalScans=" + totalScans +
                ", safeCount=" + safeCount +
                ", suspiciousCount=" + suspiciousCount +
                ", maliciousCount=" + maliciousCount +
                ", unknownCount=" + unknownCount +
                ", cleanRate=" + getCleanRate() + "%" +
                '}';
    }
}
