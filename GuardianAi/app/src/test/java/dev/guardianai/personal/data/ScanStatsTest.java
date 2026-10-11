package dev.guardianai.personal.data;

import org.junit.Test;

import dev.guardianai.personal.data.db.ScanStats;

import static org.junit.Assert.*;

public class ScanStatsTest {

    @Test
    public void testEmptyStats() {
        ScanStats stats = ScanStats.empty();
        assertEquals(0, stats.getTotalScans());
        assertEquals(0, stats.getSafeCount());
        assertEquals(0, stats.getSuspiciousCount());
        assertEquals(0, stats.getMaliciousCount());
        assertEquals(0, stats.getUnknownCount());
        assertEquals(100, stats.getCleanRate()); // 100% clean baseline when 0 scans
    }

    @Test
    public void testCleanRateCalculation() {
        // 8 safe out of 10 total = 80%
        ScanStats stats = new ScanStats(10, 8, 1, 1, 0);
        assertEquals(10, stats.getTotalScans());
        assertEquals(8, stats.getSafeCount());
        assertEquals(1, stats.getSuspiciousCount());
        assertEquals(1, stats.getMaliciousCount());
        assertEquals(80, stats.getCleanRate());

        // 0 safe out of 5 total = 0%
        ScanStats allThreats = new ScanStats(5, 0, 3, 2, 0);
        assertEquals(0, allThreats.getCleanRate());

        // 10 safe out of 10 total = 100%
        ScanStats allSafe = new ScanStats(10, 10, 0, 0, 0);
        assertEquals(100, allSafe.getCleanRate());
    }

    @Test
    public void testEqualsAndHashCode() {
        ScanStats s1 = new ScanStats(5, 4, 1, 0, 0);
        ScanStats s2 = new ScanStats(5, 4, 1, 0, 0);
        ScanStats s3 = new ScanStats(5, 3, 1, 1, 0);

        assertEquals(s1, s2);
        assertEquals(s1.hashCode(), s2.hashCode());
        assertNotEquals(s1, s3);
    }
}
