package dev.guardianai.personal.data;

import org.junit.Test;

import dev.guardianai.personal.data.db.FindingRecord;

import static org.junit.Assert.*;

public class FindingRecordTest {

    @Test
    public void testValidFindingRecordCreation() {
        FindingRecord finding = new FindingRecord(
                "f-001",
                "scan-001",
                "ACCESSIBILITY_ABUSE",
                "CRITICAL",
                "App requests BIND_ACCESSIBILITY_SERVICE",
                "Quarantine immediately"
        );

        assertEquals("f-001", finding.getId());
        assertEquals("scan-001", finding.getScanId());
        assertEquals("ACCESSIBILITY_ABUSE", finding.getIndicatorType());
        assertEquals("CRITICAL", finding.getSeverity());
        assertEquals("App requests BIND_ACCESSIBILITY_SERVICE", finding.getExplanation());
        assertEquals("Quarantine immediately", finding.getRecommendedAction());
    }

    @Test
    public void testNullParametersDefaultGracefully() {
        FindingRecord finding = new FindingRecord(
                "f-002",
                "scan-001",
                null,
                null,
                null,
                null
        );

        assertEquals("UNKNOWN", finding.getIndicatorType());
        assertEquals("INFO", finding.getSeverity());
        assertEquals("", finding.getExplanation());
        assertEquals("", finding.getRecommendedAction());
    }

    @Test(expected = NullPointerException.class)
    public void testNullIdThrowsException() {
        new FindingRecord(null, "scan-001", "TYPE", "INFO", "exp", "rec");
    }

    @Test(expected = NullPointerException.class)
    public void testNullScanIdThrowsException() {
        new FindingRecord("f-003", null, "TYPE", "INFO", "exp", "rec");
    }

    @Test
    public void testEqualsAndHashCode() {
        FindingRecord f1 = new FindingRecord("f1", "s1", "TYPE", "HIGH", "exp", "rec");
        FindingRecord f2 = new FindingRecord("f1", "s1", "TYPE", "HIGH", "exp", "rec");
        FindingRecord f3 = new FindingRecord("f2", "s1", "TYPE", "HIGH", "exp", "rec");

        assertEquals(f1, f2);
        assertEquals(f1.hashCode(), f2.hashCode());
        assertNotEquals(f1, f3);
    }
}
