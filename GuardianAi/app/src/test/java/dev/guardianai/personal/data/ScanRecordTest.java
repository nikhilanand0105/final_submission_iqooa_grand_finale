package dev.guardianai.personal.data;

import org.junit.Test;

import dev.guardianai.personal.data.db.ScanRecord;

import static org.junit.Assert.*;

public class ScanRecordTest {

    @Test
    public void testValidScanRecordCreation() {
        long now = System.currentTimeMillis();
        ScanRecord record = new ScanRecord(
                "scan-001",
                "APK",
                now,
                "COMPLETED",
                "Clean utility package",
                "utility.apk",
                "1.0.0",
                true,
                "SAFE",
                "INFO",
                "Install approved"
        );

        assertEquals("scan-001", record.getId());
        assertEquals("APK", record.getOperationType());
        assertEquals(now, record.getTimestamp());
        assertEquals("COMPLETED", record.getProcessingStatus());
        assertEquals("Clean utility package", record.getSummary());
        assertEquals("utility.apk", record.getSource());
        assertEquals("1.0.0", record.getAnalysisVersion());
        assertTrue(record.isConclusive());
        assertEquals("SAFE", record.getVerdict());
        assertEquals("INFO", record.getSeverity());
        assertEquals("Install approved", record.getActionTaken());
    }

    @Test
    public void testNullParametersDefaultGracefully() {
        ScanRecord record = new ScanRecord(
                "scan-002",
                "LINK",
                1000L,
                null,
                null,
                null,
                null,
                false,
                null,
                null,
                null
        );

        assertEquals("COMPLETED", record.getProcessingStatus());
        assertEquals("", record.getSummary());
        assertEquals("", record.getSource());
        assertEquals("1.0.0", record.getAnalysisVersion());
        assertFalse(record.isConclusive());
        assertEquals("UNKNOWN", record.getVerdict());
        assertEquals("INFO", record.getSeverity());
        assertEquals("", record.getActionTaken());
    }

    @Test(expected = NullPointerException.class)
    public void testNullIdThrowsException() {
        new ScanRecord(
                null,
                "APK",
                1000L,
                "COMPLETED",
                "summary",
                "source",
                "1.0.0",
                true,
                "SAFE",
                "INFO",
                "action"
        );
    }

    @Test(expected = NullPointerException.class)
    public void testNullOperationTypeThrowsException() {
        new ScanRecord(
                "scan-003",
                null,
                1000L,
                "COMPLETED",
                "summary",
                "source",
                "1.0.0",
                true,
                "SAFE",
                "INFO",
                "action"
        );
    }

    @Test
    public void testEqualsAndHashCode() {
        long now = 1700000000000L;
        ScanRecord r1 = new ScanRecord("id1", "APK", now, "COMPLETED", "sum", "src", "1.0.0", true, "SAFE", "INFO", "act");
        ScanRecord r2 = new ScanRecord("id1", "APK", now, "COMPLETED", "sum", "src", "1.0.0", true, "SAFE", "INFO", "act");
        ScanRecord r3 = new ScanRecord("id2", "APK", now, "COMPLETED", "sum", "src", "1.0.0", true, "SAFE", "INFO", "act");

        assertEquals(r1, r2);
        assertEquals(r1.hashCode(), r2.hashCode());
        assertNotEquals(r1, r3);
    }
}
