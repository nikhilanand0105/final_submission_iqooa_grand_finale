package dev.saathi.personal.data;

import org.junit.Test;

import dev.saathi.personal.data.db.SaathiDatabaseHelper;

import static org.junit.Assert.*;

public class DatabaseSchemaTest {

    @Test
    public void testDatabaseConstants() {
        assertEquals("saathi_personal.db", SaathiDatabaseHelper.DATABASE_NAME);
        assertEquals(1, SaathiDatabaseHelper.DATABASE_VERSION);

        assertEquals("scan_records", SaathiDatabaseHelper.TABLE_SCANS);
        assertEquals("id", SaathiDatabaseHelper.COL_SCAN_ID);
        assertEquals("operation_type", SaathiDatabaseHelper.COL_SCAN_OPERATION_TYPE);
        assertEquals("timestamp", SaathiDatabaseHelper.COL_SCAN_TIMESTAMP);
        assertEquals("processing_status", SaathiDatabaseHelper.COL_SCAN_PROCESSING_STATUS);
        assertEquals("summary", SaathiDatabaseHelper.COL_SCAN_SUMMARY);
        assertEquals("source", SaathiDatabaseHelper.COL_SCAN_SOURCE);
        assertEquals("analysis_version", SaathiDatabaseHelper.COL_SCAN_ANALYSIS_VERSION);
        assertEquals("is_conclusive", SaathiDatabaseHelper.COL_SCAN_IS_CONCLUSIVE);
        assertEquals("verdict", SaathiDatabaseHelper.COL_SCAN_VERDICT);
        assertEquals("severity", SaathiDatabaseHelper.COL_SCAN_SEVERITY);
        assertEquals("action_taken", SaathiDatabaseHelper.COL_SCAN_ACTION_TAKEN);

        assertEquals("finding_records", SaathiDatabaseHelper.TABLE_FINDINGS);
        assertEquals("id", SaathiDatabaseHelper.COL_FINDING_ID);
        assertEquals("scan_id", SaathiDatabaseHelper.COL_FINDING_SCAN_ID);
        assertEquals("indicator_type", SaathiDatabaseHelper.COL_FINDING_INDICATOR_TYPE);
        assertEquals("severity", SaathiDatabaseHelper.COL_FINDING_SEVERITY);
        assertEquals("explanation", SaathiDatabaseHelper.COL_FINDING_EXPLANATION);
        assertEquals("recommended_action", SaathiDatabaseHelper.COL_FINDING_RECOMMENDED_ACTION);
    }
}
