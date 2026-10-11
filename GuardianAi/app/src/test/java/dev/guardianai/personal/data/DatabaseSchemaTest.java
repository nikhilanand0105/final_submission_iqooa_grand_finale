package dev.guardianai.personal.data;

import org.junit.Test;

import dev.guardianai.personal.data.db.GuardianAiDatabaseHelper;

import static org.junit.Assert.*;

public class DatabaseSchemaTest {

    @Test
    public void testDatabaseConstants() {
        assertEquals("guardianai_personal.db", GuardianAiDatabaseHelper.DATABASE_NAME);
        assertEquals(1, GuardianAiDatabaseHelper.DATABASE_VERSION);

        assertEquals("scan_records", GuardianAiDatabaseHelper.TABLE_SCANS);
        assertEquals("id", GuardianAiDatabaseHelper.COL_SCAN_ID);
        assertEquals("operation_type", GuardianAiDatabaseHelper.COL_SCAN_OPERATION_TYPE);
        assertEquals("timestamp", GuardianAiDatabaseHelper.COL_SCAN_TIMESTAMP);
        assertEquals("processing_status", GuardianAiDatabaseHelper.COL_SCAN_PROCESSING_STATUS);
        assertEquals("summary", GuardianAiDatabaseHelper.COL_SCAN_SUMMARY);
        assertEquals("source", GuardianAiDatabaseHelper.COL_SCAN_SOURCE);
        assertEquals("analysis_version", GuardianAiDatabaseHelper.COL_SCAN_ANALYSIS_VERSION);
        assertEquals("is_conclusive", GuardianAiDatabaseHelper.COL_SCAN_IS_CONCLUSIVE);
        assertEquals("verdict", GuardianAiDatabaseHelper.COL_SCAN_VERDICT);
        assertEquals("severity", GuardianAiDatabaseHelper.COL_SCAN_SEVERITY);
        assertEquals("action_taken", GuardianAiDatabaseHelper.COL_SCAN_ACTION_TAKEN);

        assertEquals("finding_records", GuardianAiDatabaseHelper.TABLE_FINDINGS);
        assertEquals("id", GuardianAiDatabaseHelper.COL_FINDING_ID);
        assertEquals("scan_id", GuardianAiDatabaseHelper.COL_FINDING_SCAN_ID);
        assertEquals("indicator_type", GuardianAiDatabaseHelper.COL_FINDING_INDICATOR_TYPE);
        assertEquals("severity", GuardianAiDatabaseHelper.COL_FINDING_SEVERITY);
        assertEquals("explanation", GuardianAiDatabaseHelper.COL_FINDING_EXPLANATION);
        assertEquals("recommended_action", GuardianAiDatabaseHelper.COL_FINDING_RECOMMENDED_ACTION);
    }
}
