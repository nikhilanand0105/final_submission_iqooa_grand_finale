package dev.guardianai.personal.data.db;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * SQLite database helper for GuardianAi Personal on-device security audit trails.
 * Enforces strict foreign keys, indexing for low-latency queries, and parameterized operations.
 */
public class GuardianAiDatabaseHelper extends SQLiteOpenHelper {

    public static final String DATABASE_NAME = "guardianai_personal.db";
    public static final int DATABASE_VERSION = 1;

    // Table: scan_records
    public static final String TABLE_SCANS = "scan_records";
    public static final String COL_SCAN_ID = "id";
    public static final String COL_SCAN_OPERATION_TYPE = "operation_type";
    public static final String COL_SCAN_TIMESTAMP = "timestamp";
    public static final String COL_SCAN_PROCESSING_STATUS = "processing_status";
    public static final String COL_SCAN_SUMMARY = "summary";
    public static final String COL_SCAN_SOURCE = "source";
    public static final String COL_SCAN_ANALYSIS_VERSION = "analysis_version";
    public static final String COL_SCAN_IS_CONCLUSIVE = "is_conclusive";
    public static final String COL_SCAN_VERDICT = "verdict";
    public static final String COL_SCAN_SEVERITY = "severity";
    public static final String COL_SCAN_ACTION_TAKEN = "action_taken";

    // Table: finding_records
    public static final String TABLE_FINDINGS = "finding_records";
    public static final String COL_FINDING_ID = "id";
    public static final String COL_FINDING_SCAN_ID = "scan_id";
    public static final String COL_FINDING_INDICATOR_TYPE = "indicator_type";
    public static final String COL_FINDING_SEVERITY = "severity";
    public static final String COL_FINDING_EXPLANATION = "explanation";
    public static final String COL_FINDING_RECOMMENDED_ACTION = "recommended_action";

    private static final String SQL_CREATE_SCANS =
            "CREATE TABLE IF NOT EXISTS " + TABLE_SCANS + " (" +
                    COL_SCAN_ID + " TEXT PRIMARY KEY NOT NULL, " +
                    COL_SCAN_OPERATION_TYPE + " TEXT NOT NULL, " +
                    COL_SCAN_TIMESTAMP + " INTEGER NOT NULL, " +
                    COL_SCAN_PROCESSING_STATUS + " TEXT NOT NULL, " +
                    COL_SCAN_SUMMARY + " TEXT, " +
                    COL_SCAN_SOURCE + " TEXT, " +
                    COL_SCAN_ANALYSIS_VERSION + " TEXT NOT NULL, " +
                    COL_SCAN_IS_CONCLUSIVE + " INTEGER NOT NULL, " +
                    COL_SCAN_VERDICT + " TEXT NOT NULL, " +
                    COL_SCAN_SEVERITY + " TEXT NOT NULL, " +
                    COL_SCAN_ACTION_TAKEN + " TEXT" +
                    ");";

    private static final String SQL_CREATE_FINDINGS =
            "CREATE TABLE IF NOT EXISTS " + TABLE_FINDINGS + " (" +
                    COL_FINDING_ID + " TEXT PRIMARY KEY NOT NULL, " +
                    COL_FINDING_SCAN_ID + " TEXT NOT NULL, " +
                    COL_FINDING_INDICATOR_TYPE + " TEXT NOT NULL, " +
                    COL_FINDING_SEVERITY + " TEXT NOT NULL, " +
                    COL_FINDING_EXPLANATION + " TEXT, " +
                    COL_FINDING_RECOMMENDED_ACTION + " TEXT, " +
                    "FOREIGN KEY (" + COL_FINDING_SCAN_ID + ") REFERENCES " + TABLE_SCANS + "(" + COL_SCAN_ID + ") ON DELETE CASCADE" +
                    ");";

    private static final String SQL_INDEX_FINDINGS_SCAN_ID =
            "CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON " + TABLE_FINDINGS + "(" + COL_FINDING_SCAN_ID + ");";

    private static final String SQL_INDEX_SCANS_TIMESTAMP =
            "CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON " + TABLE_SCANS + "(" + COL_SCAN_TIMESTAMP + " DESC);";

    private static final String SQL_INDEX_SCANS_OP_TYPE =
            "CREATE INDEX IF NOT EXISTS idx_scans_op_type ON " + TABLE_SCANS + "(" + COL_SCAN_OPERATION_TYPE + ");";

    public GuardianAiDatabaseHelper(Context context) {
        super(context, DATABASE_NAME, null, DATABASE_VERSION);
    }

    public GuardianAiDatabaseHelper(Context context, String dbName) {
        super(context, dbName, null, DATABASE_VERSION);
    }

    @Override
    public void onConfigure(SQLiteDatabase db) {
        super.onConfigure(db);
        db.setForeignKeyConstraintsEnabled(true);
    }

    @Override
    public void onCreate(SQLiteDatabase db) {
        db.execSQL(SQL_CREATE_SCANS);
        db.execSQL(SQL_CREATE_FINDINGS);
        db.execSQL(SQL_INDEX_FINDINGS_SCAN_ID);
        db.execSQL(SQL_INDEX_SCANS_TIMESTAMP);
        db.execSQL(SQL_INDEX_SCANS_OP_TYPE);
    }

    @Override
    public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        // Version 1 is baseline. Future schema migrations handled monotonically here.
    }

    public void insertScan(ScanRecord scan, List<FindingRecord> findings) {
        if (scan == null) return;
        SQLiteDatabase db = getWritableDatabase();
        db.beginTransaction();
        try {
            ContentValues cv = new ContentValues();
            cv.put(COL_SCAN_ID, scan.getId());
            cv.put(COL_SCAN_OPERATION_TYPE, scan.getOperationType());
            cv.put(COL_SCAN_TIMESTAMP, scan.getTimestamp());
            cv.put(COL_SCAN_PROCESSING_STATUS, scan.getProcessingStatus());
            cv.put(COL_SCAN_SUMMARY, scan.getSummary());
            cv.put(COL_SCAN_SOURCE, scan.getSource());
            cv.put(COL_SCAN_ANALYSIS_VERSION, scan.getAnalysisVersion());
            cv.put(COL_SCAN_IS_CONCLUSIVE, scan.isConclusive() ? 1 : 0);
            cv.put(COL_SCAN_VERDICT, scan.getVerdict());
            cv.put(COL_SCAN_SEVERITY, scan.getSeverity());
            cv.put(COL_SCAN_ACTION_TAKEN, scan.getActionTaken());
            db.insertWithOnConflict(TABLE_SCANS, null, cv, SQLiteDatabase.CONFLICT_REPLACE);

            if (findings != null) {
                for (FindingRecord f : findings) {
                    ContentValues fcv = new ContentValues();
                    fcv.put(COL_FINDING_ID, f.getId());
                    fcv.put(COL_FINDING_SCAN_ID, f.getScanId());
                    fcv.put(COL_FINDING_INDICATOR_TYPE, f.getIndicatorType());
                    fcv.put(COL_FINDING_SEVERITY, f.getSeverity());
                    fcv.put(COL_FINDING_EXPLANATION, f.getExplanation());
                    fcv.put(COL_FINDING_RECOMMENDED_ACTION, f.getRecommendedAction());
                    db.insertWithOnConflict(TABLE_FINDINGS, null, fcv, SQLiteDatabase.CONFLICT_REPLACE);
                }
            }
            db.setTransactionSuccessful();
        } finally {
            db.endTransaction();
        }
    }

    public List<ScanRecord> getAllScans() {
        return queryScans(null, null, null);
    }

    public List<ScanRecord> getScansByType(String operationType) {
        if (operationType == null || operationType.isEmpty()) {
            return getAllScans();
        }
        return queryScans(COL_SCAN_OPERATION_TYPE + " = ?", new String[]{operationType}, null);
    }

    public List<ScanRecord> getRecentScans(int limit) {
        int safeLimit = Math.max(1, limit);
        return queryScans(null, null, String.valueOf(safeLimit));
    }

    public List<FindingRecord> getFindingsForScan(String scanId) {
        if (scanId == null) return Collections.emptyList();
        SQLiteDatabase db = getReadableDatabase();
        List<FindingRecord> list = new ArrayList<>();
        try (Cursor cursor = db.query(
                TABLE_FINDINGS,
                null,
                COL_FINDING_SCAN_ID + " = ?",
                new String[]{scanId},
                null,
                null,
                COL_FINDING_ID + " ASC"
        )) {
            if (cursor != null && cursor.moveToFirst()) {
                do {
                    list.add(mapFindingCursor(cursor));
                } while (cursor.moveToNext());
            }
        }
        return list;
    }

    public ScanStats getScanStats() {
        SQLiteDatabase db = getReadableDatabase();
        String sql = "SELECT " +
                "COUNT(*) AS total, " +
                "SUM(CASE WHEN " + COL_SCAN_VERDICT + " = 'SAFE' THEN 1 ELSE 0 END) AS safe_cnt, " +
                "SUM(CASE WHEN " + COL_SCAN_VERDICT + " = 'SUSPICIOUS' THEN 1 ELSE 0 END) AS susp_cnt, " +
                "SUM(CASE WHEN " + COL_SCAN_VERDICT + " = 'KNOWN_MALICIOUS' THEN 1 ELSE 0 END) AS mal_cnt " +
                "FROM " + TABLE_SCANS;

        try (Cursor cursor = db.rawQuery(sql, null)) {
            if (cursor != null && cursor.moveToFirst()) {
                int total = cursor.getInt(0);
                int safe = cursor.getInt(1);
                int susp = cursor.getInt(2);
                int mal = cursor.getInt(3);
                int unknown = Math.max(0, total - (safe + susp + mal));
                return new ScanStats(total, safe, susp, mal, unknown);
            }
        }
        return ScanStats.empty();
    }

    public boolean deleteScan(String scanId) {
        if (scanId == null) return false;
        SQLiteDatabase db = getWritableDatabase();
        int rows = db.delete(TABLE_SCANS, COL_SCAN_ID + " = ?", new String[]{scanId});
        return rows > 0;
    }

    public void clearAllScans() {
        SQLiteDatabase db = getWritableDatabase();
        db.beginTransaction();
        try {
            db.delete(TABLE_FINDINGS, null, null);
            db.delete(TABLE_SCANS, null, null);
            db.setTransactionSuccessful();
        } finally {
            db.endTransaction();
        }
    }

    private List<ScanRecord> queryScans(String selection, String[] selectionArgs, String limit) {
        SQLiteDatabase db = getReadableDatabase();
        List<ScanRecord> list = new ArrayList<>();
        try (Cursor cursor = db.query(
                TABLE_SCANS,
                null,
                selection,
                selectionArgs,
                null,
                null,
                COL_SCAN_TIMESTAMP + " DESC",
                limit
        )) {
            if (cursor != null && cursor.moveToFirst()) {
                do {
                    list.add(mapScanCursor(cursor));
                } while (cursor.moveToNext());
            }
        }
        return list;
    }

    private ScanRecord mapScanCursor(Cursor cursor) {
        return new ScanRecord(
                cursor.getString(cursor.getColumnIndexOrThrow(COL_SCAN_ID)),
                cursor.getString(cursor.getColumnIndexOrThrow(COL_SCAN_OPERATION_TYPE)),
                cursor.getLong(cursor.getColumnIndexOrThrow(COL_SCAN_TIMESTAMP)),
                cursor.getString(cursor.getColumnIndexOrThrow(COL_SCAN_PROCESSING_STATUS)),
                cursor.getString(cursor.getColumnIndexOrThrow(COL_SCAN_SUMMARY)),
                cursor.getString(cursor.getColumnIndexOrThrow(COL_SCAN_SOURCE)),
                cursor.getString(cursor.getColumnIndexOrThrow(COL_SCAN_ANALYSIS_VERSION)),
                cursor.getInt(cursor.getColumnIndexOrThrow(COL_SCAN_IS_CONCLUSIVE)) == 1,
                cursor.getString(cursor.getColumnIndexOrThrow(COL_SCAN_VERDICT)),
                cursor.getString(cursor.getColumnIndexOrThrow(COL_SCAN_SEVERITY)),
                cursor.getString(cursor.getColumnIndexOrThrow(COL_SCAN_ACTION_TAKEN))
        );
    }

    private FindingRecord mapFindingCursor(Cursor cursor) {
        return new FindingRecord(
                cursor.getString(cursor.getColumnIndexOrThrow(COL_FINDING_ID)),
                cursor.getString(cursor.getColumnIndexOrThrow(COL_FINDING_SCAN_ID)),
                cursor.getString(cursor.getColumnIndexOrThrow(COL_FINDING_INDICATOR_TYPE)),
                cursor.getString(cursor.getColumnIndexOrThrow(COL_FINDING_SEVERITY)),
                cursor.getString(cursor.getColumnIndexOrThrow(COL_FINDING_EXPLANATION)),
                cursor.getString(cursor.getColumnIndexOrThrow(COL_FINDING_RECOMMENDED_ACTION))
        );
    }
}
