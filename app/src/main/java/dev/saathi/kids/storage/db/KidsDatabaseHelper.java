package dev.saathi.kids.storage.db;

import android.content.Context;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;

/**
 * SQLite schema for Saathi Kids local storage (app-private).
 * v1: trusted_adults, lesson_progress, check_history, help_requests (local demo records)
 * v2: help_requests rebuilt for real backend requests (idempotency key, server id, truthful status).
 *     v1 help_requests rows were on-device simulations only and are not carried over.
 * v3: safety_events (metadata + at most two short evidence excerpts) and flag_history (flag level changes).
 */
public class KidsDatabaseHelper extends SQLiteOpenHelper {

    public static final String DATABASE_NAME = "saathi_kids.db";
    public static final int DATABASE_VERSION = 3;

    public static final String TABLE_TRUSTED_ADULTS = "trusted_adults";
    public static final String COL_ADULT_ID = "id";
    public static final String COL_ADULT_NAME = "name";
    public static final String COL_ADULT_RELATION = "relationship";
    public static final String COL_ADULT_PHONE = "phone_number";
    public static final String COL_ADULT_IS_PRIMARY = "is_primary";
    public static final String COL_ADULT_DISPLAY_ORDER = "display_order";
    public static final String COL_ADULT_CREATED_AT = "created_timestamp";
    public static final String COL_ADULT_UPDATED_AT = "updated_timestamp";

    public static final String TABLE_LESSON_PROGRESS = "lesson_progress";
    public static final String COL_LESSON_ID = "lesson_id";
    public static final String COL_LESSON_IS_COMPLETED = "is_completed";
    public static final String COL_LESSON_COMPLETED_AT = "completed_timestamp";
    public static final String COL_LESSON_UPDATED_AT = "updated_timestamp";

    // Check history keeps result metadata only: no message text, URL or file name.
    public static final String TABLE_CHECK_HISTORY = "check_history";
    public static final String COL_CHECK_ID = "record_id";
    public static final String COL_CHECK_TYPE = "check_type";
    public static final String COL_CHECK_TIMESTAMP = "timestamp";
    public static final String COL_CHECK_ENGINE = "engine_identifier";
    public static final String COL_CHECK_RESULT_CATEGORY = "result_category";
    public static final String COL_CHECK_SUMMARY = "summary";
    public static final String COL_CHECK_INDICATORS_SUMMARY = "indicators_summary";
    public static final String COL_CHECK_STATUS = "status";

    public static final String TABLE_HELP_REQUESTS = "help_requests";
    public static final String COL_HELP_ID = "local_id";
    public static final String COL_HELP_IDEMPOTENCY = "idempotency_key";
    public static final String COL_HELP_SERVER_ID = "server_request_id";
    public static final String COL_HELP_RECIPIENT_UID = "recipient_uid";
    public static final String COL_HELP_RECIPIENT_NAME = "recipient_name";
    public static final String COL_HELP_REASON = "reason";
    public static final String COL_HELP_LOCATION_CHOICE = "location_choice";
    public static final String COL_HELP_STATUS = "status";
    public static final String COL_HELP_FAILURE = "failure_reason";
    public static final String COL_HELP_CREATED_AT = "created_timestamp";
    public static final String COL_HELP_UPDATED_AT = "updated_timestamp";

    public static final String TABLE_SAFETY_EVENTS = "safety_events";
    public static final String TABLE_FLAG_HISTORY = "flag_history";

    public KidsDatabaseHelper(Context context) {
        super(context, DATABASE_NAME, null, DATABASE_VERSION);
    }

    @Override
    public void onCreate(SQLiteDatabase db) {
        db.execSQL("CREATE TABLE IF NOT EXISTS " + TABLE_TRUSTED_ADULTS + " ("
                + COL_ADULT_ID + " TEXT PRIMARY KEY, "
                + COL_ADULT_NAME + " TEXT NOT NULL, "
                + COL_ADULT_RELATION + " TEXT NOT NULL, "
                + COL_ADULT_PHONE + " TEXT NOT NULL, "
                + COL_ADULT_IS_PRIMARY + " INTEGER NOT NULL DEFAULT 0, "
                + COL_ADULT_DISPLAY_ORDER + " INTEGER NOT NULL DEFAULT 0, "
                + COL_ADULT_CREATED_AT + " INTEGER NOT NULL, "
                + COL_ADULT_UPDATED_AT + " INTEGER NOT NULL);");
        db.execSQL("CREATE TABLE IF NOT EXISTS " + TABLE_LESSON_PROGRESS + " ("
                + COL_LESSON_ID + " TEXT PRIMARY KEY, "
                + COL_LESSON_IS_COMPLETED + " INTEGER NOT NULL DEFAULT 0, "
                + COL_LESSON_COMPLETED_AT + " INTEGER NOT NULL DEFAULT 0, "
                + COL_LESSON_UPDATED_AT + " INTEGER NOT NULL);");
        db.execSQL("CREATE TABLE IF NOT EXISTS " + TABLE_CHECK_HISTORY + " ("
                + COL_CHECK_ID + " TEXT PRIMARY KEY, "
                + COL_CHECK_TYPE + " TEXT NOT NULL, "
                + COL_CHECK_TIMESTAMP + " INTEGER NOT NULL, "
                + COL_CHECK_ENGINE + " TEXT NOT NULL, "
                + COL_CHECK_RESULT_CATEGORY + " TEXT NOT NULL, "
                + COL_CHECK_SUMMARY + " TEXT NOT NULL, "
                + COL_CHECK_INDICATORS_SUMMARY + " TEXT, "
                + COL_CHECK_STATUS + " TEXT NOT NULL);");
        createHelpRequestsV2(db);
        createSafetyTablesV3(db);
    }

    private static void createSafetyTablesV3(SQLiteDatabase db) {
        db.execSQL("CREATE TABLE IF NOT EXISTS " + TABLE_SAFETY_EVENTS + " ("
                + "event_id TEXT PRIMARY KEY, dedupe_key TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, "
                + "source_type TEXT NOT NULL, source_app TEXT, category TEXT NOT NULL, flag TEXT NOT NULL, level TEXT NOT NULL, "
                + "severity TEXT, confidence TEXT, status TEXT NOT NULL, analysis_source TEXT NOT NULL, model_outcome TEXT, "
                + "evidence TEXT, explanation TEXT, actions TEXT, review TEXT NOT NULL, alert TEXT NOT NULL);");
        db.execSQL("CREATE INDEX IF NOT EXISTS idx_events_dedupe ON " + TABLE_SAFETY_EVENTS + "(dedupe_key, created_at)");
        db.execSQL("CREATE TABLE IF NOT EXISTS " + TABLE_FLAG_HISTORY + " ("
                + "id INTEGER PRIMARY KEY AUTOINCREMENT, flag TEXT NOT NULL, level TEXT NOT NULL, event_id TEXT, changed_at INTEGER NOT NULL);");
    }

    private static void createHelpRequestsV2(SQLiteDatabase db) {
        db.execSQL("CREATE TABLE IF NOT EXISTS " + TABLE_HELP_REQUESTS + " ("
                + COL_HELP_ID + " TEXT PRIMARY KEY, "
                + COL_HELP_IDEMPOTENCY + " TEXT NOT NULL UNIQUE, "
                + COL_HELP_SERVER_ID + " TEXT, "
                + COL_HELP_RECIPIENT_UID + " TEXT NOT NULL, "
                + COL_HELP_RECIPIENT_NAME + " TEXT NOT NULL, "
                + COL_HELP_REASON + " TEXT NOT NULL, "
                + COL_HELP_LOCATION_CHOICE + " TEXT NOT NULL, "
                + COL_HELP_STATUS + " TEXT NOT NULL, "
                + COL_HELP_FAILURE + " TEXT, "
                + COL_HELP_CREATED_AT + " INTEGER NOT NULL, "
                + COL_HELP_UPDATED_AT + " INTEGER NOT NULL);");
    }

    @Override
    public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        if (oldVersion < 2) {
            db.execSQL("DROP TABLE IF EXISTS " + TABLE_HELP_REQUESTS);
            createHelpRequestsV2(db);
        }
        if (oldVersion < 3) createSafetyTablesV3(db);
    }
}
