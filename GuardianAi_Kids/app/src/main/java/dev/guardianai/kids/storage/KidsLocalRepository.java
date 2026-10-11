package dev.guardianai.kids.storage;

import android.content.ContentValues;
import android.content.Context;
import android.content.SharedPreferences;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;

import dev.guardianai.family.TrustedAdultValidator;
import dev.guardianai.help.HelpRequest;
import dev.guardianai.help.HelpRequestStatus;
import dev.guardianai.kids.storage.db.KidsDatabaseHelper;
import dev.guardianai.kids.storage.model.CheckHistoryRecord;
import dev.guardianai.kids.ui.model.TrustedAdult;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * App-private persistence for GuardianAi Kids (SQLite + SharedPreferences). Reads come from in-memory caches loaded
 * at start-up; writes update the cache immediately and are persisted on a single background thread, in order.
 * Nothing here is shared with other apps.
 */
public class KidsLocalRepository {

    private static final String TAG = "KidsLocalRepository";
    private static final String PREFS = "guardianai_kids_prefs";
    private static volatile KidsLocalRepository instance;

    private final KidsDatabaseHelper db;
    private final SharedPreferences prefs;
    private final ExecutorService io = Executors.newSingleThreadExecutor();
    private final Handler main = new Handler(Looper.getMainLooper());

    private final List<TrustedAdult> adults = new CopyOnWriteArrayList<>();
    private final Map<String, Long> completed = Collections.synchronizedMap(new HashMap<String, Long>());
    private final List<CheckHistoryRecord> checks = new CopyOnWriteArrayList<>();
    private final List<HelpRequest> help = new CopyOnWriteArrayList<>();
    private final List<Runnable> listeners = new CopyOnWriteArrayList<>();
    private volatile boolean loadFailed;

    private KidsLocalRepository(Context ctx) {
        Context app = ctx.getApplicationContext();
        db = new KidsDatabaseHelper(app);
        prefs = app.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        load();
    }

    public static KidsLocalRepository getInstance(Context ctx) {
        if (instance == null) {
            synchronized (KidsLocalRepository.class) {
                if (instance == null) instance = new KidsLocalRepository(ctx);
            }
        }
        return instance;
    }

    /** Shared SQLite helper (one connection pool for the whole app). */
    KidsDatabaseHelper dbHelper() {
        return db;
    }

    public void addListener(Runnable r) {
        if (!listeners.contains(r)) listeners.add(r);
    }

    public void removeListener(Runnable r) {
        listeners.remove(r);
    }

    private void changed() {
        main.post(() -> {
            for (Runnable r : listeners) {
                try {
                    r.run();
                } catch (RuntimeException e) {
                    Log.e(TAG, "listener failed", e);
                }
            }
        });
    }

    /** True if the database could not be read at start-up (UI shows an error state instead of empty data). */
    public boolean didLoadFail() {
        return loadFailed;
    }

    private void load() {
        try {
            SQLiteDatabase d = db.getReadableDatabase();
            try (Cursor c = d.query(KidsDatabaseHelper.TABLE_TRUSTED_ADULTS, null, null, null, null, null,
                    KidsDatabaseHelper.COL_ADULT_DISPLAY_ORDER + " ASC, " + KidsDatabaseHelper.COL_ADULT_CREATED_AT + " ASC")) {
                while (c.moveToNext()) {
                    adults.add(new TrustedAdult(s(c, KidsDatabaseHelper.COL_ADULT_ID), s(c, KidsDatabaseHelper.COL_ADULT_NAME),
                            s(c, KidsDatabaseHelper.COL_ADULT_RELATION), s(c, KidsDatabaseHelper.COL_ADULT_PHONE),
                            (int) l(c, KidsDatabaseHelper.COL_ADULT_DISPLAY_ORDER), l(c, KidsDatabaseHelper.COL_ADULT_CREATED_AT),
                            l(c, KidsDatabaseHelper.COL_ADULT_UPDATED_AT)));
                }
            }
            try (Cursor c = d.query(KidsDatabaseHelper.TABLE_LESSON_PROGRESS, null,
                    KidsDatabaseHelper.COL_LESSON_IS_COMPLETED + "=1", null, null, null, null)) {
                while (c.moveToNext()) completed.put(s(c, KidsDatabaseHelper.COL_LESSON_ID), l(c, KidsDatabaseHelper.COL_LESSON_COMPLETED_AT));
            }
            try (Cursor c = d.query(KidsDatabaseHelper.TABLE_CHECK_HISTORY, null, null, null, null, null,
                    KidsDatabaseHelper.COL_CHECK_TIMESTAMP + " DESC", "200")) {
                while (c.moveToNext()) {
                    checks.add(new CheckHistoryRecord(s(c, KidsDatabaseHelper.COL_CHECK_ID), s(c, KidsDatabaseHelper.COL_CHECK_TYPE),
                            l(c, KidsDatabaseHelper.COL_CHECK_TIMESTAMP), s(c, KidsDatabaseHelper.COL_CHECK_ENGINE),
                            s(c, KidsDatabaseHelper.COL_CHECK_RESULT_CATEGORY), s(c, KidsDatabaseHelper.COL_CHECK_SUMMARY),
                            s(c, KidsDatabaseHelper.COL_CHECK_INDICATORS_SUMMARY), s(c, KidsDatabaseHelper.COL_CHECK_STATUS)));
                }
            }
            try (Cursor c = d.query(KidsDatabaseHelper.TABLE_HELP_REQUESTS, null, null, null, null, null,
                    KidsDatabaseHelper.COL_HELP_CREATED_AT + " DESC", "50")) {
                while (c.moveToNext()) {
                    HelpRequestStatus st;
                    try {
                        st = HelpRequestStatus.valueOf(s(c, KidsDatabaseHelper.COL_HELP_STATUS));
                    } catch (IllegalArgumentException e) {
                        st = HelpRequestStatus.DELIVERY_UNKNOWN;
                    }
                    // A request that was mid-send when the app closed has an unknown outcome; it is never resent automatically.
                    if (st == HelpRequestStatus.SENDING) st = HelpRequestStatus.DELIVERY_UNKNOWN;
                    HelpRequest.LocationChoice lc;
                    try {
                        lc = HelpRequest.LocationChoice.valueOf(s(c, KidsDatabaseHelper.COL_HELP_LOCATION_CHOICE));
                    } catch (IllegalArgumentException e) {
                        lc = HelpRequest.LocationChoice.NOT_SHARED;
                    }
                    help.add(new HelpRequest(s(c, KidsDatabaseHelper.COL_HELP_ID), s(c, KidsDatabaseHelper.COL_HELP_IDEMPOTENCY),
                            s(c, KidsDatabaseHelper.COL_HELP_SERVER_ID), s(c, KidsDatabaseHelper.COL_HELP_RECIPIENT_UID),
                            s(c, KidsDatabaseHelper.COL_HELP_RECIPIENT_NAME), s(c, KidsDatabaseHelper.COL_HELP_REASON), null, lc, null,
                            st, s(c, KidsDatabaseHelper.COL_HELP_FAILURE), l(c, KidsDatabaseHelper.COL_HELP_CREATED_AT),
                            l(c, KidsDatabaseHelper.COL_HELP_UPDATED_AT)));
                }
            }
        } catch (RuntimeException e) {
            loadFailed = true;
            Log.e(TAG, "Failed to load local data", e);
        }
    }

    private static String s(Cursor c, String col) {
        return c.getString(c.getColumnIndexOrThrow(col));
    }

    private static long l(Cursor c, String col) {
        return c.getLong(c.getColumnIndexOrThrow(col));
    }

    private void write(String what, java.util.function.Consumer<SQLiteDatabase> op) {
        io.execute(() -> {
            try {
                op.accept(db.getWritableDatabase());
            } catch (RuntimeException e) {
                Log.e(TAG, "Failed to persist " + what, e);
            }
        });
    }

    // ---------------------------------------------------------------- trusted adults

    public List<TrustedAdult> getTrustedAdults() {
        return Collections.unmodifiableList(new ArrayList<>(adults));
    }

    /** Returns null on success, otherwise a validation message. */
    public String addTrustedAdult(String name, String relation, String phone) {
        String err = TrustedAdultValidator.validate(name, relation, phone);
        if (err != null) return err;
        if (adults.size() >= 10) return "You can save up to 10 trusted adults";
        long now = System.currentTimeMillis();
        TrustedAdult a = new TrustedAdult(UUID.randomUUID().toString(), name, relation, phone, adults.size(), now, now);
        adults.add(a);
        changed();
        write("trusted adult", d -> d.insertOrThrow(KidsDatabaseHelper.TABLE_TRUSTED_ADULTS, null, adultValues(a)));
        return null;
    }

    public String updateTrustedAdult(String id, String name, String relation, String phone) {
        String err = TrustedAdultValidator.validate(name, relation, phone);
        if (err != null) return err;
        for (int i = 0; i < adults.size(); i++) {
            TrustedAdult old = adults.get(i);
            if (old.getId().equals(id)) {
                TrustedAdult a = new TrustedAdult(id, name, relation, phone, old.getDisplayOrder(), old.getCreatedTimestamp(), System.currentTimeMillis());
                adults.set(i, a);
                changed();
                write("trusted adult", d -> d.update(KidsDatabaseHelper.TABLE_TRUSTED_ADULTS, adultValues(a),
                        KidsDatabaseHelper.COL_ADULT_ID + "=?", new String[]{id}));
                return null;
            }
        }
        return "That contact no longer exists";
    }

    public void removeTrustedAdult(String id) {
        for (TrustedAdult a : adults) {
            if (a.getId().equals(id)) {
                adults.remove(a);
                changed();
                write("trusted adult delete", d -> d.delete(KidsDatabaseHelper.TABLE_TRUSTED_ADULTS, KidsDatabaseHelper.COL_ADULT_ID + "=?", new String[]{id}));
                return;
            }
        }
    }

    private static ContentValues adultValues(TrustedAdult a) {
        ContentValues v = new ContentValues();
        v.put(KidsDatabaseHelper.COL_ADULT_ID, a.getId());
        v.put(KidsDatabaseHelper.COL_ADULT_NAME, a.getName());
        v.put(KidsDatabaseHelper.COL_ADULT_RELATION, a.getRelation());
        v.put(KidsDatabaseHelper.COL_ADULT_PHONE, a.getPhone());
        v.put(KidsDatabaseHelper.COL_ADULT_IS_PRIMARY, 0);
        v.put(KidsDatabaseHelper.COL_ADULT_DISPLAY_ORDER, a.getDisplayOrder());
        v.put(KidsDatabaseHelper.COL_ADULT_CREATED_AT, a.getCreatedTimestamp());
        v.put(KidsDatabaseHelper.COL_ADULT_UPDATED_AT, a.getUpdatedTimestamp());
        return v;
    }

    // ---------------------------------------------------------------- lesson progress

    public Set<String> getCompletedLessonIds() {
        synchronized (completed) {
            return new HashSet<>(completed.keySet());
        }
    }

    public long getLessonCompletedAt(String id) {
        Long v = completed.get(id);
        return v == null ? 0 : v;
    }

    /** Called only from the explicit "Mark as complete" action in a lesson. */
    public void markLessonCompleted(String id) {
        if (id == null || completed.containsKey(id)) return;
        long now = System.currentTimeMillis();
        completed.put(id, now);
        changed();
        write("lesson progress", d -> {
            ContentValues v = new ContentValues();
            v.put(KidsDatabaseHelper.COL_LESSON_ID, id);
            v.put(KidsDatabaseHelper.COL_LESSON_IS_COMPLETED, 1);
            v.put(KidsDatabaseHelper.COL_LESSON_COMPLETED_AT, now);
            v.put(KidsDatabaseHelper.COL_LESSON_UPDATED_AT, now);
            d.insertWithOnConflict(KidsDatabaseHelper.TABLE_LESSON_PROGRESS, null, v, SQLiteDatabase.CONFLICT_REPLACE);
        });
    }

    public void resetLessonProgress() {
        completed.clear();
        changed();
        write("lesson reset", d -> d.delete(KidsDatabaseHelper.TABLE_LESSON_PROGRESS, null, null));
    }

    // ---------------------------------------------------------------- check history (metadata only)

    public List<CheckHistoryRecord> getCheckHistory() {
        return Collections.unmodifiableList(new ArrayList<>(checks));
    }

    public void recordCheck(CheckHistoryRecord r) {
        checks.add(0, r);
        while (checks.size() > 200) checks.remove(checks.size() - 1);
        changed();
        write("check history", d -> {
            ContentValues v = new ContentValues();
            v.put(KidsDatabaseHelper.COL_CHECK_ID, r.getRecordId());
            v.put(KidsDatabaseHelper.COL_CHECK_TYPE, r.getCheckType());
            v.put(KidsDatabaseHelper.COL_CHECK_TIMESTAMP, r.getTimestamp());
            v.put(KidsDatabaseHelper.COL_CHECK_ENGINE, r.getEngineIdentifier());
            v.put(KidsDatabaseHelper.COL_CHECK_RESULT_CATEGORY, r.getResultCategory());
            v.put(KidsDatabaseHelper.COL_CHECK_SUMMARY, r.getSummary());
            v.put(KidsDatabaseHelper.COL_CHECK_INDICATORS_SUMMARY, r.getIndicatorsSummary());
            v.put(KidsDatabaseHelper.COL_CHECK_STATUS, r.getStatus());
            d.insertWithOnConflict(KidsDatabaseHelper.TABLE_CHECK_HISTORY, null, v, SQLiteDatabase.CONFLICT_REPLACE);
            d.execSQL("DELETE FROM " + KidsDatabaseHelper.TABLE_CHECK_HISTORY + " WHERE " + KidsDatabaseHelper.COL_CHECK_ID
                    + " NOT IN (SELECT " + KidsDatabaseHelper.COL_CHECK_ID + " FROM " + KidsDatabaseHelper.TABLE_CHECK_HISTORY
                    + " ORDER BY " + KidsDatabaseHelper.COL_CHECK_TIMESTAMP + " DESC LIMIT 200)");
        });
    }

    public void clearCheckHistory() {
        checks.clear();
        changed();
        write("check history clear", d -> d.delete(KidsDatabaseHelper.TABLE_CHECK_HISTORY, null, null));
    }

    // ---------------------------------------------------------------- help requests

    public List<HelpRequest> getHelpRequests() {
        return Collections.unmodifiableList(new ArrayList<>(help));
    }

    /** Insert or replace by local id. The optional note and location are deliberately not stored. */
    public void saveHelpRequest(HelpRequest r) {
        boolean replaced = false;
        for (int i = 0; i < help.size(); i++) {
            if (help.get(i).localId.equals(r.localId)) {
                help.set(i, r);
                replaced = true;
                break;
            }
        }
        if (!replaced) help.add(0, r);
        changed();
        write("help request", d -> {
            ContentValues v = new ContentValues();
            v.put(KidsDatabaseHelper.COL_HELP_ID, r.localId);
            v.put(KidsDatabaseHelper.COL_HELP_IDEMPOTENCY, r.idempotencyKey);
            v.put(KidsDatabaseHelper.COL_HELP_SERVER_ID, r.serverRequestId);
            v.put(KidsDatabaseHelper.COL_HELP_RECIPIENT_UID, r.recipientUid);
            v.put(KidsDatabaseHelper.COL_HELP_RECIPIENT_NAME, r.recipientName);
            v.put(KidsDatabaseHelper.COL_HELP_REASON, r.reason);
            v.put(KidsDatabaseHelper.COL_HELP_LOCATION_CHOICE, r.locationChoice.name());
            v.put(KidsDatabaseHelper.COL_HELP_STATUS, r.status.name());
            v.put(KidsDatabaseHelper.COL_HELP_FAILURE, r.failureReason);
            v.put(KidsDatabaseHelper.COL_HELP_CREATED_AT, r.createdAt);
            v.put(KidsDatabaseHelper.COL_HELP_UPDATED_AT, r.updatedAt);
            d.insertWithOnConflict(KidsDatabaseHelper.TABLE_HELP_REQUESTS, null, v, SQLiteDatabase.CONFLICT_REPLACE);
        });
    }

    public void clearHelpHistory() {
        help.clear();
        changed();
        write("help clear", d -> d.delete(KidsDatabaseHelper.TABLE_HELP_REQUESTS, null, null));
    }

    // ---------------------------------------------------------------- preferences

    public boolean isOnboardingCompleted() { return prefs.getBoolean("onboarding_completed", false); }
    public void setOnboardingCompleted(boolean v) { prefs.edit().putBoolean("onboarding_completed", v).apply(); changed(); }

    /** "en" or "hi". */
    public String getLanguage() {
        String l = prefs.getString("language_code", "en");
        return "hi".equals(l) ? "hi" : "en";
    }
    public void setLanguage(String lang) { prefs.edit().putString("language_code", "hi".equals(lang) ? "hi" : "en").apply(); changed(); }

    public boolean isLargeText() { return prefs.getBoolean("large_typography", false); }
    public void setLargeText(boolean v) { prefs.edit().putBoolean("large_typography", v).apply(); changed(); }

    /** Whether the child agreed to send link addresses to the online safety service. Defaults to off. */
    public boolean isOnlineLinkCheckAllowed() { return prefs.getBoolean("online_link_check_allowed", false); }
    public void setOnlineLinkCheckAllowed(boolean v) { prefs.edit().putBoolean("online_link_check_allowed", v).apply(); changed(); }

    public String getChildDisplayName() { return prefs.getString("child_display_name", ""); }
    public void setChildDisplayName(String v) { prefs.edit().putString("child_display_name", v == null ? "" : v.trim()).apply(); }

    /** Removes preference keys written by earlier demo builds (local "paired" flag and fake pairing code). */
    public void removeLegacyDemoPreferences() {
        if (prefs.contains("family_paired") || prefs.contains("family_pairing_code") || prefs.contains("high_contrast")) {
            prefs.edit().remove("family_paired").remove("family_pairing_code").remove("high_contrast").apply();
        }
    }
}
