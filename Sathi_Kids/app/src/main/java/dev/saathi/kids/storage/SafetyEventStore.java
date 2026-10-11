package dev.saathi.kids.storage;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;

import dev.saathi.kids.storage.db.KidsDatabaseHelper;
import dev.saathi.safety.FlagEngine;
import dev.saathi.safety.SafetyEvent;
import dev.saathi.safety.SafetyTypes;
import dev.saathi.util.Json;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Persists safety events and flag-level changes. Called from the background processor thread; reads are served
 * from an in-memory cache. A database failure marks the store unhealthy (shown in the monitoring status) instead of
 * crashing the notification service.
 */
public final class SafetyEventStore {

    private static final String TAG = "SafetyEventStore";
    public static final long RETENTION_MS = 30L * 24 * 60 * 60 * 1000;
    private static volatile SafetyEventStore instance;

    private final KidsDatabaseHelper db;
    private final List<SafetyEvent> cache = new CopyOnWriteArrayList<>();
    private final List<Runnable> listeners = new CopyOnWriteArrayList<>();
    private final Handler main = new Handler(Looper.getMainLooper());
    private volatile boolean healthy = true;

    public static SafetyEventStore get(Context ctx) {
        if (instance == null) {
            synchronized (SafetyEventStore.class) {
                if (instance == null) instance = new SafetyEventStore(KidsLocalRepository.getInstance(ctx).dbHelper());
            }
        }
        return instance;
    }

    private SafetyEventStore(KidsDatabaseHelper db) {
        this.db = db;
        load();
    }

    public boolean isHealthy() { return healthy; }
    public void addListener(Runnable r) { if (!listeners.contains(r)) listeners.add(r); }
    public void removeListener(Runnable r) { listeners.remove(r); }

    private void changed() {
        main.post(() -> { for (Runnable r : listeners) r.run(); });
    }

    private synchronized void load() {
        try (Cursor c = db.getReadableDatabase().query(KidsDatabaseHelper.TABLE_SAFETY_EVENTS, null, null, null, null, null, "updated_at DESC", "300")) {
            while (c.moveToNext()) {
                SafetyEvent e = read(c);
                if (e != null) cache.add(e);
            }
        } catch (RuntimeException e) {
            healthy = false;
            Log.e(TAG, "load failed", e);
        }
    }

    private static SafetyEvent read(Cursor c) {
        try {
            return new SafetyEvent(s(c, "event_id"), s(c, "dedupe_key"), l(c, "created_at"), l(c, "updated_at"),
                    SafetyTypes.SourceType.valueOf(s(c, "source_type")), s(c, "source_app"), SafetyEvent.Category.valueOf(s(c, "category")),
                    SafetyEvent.Flag.valueOf(s(c, "flag")), SafetyEvent.Level.valueOf(s(c, "level")), s(c, "severity"), s(c, "confidence"),
                    SafetyTypes.Status.valueOf(s(c, "status")), SafetyTypes.Source.valueOf(s(c, "analysis_source")), s(c, "model_outcome"),
                    list(s(c, "evidence")), s(c, "explanation"), list(s(c, "actions")), SafetyEvent.Review.valueOf(s(c, "review")),
                    SafetyEvent.Alert.valueOf(s(c, "alert")));
        } catch (IllegalArgumentException | NullPointerException e) {
            return null; // row from an incompatible version: skipped rather than crashing
        }
    }

    private static String s(Cursor c, String col) { return c.getString(c.getColumnIndexOrThrow(col)); }
    private static long l(Cursor c, String col) { return c.getLong(c.getColumnIndexOrThrow(col)); }

    private static List<String> list(String json) {
        if (json == null || json.isEmpty()) return new ArrayList<>();
        try {
            Map<String, Object> o = Json.parseObject("{\"v\":" + json + "}");
            List<String> l = Json.strList(o, "v");
            return l == null ? new ArrayList<String>() : l;
        } catch (Json.ParseException e) {
            return new ArrayList<>();
        }
    }

    public List<SafetyEvent> all() {
        List<SafetyEvent> l = new ArrayList<>(cache);
        Collections.sort(l, (a, b) -> Long.compare(b.updatedAt, a.updatedAt));
        return l;
    }

    public SafetyEvent byId(String id) {
        for (SafetyEvent e : cache) if (e.eventId.equals(id)) return e;
        return null;
    }

    /** Most recent event with this dedupe key inside the dedupe window, or null. */
    public SafetyEvent recentByKey(String key, long now) {
        SafetyEvent best = null;
        for (SafetyEvent e : cache) {
            if (e.dedupeKey.equals(key) && now - e.createdAt < FlagEngine.DEDUPE_WINDOW_MS && (best == null || e.createdAt > best.createdAt)) best = e;
        }
        return best;
    }

    /** Inserts or replaces an event, records a flag-history row when a flag's level changes. Returns false on DB failure. */
    public synchronized boolean save(SafetyEvent e) {
        FlagEngine.FlagState before = e.flag == SafetyEvent.Flag.NONE ? null : FlagEngine.compute(e.flag, cache);
        SafetyEvent old = byId(e.eventId);
        if (old != null) cache.remove(old);
        cache.add(e);
        boolean ok = true;
        try {
            SQLiteDatabase d = db.getWritableDatabase();
            d.insertWithOnConflict(KidsDatabaseHelper.TABLE_SAFETY_EVENTS, null, values(e), SQLiteDatabase.CONFLICT_REPLACE);
            if (before != null) {
                FlagEngine.FlagState after = FlagEngine.compute(e.flag, cache);
                if (after.level != before.level || (e.level != SafetyEvent.Level.CLEAR && old == null)) {
                    ContentValues h = new ContentValues();
                    h.put("flag", e.flag.name());
                    h.put("level", after.level.name());
                    h.put("event_id", e.eventId);
                    h.put("changed_at", e.updatedAt);
                    d.insert(KidsDatabaseHelper.TABLE_FLAG_HISTORY, null, h);
                }
            }
            healthy = true;
        } catch (RuntimeException ex) {
            healthy = false;
            ok = false;
            Log.e(TAG, "save failed", ex);
        }
        changed();
        return ok;
    }

    public void setReview(String id, SafetyEvent.Review r) {
        SafetyEvent e = byId(id);
        if (e != null) save(e.withReview(r, System.currentTimeMillis()));
    }

    public void setAlert(String id, SafetyEvent.Alert a) {
        SafetyEvent e = byId(id);
        if (e != null) save(e.withAlert(a, e.updatedAt));
    }

    public FlagEngine.FlagState flag(SafetyEvent.Flag f) {
        return FlagEngine.compute(f, cache);
    }

    /** Flag level changes, newest first: {flag, level, eventId, changedAt}. */
    public List<String[]> flagHistory(SafetyEvent.Flag f) {
        List<String[]> out = new ArrayList<>();
        try (Cursor c = db.getReadableDatabase().query(KidsDatabaseHelper.TABLE_FLAG_HISTORY, null, "flag=?", new String[]{f.name()},
                null, null, "changed_at DESC", "50")) {
            while (c.moveToNext()) out.add(new String[]{s(c, "flag"), s(c, "level"), s(c, "event_id"), String.valueOf(l(c, "changed_at"))});
        } catch (RuntimeException e) {
            healthy = false;
        }
        return out;
    }

    public synchronized void purgeOld(long now) {
        long cutoff = now - RETENTION_MS;
        for (SafetyEvent e : cache) if (e.updatedAt < cutoff) cache.remove(e);
        try {
            SQLiteDatabase d = db.getWritableDatabase();
            d.delete(KidsDatabaseHelper.TABLE_SAFETY_EVENTS, "updated_at < ?", new String[]{String.valueOf(cutoff)});
            d.delete(KidsDatabaseHelper.TABLE_FLAG_HISTORY, "changed_at < ?", new String[]{String.valueOf(cutoff)});
        } catch (RuntimeException e) {
            healthy = false;
        }
        changed();
    }

    public synchronized void deleteAll() {
        cache.clear();
        try {
            SQLiteDatabase d = db.getWritableDatabase();
            d.delete(KidsDatabaseHelper.TABLE_SAFETY_EVENTS, null, null);
            d.delete(KidsDatabaseHelper.TABLE_FLAG_HISTORY, null, null);
        } catch (RuntimeException e) {
            healthy = false;
        }
        changed();
    }

    private static ContentValues values(SafetyEvent e) {
        ContentValues v = new ContentValues();
        v.put("event_id", e.eventId);
        v.put("dedupe_key", e.dedupeKey);
        v.put("created_at", e.createdAt);
        v.put("updated_at", e.updatedAt);
        v.put("source_type", e.sourceType.name());
        v.put("source_app", e.sourceApp);
        v.put("category", e.category.name());
        v.put("flag", e.flag.name());
        v.put("level", e.level.name());
        v.put("severity", e.severity);
        v.put("confidence", e.confidence);
        v.put("status", e.status.name());
        v.put("analysis_source", e.analysisSource.name());
        v.put("model_outcome", e.modelOutcome);
        v.put("evidence", Json.write(e.evidence));
        v.put("explanation", e.explanation);
        v.put("actions", Json.write(e.actions));
        v.put("review", e.review.name());
        v.put("alert", e.alert.name());
        return v;
    }
}
