package dev.saathi.kids.safety;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Log;

import dev.saathi.ai.explain.ModelState;
import dev.saathi.kids.ai.GemmaModelManager;
import dev.saathi.kids.storage.SafetyEventStore;
import dev.saathi.safety.FlagEngine;
import dev.saathi.safety.SafetyClassification;
import dev.saathi.safety.SafetyEvent;
import dev.saathi.safety.SafetyPipeline;
import dev.saathi.safety.SafetyTypes;
import dev.saathi.safety.SafetyTypes.SourceType;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Runs the shared Gemma-first safety pipeline for background sources (notifications) and synchronous callers
 * (manual Check, Safe Browser). One worker thread, bounded queue: when full, items are not silently lost — the
 * overflow is recorded as an "analysis unavailable" event and counted in the monitoring status.
 * Content is kept in memory only (for one later model re-check); it is never written to disk.
 */
public final class SafetyEventProcessor {

    private static final String TAG = "SafetyEventProcessor";
    private static final int QUEUE = 40;
    private static final int REANALYSIS_CACHE = 20;
    private static volatile SafetyEventProcessor instance;

    private final Context app;
    private final GemmaModelManager model;
    private final SafetyPipeline pipeline;
    private final SafetyEventStore store;
    private final AlertDispatcher alerts;
    private final SharedPreferences stats;
    private final ThreadPoolExecutor worker;
    private final AtomicInteger pending = new AtomicInteger();
    private static final long MODEL_IDLE_RELEASE_MS = 10 * 60 * 1000L;
    private final android.os.Handler main = new android.os.Handler(android.os.Looper.getMainLooper());
    private final Runnable idleRelease;
    public static final long RECENT_EVENT_COOLDOWN_MS = 5000L;
    private final Map<String, Long> recentKeyTimestamps = new LinkedHashMap<String, Long>(64, 0.75f, true) {
        @Override protected boolean removeEldestEntry(Map.Entry<String, Long> e) { return size() > 500; }
    };
    /** dedupeKey -> {sourceType, sourceApp, text} for results produced without the model. */
    private final Map<String, String[]> awaitingModel = new LinkedHashMap<String, String[]>(16, 0.75f, true) {
        @Override protected boolean removeEldestEntry(Map.Entry<String, String[]> e) { return size() > REANALYSIS_CACHE; }
    };

    public static SafetyEventProcessor get(Context ctx) {
        if (instance == null) {
            synchronized (SafetyEventProcessor.class) {
                if (instance == null) instance = new SafetyEventProcessor(ctx.getApplicationContext());
            }
        }
        return instance;
    }

    private SafetyEventProcessor(Context app) {
        this.app = app;
        this.model = GemmaModelManager.get(app);
        this.idleRelease = () -> {
            if (pending.get() == 0 && model.getState() == ModelState.READY) model.release();
        };
        this.pipeline = new SafetyPipeline(model);
        this.store = SafetyEventStore.get(app);
        this.alerts = new AlertDispatcher(app);
        this.stats = app.getSharedPreferences("saathi_monitoring", Context.MODE_PRIVATE);
        this.worker = new ThreadPoolExecutor(1, 1, 30, TimeUnit.SECONDS, new ArrayBlockingQueue<Runnable>(QUEUE), r -> {
            Thread t = new Thread(r, "saathi-safety");
            t.setPriority(Thread.NORM_PRIORITY - 1);
            return t;
        }, (r, ex) -> {
            if (r instanceof BackgroundTask) {
                pending.decrementAndGet();
                onOverflow();
            }
        });
        this.worker.allowCoreThreadTimeOut(true);
        model.addListener(this::onModelStateChanged);
        worker.execute(() -> store.purgeOld(System.currentTimeMillis()));
    }

    public AlertDispatcher alerts() { return alerts; }
    public int pendingCount() { return pending.get(); }
    public SharedPreferences stats() { return stats; }

    // ------------------------------------------------------------------ background (notifications)

    /** Queue notification text for analysis. Returns immediately. */
    public void submitBackground(SourceType type, String sourceApp, String text) {
        long now = System.currentTimeMillis();
        String key = FlagEngine.dedupeKey(type, sourceApp, text);
        synchronized (recentKeyTimestamps) {
            Long last = recentKeyTimestamps.get(key);
            if (last != null && (now - last) < RECENT_EVENT_COOLDOWN_MS) {
                return; // suppress rapid bounce within cooldown window
            }
            recentKeyTimestamps.put(key, now);
        }
        pending.incrementAndGet();
        worker.execute(new BackgroundTask(() -> {
            try {
                ensureModelLoading();
                process(type, sourceApp, text, key, true);
            } catch (RuntimeException e) {
                Log.e(TAG, "processing failed", e);
            } finally {
                pending.decrementAndGet();
                main.removeCallbacks(idleRelease);
                main.postDelayed(idleRelease, MODEL_IDLE_RELEASE_MS); // free model memory after 10 idle minutes
                stats.edit().putLong("last_processed_at", System.currentTimeMillis())
                        .putInt("processed", stats.getInt("processed", 0) + 1).apply();
            }
        }));
    }

    /** Marks queued notification work so queue overflow can be accounted for. */
    private static final class BackgroundTask implements Runnable {
        private final Runnable r;
        BackgroundTask(Runnable r) { this.r = r; }
        @Override public void run() { r.run(); }
    }

    public void recordContentUnavailable() {
        stats.edit().putInt("content_unavailable", stats.getInt("content_unavailable", 0) + 1)
                .putLong("last_content_unavailable_at", System.currentTimeMillis()).apply();
    }

    private void onOverflow() {
        int dropped = stats.getInt("dropped", 0) + 1;
        stats.edit().putInt("dropped", dropped).apply();
        long now = System.currentTimeMillis();
        String key = "overflow-" + (now / 3_600_000L);
        SafetyClassification u = SafetyClassification.unavailable(SourceType.NOTIFICATION, SafetyTypes.Status.UNAVAILABLE,
                "Too many messages arrived at once, so some couldn't be checked.");
        FlagEngine.Decision d = FlagEngine.decide(u, "QUEUE_FULL", SourceType.NOTIFICATION, "", key, store.recentByKey(key, now), now);
        if (d.event != null) store.save(d.event);
    }

    // ------------------------------------------------------------------ synchronous (manual check, browser)

    /** Analyses now on the caller's (background) thread, persists any event, and returns the pipeline result. */
    public Outcome analyzeNow(SourceType type, String sourceApp, String text, boolean dispatchAlert) {
        String key = FlagEngine.dedupeKey(type, sourceApp, text);
        return process(type, sourceApp, text, key, dispatchAlert);
    }

    public static final class Outcome {
        public final SafetyPipeline.Result result;
        public final FlagEngine.Decision decision;

        Outcome(SafetyPipeline.Result r, FlagEngine.Decision d) {
            result = r;
            decision = d;
        }
    }

    private Outcome process(SourceType type, String sourceApp, String text, String key, boolean dispatchAlert) {
        SafetyPipeline.Result r = pipeline.analyze(type, text, sourceApp.isEmpty() ? null : "from " + sourceApp, null);
        long now = System.currentTimeMillis();
        FlagEngine.Decision d = FlagEngine.decide(r.classification, r.modelOutcome.name(), type, sourceApp, key, store.recentByKey(key, now), now);
        if (d.event == null) return new Outcome(r, d);
        if (r.eligibleForModelReanalysis() && type == SourceType.NOTIFICATION) {
            synchronized (awaitingModel) {
                awaitingModel.put(key, new String[]{type.name(), sourceApp, text});
            }
        }
        if (!store.save(d.event)) Log.w(TAG, "event not persisted");
        if (dispatchAlert && d.alert != FlagEngine.AlertKind.NONE) {
            SafetyEvent.Alert a = alerts.dispatch(d.event, d.alert);
            store.setAlert(d.event.eventId, a);
        }
        return new Outcome(r, d);
    }

    // ------------------------------------------------------------------ model lifecycle

    private void ensureModelLoading() {
        ModelState s = model.getState();
        if (s == ModelState.CLOSED || s == ModelState.FAILED || s == ModelState.RESOURCE_CONSTRAINED || s == ModelState.UNAVAILABLE) {
            model.refreshAvailability();
            if (model.findModelFile() != null && (model.getState() == ModelState.CLOSED || model.getState() == ModelState.RESOURCE_CONSTRAINED)) {
                model.loadAsync(); // loads only if a model file exists and memory allows
            }
        }
    }

    /** When the model becomes ready, re-check items that were analysed by rules only (same event, no duplicate alert). */
    private void onModelStateChanged() {
        if (model.getState() != ModelState.READY) return;
        final Map<String, String[]> copy;
        synchronized (awaitingModel) {
            copy = new LinkedHashMap<>(awaitingModel);
            awaitingModel.clear();
        }
        for (Map.Entry<String, String[]> e : copy.entrySet()) {
            String[] v = e.getValue();
            worker.execute(() -> process(SourceType.valueOf(v[0]), v[1], v[2], e.getKey(), true));
        }
    }
}
