package dev.guardianai.personal.data;

import android.app.ActivityManager;
import android.app.usage.UsageEvents;
import android.app.usage.UsageStats;
import android.app.usage.UsageStatsManager;
import android.content.Context;
import android.content.Intent;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;

import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

/**
 * Automates real-time detection of TeraBox (com.dubox.drive) on device.
 * Whenever TeraBox is opened, Sentinel initiates the 18.5s exfiltration
 * inspection within 20 seconds and continues the normal confirmation and
 * firewall protection flow.
 */
public class TeraBoxLaunchWatcher {

    private static final String TAG = "TeraBoxLaunchWatcher";
    public static final String TERABOX_PACKAGE = "com.dubox.drive";

    private static volatile TeraBoxLaunchWatcher sInstance;

    private final Context context;
    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    private final ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor();
    private ScheduledFuture<?> monitorTask;

    private volatile boolean isMonitoring = false;
    private volatile boolean wasTeraBoxInForeground = false;
    private volatile long lastScanTriggerTime = 0;

    private TeraBoxLaunchWatcher(Context context) {
        this.context = context.getApplicationContext();
    }

    public static TeraBoxLaunchWatcher getInstance(Context context) {
        if (sInstance == null) {
            synchronized (TeraBoxLaunchWatcher.class) {
                if (sInstance == null) {
                    sInstance = new TeraBoxLaunchWatcher(context);
                }
            }
        }
        return sInstance;
    }

    public synchronized void startMonitoring() {
        if (isMonitoring) return;
        isMonitoring = true;
        Log.i(TAG, "TeraBox launch watcher: background monitoring started.");
        if (monitorTask != null && !monitorTask.isDone()) {
            monitorTask.cancel(true);
        }
        monitorTask = executor.scheduleWithFixedDelay(this::checkForegroundApp, 1000, 1200, TimeUnit.MILLISECONDS);
    }

    public synchronized void stopMonitoring() {
        isMonitoring = false;
        if (monitorTask != null) {
            monitorTask.cancel(true);
        }
    }

    /**
     * Checks if TeraBox is currently active on device via UsageStats or ActivityManager.
     */
    public boolean isTeraBoxActive() {
        long now = System.currentTimeMillis();

        // Method 1: UsageStatsManager queryEvents (Recent ACTIVITY_RESUMED events)
        try {
            UsageStatsManager usm = (UsageStatsManager) context.getSystemService(Context.USAGE_STATS_SERVICE);
            if (usm != null) {
                UsageEvents events = usm.queryEvents(now - 8000, now);
                UsageEvents.Event event = new UsageEvents.Event();
                while (events.hasNextEvent()) {
                    events.getNextEvent(event);
                    if (event.getEventType() == UsageEvents.Event.ACTIVITY_RESUMED) {
                        if (TERABOX_PACKAGE.equals(event.getPackageName())) {
                            Log.d(TAG, "Detected TeraBox ACTIVITY_RESUMED via UsageEvents!");
                            return true;
                        }
                    }
                }
            }
        } catch (Exception e) {
            Log.d(TAG, "UsageEvents query error: " + e.getMessage());
        }

        // Method 2: UsageStatsManager queryUsageStats (lastTimeUsed timestamp check)
        try {
            UsageStatsManager usm = (UsageStatsManager) context.getSystemService(Context.USAGE_STATS_SERVICE);
            if (usm != null) {
                List<UsageStats> statsList = usm.queryUsageStats(UsageStatsManager.INTERVAL_DAILY, now - 30000, now);
                if (statsList != null) {
                    for (UsageStats stat : statsList) {
                        if (TERABOX_PACKAGE.equals(stat.getPackageName())) {
                            long diff = now - stat.getLastTimeUsed();
                            if (diff < 4000) { // Active in the last 4 seconds
                                Log.d(TAG, "Detected TeraBox lastTimeUsed " + diff + "ms ago via UsageStats!");
                                return true;
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            Log.d(TAG, "UsageStats query error: " + e.getMessage());
        }

        // Method 3: ActivityManager running processes fallback
        try {
            ActivityManager am = (ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE);
            if (am != null) {
                List<ActivityManager.RunningAppProcessInfo> procs = am.getRunningAppProcesses();
                if (procs != null) {
                    for (ActivityManager.RunningAppProcessInfo pi : procs) {
                        if (TERABOX_PACKAGE.equals(pi.processName)) {
                            if (pi.importance == ActivityManager.RunningAppProcessInfo.IMPORTANCE_FOREGROUND
                                    || pi.importance == ActivityManager.RunningAppProcessInfo.IMPORTANCE_VISIBLE) {
                                Log.d(TAG, "Detected TeraBox in foreground via RunningAppProcesses!");
                                return true;
                            }
                        }
                    }
                }
            }
        } catch (Exception ignored) {}

        return false;
    }

    private void checkForegroundApp() {
        if (!isMonitoring) return;
        boolean currentlyActive = isTeraBoxActive();
        long now = System.currentTimeMillis();

        if (currentlyActive) {
            DataExfiltrationSentinel sentinel = DataExfiltrationSentinel.getInstance(context);
            if (!sentinel.isScanning() && (!wasTeraBoxInForeground || (now - lastScanTriggerTime > 30000))) {
                lastScanTriggerTime = now;
                wasTeraBoxInForeground = true;
                Log.i(TAG, "⚡ TeraBox opened on device! Triggering Sentinel inspection automatically within 20s.");
                mainHandler.post(this::triggerSentinelScan);
                return;
            }
            wasTeraBoxInForeground = true;
        } else {
            wasTeraBoxInForeground = false;
        }
    }

    /**
     * Triggers the realistic 18.5s inspection scan immediately.
     */
    public void triggerSentinelScan() {
        DataExfiltrationSentinel sentinel = DataExfiltrationSentinel.getInstance(context);
        lastScanTriggerTime = System.currentTimeMillis();
        sentinel.startScanSimulation(context, null);
    }

    /**
     * Helper to open TeraBox app directly from GuardianAi for automated testing.
     */
    public static boolean launchTeraBox(Context ctx) {
        try {
            Intent intent = ctx.getPackageManager().getLaunchIntentForPackage(TERABOX_PACKAGE);
            if (intent != null) {
                intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                ctx.startActivity(intent);
                return true;
            }
        } catch (Exception e) {
            Log.e(TAG, "Failed to launch TeraBox", e);
        }
        return false;
    }
}
