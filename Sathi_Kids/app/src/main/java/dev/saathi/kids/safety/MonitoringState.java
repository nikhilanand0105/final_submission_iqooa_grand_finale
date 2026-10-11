package dev.saathi.kids.safety;

import android.app.NotificationManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Build;
import android.provider.Settings;

import dev.saathi.kids.ai.GemmaModelManager;
import dev.saathi.kids.storage.SafetyEventStore;
import dev.saathi.safety.MonitoringStatus;

/** Collects the real Android state for {@link MonitoringStatus} and builds the system-settings intents. */
public final class MonitoringState {

    private MonitoringState() {}

    public static boolean notificationAccessGranted(Context c) {
        ComponentName cn = new ComponentName(c, SaathiNotificationListener.class);
        if (Build.VERSION.SDK_INT >= 27) {
            NotificationManager nm = c.getSystemService(NotificationManager.class);
            return nm != null && nm.isNotificationListenerAccessGranted(cn);
        }
        String flat = Settings.Secure.getString(c.getContentResolver(), "enabled_notification_listeners");
        return flat != null && flat.contains(cn.flattenToString());
    }

    public static MonitoringStatus compute(Context c) {
        SafetyEventProcessor p = SafetyEventProcessor.get(c);
        SharedPreferences s = p.stats();
        MonitoringStatus.Inputs in = new MonitoringStatus.Inputs();
        in.notificationAccessGranted = notificationAccessGranted(c);
        // A stale "connected" flag is not trusted once access has been revoked.
        in.listenerConnected = in.notificationAccessGranted && s.getBoolean("listener_connected", false);
        in.listenerLastConnectedAt = s.getLong("listener_connected_at", 0);
        in.postNotificationsAllowed = p.alerts().canPostNotifications();
        in.modelState = GemmaModelManager.get(c).getState();
        in.storageHealthy = SafetyEventStore.get(c).isHealthy();
        in.pendingAnalyses = p.pendingCount();
        in.lastProcessedAt = s.getLong("last_processed_at", 0);
        in.contentUnavailableCount = s.getInt("content_unavailable", 0);
        in.droppedForBackpressure = s.getInt("dropped", 0);
        return MonitoringStatus.compute(in);
    }

    public static Intent notificationAccessSettings(Context c) {
        if (Build.VERSION.SDK_INT >= 30) {
            Intent i = new Intent(Settings.ACTION_NOTIFICATION_LISTENER_DETAIL_SETTINGS);
            i.putExtra(Settings.EXTRA_NOTIFICATION_LISTENER_COMPONENT_NAME,
                    new ComponentName(c, SaathiNotificationListener.class).flattenToString());
            return i;
        }
        return new Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS);
    }

    public static Intent appNotificationSettings(Context c) {
        return new Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).putExtra(Settings.EXTRA_APP_PACKAGE, c.getPackageName());
    }
}
