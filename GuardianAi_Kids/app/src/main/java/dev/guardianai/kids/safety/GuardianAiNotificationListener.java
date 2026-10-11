package dev.guardianai.kids.safety;

import android.app.Notification;
import android.content.ComponentName;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.os.Parcelable;
import android.service.notification.NotificationListenerService;
import android.service.notification.StatusBarNotification;
import android.util.Log;

import dev.guardianai.safety.NotificationPolicy;
import dev.guardianai.safety.SafetyTypes.SourceType;

import java.util.List;

/**
 * Receives notifications Android shares after the user enables notification access, and passes the text Android
 * exposes to the shared safety pipeline. Android binds this service itself (also after reboot); the main screen does
 * not need to be open. It cannot see messages that never produce a notification, hidden/redacted previews, or text
 * the user types and sends.
 */
public class GuardianAiNotificationListener extends NotificationListenerService {

    private static final String TAG = "GuardianAiNotifListener";
    private static final NotificationPolicy.DeltaTracker DELTA = new NotificationPolicy.DeltaTracker(100);

    @Override
    public void onListenerConnected() {
        super.onListenerConnected();
        SafetyEventProcessor.get(this).stats().edit()
                .putBoolean("listener_connected", true)
                .putLong("listener_connected_at", System.currentTimeMillis()).apply();
    }

    @Override
    public void onListenerDisconnected() {
        super.onListenerDisconnected();
        SafetyEventProcessor.get(this).stats().edit().putBoolean("listener_connected", false)
                .putLong("listener_disconnected_at", System.currentTimeMillis()).apply();
        // Ask Android to bind again if access is still granted (documented API; no restart tricks).
        try {
            requestRebind(new ComponentName(this, GuardianAiNotificationListener.class));
        } catch (RuntimeException e) {
            Log.w(TAG, "rebind request failed", e);
        }
    }

    @Override
    public void onNotificationPosted(StatusBarNotification sbn) {
        try {
            NotificationPolicy.Input in = toInput(sbn);
            NotificationPolicy.Result r = NotificationPolicy.evaluate(in, getPackageName());
            SafetyEventProcessor p = SafetyEventProcessor.get(this);
            if (r.decision == NotificationPolicy.Decision.CONTENT_UNAVAILABLE) {
                p.recordContentUnavailable();
                return;
            }
            if (r.decision != NotificationPolicy.Decision.ANALYSE) return;
            List<String> fresh = DELTA.newLines(sbn.getKey(), r.lines);
            if (fresh.isEmpty()) return; // update with nothing new
            p.submitBackground(SourceType.NOTIFICATION, appLabel(this, sbn.getPackageName()), String.join("\n", fresh));
        } catch (RuntimeException e) {
            Log.e(TAG, "could not read notification", e); // never crash the listener
        }
    }

    @Override
    public void onTrimMemory(int level) {
        super.onTrimMemory(level);
        dev.guardianai.kids.ai.GemmaModelManager.get(this).onTrimMemory(level);
    }

    @Override
    public void onNotificationRemoved(StatusBarNotification sbn) {
        DELTA.forget(sbn.getKey());
    }

    static NotificationPolicy.Input toInput(StatusBarNotification sbn) {
        Notification n = sbn.getNotification();
        Bundle x = n.extras;
        NotificationPolicy.Input in = new NotificationPolicy.Input();
        in.packageName = sbn.getPackageName();
        in.key = sbn.getKey();
        in.ongoing = sbn.isOngoing();
        in.clearable = sbn.isClearable();
        in.groupSummary = (n.flags & Notification.FLAG_GROUP_SUMMARY) != 0;
        in.category = n.category;
        if (x != null) {
            in.title = str(x.getCharSequence(Notification.EXTRA_TITLE));
            in.text = str(x.getCharSequence(Notification.EXTRA_TEXT));
            in.bigText = str(x.getCharSequence(Notification.EXTRA_BIG_TEXT));
            in.subText = str(x.getCharSequence(Notification.EXTRA_SUB_TEXT));
            Parcelable[] msgs = parcelables(x, Notification.EXTRA_MESSAGES);
            if (msgs != null) {
                int start = Math.max(0, msgs.length - 10);
                for (int i = start; i < msgs.length; i++) {
                    if (!(msgs[i] instanceof Bundle)) continue;
                    Bundle m = (Bundle) msgs[i];
                    String text = str(m.getCharSequence("text"));
                    String sender = str(m.getCharSequence("sender"));
                    if (text != null) in.messageLines.add(sender != null ? sender + ": " + text : text);
                }
            }
        }
        return in;
    }

    @SuppressWarnings("deprecation")
    private static Parcelable[] parcelables(Bundle b, String key) {
        try {
            return b.getParcelableArray(key);
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static String str(CharSequence c) {
        return c == null ? null : c.toString();
    }

    /** App name if visible to GuardianAi (see &lt;queries&gt; in the manifest), else the package name. */
    static String appLabel(Context ctx, String pkg) {
        try {
            PackageManager pm = ctx.getPackageManager();
            ApplicationInfo ai = pm.getApplicationInfo(pkg, 0);
            return pm.getApplicationLabel(ai).toString();
        } catch (PackageManager.NameNotFoundException | RuntimeException e) {
            return pkg;
        }
    }
}
