package dev.saathi.kids.safety;

import android.Manifest;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;

import dev.saathi.kids.ui.MainActivity;
import dev.saathi.safety.FlagEngine;
import dev.saathi.safety.SafetyEvent;

/**
 * Delivers alerts for safety events through the right mechanism: an in-app alert when Saathi is on screen, otherwise
 * a system notification. Message text is never put on the lock screen; the public version is always generic.
 * Android decides how (or whether) a notification is presented (permission, Do Not Disturb, OEM settings), so the
 * recorded state is "delivered to Android", not "seen".
 */
public final class AlertDispatcher {

    public static final String EXTRA_EVENT_ID = "saathi_event_id";
    static final String CH_THREATS = "saathi_threats";
    static final String CH_SUPPORT = "saathi_support";
    static final String CH_INFO = "saathi_info";

    /** Implemented by MainActivity while it is visible. */
    public interface InAppPresenter {
        void presentSafetyEvent(SafetyEvent e, FlagEngine.AlertKind kind);
    }

    private static volatile InAppPresenter presenter;
    private final Context app;
    private final Handler main = new Handler(Looper.getMainLooper());

    public AlertDispatcher(Context ctx) {
        this.app = ctx.getApplicationContext();
        createChannels();
    }

    public static void setInAppPresenter(InAppPresenter p) {
        presenter = p;
    }

    public static void clearInAppPresenter(InAppPresenter p) {
        if (presenter == p) presenter = null;
    }

    public boolean canPostNotifications() {
        if (Build.VERSION.SDK_INT >= 33
                && app.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) return false;
        NotificationManager nm = app.getSystemService(NotificationManager.class);
        return nm != null && nm.areNotificationsEnabled();
    }

    private void createChannels() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return;
        NotificationManager nm = app.getSystemService(NotificationManager.class);
        if (nm == null) return;
        NotificationChannel t = new NotificationChannel(CH_THREATS, "Threat warnings", NotificationManager.IMPORTANCE_HIGH);
        t.setDescription("Messages that look like threats, blackmail or pressure");
        t.setLockscreenVisibility(Notification.VISIBILITY_PRIVATE);
        NotificationChannel s = new NotificationChannel(CH_SUPPORT, "Support check-ins", NotificationManager.IMPORTANCE_HIGH);
        s.setDescription("Gentle check-ins when something sounds really hard");
        s.setLockscreenVisibility(Notification.VISIBILITY_PRIVATE);
        NotificationChannel i = new NotificationChannel(CH_INFO, "Safety notes", NotificationManager.IMPORTANCE_DEFAULT);
        i.setDescription("Things that may need a second look");
        i.setLockscreenVisibility(Notification.VISIBILITY_PRIVATE);
        nm.createNotificationChannel(t);
        nm.createNotificationChannel(s);
        nm.createNotificationChannel(i);
    }

    /** Returns the resulting alert state for the event. Safe to call from any thread. */
    public SafetyEvent.Alert dispatch(SafetyEvent e, FlagEngine.AlertKind kind) {
        if (kind == FlagEngine.AlertKind.NONE) return e.alert;
        InAppPresenter p = presenter;
        if (p != null) {
            main.post(() -> p.presentSafetyEvent(e, kind));
            return SafetyEvent.Alert.SHOWN_IN_APP;
        }
        if (!canPostNotifications()) return SafetyEvent.Alert.NOT_PERMITTED;
        try {
            NotificationManager nm = app.getSystemService(NotificationManager.class);
            String channel;
            String title;
            String body;
            switch (kind) {
                case THREAT_ALERT:
                    channel = CH_THREATS;
                    title = "Saathi: a message may be a threat";
                    body = "A message " + from(e) + " looks like pressure or a threat. Tap to see what you can do.";
                    break;
                case SELF_HARM_SUPPORT:
                    channel = CH_SUPPORT;
                    title = "Saathi is here for you";
                    body = "Something " + from(e) + " sounded really hard. Tap if you'd like to talk to someone.";
                    break;
                case SCAM_NOTICE:
                    channel = CH_INFO;
                    title = "Saathi: a message has warning signs";
                    body = "A message " + from(e) + " may be a trick. Tap to see why.";
                    break;
                case WEBSITE_WARNING:
                    channel = CH_INFO;
                    title = "Saathi: website warning";
                    body = "A website may not be safe or suitable. Tap for details.";
                    break;
                default:
                    channel = CH_INFO;
                    title = "Saathi: something to look at";
                    body = "A message " + from(e) + " might need a second look.";
                    break;
            }
            Intent open = new Intent(app, MainActivity.class)
                    .setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP)
                    .putExtra(EXTRA_EVENT_ID, e.eventId);
            PendingIntent pi = PendingIntent.getActivity(app, e.eventId.hashCode(), open,
                    PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
            Notification publicVersion = builder(channel)
                    .setContentTitle("Saathi Kids")
                    .setContentText("Open Saathi to see a safety note")
                    .setSmallIcon(android.R.drawable.ic_dialog_info)
                    .build();
            Notification n = builder(channel)
                    .setContentTitle(title)
                    .setContentText(body)
                    .setStyle(new Notification.BigTextStyle().bigText(body))
                    .setSmallIcon(android.R.drawable.ic_dialog_info)
                    .setContentIntent(pi)
                    .setAutoCancel(true)
                    .setCategory(Notification.CATEGORY_MESSAGE)
                    .setVisibility(Notification.VISIBILITY_PRIVATE)
                    .setPublicVersion(publicVersion)
                    .setOnlyAlertOnce(true)
                    .build();
            nm.notify(e.eventId.hashCode(), n);
            return SafetyEvent.Alert.DELIVERED;
        } catch (SecurityException ex) {
            return SafetyEvent.Alert.NOT_PERMITTED;
        } catch (RuntimeException ex) {
            return SafetyEvent.Alert.FAILED;
        }
    }

    @SuppressWarnings("deprecation")
    private Notification.Builder builder(String channel) {
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.O ? new Notification.Builder(app, channel) : new Notification.Builder(app);
    }

    private static String from(SafetyEvent e) {
        return e.sourceApp.isEmpty() ? "you received" : "in " + e.sourceApp;
    }
}
