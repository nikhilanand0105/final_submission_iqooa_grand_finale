package dev.saathi.personal.network;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.VpnService;
import android.os.Build;
import android.provider.Settings;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Manages the lifecycle, persistent user preferences, and real-time state
 * of the Saathi on-device network protection service.
 */
public class NetworkProtectionManager {

    public static final int REQUEST_CODE_VPN_CONSENT = 9001;
    private static final String PREFS_NAME = "saathi_network_protection_prefs";
    private static final String KEY_USER_PREF_ENABLED = "key_vpn_user_pref_enabled";
    private static final String KEY_LAST_BLOCKED_SYSTEM = "key_last_blocked_system";
    private static final String KEY_LAST_FAILURE_REASON = "key_last_failure_reason";

    private static volatile NetworkProtectionManager instance;

    private final Context appContext;
    private final SharedPreferences prefs;
    private final List<StatusListener> listeners = new CopyOnWriteArrayList<>();

    public interface StatusListener {
        void onStatusChanged(NetworkProtectionStatus status);
    }

    private NetworkProtectionManager(Context context) {
        this.appContext = context.getApplicationContext();
        this.prefs = appContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
    }

    public static NetworkProtectionManager getInstance(Context context) {
        if (instance == null) {
            synchronized (NetworkProtectionManager.class) {
                if (instance == null) {
                    instance = new NetworkProtectionManager(context);
                }
            }
        }
        return instance;
    }

    public synchronized NetworkProtectionStatus getStatus() {
        if (SaathiVpnService.isServiceRunning()) {
            return NetworkProtectionStatus.RUNNING;
        }

        boolean userPref = prefs.getBoolean(KEY_USER_PREF_ENABLED, false);
        boolean blockedSystem = prefs.getBoolean(KEY_LAST_BLOCKED_SYSTEM, false);
        String failureReason = prefs.getString(KEY_LAST_FAILURE_REASON, null);

        if (blockedSystem) {
            return NetworkProtectionStatus.BLOCKED_BY_SYSTEM;
        }

        if (failureReason != null) {
            return NetworkProtectionStatus.FAILED;
        }

        if (userPref) {
            Intent vpnIntent = VpnService.prepare(appContext);
            if (vpnIntent != null) {
                return NetworkProtectionStatus.PERMISSION_NEEDED;
            }
            return NetworkProtectionStatus.CONFIGURED;
        }

        return NetworkProtectionStatus.STOPPED;
    }

    public boolean isUserPreferenceEnabled() {
        return prefs.getBoolean(KEY_USER_PREF_ENABLED, false);
    }

    public Intent prepareVpnIntent(Activity activity) {
        return VpnService.prepare(activity);
    }

    public void startProtection(Context context) {
        prefs.edit()
                .putBoolean(KEY_USER_PREF_ENABLED, true)
                .putBoolean(KEY_LAST_BLOCKED_SYSTEM, false)
                .remove(KEY_LAST_FAILURE_REASON)
                .apply();

        Intent intent = new Intent(context, SaathiVpnService.class);
        intent.setAction(SaathiVpnService.ACTION_START);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            context.startForegroundService(intent);
        } else {
            context.startService(intent);
        }
        notifyListeners();
    }

    public void stopProtection(Context context) {
        prefs.edit()
                .putBoolean(KEY_USER_PREF_ENABLED, false)
                .putBoolean(KEY_LAST_BLOCKED_SYSTEM, false)
                .remove(KEY_LAST_FAILURE_REASON)
                .apply();

        Intent intent = new Intent(context, SaathiVpnService.class);
        intent.setAction(SaathiVpnService.ACTION_STOP);
        context.startService(intent);
        notifyListeners();
    }

    public void onPermissionDenied() {
        prefs.edit()
                .putBoolean(KEY_LAST_BLOCKED_SYSTEM, true)
                .apply();
        notifyListeners();
    }

    public void onServiceStarted() {
        prefs.edit()
                .putBoolean(KEY_LAST_BLOCKED_SYSTEM, false)
                .remove(KEY_LAST_FAILURE_REASON)
                .apply();
        notifyListeners();
    }

    public void onServiceStopped() {
        notifyListeners();
    }

    public void onServiceFailed(String reason) {
        prefs.edit()
                .putString(KEY_LAST_FAILURE_REASON, reason)
                .apply();
        notifyListeners();
    }

    public Intent getVpnSettingsIntent() {
        try {
            return new Intent(Settings.ACTION_VPN_SETTINGS);
        } catch (Exception e) {
            return new Intent(Settings.ACTION_WIRELESS_SETTINGS);
        }
    }

    public void addListener(StatusListener listener) {
        if (listener != null && !listeners.contains(listener)) {
            listeners.add(listener);
        }
    }

    public void removeListener(StatusListener listener) {
        listeners.remove(listener);
    }

    private void notifyListeners() {
        NetworkProtectionStatus current = getStatus();
        for (StatusListener l : listeners) {
            try {
                l.onStatusChanged(current);
            } catch (Exception ignored) {}
        }
    }
}
