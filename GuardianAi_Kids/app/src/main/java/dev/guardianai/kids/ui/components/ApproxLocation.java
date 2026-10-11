package dev.guardianai.kids.ui.components;

import android.Manifest;
import android.content.Context;
import android.content.pm.PackageManager;
import android.location.Location;
import android.location.LocationListener;
import android.location.LocationManager;
import android.os.Build;
import android.os.Bundle;
import android.os.CancellationSignal;
import android.os.Handler;
import android.os.Looper;

import dev.guardianai.help.HelpRequest;

/**
 * One-shot approximate (network/coarse) location for a help request the child chose to share it with.
 * Never runs in the background and never tracks.
 */
final class ApproxLocation {

    interface Callback {
        void onResult(HelpRequest.LocationChoice choice, HelpRequest.Location loc);
    }

    private ApproxLocation() {}

    static boolean hasPermission(Context c) {
        return c.checkSelfPermission(Manifest.permission.ACCESS_COARSE_LOCATION) == PackageManager.PERMISSION_GRANTED;
    }

    @SuppressWarnings({"MissingPermission", "deprecation"})
    static void get(Context c, long timeoutMs, Callback cb) {
        if (!hasPermission(c)) {
            cb.onResult(HelpRequest.LocationChoice.PERMISSION_DENIED, null);
            return;
        }
        LocationManager lm = (LocationManager) c.getSystemService(Context.LOCATION_SERVICE);
        if (lm == null || !lm.isProviderEnabled(LocationManager.NETWORK_PROVIDER)) {
            cb.onResult(HelpRequest.LocationChoice.UNAVAILABLE, null);
            return;
        }
        Handler h = new Handler(Looper.getMainLooper());
        final boolean[] done = {false};
        Runnable timeout = () -> {
            if (!done[0]) {
                done[0] = true;
                cb.onResult(HelpRequest.LocationChoice.UNAVAILABLE, null);
            }
        };
        h.postDelayed(timeout, timeoutMs);
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                CancellationSignal cs = new CancellationSignal();
                h.postDelayed(cs::cancel, timeoutMs);
                lm.getCurrentLocation(LocationManager.NETWORK_PROVIDER, cs, c.getMainExecutor(), loc -> deliver(loc, done, h, timeout, cb));
            } else {
                lm.requestSingleUpdate(LocationManager.NETWORK_PROVIDER, new LocationListener() {
                    @Override public void onLocationChanged(Location loc) { deliver(loc, done, h, timeout, cb); }
                    @Override public void onStatusChanged(String p, int s, Bundle e) { }
                    @Override public void onProviderEnabled(String p) { }
                    @Override public void onProviderDisabled(String p) { }
                }, Looper.getMainLooper());
            }
        } catch (RuntimeException e) {
            deliver(null, done, h, timeout, cb);
        }
    }

    private static void deliver(Location loc, boolean[] done, Handler h, Runnable timeout, Callback cb) {
        if (done[0]) return;
        done[0] = true;
        h.removeCallbacks(timeout);
        if (loc == null) cb.onResult(HelpRequest.LocationChoice.UNAVAILABLE, null);
        else cb.onResult(HelpRequest.LocationChoice.SHARED,
                new HelpRequest.Location(loc.getLatitude(), loc.getLongitude(), loc.hasAccuracy() ? loc.getAccuracy() : -1, loc.getTime()));
    }
}
