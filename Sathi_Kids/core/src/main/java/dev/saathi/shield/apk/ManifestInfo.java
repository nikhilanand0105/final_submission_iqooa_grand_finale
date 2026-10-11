package dev.saathi.shield.apk;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/** Facts extracted from a compiled AndroidManifest.xml. Null means "not present in the manifest". */
public final class ManifestInfo {

    public final String packageName;
    public final String versionName;
    public final Long versionCode;
    public final Integer minSdk;
    public final Integer targetSdk;
    public final String label;
    public final List<String> permissions;
    public final int activities, services, receivers, providers;
    public final boolean hasLauncherActivity;
    public final boolean debuggable;
    public final Boolean usesCleartextTraffic;
    public final List<String> accessibilityServices;
    public final List<String> deviceAdminReceivers;
    public final List<String> notificationListeners;
    public final List<String> smsReceivers;
    public final List<String> bootReceivers;

    private ManifestInfo(Builder b) {
        packageName = b.packageName;
        versionName = b.versionName;
        versionCode = b.versionCode;
        minSdk = b.minSdk;
        targetSdk = b.targetSdk;
        label = b.label;
        permissions = Collections.unmodifiableList(new ArrayList<>(b.permissions));
        activities = b.activities;
        services = b.services;
        receivers = b.receivers;
        providers = b.providers;
        hasLauncherActivity = b.hasLauncherActivity;
        debuggable = b.debuggable;
        usesCleartextTraffic = b.usesCleartextTraffic;
        accessibilityServices = list(b.accessibilityServices);
        deviceAdminReceivers = list(b.deviceAdminReceivers);
        notificationListeners = list(b.notificationListeners);
        smsReceivers = list(b.smsReceivers);
        bootReceivers = list(b.bootReceivers);
    }

    private static List<String> list(Set<String> s) {
        return Collections.unmodifiableList(new ArrayList<>(s));
    }

    static final class Builder {
        String packageName, versionName, label;
        Long versionCode;
        Integer minSdk, targetSdk;
        final List<String> permissions = new ArrayList<>();
        int activities, services, receivers, providers;
        boolean hasLauncherActivity, debuggable, pendingMain, pendingLauncher;
        Boolean usesCleartextTraffic;
        final Set<String> accessibilityServices = new LinkedHashSet<>();
        final Set<String> deviceAdminReceivers = new LinkedHashSet<>();
        final Set<String> notificationListeners = new LinkedHashSet<>();
        final Set<String> smsReceivers = new LinkedHashSet<>();
        final Set<String> bootReceivers = new LinkedHashSet<>();

        ManifestInfo build() {
            return new ManifestInfo(this);
        }
    }
}
