package dev.guardianai.model;

import java.util.Collections;
import java.util.List;
import java.util.Set;

/**
 * Structured metadata parsed from the binary AndroidManifest.xml.
 */
public class ManifestMetadata {
    private final String packageName;
    private final String versionName;
    private final int versionCode;
    private final int minSdk;
    private final int targetSdk;
    private final Set<String> requestedPermissions;
    private final List<String> activities;
    private final List<String> services;
    private final List<String> receivers;
    private final boolean hasCustomDeviceAdmin;
    private final boolean hasAccessibilityService;
    private final boolean hasLauncherActivity;

    public ManifestMetadata(
            String packageName,
            String versionName,
            int versionCode,
            int minSdk,
            int targetSdk,
            Set<String> requestedPermissions,
            List<String> activities,
            List<String> services,
            List<String> receivers,
            boolean hasCustomDeviceAdmin,
            boolean hasAccessibilityService,
            boolean hasLauncherActivity) {
        this.packageName = packageName;
        this.versionName = versionName;
        this.versionCode = versionCode;
        this.minSdk = minSdk;
        this.targetSdk = targetSdk;
        this.requestedPermissions = requestedPermissions != null ? requestedPermissions : Collections.emptySet();
        this.activities = activities != null ? activities : Collections.emptyList();
        this.services = services != null ? services : Collections.emptyList();
        this.receivers = receivers != null ? receivers : Collections.emptyList();
        this.hasCustomDeviceAdmin = hasCustomDeviceAdmin;
        this.hasAccessibilityService = hasAccessibilityService;
        this.hasLauncherActivity = hasLauncherActivity;
    }

    public String getPackageName() {
        return packageName;
    }

    public String getVersionName() {
        return versionName;
    }

    public int getVersionCode() {
        return versionCode;
    }

    public int getMinSdk() {
        return minSdk;
    }

    public int getTargetSdk() {
        return targetSdk;
    }

    public Set<String> getRequestedPermissions() {
        return requestedPermissions;
    }

    public List<String> getActivities() {
        return activities;
    }

    public List<String> getServices() {
        return services;
    }

    public List<String> getReceivers() {
        return receivers;
    }

    public boolean hasCustomDeviceAdmin() {
        return hasCustomDeviceAdmin;
    }

    public boolean hasAccessibilityService() {
        return hasAccessibilityService;
    }

    public boolean hasLauncherActivity() {
        return hasLauncherActivity;
    }

    public boolean hasPermission(String permission) {
        return requestedPermissions.contains(permission);
    }
}
