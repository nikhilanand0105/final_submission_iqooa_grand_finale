package dev.saathi.personal.data.apps;

import android.graphics.drawable.Drawable;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Model representing an installed application on the device with its declared and
 * granted permissions, focusing on high-privilege and sensitive capabilities.
 */
public class InstalledAppInfo {

    public static final String PERM_ACCESSIBILITY = "android.permission.BIND_ACCESSIBILITY_SERVICE";
    public static final String PERM_OVERLAY = "android.permission.SYSTEM_ALERT_WINDOW";
    public static final String PERM_RECEIVE_SMS = "android.permission.RECEIVE_SMS";
    public static final String PERM_READ_SMS = "android.permission.READ_SMS";
    public static final String PERM_SEND_SMS = "android.permission.SEND_SMS";
    public static final String PERM_READ_CONTACTS = "android.permission.READ_CONTACTS";
    public static final String PERM_RECORD_AUDIO = "android.permission.RECORD_AUDIO";
    public static final String PERM_CAMERA = "android.permission.CAMERA";
    public static final String PERM_FINE_LOCATION = "android.permission.ACCESS_FINE_LOCATION";
    public static final String PERM_READ_MEDIA_IMAGES = "android.permission.READ_MEDIA_IMAGES";
    public static final String PERM_READ_MEDIA_VIDEO = "android.permission.READ_MEDIA_VIDEO";

    private static final Set<String> SENSITIVE_PERMISSION_SET;
    private static final Map<String, String> PERMISSION_LABELS;
    private static final Map<String, String> PERMISSION_EXPLANATIONS;

    static {
        Set<String> sensitive = new LinkedHashSet<>();
        sensitive.add(PERM_ACCESSIBILITY);
        sensitive.add(PERM_OVERLAY);
        sensitive.add(PERM_RECEIVE_SMS);
        sensitive.add(PERM_READ_SMS);
        sensitive.add(PERM_SEND_SMS);
        sensitive.add(PERM_READ_CONTACTS);
        sensitive.add(PERM_RECORD_AUDIO);
        sensitive.add(PERM_CAMERA);
        sensitive.add(PERM_FINE_LOCATION);
        sensitive.add(PERM_READ_MEDIA_IMAGES);
        sensitive.add(PERM_READ_MEDIA_VIDEO);
        SENSITIVE_PERMISSION_SET = Collections.unmodifiableSet(sensitive);

        Map<String, String> labels = new LinkedHashMap<>();
        labels.put(PERM_ACCESSIBILITY, "Accessibility Service (Screen Control)");
        labels.put(PERM_OVERLAY, "Display Over Other Apps (Overlay)");
        labels.put(PERM_RECEIVE_SMS, "Receive SMS Messages");
        labels.put(PERM_READ_SMS, "Read SMS Messages");
        labels.put(PERM_SEND_SMS, "Send SMS Messages");
        labels.put(PERM_READ_CONTACTS, "Read Contacts & Address Book");
        labels.put(PERM_RECORD_AUDIO, "Record Audio (Microphone)");
        labels.put(PERM_CAMERA, "Camera (Photos & Videos)");
        labels.put(PERM_FINE_LOCATION, "Precise GPS Location");
        labels.put(PERM_READ_MEDIA_IMAGES, "Photos & Gallery Media");
        labels.put(PERM_READ_MEDIA_VIDEO, "Videos & Gallery Clips");
        PERMISSION_LABELS = Collections.unmodifiableMap(labels);

        Map<String, String> explanations = new LinkedHashMap<>();
        explanations.put(PERM_ACCESSIBILITY, "Allows this app to inspect on-screen UI components, read text, and perform touch gestures on your behalf. Designed for screen readers and assistive utilities; high risk if enabled for untrusted apps.");
        explanations.put(PERM_OVERLAY, "Allows displaying floating windows or dialogs on top of any other app. Used by picture-in-picture players and navigation bubbles; can be misused to present misleading overlays over banking or login screens.");
        explanations.put(PERM_RECEIVE_SMS, "Allows the app to monitor and process incoming SMS messages. Frequently used by banking and messaging apps for automatic one-time password (OTP) verification.");
        explanations.put(PERM_READ_SMS, "Allows reading SMS text messages stored on the device. Useful for SMS inbox managers, but provides access to sensitive financial verification codes and messages.");
        explanations.put(PERM_SEND_SMS, "Allows sending outgoing SMS messages directly in the background. Used by emergency SOS or messaging utilities; may incur cellular carrier charges.");
        explanations.put(PERM_READ_CONTACTS, "Allows reading saved contacts, names, and phone numbers. Used by communication and social tools to find friends or sync contacts.");
        explanations.put(PERM_RECORD_AUDIO, "Allows recording sound using the device microphone. Used by voice recorders, voice assistants, and calling apps.");
        explanations.put(PERM_CAMERA, "Allows capturing photographs and video streams via the device cameras. Used by video calling, QR scanners, and camera utilities.");
        explanations.put(PERM_FINE_LOCATION, "Allows reading high-accuracy geographic coordinates via GPS and cellular towers. Used by map navigation, ride-hailing, and delivery services.");
        explanations.put(PERM_READ_MEDIA_IMAGES, "Allows reading private photos and image files stored on the device. Can be used for cloud backup or unauthorized media exfiltration.");
        explanations.put(PERM_READ_MEDIA_VIDEO, "Allows reading private video files and recordings. Can be used for media streaming or bulk background upload.");
        PERMISSION_EXPLANATIONS = Collections.unmodifiableMap(explanations);
    }

    private final String packageName;
    private final String appLabel;
    private final String versionName;
    private final long versionCode;
    private final int targetSdk;
    private final boolean isSystemApp;
    private final Drawable icon;
    private final long firstInstallTime;
    private final long lastUpdateTime;
    private final List<String> requestedPermissions;
    private final List<String> grantedPermissions;
    private final List<String> sensitivePermissions;

    public InstalledAppInfo(
            String packageName,
            String appLabel,
            String versionName,
            long versionCode,
            int targetSdk,
            boolean isSystemApp,
            Drawable icon,
            long firstInstallTime,
            long lastUpdateTime,
            List<String> requestedPermissions,
            List<String> grantedPermissions
    ) {
        this.packageName = packageName != null ? packageName : "";
        this.appLabel = appLabel != null ? appLabel : this.packageName;
        this.versionName = versionName != null ? versionName : "";
        this.versionCode = versionCode;
        this.targetSdk = targetSdk;
        this.isSystemApp = isSystemApp;
        this.icon = icon;
        this.firstInstallTime = firstInstallTime;
        this.lastUpdateTime = lastUpdateTime;

        this.requestedPermissions = requestedPermissions != null
                ? Collections.unmodifiableList(new ArrayList<>(requestedPermissions))
                : Collections.emptyList();

        this.grantedPermissions = grantedPermissions != null
                ? Collections.unmodifiableList(new ArrayList<>(grantedPermissions))
                : Collections.emptyList();

        List<String> sensitiveList = new ArrayList<>();
        for (String perm : this.requestedPermissions) {
            if (isSensitivePermission(perm)) {
                sensitiveList.add(perm);
            }
        }
        this.sensitivePermissions = Collections.unmodifiableList(sensitiveList);
    }

    public String getPackageName() {
        return packageName;
    }

    public String getAppLabel() {
        return appLabel;
    }

    public String getVersionName() {
        return versionName;
    }

    public long getVersionCode() {
        return versionCode;
    }

    public int getTargetSdk() {
        return targetSdk;
    }

    public boolean isSystemApp() {
        return isSystemApp;
    }

    public Drawable getIcon() {
        return icon;
    }

    public long getFirstInstallTime() {
        return firstInstallTime;
    }

    public long getLastUpdateTime() {
        return lastUpdateTime;
    }

    public List<String> getRequestedPermissions() {
        return requestedPermissions;
    }

    public List<String> getGrantedPermissions() {
        return grantedPermissions;
    }

    public List<String> getSensitivePermissions() {
        return sensitivePermissions;
    }

    public boolean hasAccessibilityService() {
        for (String perm : requestedPermissions) {
            if (PERM_ACCESSIBILITY.equalsIgnoreCase(perm) || perm.endsWith("BIND_ACCESSIBILITY_SERVICE")) {
                return true;
            }
        }
        return false;
    }

    public boolean hasSmsPermissions() {
        for (String perm : requestedPermissions) {
            if (perm.endsWith("RECEIVE_SMS") || perm.endsWith("READ_SMS") || perm.endsWith("SEND_SMS")) {
                return true;
            }
        }
        return false;
    }

    public boolean hasOverlayPermission() {
        for (String perm : requestedPermissions) {
            if (PERM_OVERLAY.equalsIgnoreCase(perm) || perm.endsWith("SYSTEM_ALERT_WINDOW")) {
                return true;
            }
        }
        return false;
    }

    public boolean isHighPrivilege() {
        return hasAccessibilityService() || hasSmsPermissions() || hasOverlayPermission();
    }

    public boolean isPermissionGranted(String permission) {
        if (permission == null) return false;
        return grantedPermissions.contains(permission);
    }

    public List<PermissionDetail> getSensitivePermissionDetails() {
        List<PermissionDetail> list = new ArrayList<>();
        for (String perm : sensitivePermissions) {
            list.add(new PermissionDetail(
                    perm,
                    getPermissionLabel(perm),
                    getPermissionExplanation(perm),
                    isPermissionGranted(perm),
                    true
            ));
        }
        return list;
    }

    public List<PermissionDetail> getAllPermissionDetails() {
        List<PermissionDetail> list = new ArrayList<>();
        for (String perm : requestedPermissions) {
            list.add(new PermissionDetail(
                    perm,
                    getPermissionLabel(perm),
                    getPermissionExplanation(perm),
                    isPermissionGranted(perm),
                    isSensitivePermission(perm)
            ));
        }
        return list;
    }

    // Static factual explanation helpers

    public static boolean isSensitivePermission(String permission) {
        if (permission == null) return false;
        if (SENSITIVE_PERMISSION_SET.contains(permission)) return true;
        for (String s : SENSITIVE_PERMISSION_SET) {
            if (permission.endsWith(s.substring(s.lastIndexOf('.') + 1))) {
                return true;
            }
        }
        return false;
    }

    public static String getPermissionLabel(String permission) {
        if (permission == null) return "Unknown Permission";
        String direct = PERMISSION_LABELS.get(permission);
        if (direct != null) return direct;

        for (Map.Entry<String, String> entry : PERMISSION_LABELS.entrySet()) {
            String key = entry.getKey();
            if (permission.endsWith(key.substring(key.lastIndexOf('.') + 1))) {
                return entry.getValue();
            }
        }

        // Return clean simple name
        int lastDot = permission.lastIndexOf('.');
        if (lastDot >= 0 && lastDot < permission.length() - 1) {
            return permission.substring(lastDot + 1).replace('_', ' ');
        }
        return permission;
    }

    public static String getPermissionExplanation(String permission) {
        if (permission == null) return "Declared permission.";
        String direct = PERMISSION_EXPLANATIONS.get(permission);
        if (direct != null) return direct;

        for (Map.Entry<String, String> entry : PERMISSION_EXPLANATIONS.entrySet()) {
            String key = entry.getKey();
            if (permission.endsWith(key.substring(key.lastIndexOf('.') + 1))) {
                return entry.getValue();
            }
        }

        return "Standard Android platform permission declared in application package.";
    }

    public static class PermissionDetail {
        private final String permission;
        private final String label;
        private final String explanation;
        private final boolean isGranted;
        private final boolean isSensitive;

        public PermissionDetail(String permission, String label, String explanation, boolean isGranted, boolean isSensitive) {
            this.permission = permission;
            this.label = label;
            this.explanation = explanation;
            this.isGranted = isGranted;
            this.isSensitive = isSensitive;
        }

        public String getPermission() {
            return permission;
        }

        public String getLabel() {
            return label;
        }

        public String getExplanation() {
            return explanation;
        }

        public boolean isGranted() {
            return isGranted;
        }

        public boolean isSensitive() {
            return isSensitive;
        }
    }
}
