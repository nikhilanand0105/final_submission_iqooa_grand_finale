package dev.saathi.engine;

/**
 * Android Intent generator for policy-compliant APK installation handoff.
 * 
 * Google Play Policy Compliance:
 * Rather than requesting android.permission.REQUEST_INSTALL_PACKAGES (which gets rejected
 * during Play Store review for non-store utility apps), Saathi prepares a standard 
 * Intent.ACTION_VIEW with FLAG_GRANT_READ_URI_PERMISSION.
 * 
 * This triggers Android's system PackageInstaller, ensuring the operating system's native
 * Play Protect and permission dialogs remain fully in control.
 */
public class ApkInstallHandoffHelper {

    public static class InstallIntentDescriptor {
        public final String action;
        public final String uriString;
        public final String mimeType;
        public final int flags;

        public InstallIntentDescriptor(String action, String uriString, String mimeType, int flags) {
            this.action = action;
            this.uriString = uriString;
            this.mimeType = mimeType;
            this.flags = flags;
        }

        @Override
        public String toString() {
            return String.format("Intent[action=%s, type=%s, uri=%s, flags=0x%X]", action, mimeType, uriString, flags);
        }
    }

    // Android Intent flag constants
    public static final int FLAG_GRANT_READ_URI_PERMISSION = 0x00000001;
    public static final int FLAG_ACTIVITY_NEW_TASK = 0x10000000;
    public static final int FLAG_ACTIVITY_CLEAR_TOP = 0x04000000;

    /**
     * Constructs the intent specification for the Android system installer handoff.
     */
    public static InstallIntentDescriptor createSystemInstallIntent(String contentUriString) {
        int flags = FLAG_GRANT_READ_URI_PERMISSION | FLAG_ACTIVITY_NEW_TASK | FLAG_ACTIVITY_CLEAR_TOP;
        return new InstallIntentDescriptor(
                "android.intent.action.VIEW",
                contentUriString,
                "application/vnd.android.package-archive",
                flags
        );
    }
}
