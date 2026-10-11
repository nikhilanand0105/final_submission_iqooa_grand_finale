package dev.saathi.personal.network;

/**
 * States of the on-device network protection service.
 * UI states derive strictly from real system and service status,
 * without artificial counters or false guarantees.
 */
public enum NetworkProtectionStatus {
    /**
     * Protection is stopped. No background network filter is running.
     */
    STOPPED("INACTIVE", "Network protection is currently stopped. No local filtering is running.", 0xFF888888),

    /**
     * User preference is enabled, but the background service has not yet been started or was killed.
     */
    CONFIGURED("CONFIGURED", "Protection is configured to run, but the service is currently stopped.", 0xFF4A7C59),

    /**
     * Android system VPN permission-consent dialog is required before starting.
     */
    PERMISSION_NEEDED("PERMISSION NEEDED", "System VPN permission required to enable on-device DNS protection.", 0xFF855A12),

    /**
     * Service is actively running with an established TUN interface and foreground notification.
     */
    RUNNING("PROTECTED", "Active on-device DNS firewall. Known malware & phishing domains are sinkholed locally.", 0xFF386B57),

    /**
     * Another active VPN is running, or user/device administrator denied VPN establishment.
     */
    BLOCKED_BY_SYSTEM("BLOCKED BY SYSTEM", "Cannot start: Another VPN is active or system permission was denied.", 0xFFA63232),

    /**
     * Failed to establish the VPN interface or bind the TUN file descriptor.
     */
    FAILED("SERVICE ERROR", "Failed to bind the local TUN interface. Tap to retry or check settings.", 0xFFA63232);

    private final String badgeText;
    private final String description;
    private final int badgeColor;

    NetworkProtectionStatus(String badgeText, String description, int badgeColor) {
        this.badgeText = badgeText;
        this.description = description;
        this.badgeColor = badgeColor;
    }

    public String getBadgeText() {
        return badgeText;
    }

    public String getDescription() {
        return description;
    }

    public int getBadgeColor() {
        return badgeColor;
    }
}
