package dev.guardianai.personal.ui.model;

public enum ScanMode {
    APK_CHECK("APK / File Check", "Inspect package manifest, DEX hooks & signatures"),
    LINK_CHECK("Link Check", "Detect phishing, punycode spoofing & fraud domains"),
    MESSAGE_CHECK("Message Check", "Analyze SMS, OTP scams, UPI fraud & coercion cues"),
    INSTALLED_APPS("Installed Apps", "Audit sensitive permissions & accessibility abusers");

    private final String title;
    private final String description;

    ScanMode(String title, String description) {
        this.title = title;
        this.description = description;
    }

    public String getTitle() {
        return title;
    }

    public String getDescription() {
        return description;
    }
}
