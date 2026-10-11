package dev.guardianai.storage;

/**
 * Designated family member or trusted helper for an elderly or minor user.
 * Authorized to receive summary security health alerts without accessing private banking or conversation details.
 */
public class TrustedHelper {
    private final String helperId;
    private final String name;
    private final String relationship;
    private final String phoneNumber;
    private boolean isSecurityAlertsEnabled;

    public TrustedHelper(String helperId, String name, String relationship, String phoneNumber, boolean isSecurityAlertsEnabled) {
        this.helperId = helperId;
        this.name = name;
        this.relationship = relationship;
        this.phoneNumber = phoneNumber;
        this.isSecurityAlertsEnabled = isSecurityAlertsEnabled;
    }

    public String getHelperId() {
        return helperId;
    }

    public String getName() {
        return name;
    }

    public String getRelationship() {
        return relationship;
    }

    public String getPhoneNumber() {
        return phoneNumber;
    }

    public boolean isSecurityAlertsEnabled() {
        return isSecurityAlertsEnabled;
    }

    public void setSecurityAlertsEnabled(boolean enabled) {
        this.isSecurityAlertsEnabled = enabled;
    }
}
