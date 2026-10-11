package dev.saathi.family;

import java.util.Date;
import java.util.Objects;

/**
 * A device (phone) that has joined a family group via a verified {@link PairingChallenge}.
 *
 * <p>Pairing state is authoritative in the backend. A client-provided {@code isPaired=true}
 * flag is never trusted — membership is confirmed only once the server validates and records
 * the challenge redemption.
 */
public class PairedDevice {

    /** Current pairing status of a device in the family group. */
    public enum PairingStatus {
        /** Pairing challenge was redeemed and server confirmed membership. */
        ACTIVE,
        /** Device was explicitly unpaired by the group owner. */
        REVOKED,
        /** Device has not responded or synced within the expected window. */
        STALE
    }

    private final String deviceId;
    private final String familyId;
    private final String displayName;
    private final String assignedMemberName;
    private final FamilyGroup.MemberRole role;
    private final Date pairedAt;
    private PairingStatus status;
    private Date lastSeenAt;
    /**
     * FCM token for push notification delivery.
     * Stored encrypted at rest; never logged in plaintext.
     * Null until the device registers its token with the backend.
     */
    private String fcmToken;

    public PairedDevice(
            String deviceId,
            String familyId,
            String displayName,
            String assignedMemberName,
            FamilyGroup.MemberRole role,
            Date pairedAt,
            PairingStatus status,
            Date lastSeenAt,
            String fcmToken) {
        this.deviceId = Objects.requireNonNull(deviceId, "deviceId cannot be null");
        this.familyId = Objects.requireNonNull(familyId, "familyId cannot be null");
        this.displayName = displayName != null ? displayName : "Unknown Device";
        this.assignedMemberName = assignedMemberName != null ? assignedMemberName : "Unknown";
        this.role = role != null ? role : FamilyGroup.MemberRole.PROTECTED_MEMBER;
        this.pairedAt = pairedAt != null ? pairedAt : new Date();
        this.status = status != null ? status : PairingStatus.ACTIVE;
        this.lastSeenAt = lastSeenAt;
        this.fcmToken = fcmToken; // may be null
    }

    public String getDeviceId() { return deviceId; }
    public String getFamilyId() { return familyId; }
    public String getDisplayName() { return displayName; }
    public String getAssignedMemberName() { return assignedMemberName; }
    public FamilyGroup.MemberRole getRole() { return role; }
    public Date getPairedAt() { return new Date(pairedAt.getTime()); }
    public PairingStatus getStatus() { return status; }
    public void setStatus(PairingStatus status) { this.status = status; }
    public Date getLastSeenAt() { return lastSeenAt != null ? new Date(lastSeenAt.getTime()) : null; }
    public void setLastSeenAt(Date lastSeenAt) { this.lastSeenAt = lastSeenAt; }

    /** @return null if no FCM token has been registered for this device. */
    public String getFcmToken() { return fcmToken; }
    public void setFcmToken(String fcmToken) { this.fcmToken = fcmToken; }

    public boolean isActive() { return status == PairingStatus.ACTIVE; }
}
