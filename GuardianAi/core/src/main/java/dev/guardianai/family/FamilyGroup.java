package dev.guardianai.family;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Objects;

/**
 * Root aggregate for a GuardianAi family group.
 *
 * <p>A family group is created by a parent/guardian (the owner). Other devices join by
 * redeeming a {@link PairingChallenge} code. The group is identified by a server-assigned
 * {@code familyId}; clients must never generate or trust a client-supplied family ID.
 *
 * <p>All mutable state that must survive a process restart should be persisted via
 * {@link FamilyRepository}, not held only in memory.
 */
public class FamilyGroup {

    /** Role of a member within the family group. */
    public enum MemberRole {
        /** Account owner — can create pairing codes, remove members, manage contacts. */
        OWNER,
        /** Parent or guardian — can receive safety reports and SOS requests. */
        PARENT_GUARDIAN,
        /** Child or senior — can submit safety reports and SOS requests. */
        PROTECTED_MEMBER
    }

    private final String familyId;
    private final String ownerUid;
    private final String ownerDisplayName;
    private final Date createdAt;
    private final List<PairedDevice> pairedDevices;

    public FamilyGroup(
            String familyId,
            String ownerUid,
            String ownerDisplayName,
            Date createdAt,
            List<PairedDevice> pairedDevices) {
        this.familyId = Objects.requireNonNull(familyId, "familyId cannot be null");
        this.ownerUid = Objects.requireNonNull(ownerUid, "ownerUid cannot be null");
        this.ownerDisplayName = ownerDisplayName != null ? ownerDisplayName : "Family Owner";
        this.createdAt = createdAt != null ? createdAt : new Date();
        this.pairedDevices = pairedDevices != null ? new ArrayList<>(pairedDevices) : new ArrayList<>();
    }

    public String getFamilyId() { return familyId; }
    public String getOwnerUid() { return ownerUid; }
    public String getOwnerDisplayName() { return ownerDisplayName; }
    public Date getCreatedAt() { return new Date(createdAt.getTime()); }
    public List<PairedDevice> getPairedDevices() { return Collections.unmodifiableList(pairedDevices); }
}
