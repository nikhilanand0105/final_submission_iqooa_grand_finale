package dev.guardianai.family;

import java.util.Date;
import java.util.Objects;

/**
 * A server-issued, short-lived, single-use pairing challenge.
 *
 * <p>The challenge lifecycle:
 * <ol>
 *   <li>Owner requests a new code from the backend. The backend generates a
 *       cryptographically random code and stores it server-side with an expiry and a
 *       {@code used=false} flag. The client displays only what the server returns.
 *   <li>The joining device submits the code to the backend. The backend validates:
 *       expiry not exceeded, {@code used == false}, code matches. On success it marks
 *       {@code used=true} and creates the {@link PairedDevice} record.
 *   <li>Codes cannot be reused. Expired codes are rejected. The joining device's
 *       membership is solely determined by the backend-side record, not any client flag.
 * </ol>
 *
 * <p>This class represents the state the <em>owner's</em> device knows about the challenge.
 * The raw code is displayed to the owner so they can share it; it is never logged or
 * included in analytics.
 */
public class PairingChallenge {

    /** Lifecycle state of a pairing challenge as known to the owner's device. */
    public enum ChallengeState {
        /** Code generated locally, not yet confirmed by backend (no backend configured). */
        LOCAL_ONLY,
        /** Code issued by the backend, waiting to be redeemed. */
        PENDING,
        /** A device successfully redeemed this code and joined the family group. */
        REDEEMED,
        /** Code passed its expiry timestamp without being redeemed. */
        EXPIRED,
        /** Code was explicitly cancelled by the owner before redemption. */
        CANCELLED
    }

    private static final long TTL_MS = 15 * 60 * 1000L; // 15 minutes

    private final String challengeId;
    private final String familyId;
    private final String code;         // what the owner shares with the joining person
    private final Date issuedAt;
    private final Date expiresAt;
    private ChallengeState state;

    public PairingChallenge(
            String challengeId,
            String familyId,
            String code,
            Date issuedAt,
            ChallengeState state) {
        this.challengeId = Objects.requireNonNull(challengeId, "challengeId cannot be null");
        this.familyId = Objects.requireNonNull(familyId, "familyId cannot be null");
        this.code = Objects.requireNonNull(code, "code cannot be null");
        this.issuedAt = issuedAt != null ? issuedAt : new Date();
        this.expiresAt = new Date(this.issuedAt.getTime() + TTL_MS);
        this.state = state != null ? state : ChallengeState.PENDING;
    }

    public String getChallengeId() { return challengeId; }
    public String getFamilyId() { return familyId; }
    public String getCode() { return code; }
    public Date getIssuedAt() { return new Date(issuedAt.getTime()); }
    public Date getExpiresAt() { return new Date(expiresAt.getTime()); }
    public ChallengeState getState() { return state; }
    public void setState(ChallengeState state) { this.state = state; }

    /** Returns true if this challenge has not expired and has not been used or cancelled. */
    public boolean isValid() {
        return state == ChallengeState.PENDING
                && System.currentTimeMillis() < expiresAt.getTime();
    }

    /** Remaining valid time in milliseconds; 0 if already expired. */
    public long remainingMs() {
        return Math.max(0L, expiresAt.getTime() - System.currentTimeMillis());
    }

    /** Whole minutes of validity remaining (for display). */
    public int remainingMinutes() {
        return (int) (remainingMs() / 60_000L);
    }
}
