package dev.saathi.family;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Family connection state as reported by the server (never inferred from local flags). */
public final class FamilyStatus {

    public enum State {
        /** No backend configured in this build. */
        NOT_CONFIGURED,
        /** Server says this child account has no pairing. */
        NOT_PAIRED,
        /** Code redeemed; waiting for the adult to confirm in Saathi Personal. */
        PENDING_CONFIRMATION,
        /** Server confirms an active pairing. */
        ACTIVE,
        /** The pairing was revoked by the adult or the child. */
        REVOKED,
        /** The server could not be reached; state unknown. */
        UNREACHABLE,
        /** The server answered with an error or an unreadable response. */
        ERROR
    }

    /** An adult in the family who can receive help requests through Saathi Personal. */
    public static final class Adult {
        public final String uid;
        public final String displayName;
        public final boolean canReceiveHelp;

        public Adult(String uid, String displayName, boolean canReceiveHelp) {
            this.uid = uid;
            this.displayName = displayName;
            this.canReceiveHelp = canReceiveHelp;
        }
    }

    public final State state;
    public final String pairingId;
    public final String familyDisplayName;
    public final List<Adult> adults;
    public final String message;
    public final long checkedAtMillis;

    public FamilyStatus(State state, String pairingId, String familyDisplayName, List<Adult> adults, String message, long checkedAt) {
        this.state = state;
        this.pairingId = pairingId;
        this.familyDisplayName = familyDisplayName;
        this.adults = Collections.unmodifiableList(adults == null ? new ArrayList<Adult>() : new ArrayList<>(adults));
        this.message = message == null ? "" : message;
        this.checkedAtMillis = checkedAt;
    }

    public static FamilyStatus of(State s, String message) {
        return new FamilyStatus(s, null, null, null, message, System.currentTimeMillis());
    }

    public List<Adult> helpRecipients() {
        List<Adult> l = new ArrayList<>();
        if (state == State.ACTIVE) for (Adult a : adults) if (a.canReceiveHelp) l.add(a);
        return l;
    }
}
