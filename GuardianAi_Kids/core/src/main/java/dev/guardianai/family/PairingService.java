package dev.guardianai.family;

import dev.guardianai.util.Json;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Kids-side implementation of the family pairing protocol (see docs/PERSONAL_INTEGRATION_CONTRACT.md).
 * The child redeems a short-lived, single-use code created in GuardianAi Personal; the server validates it and the
 * adult must confirm. Pairing status always comes from the server.
 */
public class PairingService {

    /** Codes are 8 characters from the Crockford base32 alphabet (no I, L, O, U), shown as XXXX-XXXX. */
    public static final int CODE_LENGTH = 8;
    private static final String ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

    public static final class RedeemResult {
        public final boolean ok;
        public final FamilyStatus status;     // on success: PENDING_CONFIRMATION or ACTIVE
        public final String errorCode;        // e.g. INVALID_CODE, EXPIRED_CODE, CODE_USED, RATE_LIMITED, OFFLINE
        public final String message;          // child-friendly

        RedeemResult(boolean ok, FamilyStatus status, String errorCode, String message) {
            this.ok = ok;
            this.status = status;
            this.errorCode = errorCode;
            this.message = message;
        }
    }

    private final BackendClient client;

    public PairingService(BackendClient client) {
        this.client = client;
    }

    public boolean isConfigured() {
        return client != null && client.isConfigured();
    }

    /** Uppercases, strips spaces/dashes and maps lookalikes (O->0, I/L->1). Returns null if not a valid code shape. */
    public static String normalizeCode(String raw) {
        if (raw == null) return null;
        StringBuilder b = new StringBuilder();
        for (char c : raw.toUpperCase(Locale.ROOT).toCharArray()) {
            if (c == ' ' || c == '-') continue;
            if (c == 'O') c = '0';
            if (c == 'I' || c == 'L') c = '1';
            if (ALPHABET.indexOf(c) < 0) return null;
            b.append(c);
        }
        return b.length() == CODE_LENGTH ? b.toString() : null;
    }

    public static String validateDisplayName(String name) {
        if (name == null) return "Please type a name your family will recognise";
        String t = name.trim();
        if (t.isEmpty()) return "Please type a name your family will recognise";
        if (t.length() > 40) return "Please use 40 characters or fewer";
        if (!t.matches("^[\\p{L}\\p{M}\\p{N} .'-]+$")) return "Please use only letters, numbers and spaces";
        return null;
    }

    public RedeemResult redeem(String rawCode, String childDisplayName) {
        if (!isConfigured()) return new RedeemResult(false, null, "NOT_CONFIGURED", "Family pairing isn't set up in this version of the app.");
        String code = normalizeCode(rawCode);
        if (code == null) return new RedeemResult(false, null, "INVALID_CODE", "That code doesn't look right. It should have 8 letters and numbers.");
        String nameErr = validateDisplayName(childDisplayName);
        if (nameErr != null) return new RedeemResult(false, null, "INVALID_ARGUMENT", nameErr);
        BackendClient.Result r = client.call("/pairing/redeem", Json.map("code", code, "childDisplayName", childDisplayName.trim()));
        if (!r.ok()) return new RedeemResult(false, null, errorCodeOf(r), redeemMessage(r));
        FamilyStatus st = parseStatus(r.body);
        if (st.state != FamilyStatus.State.PENDING_CONFIRMATION && st.state != FamilyStatus.State.ACTIVE) {
            return new RedeemResult(false, null, "BAD_RESPONSE", "The server gave an unexpected answer. Please try again later.");
        }
        return new RedeemResult(true, st, null, st.state == FamilyStatus.State.ACTIVE
                ? "You're connected with " + st.familyDisplayName + "."
                : "Code accepted. Ask your adult to confirm in GuardianAi Personal.");
    }

    public FamilyStatus fetchStatus() {
        if (!isConfigured()) return FamilyStatus.of(FamilyStatus.State.NOT_CONFIGURED, "Family connection isn't set up in this version of the app.");
        BackendClient.Result r = client.call("/family/status", Json.map());
        if (!r.ok()) {
            if (r.failure == BackendClient.Failure.OFFLINE || r.failure == BackendClient.Failure.TIMEOUT) {
                return FamilyStatus.of(FamilyStatus.State.UNREACHABLE, "Couldn't reach the GuardianAi server, so the family connection can't be confirmed right now.");
            }
            return FamilyStatus.of(FamilyStatus.State.ERROR, "The GuardianAi server returned an error (" + errorCodeOf(r) + ").");
        }
        return parseStatus(r.body);
    }

    public BackendClient.Result revoke(String pairingId) {
        if (!isConfigured()) return new BackendClient.Result(BackendClient.Failure.NOT_CONFIGURED, 0, null, "Not set up", null);
        return client.call("/pairing/revoke", Json.map("pairingId", pairingId));
    }

    static FamilyStatus parseStatus(Map<String, Object> body) {
        String s = Json.str(body, "status");
        FamilyStatus.State st;
        if ("active".equals(s)) st = FamilyStatus.State.ACTIVE;
        else if ("pending_parent_confirmation".equals(s)) st = FamilyStatus.State.PENDING_CONFIRMATION;
        else if ("revoked".equals(s)) st = FamilyStatus.State.REVOKED;
        else if ("none".equals(s)) st = FamilyStatus.State.NOT_PAIRED;
        else return FamilyStatus.of(FamilyStatus.State.ERROR, "Unexpected pairing status from server");
        List<FamilyStatus.Adult> adults = new ArrayList<>();
        List<Object> arr = Json.arr(body, "adults");
        if (arr != null) {
            for (Object o : arr) {
                if (!(o instanceof Map)) continue;
                @SuppressWarnings("unchecked") Map<String, Object> m = (Map<String, Object>) o;
                String uid = Json.str(m, "uid");
                String name = Json.str(m, "displayName");
                Boolean can = Json.bool(m, "canReceiveHelp");
                if (uid != null && name != null) adults.add(new FamilyStatus.Adult(uid, name, Boolean.TRUE.equals(can)));
            }
        }
        return new FamilyStatus(st, Json.str(body, "pairingId"), Json.str(body, "familyDisplayName"), adults, "", System.currentTimeMillis());
    }

    static String errorCodeOf(BackendClient.Result r) {
        if (r.errorCode != null) return r.errorCode;
        return r.failure.name();
    }

    private static String redeemMessage(BackendClient.Result r) {
        String c = errorCodeOf(r);
        switch (c) {
            case "INVALID_CODE": return "That code wasn't recognised. Check it with your adult.";
            case "EXPIRED_CODE": return "That code has expired. Ask your adult to make a new one in GuardianAi Personal.";
            case "CODE_USED": return "That code was already used. Ask your adult for a new one.";
            case "RATE_LIMITED": return "Too many tries. Please wait a few minutes and try again.";
            case "ALREADY_PAIRED": return "This phone is already connected to a family.";
            case "OFFLINE": return "No internet connection. Connect and try again.";
            case "TIMEOUT": return "The server didn't answer. Please try again.";
            default: return "Pairing didn't work (" + c + "). Please try again later.";
        }
    }
}
