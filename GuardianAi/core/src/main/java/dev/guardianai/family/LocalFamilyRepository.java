package dev.guardianai.family;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * On-device-only implementation of {@link FamilyRepository}.
 *
 * <p><strong>Limitations — be honest about these in the UI:</strong>
 * <ul>
 *   <li>Data does not survive app uninstall.
 *   <li>Pairing codes are LOCAL_ONLY — another device cannot redeem them because there is no
 *       shared authority. Both devices would need to be on the same physical device (impossible).
 *   <li>SOS requests are saved locally but no notification reaches anyone. The sender must
 *       physically show the screen or call the contact.
 *   <li>Revocation only works locally — the "paired" device does not know it has been removed.
 * </ul>
 *
 * <p>All callbacks are invoked on the calling thread (no threading guarantee; callers
 * on Android must dispatch to the main thread themselves if needed).
 */
public class LocalFamilyRepository implements FamilyRepository {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final String CODE_CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // no 0/O/1/I

    private FamilyGroup cachedGroup;
    private final Map<String, PairingChallenge> challenges = new ConcurrentHashMap<>();
    private final List<PairedDevice> pairedDevices = Collections.synchronizedList(new ArrayList<>());
    private final List<SosRequest> sosRequests = Collections.synchronizedList(new ArrayList<>());

    public LocalFamilyRepository() {}

    @Override
    public boolean isServerBacked() {
        return false;
    }

    @Override
    public void loadFamilyGroup(Callback<FamilyGroup> callback) {
        callback.onSuccess(cachedGroup); // null = not in a group yet
    }

    @Override
    public void createPairingChallenge(String familyId, Callback<PairingChallenge> callback) {
        if (familyId == null || familyId.isBlank()) {
            callback.onError("familyId is required to create a pairing challenge.");
            return;
        }
        // Expire all previous challenges for this family first
        for (PairingChallenge c : challenges.values()) {
            if (c.getFamilyId().equals(familyId) && c.isValid()) {
                c.setState(PairingChallenge.ChallengeState.EXPIRED);
            }
        }
        String code = generateCode(8);
        String id = UUID.randomUUID().toString();
        PairingChallenge challenge = new PairingChallenge(
                id, familyId, code, new Date(),
                PairingChallenge.ChallengeState.LOCAL_ONLY
        );
        challenges.put(id, challenge);
        callback.onSuccess(challenge);
    }

    @Override
    public void getActiveChallenges(String familyId, Callback<List<PairingChallenge>> callback) {
        List<PairingChallenge> active = new ArrayList<>();
        for (PairingChallenge c : challenges.values()) {
            if (c.getFamilyId().equals(familyId) && c.isValid()) {
                active.add(c);
            }
        }
        callback.onSuccess(active);
    }

    @Override
    public void cancelChallenge(String challengeId, Callback<Void> callback) {
        PairingChallenge c = challenges.get(challengeId);
        if (c == null) {
            callback.onError("Challenge not found: " + challengeId);
            return;
        }
        c.setState(PairingChallenge.ChallengeState.CANCELLED);
        callback.onSuccess(null);
    }

    @Override
    public void redeemPairingCode(String code, String joiningDeviceId, String displayName, Callback<PairedDevice> callback) {
        // Local-only: code cannot be cross-validated. Find a matching LOCAL_ONLY challenge.
        PairingChallenge matched = null;
        for (PairingChallenge c : challenges.values()) {
            if (c.getCode().equalsIgnoreCase(code) && c.isValid()) {
                matched = c;
                break;
            }
        }
        if (matched == null) {
            callback.onError("Code not found, already used, or expired. Please ask the family owner for a new code.");
            return;
        }
        matched.setState(PairingChallenge.ChallengeState.REDEEMED);
        PairedDevice device = new PairedDevice(
                joiningDeviceId != null ? joiningDeviceId : UUID.randomUUID().toString(),
                matched.getFamilyId(),
                displayName,
                displayName,
                FamilyGroup.MemberRole.PROTECTED_MEMBER,
                new Date(),
                PairedDevice.PairingStatus.ACTIVE,
                new Date(),
                null
        );
        pairedDevices.add(device);
        callback.onSuccess(device);
    }

    @Override
    public void listPairedDevices(String familyId, Callback<List<PairedDevice>> callback) {
        List<PairedDevice> result = new ArrayList<>();
        for (PairedDevice d : pairedDevices) {
            if (d.getFamilyId().equals(familyId)) {
                result.add(d);
            }
        }
        callback.onSuccess(result);
    }

    @Override
    public void revokeDevice(String familyId, String deviceId, Callback<Void> callback) {
        boolean found = false;
        for (PairedDevice d : pairedDevices) {
            if (d.getFamilyId().equals(familyId) && d.getDeviceId().equals(deviceId)) {
                d.setStatus(PairedDevice.PairingStatus.REVOKED);
                found = true;
                break;
            }
        }
        if (!found) {
            callback.onError("Device not found or already revoked.");
        } else {
            callback.onSuccess(null);
        }
    }

    @Override
    public void submitSosRequest(SosRequest request, ProgressCallback<SosRequest> callback) {
        // Local-only: save it, mark LOCAL_ONLY, no notification is sent.
        request.updateStatus(SosRequest.DeliveryStatus.CONFIRMED_BY_USER, null);
        callback.onProgress(request, "confirmed");

        sosRequests.add(0, request);

        // We cannot send any notification without a backend. Be explicit.
        request.updateStatus(SosRequest.DeliveryStatus.LOCAL_ONLY, null);
        callback.onProgress(request, "local_only");
        callback.onComplete(request);
        // Caller should display the LOCAL_ONLY status and instruct the user to call directly.
    }

    @Override
    public void loadSentSosRequests(String senderDeviceId, Callback<List<SosRequest>> callback) {
        List<SosRequest> result = new ArrayList<>();
        for (SosRequest r : sosRequests) {
            if (r.getSenderDeviceId().equals(senderDeviceId)) {
                result.add(r);
            }
        }
        callback.onSuccess(result);
    }

    /** Set/update the cached family group (call after user creates or joins one). */
    public void setFamilyGroup(FamilyGroup group) {
        this.cachedGroup = group;
    }

    // ---- helpers ----

    private String generateCode(int length) {
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(CODE_CHARS.charAt(SECURE_RANDOM.nextInt(CODE_CHARS.length())));
        }
        return sb.toString();
    }
}
