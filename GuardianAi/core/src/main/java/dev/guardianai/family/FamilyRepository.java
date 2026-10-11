package dev.guardianai.family;

import java.util.List;

/**
 * Repository interface for family group data.
 *
 * <p>Implementations:
 * <ul>
 *   <li>{@code LocalFamilyRepository} — on-device only, SharedPreferences + in-memory.
 *       Used when no backend is configured. Cannot enforce cross-device pairing, cannot
 *       deliver SOS notifications to other devices.
 *   <li>{@code FirebaseFamilyRepository} (in the {@code :app} module) — backed by Firestore.
 *       Requires a valid Firebase project, {@code google-services.json}, and user authentication.
 *       All access control is enforced by Firestore Security Rules server-side.
 * </ul>
 *
 * <p>Callers receive results via callbacks to avoid blocking the main thread. Implementations
 * must always invoke the callback (with an error if one occurs) and never silently drop results.
 */
public interface FamilyRepository {

    /**
     * Whether this implementation is backed by a real server. If false, all data is local-only
     * and cross-device features (pairing confirmation, SOS delivery) are unavailable.
     */
    boolean isServerBacked();

    // ---- Group management ----

    /** Load the family group this device belongs to (if any). Callback receives null if not in a group. */
    void loadFamilyGroup(Callback<FamilyGroup> callback);

    // ---- Pairing ----

    /**
     * Request a new pairing challenge code.
     *
     * <p>If server-backed, the backend generates and stores the code. If local-only, the code is
     * generated on-device and noted as {@link PairingChallenge.ChallengeState#LOCAL_ONLY} —
     * another device cannot validate it because there is no shared authority.
     */
    void createPairingChallenge(String familyId, Callback<PairingChallenge> callback);

    /**
     * Retrieve all active (non-expired, non-used) challenges for display.
     * The code itself is included — the owner is expected to share it manually.
     */
    void getActiveChallenges(String familyId, Callback<List<PairingChallenge>> callback);

    /**
     * Cancel a pending challenge before it is redeemed.
     * After cancellation the challenge is marked CANCELLED and cannot be redeemed.
     */
    void cancelChallenge(String challengeId, Callback<Void> callback);

    /**
     * Attempt to redeem a code on the joining device.
     *
     * <p>This sends the code to the backend for validation. The backend checks:
     * expiry, single-use, ownership, and then creates the PairedDevice record.
     * The callback receives the resulting PairedDevice on success, or an error.
     */
    void redeemPairingCode(String code, String joiningDeviceId, String displayName, Callback<PairedDevice> callback);

    /**
     * List all currently paired devices for a family group.
     * Only the group owner may call this; enforced server-side.
     */
    void listPairedDevices(String familyId, Callback<List<PairedDevice>> callback);

    /**
     * Revoke a paired device's membership. The device is marked REVOKED and its FCM token
     * is invalidated server-side. Must be called by the group owner.
     */
    void revokeDevice(String familyId, String deviceId, Callback<Void> callback);

    // ---- SOS ----

    /**
     * Persist and submit an SOS request.
     *
     * <p>The implementation is responsible for:
     * <ol>
     *   <li>Writing the SosRequest to the backend.
     *   <li>Triggering an FCM notification to the recipient device.
     *   <li>Updating the request's {@link SosRequest.DeliveryStatus} as it progresses.
     * </ol>
     *
     * <p>If server-backed, the callback updates are asynchronous as each stage completes.
     * If local-only, the request is saved in-memory with {@link SosRequest.DeliveryStatus#LOCAL_ONLY}.
     *
     * <p>The caller must not interpret any callback invocation as proof of delivery to a person.
     */
    void submitSosRequest(SosRequest request, ProgressCallback<SosRequest> callback);

    /** Load recent SOS requests sent by this device. */
    void loadSentSosRequests(String senderDeviceId, Callback<List<SosRequest>> callback);

    // ---- Callbacks ----

    interface Callback<T> {
        void onSuccess(T result);
        void onError(String errorMessage);
    }

    /**
     * Callback that may be invoked multiple times as a request progresses through stages.
     * {@link #onProgress} is called each time the status changes; {@link #onComplete} when
     * the request reaches a terminal state.
     */
    interface ProgressCallback<T> {
        void onProgress(T item, String stageName);
        void onComplete(T item);
        void onError(String errorMessage);
    }
}
