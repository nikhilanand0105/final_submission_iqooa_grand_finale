package dev.saathi.help;

import dev.saathi.family.BackendClient;
import dev.saathi.util.Json;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Sends help requests through the Saathi backend and reports the real outcome.
 * - Only explicit calls send anything; there is no background retry queue, so nothing is replayed automatically.
 * - The idempotency key is fixed when the child confirms; a manual retry reuses it so the server deduplicates.
 * - Concurrent submits of the same request are ignored (double taps).
 * - A timeout yields DELIVERY_UNKNOWN (the server may have received it), never a success state.
 */
public class HelpRequestService {

    public static final Set<String> REASONS = new HashSet<>(Arrays.asList(
            "someone_mean", "pressure", "shared_by_mistake", "unsafe", "something_else"));
    public static final int MAX_NOTE = 280;

    private final BackendClient client;
    private final Set<String> inFlight = ConcurrentHashMap.newKeySet();

    public HelpRequestService(BackendClient client) {
        this.client = client;
    }

    public boolean isConfigured() {
        return client != null && client.isConfigured();
    }

    /** Creates a confirmed request ready to send. Nothing is sent here. */
    public static HelpRequest confirmDraft(String recipientUid, String recipientName, String reason, String note,
                                           HelpRequest.LocationChoice choice, HelpRequest.Location loc, long now) {
        if (recipientUid == null || recipientUid.isEmpty()) throw new IllegalArgumentException("recipient required");
        if (!REASONS.contains(reason)) throw new IllegalArgumentException("unknown reason");
        String n = note == null ? null : note.trim();
        if (n != null && n.isEmpty()) n = null;
        if (n != null && n.length() > MAX_NOTE) n = n.substring(0, MAX_NOTE);
        return new HelpRequest(UUID.randomUUID().toString(), UUID.randomUUID().toString(), null, recipientUid, recipientName,
                reason, n, choice, loc, HelpRequestStatus.DRAFT, null, now, now);
    }

    /**
     * Sends (or manually re-sends) a request. Returns the new snapshot; callers persist it.
     * Returns the input unchanged if the same request is already being sent.
     */
    public HelpRequest submit(HelpRequest r) {
        long now = System.currentTimeMillis();
        if (r.status == HelpRequestStatus.CANCELLED || r.status == HelpRequestStatus.ACKNOWLEDGED) return r;
        if (!isConfigured()) return r.with(HelpRequestStatus.FAILED, null, "The help service isn't set up in this version of the app", now);
        if (!inFlight.add(r.idempotencyKey)) return r;
        try {
            Map<String, Object> p = Json.map("idempotencyKey", r.idempotencyKey, "recipientUid", r.recipientUid, "reason", r.reason,
                    "locationChoice", r.locationChoice.name().toLowerCase());
            if (r.note != null) p.put("note", r.note);
            if (r.location != null) {
                p.put("location", Json.map("lat", r.location.lat, "lng", r.location.lng,
                        "accuracyM", (double) r.location.accuracyMeters, "capturedAt", (double) r.location.capturedAtMillis));
            }
            BackendClient.Result res = client.call("/help/create", p);
            return apply(r, res, now);
        } finally {
            inFlight.remove(r.idempotencyKey);
        }
    }

    /** Asks the server for the current state (e.g. to see an acknowledgement, or resolve DELIVERY_UNKNOWN). */
    public HelpRequest refresh(HelpRequest r) {
        long now = System.currentTimeMillis();
        if (!isConfigured() || r.status == HelpRequestStatus.DRAFT || r.status == HelpRequestStatus.CANCELLED) return r;
        Map<String, Object> p = r.serverRequestId != null ? Json.map("requestId", r.serverRequestId) : Json.map("idempotencyKey", r.idempotencyKey);
        BackendClient.Result res = client.call("/help/status", p);
        if (!res.ok()) {
            if ("NOT_FOUND".equals(res.errorCode) && r.status == HelpRequestStatus.DELIVERY_UNKNOWN) {
                return r.with(HelpRequestStatus.FAILED, null, "The server never received this request", now);
            }
            return r; // keep last known state; status check failure says nothing new
        }
        return applyBody(r, res.body, now);
    }

    public HelpRequest cancel(HelpRequest r) {
        long now = System.currentTimeMillis();
        if (r.status == HelpRequestStatus.DRAFT || r.status == HelpRequestStatus.FAILED) return r.with(HelpRequestStatus.CANCELLED, null, null, now);
        if (r.status == HelpRequestStatus.ACKNOWLEDGED || r.status == HelpRequestStatus.CANCELLED || !isConfigured()) return r;
        BackendClient.Result res = client.call("/help/cancel", r.serverRequestId != null
                ? Json.map("requestId", r.serverRequestId) : Json.map("idempotencyKey", r.idempotencyKey));
        if (res.ok()) return applyBody(r, res.body, now);
        return r;
    }

    private HelpRequest apply(HelpRequest r, BackendClient.Result res, long now) {
        if (res.ok()) return applyBody(r, res.body, now);
        switch (res.failure) {
            case TIMEOUT:
                return r.with(HelpRequestStatus.DELIVERY_UNKNOWN, null, "The server didn't answer in time, so we don't know if it arrived", now);
            case OFFLINE:
                return r.with(HelpRequestStatus.FAILED, null, "No internet connection — the request was not sent", now);
            case AUTH:
                return r.with(HelpRequestStatus.FAILED, null, "Sign-in problem — the request was not sent", now);
            case SERVER_ERROR:
                // 5xx after the request reached the server: it may or may not have been stored.
                return r.with(HelpRequestStatus.DELIVERY_UNKNOWN, null, "The server had a problem; we don't know if it was saved", now);
            case API_ERROR:
                return r.with(HelpRequestStatus.FAILED, null, apiMessage(res.errorCode), now);
            default:
                return r.with(HelpRequestStatus.DELIVERY_UNKNOWN, null, "Unexpected answer from the server", now);
        }
    }

    private HelpRequest applyBody(HelpRequest r, Map<String, Object> body, long now) {
        String id = Json.str(body, "requestId");
        HelpRequestStatus s = HelpRequestStatus.fromServer(Json.str(body, "status"));
        if (id == null && s != HelpRequestStatus.CANCELLED) {
            return r.with(HelpRequestStatus.DELIVERY_UNKNOWN, null, "The server's answer was missing the request id", now);
        }
        String note = null;
        if ("notification_failed".equals(Json.str(body, "status"))) note = "The server saved it but couldn't notify their phone";
        else if (s == HelpRequestStatus.ACCEPTED_BY_SERVER && Boolean.FALSE.equals(Json.bool(body, "recipientHasDevice"))) {
            note = "Saved, but this adult hasn't set up notifications in Saathi Personal";
        }
        return r.with(s, id, note, now);
    }

    static String apiMessage(String code) {
        if (code == null) return "The server refused the request";
        switch (code) {
            case "NOT_PAIRED": return "This phone isn't connected to that adult";
            case "PAIRING_REVOKED": return "The family connection was turned off, so the request wasn't sent";
            case "RECIPIENT_NOT_AUTHORIZED": return "That adult can't receive help requests from this phone";
            case "RATE_LIMITED": return "Too many requests in a short time. Please talk to someone nearby or call for help";
            case "INVALID_ARGUMENT": return "Something in the request wasn't valid";
            default: return "The server refused the request (" + code + ")";
        }
    }
}
