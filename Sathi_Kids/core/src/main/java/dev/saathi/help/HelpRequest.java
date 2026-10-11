package dev.saathi.help;

/** Immutable snapshot of a help request. Holds only what the request needs. */
public final class HelpRequest {

    public enum LocationChoice { NOT_SHARED, SHARED, PERMISSION_DENIED, UNAVAILABLE }

    /** Approximate location the child chose to share. */
    public static final class Location {
        public final double lat, lng;
        public final float accuracyMeters;
        public final long capturedAtMillis;

        public Location(double lat, double lng, float accuracyMeters, long capturedAtMillis) {
            this.lat = lat;
            this.lng = lng;
            this.accuracyMeters = accuracyMeters;
            this.capturedAtMillis = capturedAtMillis;
        }
    }

    public final String localId;          // stable local id
    public final String idempotencyKey;   // assigned at confirmation; reused on manual retry
    public final String serverRequestId;  // null until the server returns one
    public final String recipientUid;
    public final String recipientName;
    public final String reason;           // category key
    public final String note;             // optional, never persisted locally after sending
    public final LocationChoice locationChoice;
    public final Location location;       // null unless SHARED
    public final HelpRequestStatus status;
    public final String failureReason;
    public final long createdAt;
    public final long updatedAt;

    public HelpRequest(String localId, String idempotencyKey, String serverRequestId, String recipientUid, String recipientName,
                       String reason, String note, LocationChoice locationChoice, Location location, HelpRequestStatus status,
                       String failureReason, long createdAt, long updatedAt) {
        this.localId = localId;
        this.idempotencyKey = idempotencyKey;
        this.serverRequestId = serverRequestId;
        this.recipientUid = recipientUid;
        this.recipientName = recipientName;
        this.reason = reason;
        this.note = note;
        this.locationChoice = locationChoice == null ? LocationChoice.NOT_SHARED : locationChoice;
        this.location = this.locationChoice == LocationChoice.SHARED ? location : null;
        this.status = status;
        this.failureReason = failureReason;
        this.createdAt = createdAt;
        this.updatedAt = updatedAt;
    }

    public HelpRequest with(HelpRequestStatus s, String serverId, String failure, long now) {
        return new HelpRequest(localId, idempotencyKey, serverId != null ? serverId : serverRequestId, recipientUid, recipientName,
                reason, note, locationChoice, location, s, failure, createdAt, now);
    }
}
