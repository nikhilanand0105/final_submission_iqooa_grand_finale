package dev.guardianai.family;

import java.util.Date;
import java.util.Objects;

/**
 * A help/distress request initiated by a protected family member.
 *
 * <h2>Lifecycle</h2>
 * <pre>
 *   DRAFT
 *     └─ user confirms ──→ CONFIRMED_BY_USER
 *                              └─ backend accepts ──→ BACKEND_ACCEPTED
 *                                                        └─ FCM queued ──→ NOTIFICATION_QUEUED
 *                                                                              ├─ DELIVERED  (FCM ack)
 *                                                                              └─ NOTIFICATION_FAILED
 *     └─ user cancels ──→ CANCELLED_BEFORE_SEND (at any pre-BACKEND_ACCEPTED stage)
 * </pre>
 *
 * <h2>Delivery honesty</h2>
 * <ul>
 *   <li>{@link DeliveryStatus#BACKEND_ACCEPTED} means the database write succeeded — it does
 *       NOT mean anyone has seen or acknowledged the request.
 *   <li>{@link DeliveryStatus#NOTIFICATION_QUEUED} means FCM accepted the message for delivery —
 *       it does NOT guarantee the recipient's device received or displayed it.
 *   <li>{@link DeliveryStatus#DELIVERED} is set only when reliable end-to-end confirmation
 *       actually exists (e.g., a read-receipt write from the recipient app).
 *   <li>Never derive a "safe" conclusion from a successful database write alone.
 * </ul>
 *
 * <h2>Privacy</h2>
 * <ul>
 *   <li>Message contents are never included unless the sender explicitly adds them.
 *   <li>Location is included only when the sender granted the permission AND location
 *       was actually available. Both {@code hasLocation} and coordinate fields distinguish
 *       "location not included" from "location unavailable".
 * </ul>
 */
public class SosRequest {

    /** Reason the protected member is sending the SOS. */
    public enum SosReason {
        FEELING_UNSAFE("I feel unsafe"),
        SUSPICIOUS_CONTACT("Suspicious contact / message"),
        FINANCIAL_PRESSURE("Pressure to send money"),
        NEED_HELP("I need help"),
        OTHER("Other");

        public final String displayLabel;

        SosReason(String displayLabel) {
            this.displayLabel = displayLabel;
        }
    }

    /** Authoritative delivery lifecycle, distinguishing back-end acceptance from actual delivery. */
    public enum DeliveryStatus {
        /** Request created locally, not yet confirmed by the user. */
        DRAFT,
        /** User pressed "Send Help Request" — confirmed and ready to submit. */
        CONFIRMED_BY_USER,
        /** Backend wrote the record to Firestore. Recipient not yet notified. */
        BACKEND_ACCEPTED,
        /** FCM notification dispatched. Delivery to device not confirmed. */
        NOTIFICATION_QUEUED,
        /** Recipient's device confirmed receipt (read-receipt from Kids app). */
        DELIVERED,
        /** FCM dispatch failed — recipient may not have been notified. */
        NOTIFICATION_FAILED,
        /** No backend is configured; request stored locally only. */
        LOCAL_ONLY,
        /** Sender cancelled the request. */
        CANCELLED_BEFORE_SEND
    }

    private final String requestId;
    private final String senderDeviceId;
    private final String senderDisplayName;
    private final String familyId;
    /** Device ID of the intended recipient. Server validates this belongs to an OWNER or PARENT_GUARDIAN. */
    private final String recipientDeviceId;
    private final SosReason reason;
    private final Date createdAt;

    // Optional fields — only set when sender explicitly included them
    private final String optionalMessage;
    private final boolean hasLocation;
    private final double locationLat;
    private final double locationLng;
    private final float locationAccuracyMeters;

    private DeliveryStatus deliveryStatus;
    private Date statusUpdatedAt;
    private String failureReason;

    public SosRequest(
            String requestId,
            String senderDeviceId,
            String senderDisplayName,
            String familyId,
            String recipientDeviceId,
            SosReason reason,
            Date createdAt,
            String optionalMessage,
            boolean hasLocation,
            double locationLat,
            double locationLng,
            float locationAccuracyMeters,
            DeliveryStatus deliveryStatus) {
        this.requestId = Objects.requireNonNull(requestId, "requestId cannot be null");
        this.senderDeviceId = Objects.requireNonNull(senderDeviceId, "senderDeviceId cannot be null");
        this.senderDisplayName = senderDisplayName != null ? senderDisplayName : "Family Member";
        this.familyId = Objects.requireNonNull(familyId, "familyId cannot be null");
        this.recipientDeviceId = Objects.requireNonNull(recipientDeviceId, "recipientDeviceId cannot be null");
        this.reason = reason != null ? reason : SosReason.NEED_HELP;
        this.createdAt = createdAt != null ? createdAt : new Date();
        this.optionalMessage = optionalMessage; // null = no message included
        this.hasLocation = hasLocation;
        this.locationLat = locationLat;
        this.locationLng = locationLng;
        this.locationAccuracyMeters = locationAccuracyMeters;
        this.deliveryStatus = deliveryStatus != null ? deliveryStatus : DeliveryStatus.DRAFT;
        this.statusUpdatedAt = this.createdAt;
    }

    public String getRequestId() { return requestId; }
    public String getSenderDeviceId() { return senderDeviceId; }
    public String getSenderDisplayName() { return senderDisplayName; }
    public String getFamilyId() { return familyId; }
    public String getRecipientDeviceId() { return recipientDeviceId; }
    public SosReason getReason() { return reason; }
    public Date getCreatedAt() { return new Date(createdAt.getTime()); }
    public String getOptionalMessage() { return optionalMessage; }
    public boolean isHasLocation() { return hasLocation; }
    public double getLocationLat() { return locationLat; }
    public double getLocationLng() { return locationLng; }
    public float getLocationAccuracyMeters() { return locationAccuracyMeters; }
    public DeliveryStatus getDeliveryStatus() { return deliveryStatus; }
    public Date getStatusUpdatedAt() { return statusUpdatedAt != null ? new Date(statusUpdatedAt.getTime()) : null; }
    public String getFailureReason() { return failureReason; }

    public void updateStatus(DeliveryStatus newStatus, String failureReason) {
        this.deliveryStatus = newStatus;
        this.statusUpdatedAt = new Date();
        this.failureReason = failureReason;
    }

    /** Human-readable status for display. Never implies the person has seen the message. */
    public String getDisplayStatus() {
        switch (deliveryStatus) {
            case DRAFT: return "Not yet sent";
            case CONFIRMED_BY_USER: return "Submitting…";
            case BACKEND_ACCEPTED: return "Recorded by server (recipient not yet notified)";
            case NOTIFICATION_QUEUED: return "Notification sent — awaiting receipt from device";
            case DELIVERED: return "Confirmed received by recipient's device";
            case NOTIFICATION_FAILED: return "Notification dispatch failed — call your contact directly";
            case LOCAL_ONLY: return "Saved locally (no backend — share this screen with a trusted adult)";
            case CANCELLED_BEFORE_SEND: return "Cancelled before sending";
            default: return "Unknown";
        }
    }

    /** Returns true only if the request has been fully confirmed — and only when real confirmation exists. */
    public boolean isConfirmedDelivered() {
        return deliveryStatus == DeliveryStatus.DELIVERED;
    }

    public boolean isTerminal() {
        return deliveryStatus == DeliveryStatus.DELIVERED
                || deliveryStatus == DeliveryStatus.NOTIFICATION_FAILED
                || deliveryStatus == DeliveryStatus.LOCAL_ONLY
                || deliveryStatus == DeliveryStatus.CANCELLED_BEFORE_SEND;
    }
}
