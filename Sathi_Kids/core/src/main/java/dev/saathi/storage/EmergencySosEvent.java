package dev.saathi.storage;

import java.util.Date;

/**
 * Tracks an emergency SOS dispatch event initiated by a child or senior.
 * Accommodates offline queuing and timestamped last-known GPS location without continuous surveillance.
 */
public class EmergencySosEvent {

    public enum SosStatus {
        QUEUED_OFFLINE,
        TRANSMITTED_TO_TRUSTED_CONTACTS,
        ACKNOWLEDGED_BY_CONTACT,
        CANCELLED_BY_USER
    }

    private final String eventId;
    private final Date timestamp;
    private final double latitude;
    private final double longitude;
    private final float accuracyMeters;
    private SosStatus status;
    private final String reasonNote;

    public EmergencySosEvent(
            String eventId,
            Date timestamp,
            double latitude,
            double longitude,
            float accuracyMeters,
            SosStatus status,
            String reasonNote) {
        this.eventId = eventId;
        this.timestamp = timestamp != null ? timestamp : new Date();
        this.latitude = latitude;
        this.longitude = longitude;
        this.accuracyMeters = accuracyMeters;
        this.status = status;
        this.reasonNote = reasonNote;
    }

    public String getEventId() {
        return eventId;
    }

    public Date getTimestamp() {
        return timestamp;
    }

    public double getLatitude() {
        return latitude;
    }

    public double getLongitude() {
        return longitude;
    }

    public float getAccuracyMeters() {
        return accuracyMeters;
    }

    public SosStatus getStatus() {
        return status;
    }

    public void setStatus(SosStatus status) {
        this.status = status;
    }

    public String getReasonNote() {
        return reasonNote;
    }
}
