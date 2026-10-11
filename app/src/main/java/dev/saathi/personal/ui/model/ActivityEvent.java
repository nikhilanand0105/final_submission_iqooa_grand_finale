package dev.saathi.personal.ui.model;

import dev.saathi.model.ThreatSeverity;

import java.util.Date;
import java.util.List;

public class ActivityEvent {
    public enum EventCategory {
        APK("APK Threat"),
        SENSE("Sense AI"),
        PHISHING("Phishing Link"),
        FIREWALL("DNS Firewall"),
        SYSTEM("System");

        private final String displayName;

        EventCategory(String displayName) {
            this.displayName = displayName;
        }

        public String getDisplayName() {
            return displayName;
        }
    }

    private final String id;
    private final Date timestamp;
    private final EventCategory category;
    private final ThreatSeverity severity;
    private final String title;
    private final String summary;
    private final List<String> technicalDetails;
    private final String actionLabel;
    private boolean resolved;

    public ActivityEvent(
            String id,
            Date timestamp,
            EventCategory category,
            ThreatSeverity severity,
            String title,
            String summary,
            List<String> technicalDetails,
            String actionLabel) {
        this.id = id;
        this.timestamp = timestamp;
        this.category = category;
        this.severity = severity;
        this.title = title;
        this.summary = summary;
        this.technicalDetails = technicalDetails;
        this.actionLabel = actionLabel;
        this.resolved = false;
    }

    public String getId() {
        return id;
    }

    public Date getTimestamp() {
        return timestamp;
    }

    public EventCategory getCategory() {
        return category;
    }

    public ThreatSeverity getSeverity() {
        return severity;
    }

    public String getTitle() {
        return title;
    }

    public String getSummary() {
        return summary;
    }

    public List<String> getTechnicalDetails() {
        return technicalDetails;
    }

    public String getActionLabel() {
        return actionLabel;
    }

    public boolean isResolved() {
        return resolved;
    }

    public void setResolved(boolean resolved) {
        this.resolved = resolved;
    }
}
