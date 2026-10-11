package dev.guardianai.personal.ui.model;

import java.util.Date;

public class SafetyReport {
    private final String id;
    private final String submittedBy;
    private final Date timestamp;
    private final String category;
    private final String excerpt;
    private final String status;
    private final String actionTaken;

    public SafetyReport(String id, String submittedBy, Date timestamp, String category, String excerpt, String status, String actionTaken) {
        this.id = id;
        this.submittedBy = submittedBy;
        this.timestamp = timestamp;
        this.category = category;
        this.excerpt = excerpt;
        this.status = status;
        this.actionTaken = actionTaken;
    }

    public String getId() {
        return id;
    }

    public String getSubmittedBy() {
        return submittedBy;
    }

    public Date getTimestamp() {
        return timestamp;
    }

    public String getCategory() {
        return category;
    }

    public String getExcerpt() {
        return excerpt;
    }

    public String getStatus() {
        return status;
    }

    public String getActionTaken() {
        return actionTaken;
    }
}
