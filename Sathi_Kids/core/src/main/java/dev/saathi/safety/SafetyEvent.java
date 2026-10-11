package dev.saathi.safety;

import dev.saathi.safety.SafetyTypes.Source;
import dev.saathi.safety.SafetyTypes.SourceType;
import dev.saathi.safety.SafetyTypes.Status;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * A persisted safety event. Stores metadata plus at most a couple of short evidence excerpts for events that raised a
 * concern (so the child/adult can see why). Full message text is never stored.
 */
public final class SafetyEvent {

    public enum Flag { NONE, THREATS, SELF_HARM }
    public enum Category { THREAT, SELF_HARM, SCAM, WEBSITE, AGE_SUITABILITY, UNAVAILABLE }
    public enum Level { CLEAR, NEEDS_REVIEW, ACTIVE }
    public enum Review { NEW, REVIEWED, DISMISSED }
    public enum Alert { NOT_NEEDED, PENDING, DELIVERED, SHOWN_IN_APP, NOT_PERMITTED, SUPPRESSED_DUPLICATE, FAILED, UNKNOWN }

    public static final int MAX_EVIDENCE = 2;
    public static final int MAX_EVIDENCE_CHARS = 80;

    public final String eventId;
    public final String dedupeKey;
    public final long createdAt;
    public final long updatedAt;
    public final SourceType sourceType;
    public final String sourceApp;        // app label for notifications, host for websites; may be empty
    public final Category category;
    public final Flag flag;
    public final Level level;
    public final String severity;
    public final String confidence;
    public final Status status;
    public final Source analysisSource;
    public final String modelOutcome;
    public final List<String> evidence;
    public final String explanation;
    public final List<String> actions;
    public final Review review;
    public final Alert alert;

    public SafetyEvent(String eventId, String dedupeKey, long createdAt, long updatedAt, SourceType sourceType, String sourceApp,
                       Category category, Flag flag, Level level, String severity, String confidence, Status status,
                       Source analysisSource, String modelOutcome, List<String> evidence, String explanation, List<String> actions,
                       Review review, Alert alert) {
        this.eventId = eventId;
        this.dedupeKey = dedupeKey;
        this.createdAt = createdAt;
        this.updatedAt = updatedAt;
        this.sourceType = sourceType;
        this.sourceApp = sourceApp == null ? "" : sourceApp;
        this.category = category;
        this.flag = flag;
        this.level = level;
        this.severity = severity;
        this.confidence = confidence;
        this.status = status;
        this.analysisSource = analysisSource;
        this.modelOutcome = modelOutcome == null ? "" : modelOutcome;
        this.evidence = trimEvidence(evidence);
        this.explanation = explanation == null ? "" : explanation;
        this.actions = actions == null ? Collections.<String>emptyList() : Collections.unmodifiableList(new ArrayList<>(actions));
        this.review = review;
        this.alert = alert;
    }

    static List<String> trimEvidence(List<String> ev) {
        List<String> out = new ArrayList<>();
        if (ev == null) return out;
        for (String e : ev) {
            if (e == null || e.trim().isEmpty()) continue;
            String t = e.trim();
            out.add(t.length() > MAX_EVIDENCE_CHARS ? t.substring(0, MAX_EVIDENCE_CHARS) + "…" : t);
            if (out.size() == MAX_EVIDENCE) break;
        }
        return Collections.unmodifiableList(out);
    }

    public SafetyEvent withReview(Review r, long now) {
        return new SafetyEvent(eventId, dedupeKey, createdAt, now, sourceType, sourceApp, category, flag, level, severity, confidence,
                status, analysisSource, modelOutcome, evidence, explanation, actions, r, alert);
    }

    public SafetyEvent withAlert(Alert a, long now) {
        return new SafetyEvent(eventId, dedupeKey, createdAt, now, sourceType, sourceApp, category, flag, level, severity, confidence,
                status, analysisSource, modelOutcome, evidence, explanation, actions, review, a);
    }
}
