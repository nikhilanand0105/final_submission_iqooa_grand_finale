package dev.guardianai.shield.apk;

import dev.guardianai.model.ThreatSeverity;

/** One static finding derived from the selected file, with the evidence that triggered it. */
public final class ApkIndicator {

    public final String id;
    public final String title;
    public final String explanation;
    public final String evidence;
    public final ThreatSeverity severity;

    public ApkIndicator(String id, String title, String explanation, String evidence, ThreatSeverity severity) {
        this.id = id;
        this.title = title;
        this.explanation = explanation;
        this.evidence = evidence == null ? "" : evidence;
        this.severity = severity;
    }

    @Override
    public String toString() {
        return "[" + severity + "] " + id + ": " + evidence;
    }
}
