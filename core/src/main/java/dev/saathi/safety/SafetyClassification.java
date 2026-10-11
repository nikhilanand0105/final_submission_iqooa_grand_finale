package dev.saathi.safety;

import dev.saathi.safety.SafetyTypes.AgeConcern;
import dev.saathi.safety.SafetyTypes.Confidence;
import dev.saathi.safety.SafetyTypes.ScamKind;
import dev.saathi.safety.SafetyTypes.SelfHarmKind;
import dev.saathi.safety.SafetyTypes.Severity;
import dev.saathi.safety.SafetyTypes.Source;
import dev.saathi.safety.SafetyTypes.SourceType;
import dev.saathi.safety.SafetyTypes.Status;
import dev.saathi.safety.SafetyTypes.ThreatKind;
import dev.saathi.safety.SafetyTypes.WebsiteConcern;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Validated, structured result of the safety pipeline for one piece of content. Immutable. */
public final class SafetyClassification {

    public final SourceType sourceType;
    public final ThreatKind threat;
    public final Severity threatSeverity;
    public final SelfHarmKind selfHarm;
    public final Severity selfHarmSeverity;
    public final ScamKind scam;
    public final WebsiteConcern website;
    public final AgeConcern age;
    public final Confidence confidence;
    public final List<String> evidence;      // short excerpts of the analysed content
    public final String explanation;         // plain-language, child-facing
    public final List<String> actions;
    public final Status status;
    public final Source source;
    public final String modelId;             // null unless a model contributed
    public final List<String> guardNotes;    // why deterministic checks escalated/kept a concern

    public SafetyClassification(SourceType sourceType, ThreatKind threat, Severity threatSeverity, SelfHarmKind selfHarm,
                                Severity selfHarmSeverity, ScamKind scam, WebsiteConcern website, AgeConcern age,
                                Confidence confidence, List<String> evidence, String explanation, List<String> actions,
                                Status status, Source source, String modelId, List<String> guardNotes) {
        this.sourceType = sourceType;
        this.threat = threat;
        this.threatSeverity = threatSeverity;
        this.selfHarm = selfHarm;
        this.selfHarmSeverity = selfHarmSeverity;
        this.scam = scam;
        this.website = website;
        this.age = age;
        this.confidence = confidence;
        this.evidence = list(evidence);
        this.explanation = explanation == null ? "" : explanation;
        this.actions = list(actions);
        this.status = status;
        this.source = source;
        this.modelId = modelId;
        this.guardNotes = list(guardNotes);
    }

    private static List<String> list(List<String> l) {
        return l == null ? Collections.<String>emptyList() : Collections.unmodifiableList(new ArrayList<>(l));
    }

    public static SafetyClassification unavailable(SourceType t, Status status, String why) {
        return new SafetyClassification(t, ThreatKind.NONE, Severity.NONE, SelfHarmKind.NONE, Severity.NONE, ScamKind.NONE,
                WebsiteConcern.NONE, AgeConcern.NONE, Confidence.LOW, null, why, null, status, Source.NONE, null, null);
    }

    public Builder toBuilder() {
        return new Builder(this);
    }

    public boolean hasAnyConcern() {
        return threat != ThreatKind.NONE || selfHarm.isPersonalRisk() || scam != ScamKind.NONE
                || (website != WebsiteConcern.NONE && website != WebsiteConcern.UNKNOWN) || (age != AgeConcern.NONE && age != AgeConcern.UNKNOWN);
    }

    /** Mutable copy used by the pipeline stages (guard, technical merge). */
    public static final class Builder {
        public SourceType sourceType;
        public ThreatKind threat;
        public Severity threatSeverity;
        public SelfHarmKind selfHarm;
        public Severity selfHarmSeverity;
        public ScamKind scam;
        public WebsiteConcern website;
        public AgeConcern age;
        public Confidence confidence;
        public List<String> evidence;
        public String explanation;
        public List<String> actions;
        public Status status;
        public Source source;
        public String modelId;
        public List<String> guardNotes;

        Builder(SafetyClassification c) {
            sourceType = c.sourceType; threat = c.threat; threatSeverity = c.threatSeverity; selfHarm = c.selfHarm;
            selfHarmSeverity = c.selfHarmSeverity; scam = c.scam; website = c.website; age = c.age; confidence = c.confidence;
            evidence = new ArrayList<>(c.evidence); explanation = c.explanation; actions = new ArrayList<>(c.actions);
            status = c.status; source = c.source; modelId = c.modelId; guardNotes = new ArrayList<>(c.guardNotes);
        }

        public SafetyClassification build() {
            return new SafetyClassification(sourceType, threat, threatSeverity, selfHarm, selfHarmSeverity, scam, website, age,
                    confidence, evidence, explanation, actions, status, source, modelId, guardNotes);
        }
    }
}
