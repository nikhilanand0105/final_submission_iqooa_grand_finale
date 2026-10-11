package dev.saathi.safety;

import dev.saathi.safety.SafetyTypes.Confidence;
import dev.saathi.safety.SafetyTypes.SelfHarmKind;
import dev.saathi.safety.SafetyTypes.Severity;
import dev.saathi.safety.SafetyTypes.Source;
import dev.saathi.safety.SafetyTypes.Status;
import dev.saathi.safety.SafetyTypes.ThreatKind;

/**
 * Deterministic check applied after the model (or fallback). It can keep or escalate a strong concern the model
 * missed, and it marks contradictory model claims for review. It never removes a concern.
 */
public final class SafetyGuard {

    private SafetyGuard() {}

    public static SafetyClassification apply(SafetyClassification c, String text) {
        SafetyRules.Finding sh = SafetyRules.selfHarm(text);
        SafetyRules.Finding th = SafetyRules.threat(text);
        SafetyClassification.Builder b = c.toBuilder();
        boolean changed = false;

        SelfHarmKind ruleSh = SelfHarmKind.valueOf(sh.kind);
        // Web page text is written by someone else; personal-risk wording there is not the child's own statement.
        if (c.sourceType == SafetyTypes.SourceType.BROWSER_PAGE && ruleSh.isPersonalRisk()) ruleSh = SelfHarmKind.AMBIGUOUS;
        if (ruleSh.isPersonalRisk() && sh.severity.rank >= Severity.HIGH.rank) {
            if (!c.selfHarm.isPersonalRisk() || c.selfHarmSeverity.rank < sh.severity.rank) {
                b.selfHarm = c.selfHarm.isPersonalRisk() && c.selfHarm == SelfHarmKind.PERSONAL_INTENT ? c.selfHarm : ruleSh;
                b.selfHarmSeverity = Severity.max(c.selfHarmSeverity, sh.severity);
                b.evidence.addAll(sh.evidence);
                b.guardNotes.add("Safety rules: " + sh.note + " — kept as a concern.");
                if (b.status == Status.COMPLETE || b.status == Status.NEEDS_REVIEW) b.status = Status.COMPLETE;
                changed = true;
            }
        } else if (c.selfHarm.isPersonalRisk() && c.selfHarmSeverity.rank >= Severity.HIGH.rank
                && (ruleSh == SelfHarmKind.INFORMATIONAL || ruleSh == SelfHarmKind.NEWS_OR_PREVENTION)) {
            // Model says personal risk, but the text reads as education/news with no first-person statement.
            b.status = Status.NEEDS_REVIEW;
            b.confidence = Confidence.LOW;
            b.guardNotes.add("Safety rules: this reads like " + (ruleSh == SelfHarmKind.NEWS_OR_PREVENTION ? "news or prevention material" : "school or research content")
                    + ", so this needs a person to look at it rather than an automatic alert.");
            changed = true;
        }

        ThreatKind ruleTh = ThreatKind.valueOf(th.kind);
        if (ruleTh != ThreatKind.NONE && th.severity.rank >= Severity.HIGH.rank && c.threatSeverity.rank < th.severity.rank) {
            if (c.threat == ThreatKind.NONE) b.threat = ruleTh;
            b.threatSeverity = th.severity;
            b.evidence.addAll(th.evidence);
            b.guardNotes.add("Safety rules: " + th.note + " — kept as a concern.");
            changed = true;
        }

        if (!changed) return c;
        if (c.source == Source.GEMMA) b.source = Source.GEMMA_WITH_GUARD;
        else if (c.source == Source.RULES_FALLBACK) b.source = Source.RULES_WITH_GUARD;
        // de-duplicate evidence
        java.util.LinkedHashSet<String> ev = new java.util.LinkedHashSet<>(b.evidence);
        b.evidence = new java.util.ArrayList<>(ev);
        return b.build();
    }
}
