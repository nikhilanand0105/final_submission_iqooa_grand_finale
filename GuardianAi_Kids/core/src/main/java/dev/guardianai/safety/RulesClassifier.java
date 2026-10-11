package dev.guardianai.safety;

import dev.guardianai.safety.SafetyTypes.AgeConcern;
import dev.guardianai.safety.SafetyTypes.Confidence;
import dev.guardianai.safety.SafetyTypes.ScamKind;
import dev.guardianai.safety.SafetyTypes.SelfHarmKind;
import dev.guardianai.safety.SafetyTypes.Severity;
import dev.guardianai.safety.SafetyTypes.Source;
import dev.guardianai.safety.SafetyTypes.SourceType;
import dev.guardianai.safety.SafetyTypes.Status;
import dev.guardianai.safety.SafetyTypes.ThreatKind;
import dev.guardianai.safety.SafetyTypes.WebsiteConcern;
import dev.guardianai.sense.analyzer.MessageAnalysisResult;
import dev.guardianai.sense.analyzer.RuleBasedMessageSafetyAnalyzer;
import dev.guardianai.sense.analyzer.SafetyIndicator;

import java.util.ArrayList;
import java.util.List;

/** Rules-based fallback classifier: {@link SafetyRules} for threats/self-harm + the existing message analyzer for scams. */
public final class RulesClassifier {

    private final RuleBasedMessageSafetyAnalyzer messageRules = new RuleBasedMessageSafetyAnalyzer();

    public SafetyClassification classify(SourceType type, String text) {
        SafetyRules.Finding sh = SafetyRules.selfHarm(text);
        SafetyRules.Finding th = SafetyRules.threat(text);
        SelfHarmKind shKind = SelfHarmKind.valueOf(sh.kind);
        ThreatKind thKind = ThreatKind.valueOf(th.kind);
        Severity thSev = th.severity;
        List<String> evidence = new ArrayList<>(sh.evidence);
        evidence.addAll(th.evidence);

        ScamKind scam = ScamKind.NONE;
        MessageAnalysisResult m = messageRules.analyze(text);
        for (SafetyIndicator i : m.getMatchedIndicators()) {
            switch (i.getCategory()) {
                case CREDENTIAL_THEFT: if (scam == ScamKind.NONE) scam = ScamKind.CREDENTIAL_PHISHING; break;
                case FINANCIAL_DEMAND: if (scam == ScamKind.NONE) scam = ScamKind.PAYMENT_REQUEST; break;
                case PRIZE_SCAM: if (scam == ScamKind.NONE) scam = ScamKind.PRIZE_OR_REWARD; break;
                case SECRECY_PRESSURE:
                case PLATFORM_MIGRATION:
                case PRIVACY_INVASION: scam = ScamKind.GROOMING_OR_SECRECY; break;
                case BULLYING_HARASSMENT:
                    if (thKind == ThreatKind.NONE) {
                        thKind = ThreatKind.INTIMIDATION;
                        thSev = Severity.MEDIUM;
                    }
                    break;
                case COERCION_INTIMIDATION:
                    if (thKind == ThreatKind.NONE) {
                        thKind = ThreatKind.INTIMIDATION;
                        thSev = Severity.MEDIUM;
                    }
                    break;
                default: break;
            }
            if (i.getCategory() != dev.guardianai.sense.analyzer.SafetyIndicatorCategory.INSUFFICIENT_CONTEXT
                    && i.getEvidenceExcerpt() != null && !i.getEvidenceExcerpt().isEmpty()) {
                evidence.add(i.getEvidenceExcerpt());
            }
        }

        AgeConcern age = AgeConcern.NONE;
        if (type == SourceType.BROWSER_PAGE) {
            WebSafety.AgeFinding af = WebSafety.pageSuitability(text);
            age = af.concern;
            evidence.addAll(af.evidence);
        }
        boolean weak = shKind == SelfHarmKind.AMBIGUOUS || (thKind != ThreatKind.NONE && thSev == Severity.LOW);
        boolean strong = shKind.isPersonalRisk() || thSev.rank >= Severity.HIGH.rank;
        Status status = weak && !strong ? Status.NEEDS_REVIEW : Status.COMPLETE;
        Confidence conf = strong ? Confidence.MEDIUM : Confidence.LOW;

        String expl;
        List<String> actions = new ArrayList<>();
        if (shKind.isPersonalRisk()) {
            expl = "This sounds like someone is going through something really hard and may be thinking about hurting themselves.";
            actions.add("Talk to a trusted adult now");
            actions.add("If you're in danger, call 112");
        } else if (thSev.rank >= Severity.HIGH.rank) {
            expl = "This message has a threat or a demand with a consequence. " + th.note + ".";
            actions.add("Don't pay, send photos, or share any codes");
            actions.add("Keep a screenshot if it's safe, and don't reply");
            actions.add("Show a trusted adult");
        } else if (thKind != ThreatKind.NONE || scam != ScamKind.NONE) {
            expl = "This message has some warning signs worth talking about with someone you trust.";
            actions.add("Don't share private information");
            actions.add("Ask a trusted adult if you're unsure");
        } else if (shKind == SelfHarmKind.AMBIGUOUS) {
            expl = "This mentions self-harm, but it isn't clear what it means.";
            actions.add("If this is about you or a friend, talk to a trusted adult");
        } else {
            expl = "GuardianAi's rules didn't find warning signs in this text. That doesn't prove it's safe.";
        }
        dedupe(evidence);
        return new SafetyClassification(type, thKind, thSev, shKind, sh.severity, scam, WebsiteConcern.NONE, age,
                conf, evidence.size() > 4 ? evidence.subList(0, 4) : evidence, expl, actions, status, Source.RULES_FALLBACK, null, null);
    }

    private static void dedupe(List<String> l) {
        java.util.LinkedHashSet<String> s = new java.util.LinkedHashSet<>(l);
        s.remove(null);
        l.clear();
        l.addAll(s);
    }
}
