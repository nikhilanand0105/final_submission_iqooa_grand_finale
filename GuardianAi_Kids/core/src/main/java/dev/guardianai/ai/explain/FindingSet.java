package dev.guardianai.ai.explain;

import dev.guardianai.sense.analyzer.MessageAnalysisResult;
import dev.guardianai.sense.analyzer.SafetyIndicator;
import dev.guardianai.shield.apk.ApkAnalysisResult;
import dev.guardianai.shield.apk.ApkIndicator;
import dev.guardianai.shield.url.UrlAnalysisResult;
import dev.guardianai.shield.url.UrlStructuralIndicator;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * The complete, analyzer-produced facts about one check. This is the only factual material an explanation
 * (model or rules) may draw on. Built from the real analyzer outputs; never hand-written.
 */
public final class FindingSet {

    public enum Kind { MESSAGE, LINK, FILE }

    public final Kind kind;
    public final String verdictLabel;
    public final String analyzerSummary;
    public final List<Finding> findings;
    public final List<String> analyzerNextSteps;
    public final String limitations;
    /** Facts about external checks, stated exactly (e.g. "Online safety list: not checked"). */
    public final String externalCheckStatus;

    public FindingSet(Kind kind, String verdictLabel, String analyzerSummary, List<Finding> findings,
                      List<String> analyzerNextSteps, String limitations, String externalCheckStatus) {
        this.kind = kind;
        this.verdictLabel = verdictLabel;
        this.analyzerSummary = analyzerSummary == null ? "" : analyzerSummary;
        this.findings = Collections.unmodifiableList(new ArrayList<>(findings));
        this.analyzerNextSteps = Collections.unmodifiableList(new ArrayList<>(analyzerNextSteps));
        this.limitations = limitations == null ? "" : limitations;
        this.externalCheckStatus = externalCheckStatus == null ? "" : externalCheckStatus;
    }

    public Set<String> ids() {
        Set<String> s = new HashSet<>();
        for (Finding f : findings) s.add(f.id);
        return s;
    }

    public Finding byId(String id) {
        for (Finding f : findings) if (f.id.equals(id)) return f;
        return null;
    }

    public static FindingSet fromMessage(MessageAnalysisResult r) {
        List<Finding> fs = new ArrayList<>();
        Set<String> used = new HashSet<>();
        for (SafetyIndicator i : r.getMatchedIndicators()) {
            String id = unique(i.getId(), used);
            fs.add(new Finding(id, i.getName(), i.getDescription(), i.getEvidenceExcerpt(), String.valueOf(i.getSeverity())));
        }
        return new FindingSet(Kind.MESSAGE, r.getVerdict().getLabel(), r.getExplanation(), fs, r.getNextSteps(),
                r.getLimitationsNote(), "No online service was used for message checks.");
    }

    public static FindingSet fromUrl(UrlAnalysisResult r) {
        List<Finding> fs = new ArrayList<>();
        Set<String> used = new HashSet<>();
        for (UrlStructuralIndicator i : r.getLocalIndicators()) {
            fs.add(new Finding(unique(i.getId(), used), i.getName(), i.getDescription(), i.getEvidenceExcerpt(), i.getSeverity().name()));
        }
        return new FindingSet(Kind.LINK, r.getVerdict().getLabel(), r.getSummary(), fs, r.getNextSteps(), r.getLimitations(),
                "Online safety list: " + onlineStatus(r.getStatus()) + ". " + r.getLiveCheckNote());
    }

    public static FindingSet fromApk(ApkAnalysisResult r) {
        List<Finding> fs = new ArrayList<>();
        Set<String> used = new HashSet<>();
        for (ApkIndicator i : r.indicators) {
            fs.add(new Finding(unique(i.id, used), i.title, i.explanation, i.evidence, i.severity.name()));
        }
        String hash;
        switch (r.hashLookup) {
            case KNOWN_MALICIOUS: hash = "Threat database (" + r.hashProviderName + "): this exact file is known to be harmful."; break;
            case NOT_KNOWN: hash = "Threat database (" + r.hashProviderName + "): no record of this file."; break;
            case UNAVAILABLE: hash = "Threat database: could not be reached."; break;
            default: hash = "Threat database: not checked."; break;
        }
        return new FindingSet(Kind.FILE, r.verdict.getLabel(), r.summary, fs, r.nextSteps, r.limitations, hash);
    }

    private static String onlineStatus(dev.guardianai.shield.url.ReputationStatus s) {
        switch (s) {
            case THREAT_MATCH: return "lists this address as dangerous";
            case NO_KNOWN_THREAT: return "no warning listed";
            case TIMEOUT_OR_NETWORK_ERROR:
            case PROVIDER_UNAVAILABLE: return "check did not complete";
            default: return "not checked";
        }
    }

    private static String unique(String id, Set<String> used) {
        String base = id == null || id.isEmpty() ? "F" : id;
        String v = base;
        int n = 2;
        while (!used.add(v)) v = base + "_" + n++;
        return v;
    }
}
