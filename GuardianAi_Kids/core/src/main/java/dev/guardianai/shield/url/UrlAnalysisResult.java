package dev.guardianai.shield.url;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Result of a link check. Local structural findings ({@link #getLocalIndicators()}) and the online reputation
 * outcome ({@link #getReputation()}) are kept separate; {@link #getStatus()} summarises which applies.
 */
public final class UrlAnalysisResult {

    private final ParsedUrl parsedUrl;
    private final UrlRiskVerdict verdict;
    private final ReputationStatus status;
    private final ReputationResult reputation; // null when no online lookup was attempted
    private final String liveCheckNote;
    private final List<UrlStructuralIndicator> localIndicators;
    private final String summary;
    private final String whyItMatters;
    private final List<String> nextSteps;
    private final String limitations;
    private final String providerName;
    private final long analyzedAtMillis;

    UrlAnalysisResult(ParsedUrl parsedUrl, UrlRiskVerdict verdict, ReputationStatus status, ReputationResult reputation,
                      String liveCheckNote, List<UrlStructuralIndicator> localIndicators, String summary,
                      String whyItMatters, List<String> nextSteps, String limitations, String providerName,
                      long analyzedAtMillis) {
        this.parsedUrl = parsedUrl;
        this.verdict = verdict;
        this.status = status;
        this.reputation = reputation;
        this.liveCheckNote = liveCheckNote == null ? "" : liveCheckNote;
        this.localIndicators = Collections.unmodifiableList(new ArrayList<>(localIndicators));
        this.summary = summary;
        this.whyItMatters = whyItMatters;
        this.nextSteps = Collections.unmodifiableList(new ArrayList<>(nextSteps));
        this.limitations = limitations;
        this.providerName = providerName == null ? "" : providerName;
        this.analyzedAtMillis = analyzedAtMillis;
    }

    public ParsedUrl getParsedUrl() { return parsedUrl; }
    public UrlRiskVerdict getVerdict() { return verdict; }
    public ReputationStatus getStatus() { return status; }
    public ReputationResult getReputation() { return reputation; }
    /** Why the online check did or didn't run / finish, in plain words. */
    public String getLiveCheckNote() { return liveCheckNote; }
    public List<UrlStructuralIndicator> getLocalIndicators() { return localIndicators; }
    public String getSummary() { return summary; }
    public String getWhyItMatters() { return whyItMatters; }
    public List<String> getNextSteps() { return nextSteps; }
    public String getLimitations() { return limitations; }
    public String getProviderName() { return providerName; }
    public long getAnalyzedAtMillis() { return analyzedAtMillis; }

    public List<String> getEvidenceExcerpts() {
        List<String> ev = new ArrayList<>();
        for (UrlStructuralIndicator i : localIndicators) if (!i.getEvidenceExcerpt().isEmpty()) ev.add(i.getEvidenceExcerpt());
        return ev;
    }
}
