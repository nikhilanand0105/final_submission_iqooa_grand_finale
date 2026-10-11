package dev.saathi.ai;

import dev.saathi.model.ScanVerdict;
import dev.saathi.shield.message.MessageIndicator;
import dev.saathi.shield.message.MessageRiskAssessment;
import dev.saathi.shield.network.url.UrlAnalysisResult;
import dev.saathi.shield.network.url.UrlIndicator;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Context container holding ONLY the structured indicators and sanitised text
 * that the user has deliberately chosen to explain with the on-device AI Copilot.
 */
public class SecurityFindingContext {

    public enum FindingType {
        MESSAGE,
        URL,
        APK,
        GENERAL_QUERY
    }

    private final FindingType type;
    private final String targetIdentifier;
    private final String rawUntrustedSnippet;
    private final ScanVerdict verdict;
    private final List<IndicatorDetail> indicators;
    private final List<String> practicalSteps;
    private final String uncertaintyNote;
    private final boolean seniorMode;
    private final boolean hindi;

    public static class IndicatorDetail {
        private final String code;
        private final String title;
        private final String explanation;
        private final String evidenceQuote;

        public IndicatorDetail(String code, String title, String explanation, String evidenceQuote) {
            this.code = code != null ? code : "";
            this.title = title != null ? title : "";
            this.explanation = explanation != null ? explanation : "";
            this.evidenceQuote = evidenceQuote != null ? evidenceQuote : "";
        }

        public String getCode() { return code; }
        public String getTitle() { return title; }
        public String getExplanation() { return explanation; }
        public String getEvidenceQuote() { return evidenceQuote; }
    }

    public SecurityFindingContext(
            FindingType type,
            String targetIdentifier,
            String rawUntrustedSnippet,
            ScanVerdict verdict,
            List<IndicatorDetail> indicators,
            List<String> practicalSteps,
            String uncertaintyNote,
            boolean seniorMode,
            boolean hindi
    ) {
        this.type = type != null ? type : FindingType.GENERAL_QUERY;
        this.targetIdentifier = targetIdentifier != null ? targetIdentifier : "";
        this.rawUntrustedSnippet = rawUntrustedSnippet != null ? rawUntrustedSnippet : "";
        this.verdict = verdict != null ? verdict : ScanVerdict.NO_KNOWN_THREAT_DETECTED;
        this.indicators = indicators != null ? Collections.unmodifiableList(new ArrayList<>(indicators)) : Collections.emptyList();
        this.practicalSteps = practicalSteps != null ? Collections.unmodifiableList(new ArrayList<>(practicalSteps)) : Collections.emptyList();
        this.uncertaintyNote = uncertaintyNote != null ? uncertaintyNote : "";
        this.seniorMode = seniorMode;
        this.hindi = hindi;
    }

    public static SecurityFindingContext fromMessageAssessment(
            String originalText,
            MessageRiskAssessment assessment,
            boolean seniorMode,
            boolean hindi
    ) {
        List<IndicatorDetail> indList = new ArrayList<>();
        if (assessment != null && assessment.getIndicators() != null) {
            for (MessageIndicator ind : assessment.getIndicators()) {
                indList.add(new IndicatorDetail(
                        ind.getType().name(),
                        ind.getTitle(),
                        ind.getPlainLanguageExplanation(),
                        ind.getEvidenceText()
                ));
            }
        }

        ScanVerdict v = ScanVerdict.NO_KNOWN_THREAT_DETECTED;
        if (assessment != null && assessment.getCategory() != null) {
            v = assessment.getCategory().toScanVerdict();
        }

        String note = (assessment != null && assessment.getLimitations() != null)
                ? assessment.getLimitations()
                : "Rule-based analysis evaluates observable text patterns; cannot determine real-world identity.";

        List<String> steps = (assessment != null && assessment.getSuggestedActions() != null)
                ? assessment.getSuggestedActions()
                : Collections.emptyList();

        return new SecurityFindingContext(
                FindingType.MESSAGE,
                "Message Analysis",
                originalText,
                v,
                indList,
                steps,
                note,
                seniorMode,
                hindi
        );
    }

    public static SecurityFindingContext fromUrlResult(
            UrlAnalysisResult urlResult,
            boolean seniorMode,
            boolean hindi
    ) {
        List<IndicatorDetail> indList = new ArrayList<>();
        if (urlResult != null && urlResult.getIndicators() != null) {
            for (UrlIndicator ind : urlResult.getIndicators()) {
                indList.add(new IndicatorDetail(
                        ind.getCategory(),
                        ind.getTitle(),
                        ind.getExplanation(),
                        ind.getEvidence()
                ));
            }
        }

        ScanVerdict v = urlResult != null ? urlResult.getCombinedVerdict() : ScanVerdict.NO_KNOWN_THREAT_DETECTED;
        String note = (urlResult != null && urlResult.getReputationResult() != null)
                ? urlResult.getReputationResult().getStatusMessage()
                : "";

        return new SecurityFindingContext(
                FindingType.URL,
                urlResult != null && urlResult.getParsedUrl() != null ? urlResult.getParsedUrl().getOriginalInput() : "URL",
                urlResult != null && urlResult.getParsedUrl() != null ? urlResult.getParsedUrl().getOriginalInput() : "",
                v,
                indList,
                urlResult != null ? urlResult.getPracticalNextSteps() : Collections.emptyList(),
                note,
                seniorMode,
                hindi
        );
    }

    public static SecurityFindingContext createGeneralQuery(String userQuery, boolean seniorMode, boolean hindi) {
        return new SecurityFindingContext(
                FindingType.GENERAL_QUERY,
                "General Security Question",
                userQuery,
                ScanVerdict.NO_KNOWN_THREAT_DETECTED,
                Collections.emptyList(),
                Collections.emptyList(),
                "General safety guidance based on standard cybersecurity practices.",
                seniorMode,
                hindi
        );
    }

    public FindingType getType() { return type; }
    public String getTargetIdentifier() { return targetIdentifier; }
    public String getRawUntrustedSnippet() { return rawUntrustedSnippet; }
    public ScanVerdict getVerdict() { return verdict; }
    public List<IndicatorDetail> getIndicators() { return indicators; }
    public List<String> getPracticalSteps() { return practicalSteps; }
    public String getUncertaintyNote() { return uncertaintyNote; }
    public boolean isSeniorMode() { return seniorMode; }
    public boolean isHindi() { return hindi; }
}
