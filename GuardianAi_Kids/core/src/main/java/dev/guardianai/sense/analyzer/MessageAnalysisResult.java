package dev.guardianai.sense.analyzer;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Complete, structured result contract for message safety analysis.
 */
public class MessageAnalysisResult {

    private final MessageRiskVerdict verdict;
    private final ProcessingStatus status;
    private final List<SafetyIndicator> matchedIndicators;
    private final List<String> evidenceExcerpts;
    private final String explanation;
    private final String whyItMatters;
    private final List<String> nextSteps;
    private final String limitationsNote;
    private final String analyzerType;
    private final String analyzerVersion;
    private final long analyzedAtMillis;
    private final int characterCount;
    private final int wordCount;

    public MessageAnalysisResult(
            MessageRiskVerdict verdict,
            ProcessingStatus status,
            List<SafetyIndicator> matchedIndicators,
            List<String> evidenceExcerpts,
            String explanation,
            String whyItMatters,
            List<String> nextSteps,
            String limitationsNote,
            String analyzerType,
            String analyzerVersion,
            long analyzedAtMillis,
            int characterCount,
            int wordCount) {
        this.verdict = verdict;
        this.status = status;
        this.matchedIndicators = matchedIndicators != null ? Collections.unmodifiableList(new ArrayList<>(matchedIndicators)) : Collections.emptyList();
        this.evidenceExcerpts = evidenceExcerpts != null ? Collections.unmodifiableList(new ArrayList<>(evidenceExcerpts)) : Collections.emptyList();
        this.explanation = explanation != null ? explanation : "";
        this.whyItMatters = whyItMatters != null ? whyItMatters : "";
        this.nextSteps = nextSteps != null ? Collections.unmodifiableList(new ArrayList<>(nextSteps)) : Collections.emptyList();
        this.limitationsNote = limitationsNote != null ? limitationsNote : "";
        this.analyzerType = analyzerType != null ? analyzerType : "Unknown";
        this.analyzerVersion = analyzerVersion != null ? analyzerVersion : "1.0.0";
        this.analyzedAtMillis = analyzedAtMillis;
        this.characterCount = characterCount;
        this.wordCount = wordCount;
    }

    public MessageRiskVerdict getVerdict() {
        return verdict;
    }

    public ProcessingStatus getStatus() {
        return status;
    }

    public List<SafetyIndicator> getMatchedIndicators() {
        return matchedIndicators;
    }

    public List<String> getEvidenceExcerpts() {
        return evidenceExcerpts;
    }

    public String getExplanation() {
        return explanation;
    }

    public String getWhyItMatters() {
        return whyItMatters;
    }

    public List<String> getNextSteps() {
        return nextSteps;
    }

    public String getLimitationsNote() {
        return limitationsNote;
    }

    public String getAnalyzerType() {
        return analyzerType;
    }

    public String getAnalyzerVersion() {
        return analyzerVersion;
    }

    public long getAnalyzedAtMillis() {
        return analyzedAtMillis;
    }

    public int getCharacterCount() {
        return characterCount;
    }

    public int getWordCount() {
        return wordCount;
    }

    public boolean hasWarnings() {
        return verdict == MessageRiskVerdict.WARNING_SIGNS_DETECTED || verdict == MessageRiskVerdict.BE_CAREFUL;
    }

    public boolean shouldSuggestAdultHelp() {
        return verdict == MessageRiskVerdict.WARNING_SIGNS_DETECTED;
    }
}
