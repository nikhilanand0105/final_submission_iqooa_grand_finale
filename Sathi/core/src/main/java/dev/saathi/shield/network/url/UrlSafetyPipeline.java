package dev.saathi.shield.network.url;

import dev.saathi.model.ScanVerdict;

import java.util.List;
import java.util.Objects;

/**
 * End-to-end URL evaluation pipeline.
 * Coordinates parsing, local heuristic indicator analysis, and online threat reputation checks.
 */
public class UrlSafetyPipeline {

    private final LocalUrlAnalyzer localAnalyzer;
    private final ThreatReputationProvider reputationProvider;

    public UrlSafetyPipeline() {
        this(new LocalUrlAnalyzer(), new ThreatReputationProvider.NoOpReputationProvider());
    }

    public UrlSafetyPipeline(LocalUrlAnalyzer localAnalyzer, ThreatReputationProvider reputationProvider) {
        this.localAnalyzer = Objects.requireNonNull(localAnalyzer, "localAnalyzer cannot be null");
        this.reputationProvider = Objects.requireNonNull(reputationProvider, "reputationProvider cannot be null");
    }

    /**
     * Executes full URL safety analysis on the user input.
     *
     * @param rawInput exact URL entered or pasted by the user.
     * @return Complete {@link UrlAnalysisResult}.
     * @throws UrlParseException if raw input cannot be parsed or normalised.
     */
    public UrlAnalysisResult analyze(String rawInput) throws UrlParseException {
        // 1. Parsing and normalisation
        ParsedUrl parsedUrl = UrlParser.parse(rawInput);

        // 2. Local heuristic indicator analysis
        List<UrlIndicator> indicators = localAnalyzer.analyze(parsedUrl);
        ScanVerdict localVerdict = localAnalyzer.determineVerdict(indicators);

        // 3. Online threat-reputation provider check
        ReputationResult reputationResult;
        if (reputationProvider.isConfigured()) {
            reputationResult = reputationProvider.checkReputation(parsedUrl);
        } else {
            reputationResult = ReputationResult.notChecked("Live reputation provider is not configured. Local heuristics only.");
        }

        // 4. Result synthesis
        return new UrlAnalysisResult(parsedUrl, indicators, localVerdict, reputationResult);
    }

    public LocalUrlAnalyzer getLocalAnalyzer() {
        return localAnalyzer;
    }

    public ThreatReputationProvider getReputationProvider() {
        return reputationProvider;
    }
}
