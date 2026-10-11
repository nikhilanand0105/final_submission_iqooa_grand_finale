package dev.guardianai.shield.network;

import dev.guardianai.model.ThreatSeverity;
import dev.guardianai.shield.network.url.ParsedUrl;
import dev.guardianai.shield.network.url.UrlAnalysisResult;
import dev.guardianai.shield.network.url.UrlIndicator;
import dev.guardianai.shield.network.url.UrlParseException;
import dev.guardianai.shield.network.url.UrlSafetyPipeline;

import java.util.*;

/**
 * High-level scanner facade for user-submitted URLs and links extracted from SMS/messages.
 * Backed by the robust {@link UrlSafetyPipeline} for deterministic parsing, local structural heuristics,
 * and threat-reputation provider integration.
 */
public class PhishingUrlScanner {

    public enum UrlRiskLevel {
        KNOWN_PHISHING,
        SUSPICIOUS_DESTINATION,
        UNVERIFIED,
        SAFE_REPUTATION
    }

    public static class UrlScanResult {
        public final String originalUrl;
        public final String domain;
        public final UrlRiskLevel riskLevel;
        public final ThreatSeverity severity;
        public final List<String> warningReasons;
        public final String plainAdvice;
        public final UrlAnalysisResult pipelineResult;

        public UrlScanResult(
                String originalUrl,
                String domain,
                UrlRiskLevel riskLevel,
                ThreatSeverity severity,
                List<String> warningReasons,
                String plainAdvice) {
            this(originalUrl, domain, riskLevel, severity, warningReasons, plainAdvice, null);
        }

        public UrlScanResult(
                String originalUrl,
                String domain,
                UrlRiskLevel riskLevel,
                ThreatSeverity severity,
                List<String> warningReasons,
                String plainAdvice,
                UrlAnalysisResult pipelineResult) {
            this.originalUrl = originalUrl;
            this.domain = domain != null ? domain : "";
            this.riskLevel = riskLevel;
            this.severity = severity;
            this.warningReasons = warningReasons != null ? warningReasons : Collections.emptyList();
            this.plainAdvice = plainAdvice;
            this.pipelineResult = pipelineResult;
        }
    }

    private final UrlSafetyPipeline pipeline;

    public PhishingUrlScanner() {
        this(new UrlSafetyPipeline());
    }

    public PhishingUrlScanner(UrlSafetyPipeline pipeline) {
        this.pipeline = Objects.requireNonNull(pipeline, "pipeline cannot be null");
    }

    public UrlSafetyPipeline getPipeline() {
        return pipeline;
    }

    /**
     * Executes comprehensive URL safety analysis through the pipeline.
     */
    public UrlAnalysisResult analyze(String rawUrl) throws UrlParseException {
        return pipeline.analyze(rawUrl);
    }

    /**
     * Compatibility entry point mapping pipeline outcomes to legacy UrlScanResult.
     */
    public UrlScanResult scanUrl(String rawUrl) {
        if (rawUrl == null || rawUrl.isBlank()) {
            return new UrlScanResult(
                    rawUrl,
                    "",
                    UrlRiskLevel.UNVERIFIED,
                    ThreatSeverity.INFO,
                    List.of("The web address cannot be empty or blank."),
                    "No link provided."
            );
        }

        try {
            UrlAnalysisResult analysis = pipeline.analyze(rawUrl);
            UrlRiskLevel risk;
            switch (analysis.getCombinedVerdict()) {
                case KNOWN_MALICIOUS:
                case HIGH_RISK:
                    risk = UrlRiskLevel.KNOWN_PHISHING;
                    break;
                case CAUTION:
                    risk = UrlRiskLevel.SUSPICIOUS_DESTINATION;
                    break;
                case NO_KNOWN_THREAT_DETECTED:
                default:
                    risk = UrlRiskLevel.SAFE_REPUTATION;
                    break;
            }

            List<String> reasons = new ArrayList<>();
            for (UrlIndicator ind : analysis.getIndicators()) {
                reasons.add(ind.getTitle() + ": " + ind.getExplanation());
            }

            String domain = analysis.getParsedUrl().getAsciiHost();
            return new UrlScanResult(
                    rawUrl,
                    domain,
                    risk,
                    analysis.getOverallSeverity(),
                    reasons,
                    analysis.getPlainAdvice(),
                    analysis
            );
        } catch (UrlParseException e) {
            return new UrlScanResult(
                    rawUrl,
                    "",
                    UrlRiskLevel.UNVERIFIED,
                    ThreatSeverity.LOW,
                    List.of("Could not parse URL: " + e.getMessage()),
                    "Unable to verify this web address."
            );
        } catch (Exception e) {
            return new UrlScanResult(
                    rawUrl,
                    "",
                    UrlRiskLevel.UNVERIFIED,
                    ThreatSeverity.LOW,
                    List.of("Analysis failed: " + e.getMessage()),
                    "Unable to verify this web address."
            );
        }
    }
}
