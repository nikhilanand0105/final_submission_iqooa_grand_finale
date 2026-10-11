package dev.saathi.ai;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Strongly typed response contract for on-device security explanations.
 */
public class ExplanationResult {

    public enum ExplanationSource {
        MODEL_INFERENCE,
        RULES_FALLBACK,
        MODEL_UNAVAILABLE,
        INFERENCE_FAILED
    }

    private final String summary;
    private final String indicatorExplanation;
    private final List<String> practicalAdvice;
    private final String uncertaintyDisclosure;
    private final ExplanationSource source;
    private final String modelName;
    private final String backendName;
    private final long latencyMs;

    public ExplanationResult(
            String summary,
            String indicatorExplanation,
            List<String> practicalAdvice,
            String uncertaintyDisclosure,
            ExplanationSource source,
            String modelName,
            String backendName,
            long latencyMs
    ) {
        this.summary = summary != null ? summary : "";
        this.indicatorExplanation = indicatorExplanation != null ? indicatorExplanation : "";
        this.practicalAdvice = practicalAdvice != null ? Collections.unmodifiableList(new ArrayList<>(practicalAdvice)) : Collections.emptyList();
        this.uncertaintyDisclosure = uncertaintyDisclosure != null ? uncertaintyDisclosure : "";
        this.source = source != null ? source : ExplanationSource.RULES_FALLBACK;
        this.modelName = modelName != null ? modelName : "Unknown";
        this.backendName = backendName != null ? backendName : "Unknown";
        this.latencyMs = Math.max(0, latencyMs);
    }

    public String getSummary() { return summary; }
    public String getIndicatorExplanation() { return indicatorExplanation; }
    public List<String> getPracticalAdvice() { return practicalAdvice; }
    public String getUncertaintyDisclosure() { return uncertaintyDisclosure; }
    public ExplanationSource getSource() { return source; }
    public String getModelName() { return modelName; }
    public String getBackendName() { return backendName; }
    public long getLatencyMs() { return latencyMs; }

    public boolean isModelGenerated() {
        return source == ExplanationSource.MODEL_INFERENCE;
    }

    public boolean isFailure() {
        return source == ExplanationSource.MODEL_UNAVAILABLE || source == ExplanationSource.INFERENCE_FAILED;
    }

    /**
     * Formats clean, human-readable text for chat bubbles and detail cards.
     */
    public String toFormattedDisplay() {
        if (source == ExplanationSource.MODEL_UNAVAILABLE) {
            StringBuilder sb = new StringBuilder();
            sb.append("⚠️ SAATHI LOCAL AI UNAVAILABLE\n\n");
            if (!summary.isEmpty()) sb.append(summary).append("\n\n");
            if (!uncertaintyDisclosure.isEmpty()) sb.append(uncertaintyDisclosure);
            return sb.toString().trim();
        }

        if (source == ExplanationSource.INFERENCE_FAILED) {
            StringBuilder sb = new StringBuilder();
            sb.append("❌ LOCAL AI INFERENCE FAILED\n\n");
            if (!summary.isEmpty()) sb.append(summary).append("\n\n");
            if (!uncertaintyDisclosure.isEmpty()) sb.append(uncertaintyDisclosure);
            return sb.toString().trim();
        }

        if (source == ExplanationSource.RULES_FALLBACK) {
            StringBuilder sb = new StringBuilder();
            sb.append("🛡️ DETERMINISTIC RULES-BASED GUIDANCE\n");
            sb.append("[Gemma on-device model not initialized. Output derived strictly from local rules.]\n\n");
            if (!summary.isEmpty()) sb.append(summary).append("\n\n");
            if (!indicatorExplanation.isEmpty()) sb.append("🔍 Observable Security Indicators:\n").append(indicatorExplanation).append("\n\n");
            if (!practicalAdvice.isEmpty()) {
                sb.append("💡 Recommended Next Steps:\n");
                for (String step : practicalAdvice) sb.append("• ").append(step).append("\n");
                sb.append("\n");
            }
            if (!uncertaintyDisclosure.isEmpty()) sb.append("⚠️ ").append(uncertaintyDisclosure);
            return sb.toString().trim();
        }

        // MODEL_INFERENCE
        StringBuilder sb = new StringBuilder();
        if (!summary.isEmpty()) {
            sb.append(summary).append("\n\n");
        }

        if (!indicatorExplanation.isEmpty()) {
            sb.append("🔍 Key Factors:\n");
            sb.append(indicatorExplanation).append("\n\n");
        }

        if (!practicalAdvice.isEmpty()) {
            sb.append("💡 Recommended Steps:\n");
            for (String step : practicalAdvice) {
                sb.append("• ").append(step).append("\n");
            }
            sb.append("\n");
        }

        if (!uncertaintyDisclosure.isEmpty()) {
            sb.append("⚠️ Note: ").append(uncertaintyDisclosure).append("\n\n");
        }

        sb.append("— Gemma 4-E2B-it (").append(backendName).append(" • ").append(latencyMs).append("ms)");
        return sb.toString().trim();
    }
}
