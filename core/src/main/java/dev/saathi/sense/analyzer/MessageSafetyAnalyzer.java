package dev.saathi.sense.analyzer;

/**
 * Contract for inspecting messages for child-safety warning signs.
 * Decouples rule evaluation from UI presentation.
 */
public interface MessageSafetyAnalyzer {

    /**
     * Analyzes the supplied text excerpt and produces an explainable, child-friendly report.
     *
     * @param messageText Raw text provided or selected by the child.
     * @return Structured analysis result.
     */
    MessageAnalysisResult analyze(String messageText);

    /**
     * Engine type identifier for auditing and telemetry (e.g., "DeterministicRuleBasedAnalyzer").
     */
    String getAnalyzerType();

    /**
     * Engine version identifier.
     */
    String getVersion();
}
