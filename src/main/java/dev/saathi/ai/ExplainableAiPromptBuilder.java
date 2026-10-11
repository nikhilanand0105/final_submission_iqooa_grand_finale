package dev.saathi.ai;

import dev.saathi.model.ApkAnalysisReport;
import dev.saathi.model.ThreatIndicator;

/**
 * Builds structured prompts for on-device quantized models (LiteRT / Gemma 2B / Gemini Nano)
 * to synthesize explainable, evidence-backed security explanations.
 */
public class ExplainableAiPromptBuilder {

    public static String buildApkExplanationPrompt(ApkAnalysisReport report, boolean seniorModeTarget) {
        StringBuilder sb = new StringBuilder();
        sb.append("System: You are Saathi, an on-device digital safety assistant in India.\n");
        sb.append("Task: Explain why the following Android APK security findings are concerning.\n");
        sb.append("Audience: ").append(seniorModeTarget ? "Elderly user (use clear, warm, non-jargon language, caution against OTP theft)" : "General Android user").append("\n\n");

        sb.append("Package Name: ").append(report.getManifestMetadata() != null ? report.getManifestMetadata().getPackageName() : "unknown").append("\n");
        sb.append("Verdict: ").append(report.getVerdict().getDisplayName()).append("\n");
        sb.append("Identified Indicators:\n");

        for (ThreatIndicator ti : report.getIndicators()) {
            sb.append("- [").append(ti.getCategory()).append("] ").append(ti.getTitle()).append(": ").append(ti.getDescription()).append("\n");
        }

        sb.append("\nInstructions:\n");
        sb.append("1. State directly whether it is safe to install.\n");
        sb.append("2. Explain the specific risk in simple everyday terms (e.g., OTP theft, screen reading).\n");
        sb.append("3. Provide exactly two actionable recommendations.\n");

        return sb.toString();
    }
}
