package dev.saathi.ai;

import dev.saathi.model.ApkAnalysisReport;
import dev.saathi.model.ThreatIndicator;
import java.util.List;

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

    public static String buildKidApkExplanationPrompt(String fileName, String verdict, List<String> indicators, List<String> permissions, boolean hindiPreferred) {
        StringBuilder sb = new StringBuilder();
        sb.append("System: You are Saathi, a friendly digital safety friend for kids in India. ");
        sb.append("Explain phone app downloads in clear, warm, non-scary language.\n\n");
        sb.append("Task: Explain whether this downloaded app file is safe to install.\n");
        sb.append("Language: ").append(hindiPreferred ? "Hindi / Hinglish" : "Simple English").append("\n");
        sb.append("File Name: \"").append(fileName).append("\"\n");
        sb.append("Safety Verdict: ").append(verdict).append("\n");
        if (indicators != null && !indicators.isEmpty()) {
            sb.append("Clues found:\n");
            for (String ind : indicators) {
                sb.append("- ").append(ind).append("\n");
            }
        }
        if (permissions != null && !permissions.isEmpty()) {
            sb.append("Requested Permissions: ").append(String.join(", ", permissions)).append("\n");
        }
        sb.append("\nInstructions:\n");
        sb.append("1. In 2 simple sentences, tell the child why downloading this app might be risky or safe.\n");
        sb.append("2. Give 2 clear next steps (e.g. check with parents, delete from Downloads, download from Google Play).\n");
        return sb.toString();
    }

    public static String buildMessageExplanationPrompt(String message, String category, List<String> indicators, boolean hindiPreferred) {
        StringBuilder sb = new StringBuilder();
        sb.append("System: You are Saathi, a friendly digital safety companion for kids and teenagers in India. ");
        sb.append("Explain risks in warm, reassuring, non-scary language. Always empower the child and encourage talking to trusted adults.\n\n");
        sb.append("Task: Explain why this message may be unsafe or tricky.\n");
        sb.append("Language: ").append(hindiPreferred ? "Hindi / Hinglish (friendly, relatable Indian phrasing)" : "Simple, child-friendly English").append("\n");
        sb.append("Detected Category: ").append(category).append("\n");
        if (indicators != null && !indicators.isEmpty()) {
            sb.append("Detected Clues:\n");
            for (String ind : indicators) {
                sb.append("- ").append(ind).append("\n");
            }
        }
        sb.append("Original Message: \"").append(message).append("\"\n\n");
        sb.append("Instructions:\n");
        sb.append("1. In 2-3 sentences, explain why this message is tricky or dangerous.\n");
        sb.append("2. Give 2 concrete, safe actions the child should take right now.\n");
        return sb.toString();
    }

    public static String buildUrlExplanationPrompt(String url, String verdict, List<String> indicators, boolean hindiPreferred) {
        StringBuilder sb = new StringBuilder();
        sb.append("System: You are Saathi, an on-device digital safety companion for kids in India. ");
        sb.append("Explain website links in simple, easy terms without confusing technical jargon.\n\n");
        sb.append("Task: Explain why this website link is suspicious or safe.\n");
        sb.append("Language: ").append(hindiPreferred ? "Hindi / Hinglish" : "Simple English").append("\n");
        sb.append("Verdict: ").append(verdict).append("\n");
        if (indicators != null && !indicators.isEmpty()) {
            sb.append("Clues found:\n");
            for (String ind : indicators) {
                sb.append("- ").append(ind).append("\n");
            }
        }
        sb.append("Web Address: \"").append(url).append("\"\n\n");
        sb.append("Instructions:\n");
        sb.append("1. Explain what the address is doing (e.g., pretending to be Roblox, asking for login on fake page).\n");
        sb.append("2. Tell the child whether it is safe to tap or enter information.\n");
        return sb.toString();
    }

    public static String buildChildSafetyQuestionPrompt(String question, boolean hindiPreferred) {
        StringBuilder sb = new StringBuilder();
        sb.append("System: You are Saathi, a trusted, protective AI safety friend for children in India. ");
        sb.append("Never blame or scold the child. Provide clear, empathetic, practical safety guidance.\n\n");
        sb.append("Child's Question: \"").append(question).append("\"\n");
        sb.append("Language: ").append(hindiPreferred ? "Hindi / Hinglish" : "Simple English").append("\n\n");
        sb.append("Instructions: Answer the child's question warmly, reassuring them that they did nothing wrong and explaining how to stay safe.\n");
        return sb.toString();
    }
}
