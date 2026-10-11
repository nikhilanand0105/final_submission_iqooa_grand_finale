package dev.guardianai.ai;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Validates and sanitises raw LLM outputs to guarantee schema conformance,
 * prevent prompt injection escapes, and block fabricated threat intelligence.
 */
public class ExplanationResponseValidator {

    private static final Pattern TAG_SUMMARY = Pattern.compile("<summary>(.*?)</summary>", Pattern.DOTALL | Pattern.CASE_INSENSITIVE);
    private static final Pattern TAG_EXPLANATION = Pattern.compile("<explanation>(.*?)</explanation>", Pattern.DOTALL | Pattern.CASE_INSENSITIVE);
    private static final Pattern TAG_ACTIONS = Pattern.compile("<actions>(.*?)</actions>", Pattern.DOTALL | Pattern.CASE_INSENSITIVE);
    private static final Pattern TAG_UNCERTAINTY = Pattern.compile("<uncertainty>(.*?)</uncertainty>", Pattern.DOTALL | Pattern.CASE_INSENSITIVE);

    public static ExplanationResult validateAndBuild(
            String rawOutput,
            SecurityFindingContext context,
            String modelName,
            String backendName,
            long latencyMs
    ) {
        if (rawOutput == null || rawOutput.trim().isEmpty()) {
            if (context != null) {
                return RulesBasedExplanationFallback.generateFallback(context, "Model returned empty output");
            } else {
                return new ExplanationResult(
                        "Model returned empty output.",
                        "",
                        java.util.Collections.emptyList(),
                        "Inference completed but produced no text.",
                        ExplanationResult.ExplanationSource.INFERENCE_FAILED,
                        modelName,
                        backendName,
                        latencyMs
                );
            }
        }

        // Sanitise against prompt injection / control character tricks
        String cleanOutput = sanitizeOutput(rawOutput);

        String summary = extractTag(cleanOutput, TAG_SUMMARY);
        String explanation = extractTag(cleanOutput, TAG_EXPLANATION);
        String actionsBlock = extractTag(cleanOutput, TAG_ACTIONS);
        String uncertainty = extractTag(cleanOutput, TAG_UNCERTAINTY);

        List<String> actions = new ArrayList<>();
        if (!actionsBlock.isEmpty()) {
            for (String line : actionsBlock.split("\n")) {
                String trimmed = line.replaceAll("^[-•*0-9.]+\\s*", "").trim();
                if (!trimmed.isEmpty()) {
                    actions.add(trimmed);
                }
            }
        }

        // Fallback parsing if model used markdown headers instead of xml tags
        if (summary.isEmpty() && explanation.isEmpty()) {
            return parseMarkdownOrPlainOutput(cleanOutput, context, modelName, backendName, latencyMs);
        }

        // Guard against hallucinated APK execution or network connections
        summary = censorFabricatedFacts(summary);
        explanation = censorFabricatedFacts(explanation);

        if (actions.isEmpty() && context != null && !context.getPracticalSteps().isEmpty()) {
            actions.addAll(context.getPracticalSteps());
        }

        if (uncertainty.isEmpty() && context != null) {
            uncertainty = "On-device AI explanation is advisory. Always independently confirm with official support or 1930.";
        }

        return new ExplanationResult(
                summary,
                explanation,
                actions,
                uncertainty,
                ExplanationResult.ExplanationSource.MODEL_INFERENCE,
                modelName,
                backendName,
                latencyMs
        );
    }

    private static ExplanationResult parseMarkdownOrPlainOutput(
            String text,
            SecurityFindingContext context,
            String modelName,
            String backendName,
            long latencyMs
    ) {
        String clean = censorFabricatedFacts(text);
        List<String> actions = new ArrayList<>();
        if (context != null && !context.getPracticalSteps().isEmpty()) {
            actions.addAll(context.getPracticalSteps());
        }

        String uncertainty = context != null ? "On-device AI explanation is advisory." : "";

        return new ExplanationResult(
                clean,
                "",
                actions,
                uncertainty,
                ExplanationResult.ExplanationSource.MODEL_INFERENCE,
                modelName,
                backendName,
                latencyMs
        );
    }

    private static String extractTag(String text, Pattern pattern) {
        Matcher matcher = pattern.matcher(text);
        if (matcher.find()) {
            return matcher.group(1).trim();
        }
        return "";
    }

    private static String sanitizeOutput(String text) {
        // Remove zero-width characters and control codes except standard whitespace
        return text.replaceAll("[\u200B-\u200D\uFEFF]", "")
                   .replaceAll("</?start_of_turn>", "")
                   .replaceAll("</?end_of_turn>", "")
                   .trim();
    }

    private static String censorFabricatedFacts(String text) {
        // Ensure model never falsely claims GuardianAi ran an APK or queried live servers
        return text.replaceAll("(?i)I executed this (app|apk)", "Static heuristics inspected this package")
                   .replaceAll("(?i)I connected to (the|a) server", "Analysis inspected server address patterns")
                   .replaceAll("(?i)I tested the link live", "Link safety was evaluated via structural heuristics");
    }
}
