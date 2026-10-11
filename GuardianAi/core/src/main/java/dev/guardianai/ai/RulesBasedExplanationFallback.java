package dev.guardianai.ai;

import dev.guardianai.model.ScanVerdict;

import java.util.ArrayList;
import java.util.List;

/**
 * Deterministic fallback generator that produces structured security explanations
 * directly from verified rules-engine indicators when the on-device language model
 * is missing, loading, or failed.
 *
 * GUARANTEE: Never labels output as AI-generated. Discloses deterministic rules provenance.
 */
public class RulesBasedExplanationFallback {

    public static ExplanationResult generateFallback(SecurityFindingContext context, String reason) {
        if (context == null) {
            return new ExplanationResult(
                    "No security finding context provided.",
                    "",
                    List.of("Enter or paste text to perform a rules-based security analysis."),
                    "No data available.",
                    ExplanationResult.ExplanationSource.RULES_FALLBACK,
                    "Rules Engine v2026.10",
                    "Deterministic Fallback",
                    0
            );
        }

        StringBuilder summary = new StringBuilder();
        StringBuilder indicatorsExp = new StringBuilder();
        List<String> advice = new ArrayList<>(context.getPracticalSteps());

        ScanVerdict verdict = context.getVerdict();

        if (context.isHindi()) {
            if (verdict == ScanVerdict.KNOWN_MALICIOUS || verdict == ScanVerdict.HIGH_RISK) {
                summary.append("⚠️ उच्च जोखिम चेतावनी: इस संदेश/लिंक में ज्ञात ऑनलाइन धोखाधड़ी और जबरन वसूली के स्पष्ट संकेत पाए गए हैं।");
            } else if (verdict == ScanVerdict.CAUTION) {
                summary.append("⚠️ सावधानी बरतें: इस सामग्री में कुछ असामान्य या संदिग्ध पैटर्न दिखे हैं।");
            } else {
                summary.append("✅ कोई ज्ञात खतरा नहीं मिला: इस इनपुट में कोई ज्ञात दुर्भावनापूर्ण पैटर्न नहीं दिखा।");
            }
        } else {
            if (verdict == ScanVerdict.KNOWN_MALICIOUS || verdict == ScanVerdict.HIGH_RISK) {
                summary.append("🛑 High-Risk Scam Alert: Verified rules identified multiple patterns associated with financial fraud, credential harvesting, or coercion.");
            } else if (verdict == ScanVerdict.CAUTION) {
                summary.append("⚠️ Caution Advised: This item contains unusual or suspicious patterns that warrant independent verification before taking action.");
            } else {
                summary.append("✅ No Known Threats Detected: Verified heuristic rules did not detect deceptive patterns, credential lures, or coercive demands.");
            }
        }

        // Format observable indicators
        if (context.getIndicators().isEmpty()) {
            indicatorsExp.append("• No threat indicators matched by local heuristics.");
        } else {
            for (SecurityFindingContext.IndicatorDetail ind : context.getIndicators()) {
                indicatorsExp.append("• [").append(ind.getTitle()).append("]: ").append(ind.getExplanation());
                if (!ind.getEvidenceQuote().isEmpty()) {
                    indicatorsExp.append(" (Quoted Evidence: \"").append(ind.getEvidenceQuote()).append("\")");
                }
                indicatorsExp.append("\n");
            }
        }

        if (advice.isEmpty()) {
            if (verdict == ScanVerdict.KNOWN_MALICIOUS || verdict == ScanVerdict.HIGH_RISK) {
                advice.add("Do not click links, send money, or share OTPs.");
                advice.add("If funds are at risk, immediately call 1930 (National Cyber Crime Helpline).");
                advice.add("Block and report the sender on your messaging app.");
            } else {
                advice.add("Always verify unexpected payment requests via an independent phone call.");
                advice.add("Never share bank account passwords or UPI PINs.");
            }
        }

        String uncertainty = context.getUncertaintyNote();
        if (uncertainty == null || uncertainty.isEmpty()) {
            uncertainty = "Rules-based classification analyzes observable text patterns. It cannot verify the true identity or intentions of the real-world sender.";
        }
        if (reason != null && !reason.isEmpty()) {
            uncertainty = "[Model State: " + reason + "] " + uncertainty;
        }

        return new ExplanationResult(
                summary.toString().trim(),
                indicatorsExp.toString().trim(),
                advice,
                uncertainty,
                ExplanationResult.ExplanationSource.RULES_FALLBACK,
                "GuardianAi Deterministic Rules Engine (v2026.10)",
                "Deterministic Local Engine",
                0
        );
    }
}
