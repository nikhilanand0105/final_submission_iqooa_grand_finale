package dev.guardianai.shield.message;

import dev.guardianai.model.ThreatSeverity;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Deterministic on-device message risk analysis engine.
 * Inspects observable linguistic, structural, and behavioral indicators
 * without making moral assumptions or claims about an individual's intent.
 */
public final class RuleBasedMessageRiskAnalyzer implements MessageRiskAnalyzer {

    private static final String LIMITATIONS_STATEMENT =
            "Deterministic on-device heuristic engine (Rules v" + MessageRulesCatalogue.RULES_VERSION + "). " +
            "Evaluates observable linguistic patterns, urgency markers, and credential requests without making claims " +
            "about an individual's character or intent. Zero-day evasion techniques, subtle manipulation, or informal " +
            "slang may fall outside rule patterns. Always independently verify suspicious demands.";

    @Override
    public MessageRiskAssessment analyze(String rawMessage) {
        long timestamp = System.currentTimeMillis();

        if (rawMessage == null || rawMessage.trim().isEmpty()) {
            return new MessageRiskAssessment(
                    MessageRiskCategory.INSUFFICIENT_INPUT,
                    ThreatSeverity.INFO,
                    Collections.emptyList(),
                    "The message text is empty or blank. Please enter or paste message content to inspect.",
                    List.of("Paste an SMS, chat excerpt, or message body to evaluate its safety."),
                    LIMITATIONS_STATEMENT,
                    getEngineId(),
                    getRulesVersion(),
                    0,
                    timestamp
            );
        }

        MessageNormalizer.ProcessedText processed = MessageNormalizer.process(rawMessage);
        String clean = processed.getCleanText();

        if (clean.length() < 3) {
            return new MessageRiskAssessment(
                    MessageRiskCategory.INSUFFICIENT_INPUT,
                    ThreatSeverity.INFO,
                    Collections.emptyList(),
                    "Input is too brief to identify meaningful context or indicators.",
                    List.of("Enter a complete sentence or message excerpt for evaluation."),
                    LIMITATIONS_STATEMENT,
                    getEngineId(),
                    getRulesVersion(),
                    clean.length(),
                    timestamp
            );
        }

        // 1. Evaluate rules catalogue
        List<MessageIndicator> rawIndicators = MessageRulesCatalogue.evaluateRules(processed);

        // 2. Check for benign counter-signals (e.g., surprise birthday party, educational warnings)
        boolean hasBenignContext = MessageRulesCatalogue.hasBenignCounterSignal(clean);
        boolean isInformationalBankAlert = MessageRulesCatalogue.isInformationalBankAlert(clean);

        // Filter out false positives if counter-signals are present
        List<MessageIndicator> filteredIndicators = new ArrayList<>();
        if (hasBenignContext) {
            // Under benign celebration context (e.g., "Rahul ki surprise birthday party, kisi ko mat batana"),
            // suppress secrecy alerts unless critical threats (like camera/photo coercion or OTP demands) are present
            for (MessageIndicator ind : rawIndicators) {
                if (ind.getSeverity() == ThreatSeverity.CRITICAL) {
                    filteredIndicators.add(ind);
                }
            }
        } else if (isInformationalBankAlert) {
            // Legitimate transaction notifications (credit alerts) without action triggers
            // suppress payment pressure flags
            for (MessageIndicator ind : rawIndicators) {
                if (ind.getType() != MessageIndicatorType.URGENT_PAYMENT_PRESSURE) {
                    filteredIndicators.add(ind);
                }
            }
        } else {
            filteredIndicators.addAll(rawIndicators);
        }

        // 3. Aggregate signals and determine category & severity
        MessageRiskCategory category;
        ThreatSeverity severity;
        String summary;
        List<String> actions = new ArrayList<>();

        boolean hasCritical = false;
        int highCount = 0;
        int mediumCount = 0;

        for (MessageIndicator ind : filteredIndicators) {
            if (ind.getSeverity() == ThreatSeverity.CRITICAL) {
                hasCritical = true;
            } else if (ind.getSeverity() == ThreatSeverity.HIGH) {
                highCount++;
            } else if (ind.getSeverity() == ThreatSeverity.MEDIUM) {
                mediumCount++;
            }
        }

        if (hasCritical || (highCount >= 2) || (highCount >= 1 && mediumCount >= 1)) {
            category = MessageRiskCategory.HIGH_RISK;
            severity = hasCritical ? ThreatSeverity.CRITICAL : ThreatSeverity.HIGH;
            summary = "High risk of fraud, credential theft, or extortion coercion detected. " +
                    "This message exhibits " + filteredIndicators.size() + " corroborated indicator(s).";
            actions.add("Never share OTPs, UPI PINs, passwords, or government IDs (Aadhaar/PAN).");
            actions.add("Do not click links or install remote-access tools (AnyDesk/TeamViewer/APKs).");
            actions.add("If funds were deducted or you feel threatened, call the National Cyber Helpline at 1930 immediately.");
            actions.add("Block the sender and report the conversation on your messaging app.");
        } else if (highCount == 1 || mediumCount >= 2) {
            category = MessageRiskCategory.SUSPICIOUS;
            severity = ThreatSeverity.HIGH;
            summary = "Suspicious message patterns identified (" + filteredIndicators.size() + " indicator(s)). " +
                    "Proceed with heightened caution and verify the sender independently.";
            actions.add("Verify the claim through official channels (e.g., call your bank's published helpline).");
            actions.add("Do not send money or follow urgent instructions without independent verification.");
            actions.add("Talk to a trusted family member or adviser before proceeding.");
        } else if (mediumCount == 1) {
            category = MessageRiskCategory.AMBIGUOUS;
            severity = ThreatSeverity.MEDIUM;
            summary = "Ambiguous message: Contains sensitive terms or potential lures, but lacks definitive malicious corroboration.";
            actions.add("Confirm the sender's identity through a separate phone call.");
            actions.add("Exercise standard caution and avoid sharing confidential information.");
        } else {
            category = MessageRiskCategory.LOW_RISK;
            severity = ThreatSeverity.LOW;
            summary = "No known threat indicators detected in this message. Standard precautions apply.";
            actions.add("Continue normal communication while remaining alert to unsolicited requests.");
        }

        return new MessageRiskAssessment(
                category,
                severity,
                filteredIndicators,
                summary,
                actions,
                LIMITATIONS_STATEMENT,
                getEngineId(),
                getRulesVersion(),
                clean.length(),
                timestamp
        );
    }

    @Override
    public String getEngineId() {
        return MessageRulesCatalogue.ENGINE_ID;
    }

    @Override
    public String getRulesVersion() {
        return MessageRulesCatalogue.RULES_VERSION;
    }
}
