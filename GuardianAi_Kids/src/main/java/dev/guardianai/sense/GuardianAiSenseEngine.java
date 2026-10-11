package dev.guardianai.sense;

import dev.guardianai.model.ThreatSeverity;

import java.util.ArrayList;
import java.util.List;

/**
 * Main inference engine for GuardianAi Sense (Child Online Safety & Grooming Detection).
 * Evaluates submitted conversation excerpts with nuanced linguistic and cultural understanding.
 */
public class GuardianAiSenseEngine {

    public ConversationRiskReport analyze(String messageText) {
        if (messageText == null || messageText.isBlank()) {
            return new ConversationRiskReport(
                    SafetyCategory.BENIGN,
                    ThreatSeverity.INFO,
                    List.of(),
                    "No message text provided to analyze.",
                    List.of("Continue browsing safely"),
                    false
            );
        }

        HinglishContextEvaluator.ContextEvaluation eval = HinglishContextEvaluator.evaluate(messageText);

        // 1. Check for Benign Counter-Signals (e.g. surprise birthday party)
        if (eval.hasBenignCounterSignal && !eval.hasPrivacyInvasion && !eval.hasGamingScam) {
            return new ConversationRiskReport(
                    SafetyCategory.BENIGN,
                    ThreatSeverity.LOW,
                    eval.matchedPhrases,
                    "This looks like an innocent conversation about a party, surprise, or school project. No threat detected.",
                    List.of("Enjoy your celebration!", "Always stay safe online."),
                    false
            );
        }

        // 2. High/Critical Grooming Pattern: Secrecy + Camera/Photo Demand or Isolation
        if (eval.hasSecrecy && eval.hasPrivacyInvasion) {
            List<String> options = new ArrayList<>();
            options.add("Do not send any photos or turn on your camera.");
            options.add("Talk to a parent, teacher, or trusted adult right now.");
            options.add("Block this person immediately.");
            options.add("Press GuardianAi SOS if you feel scared or unsafe.");

            return new ConversationRiskReport(
                    SafetyCategory.GROOMING_MANIPULATION,
                    ThreatSeverity.CRITICAL,
                    eval.matchedPhrases,
                    "⚠️ Important Safety Warning: This person is asking for private photos or camera access and asking you to keep it secret from your parents. Real friends will never ask you to keep secrets from your family or do uncomfortable things.",
                    options,
                    true // Prompt SOS option
            );
        }

        // 3. Platform Hopping + Secrecy (Attempted Isolation)
        if (eval.hasSecrecy && eval.hasPlatformHopping) {
            List<String> options = new ArrayList<>();
            options.add("Stay on this app where you are protected.");
            options.add("Do not move to private or disappearing messaging apps with strangers.");
            options.add("Show this conversation to an adult you trust.");

            return new ConversationRiskReport(
                    SafetyCategory.GROOMING_MANIPULATION,
                    ThreatSeverity.HIGH,
                    eval.matchedPhrases,
                    "⚠️ Caution: This person is trying to move you away to another private app while asking you to hide it from your parents. This is a common tactic people use to isolate you.",
                    options,
                    false
            );
        }

        // 4. Gaming Currency & Account Scam
        if (eval.hasGamingScam) {
            List<String> options = new ArrayList<>();
            options.add("Never share your password, OTP, or UPI PIN with anyone.");
            options.add("Do not click links offering free game diamonds or currency.");
            options.add("Official game creators do not give away items through unofficial chats.");

            return new ConversationRiskReport(
                    SafetyCategory.CHILD_FINANCIAL_SCAM,
                    ThreatSeverity.HIGH,
                    eval.matchedPhrases,
                    "🛑 Scam Warning: Offers for 'free diamonds', 'UC', or requests for login/payment details are almost always scams designed to steal accounts or your family's money.",
                    options,
                    false
            );
        }

        // 5. Mild Secrecy Cue without other red flags
        if (eval.hasSecrecy) {
            List<String> options = new ArrayList<>();
            options.add("Think about why this person wants you to hide things.");
            options.add("It is always safe to talk to your parents if something feels strange.");

            return new ConversationRiskReport(
                    SafetyCategory.GROOMING_MANIPULATION,
                    ThreatSeverity.MEDIUM,
                    eval.matchedPhrases,
                    "Notice: This person asked you not to tell anyone. Remember that you never have to keep online secrets that make you feel uncomfortable.",
                    options,
                    false
            );
        }

        // Default Benign
        return new ConversationRiskReport(
                SafetyCategory.BENIGN,
                ThreatSeverity.INFO,
                List.of(),
                "No safety concerns detected in this conversation excerpt.",
                List.of("Continue chatting safely!"),
                false
        );
    }
}
