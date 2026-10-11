package dev.guardianai.sense;

import java.util.*;

/**
 * Linguistic and context evaluator for English, Hindi, and Hinglish (Romanized Hindi).
 * Distinguishes innocent secrets (e.g., surprise birthday gifts) from predatory secrecy and coercion.
 */
public class HinglishContextEvaluator {

    // Secrecy cues
    private static final List<String> SECRECY_CUES = Arrays.asList(
            "kisi ko mat batana",
            "kisi ko mat bolna",
            "kisi se share mat karna",
            "mummy papa ko mat batana",
            "parents ko mat batana",
            "ghar pe mat bolna",
            "delete this chat",
            "secret between us",
            "don't tell anyone",
            "keep this secret"
    );

    // Platform hopping cues (isolation tactic)
    private static final List<String> PLATFORM_HOPPING_CUES = Arrays.asList(
            "telegram pe aao",
            "telegram pe message kar",
            "insta pe message kar",
            "instagram pe aao",
            "snapchat pe add kar",
            "private room mein aao",
            "move to telegram",
            "add me on snap"
    );

    // Child scam & gaming currency cues
    private static final List<String> GAMING_SCAM_CUES = Arrays.asList(
            "free diamonds",
            "free robux",
            "bgmi uc free",
            "free skin code",
            "free redeem code",
            "upi id do",
            "upi pin daal",
            "give your password",
            "login credentials"
    );

    // Exploitation & privacy invasion cues
    private static final List<String> PRIVACY_INVASION_CUES = Arrays.asList(
            "photo bhej",
            "camera on kar",
            "video call akele mein",
            "send your photo",
            "show your face",
            "turn on your camera",
            "private photo"
    );

    // Benign counter-signals
    private static final List<String> BENIGN_COUNTER_SIGNALS = Arrays.asList(
            "surprise party",
            "birthday gift",
            "birthday surprise",
            "homework project",
            "exam prep",
            "surprise present"
    );

    public static class ContextEvaluation {
        public boolean hasSecrecy = false;
        public boolean hasPlatformHopping = false;
        public boolean hasGamingScam = false;
        public boolean hasPrivacyInvasion = false;
        public boolean hasBenignCounterSignal = false;
        public List<String> matchedPhrases = new ArrayList<>();
    }

    public static ContextEvaluation evaluate(String text) {
        ContextEvaluation eval = new ContextEvaluation();
        if (text == null || text.isBlank()) return eval;

        String lower = text.toLowerCase().replaceAll("[^a-zA-Z0-9\\s]", " ");

        // Check benign counter signals first
        boolean compositeBenign = (lower.contains("surprise") && (lower.contains("birthday") || lower.contains("party") || lower.contains("gift")))
                || (lower.contains("birthday") && lower.contains("party"))
                || (lower.contains("homework") || lower.contains("assignment"));

        if (compositeBenign) {
            eval.hasBenignCounterSignal = true;
            eval.matchedPhrases.add("Benign Context: Birthday / Celebration / School Context");
        }

        for (String cue : BENIGN_COUNTER_SIGNALS) {
            if (lower.contains(cue)) {
                eval.hasBenignCounterSignal = true;
                eval.matchedPhrases.add("Benign Context: " + cue);
            }
        }

        for (String cue : SECRECY_CUES) {
            if (lower.contains(cue)) {
                eval.hasSecrecy = true;
                eval.matchedPhrases.add("Secrecy Demand: " + cue);
            }
        }

        for (String cue : PLATFORM_HOPPING_CUES) {
            if (lower.contains(cue)) {
                eval.hasPlatformHopping = true;
                eval.matchedPhrases.add("Platform Hopping: " + cue);
            }
        }

        for (String cue : GAMING_SCAM_CUES) {
            if (lower.contains(cue)) {
                eval.hasGamingScam = true;
                eval.matchedPhrases.add("Gaming/Financial Offer: " + cue);
            }
        }

        for (String cue : PRIVACY_INVASION_CUES) {
            if (lower.contains(cue)) {
                eval.hasPrivacyInvasion = true;
                eval.matchedPhrases.add("Privacy/Media Demand: " + cue);
            }
        }

        return eval;
    }
}
