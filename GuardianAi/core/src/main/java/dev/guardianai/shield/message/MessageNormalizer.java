package dev.guardianai.shield.message;

import java.text.Normalizer;
import java.util.regex.Pattern;

/**
 * Text normalisation utility for robust message inspection.
 * Cleanses zero-width Unicode obfuscations, decomposes compatibility characters (NFKC),
 * and standardises whitespace without destroying evidence spans or original text.
 */
public final class MessageNormalizer {

    // Common zero-width and invisible bypass characters used to evade keyword filters
    private static final Pattern ZERO_WIDTH_PATTERN = Pattern.compile(
            "[\u200B\u200C\u200D\uFEFF\u2060\u00AD\u200E\u200F\u202A-\u202E]"
    );

    private static final Pattern MULTI_WHITESPACE = Pattern.compile("[ \\t\\r\\n]+");

    private MessageNormalizer() {
        // Utility class
    }

    public static final class ProcessedText {
        private final String originalText;
        private final String cleanText;
        private final String searchLower;

        public ProcessedText(String originalText, String cleanText, String searchLower) {
            this.originalText = originalText;
            this.cleanText = cleanText;
            this.searchLower = searchLower;
        }

        public String getOriginalText() {
            return originalText;
        }

        public String getCleanText() {
            return cleanText;
        }

        public String getSearchLower() {
            return searchLower;
        }

        public EvidenceSpan createSpan(int start, int end) {
            if (cleanText == null || start < 0 || end > cleanText.length() || start >= end) {
                return new EvidenceSpan(0, 0, "");
            }
            String matched = cleanText.substring(start, end);
            return new EvidenceSpan(start, end, matched);
        }
    }

    /**
     * Normalises user-supplied text for deterministic rules inspection.
     *
     * @param raw the raw input string
     * @return ProcessedText containing original, clean, and search-optimized representations
     */
    public static ProcessedText process(String raw) {
        if (raw == null) {
            return new ProcessedText("", "", "");
        }

        // 1. Unicode NFKC normalization (flattens full-width, ligature, and decomposed characters)
        String nfkc = Normalizer.normalize(raw, Normalizer.Form.NFKC);

        // 2. Strip zero-width evasion artifacts
        String stripped = ZERO_WIDTH_PATTERN.matcher(nfkc).replaceAll("");

        // 3. Regularize whitespace
        String clean = MULTI_WHITESPACE.matcher(stripped).replaceAll(" ").trim();

        // 4. Lowercase for case-insensitive matching
        String lower = clean.toLowerCase();

        return new ProcessedText(raw, clean, lower);
    }
}
