package dev.saathi.sense.analyzer;

/**
 * Child-friendly risk verdict emitted by the message safety analyzer.
 */
public enum MessageRiskVerdict {
    WARNING_SIGNS_DETECTED(
            "There are warning signs 🛑",
            "Multiple red flags or dangerous requests were detected in this message.",
            "#A63232",
            "#F8EAE8",
            "🛑"
    ),
    BE_CAREFUL(
            "Let's be careful ⚠️",
            "There are suspicious clues or pressure in this message that warrant caution.",
            "#855A12",
            "#F8F0DF",
            "⚠️"
    ),
    NO_FLAGS_DETECTED(
            "Looks okay from what I can see ✅",
            "No obvious warning signs were found in this specific message excerpt.",
            "#386B57",
            "#EAF3ED",
            "✅"
    ),
    INCONCLUSIVE(
            "I can't tell from this alone ℹ️",
            "This message is too short or ambiguous to evaluate reliably.",
            "#555555",
            "#F0F0EE",
            "ℹ️"
    ),
    ANALYSIS_FAILED(
            "Check could not be completed ⚠️",
            "An error occurred while evaluating the message text.",
            "#666666",
            "#EEEEEE",
            "❓"
    );

    private final String label;
    private final String description;
    private final String textColorHex;
    private final String bgColorHex;
    private final String badgeEmoji;

    MessageRiskVerdict(String label, String description, String textColorHex, String bgColorHex, String badgeEmoji) {
        this.label = label;
        this.description = description;
        this.textColorHex = textColorHex;
        this.bgColorHex = bgColorHex;
        this.badgeEmoji = badgeEmoji;
    }

    public String getLabel() {
        return label;
    }

    public String getDescription() {
        return description;
    }

    public String getTextColorHex() {
        return textColorHex;
    }

    public String getBgColorHex() {
        return bgColorHex;
    }

    public String getBadgeEmoji() {
        return badgeEmoji;
    }
}
