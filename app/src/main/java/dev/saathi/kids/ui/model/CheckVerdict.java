package dev.saathi.kids.ui.model;

/**
 * Child-friendly verdict types for Saathi Kids checking engine.
 */
public enum CheckVerdict {
    LOOKS_OKAY("No warning signs found", "#386B57", "#EAF3ED", "✅"),
    BE_CAREFUL("Let's be careful", "#855A12", "#F8F0DF", "⚠️"),
    WARNING_SIGNS("There are warning signs", "#A63232", "#F8EAE8", "🛑"),
    CANNOT_TELL("I can't tell from this alone", "#555555", "#F0F0EE", "ℹ️");

    private final String label;
    private final String textColorHex;
    private final String bgColorHex;
    private final String badgeEmoji;

    CheckVerdict(String label, String textColorHex, String bgColorHex, String badgeEmoji) {
        this.label = label;
        this.textColorHex = textColorHex;
        this.bgColorHex = bgColorHex;
        this.badgeEmoji = badgeEmoji;
    }

    public String getLabel() { return label; }
    public String getTextColorHex() { return textColorHex; }
    public String getBgColorHex() { return bgColorHex; }
    public String getBadgeEmoji() { return badgeEmoji; }
}
