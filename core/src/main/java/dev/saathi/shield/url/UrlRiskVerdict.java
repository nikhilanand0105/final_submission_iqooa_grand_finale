package dev.saathi.shield.url;

/** Child-facing verdict for a link check. None of these values claim a link is "safe". */
public enum UrlRiskVerdict {
    /** Known threat listing, or strong structural deception (e.g. fake host before '@', brand in the wrong place). */
    WARNING_SIGNS("There are warning signs"),
    /** One or more moderate warning signs. */
    BE_CAREFUL("Let's be careful"),
    /** No (or only minor) structural warning signs, and no threat listing where a lookup was done. */
    NO_WARNING_SIGNS_FOUND("No warning signs found"),
    /** Invalid input, or the online check failed with nothing found locally. */
    CANNOT_TELL("I can't tell from this alone");

    private final String label;

    UrlRiskVerdict(String label) {
        this.label = label;
    }

    public String getLabel() { return label; }
}
