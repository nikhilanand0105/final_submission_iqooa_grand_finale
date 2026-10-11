package dev.saathi.shield.message;

import java.util.Objects;

/**
 * Verbatim text span extracted from the user's supplied input.
 * Guarantees that evidence quotes match genuine input and prevents fabrication.
 */
public final class EvidenceSpan {
    private final int startOffset;
    private final int endOffset;
    private final String matchedText;

    public EvidenceSpan(int startOffset, int endOffset, String matchedText) {
        this.startOffset = Math.max(0, startOffset);
        this.endOffset = Math.max(this.startOffset, endOffset);
        this.matchedText = matchedText != null ? matchedText : "";
    }

    public int getStartOffset() {
        return startOffset;
    }

    public int getEndOffset() {
        return endOffset;
    }

    public String getMatchedText() {
        return matchedText;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        EvidenceSpan that = (EvidenceSpan) o;
        return startOffset == that.startOffset &&
                endOffset == that.endOffset &&
                Objects.equals(matchedText, that.matchedText);
    }

    @Override
    public int hashCode() {
        return Objects.hash(startOffset, endOffset, matchedText);
    }

    @Override
    public String toString() {
        return "[" + startOffset + ".." + endOffset + ": \"" + matchedText + "\"]";
    }
}
