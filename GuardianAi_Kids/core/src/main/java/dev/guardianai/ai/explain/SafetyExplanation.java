package dev.guardianai.ai.explain;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Typed, validated explanation shown to the child. {@link #source} says truthfully who wrote it. */
public final class SafetyExplanation {

    public enum Source { ON_DEVICE_MODEL, RULES }

    public final Source source;
    public final String modelId;              // null for RULES
    public final String summary;
    public final List<String> evidenceRefs;   // ids into the FindingSet
    public final List<String> nextSteps;
    public final String limitations;
    public final String language;             // "en" or "hi"

    public SafetyExplanation(Source source, String modelId, String summary, List<String> evidenceRefs,
                             List<String> nextSteps, String limitations, String language) {
        this.source = source;
        this.modelId = modelId;
        this.summary = summary;
        this.evidenceRefs = Collections.unmodifiableList(new ArrayList<>(evidenceRefs));
        this.nextSteps = Collections.unmodifiableList(new ArrayList<>(nextSteps));
        this.limitations = limitations == null ? "" : limitations;
        this.language = language;
    }

    /** Label to display alongside the text. */
    public String sourceLabel() {
        return source == Source.ON_DEVICE_MODEL
                ? "Written by the on-device AI model (" + modelId + "), based only on the findings above"
                : "Rules-based guidance (no AI model was used)";
    }
}
