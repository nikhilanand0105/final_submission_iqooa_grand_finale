package dev.saathi.safety;

import dev.saathi.ai.explain.LanguageModel;
import dev.saathi.ai.explain.ModelState;
import dev.saathi.safety.SafetyTypes.Confidence;
import dev.saathi.safety.SafetyTypes.ScamKind;
import dev.saathi.safety.SafetyTypes.SelfHarmKind;
import dev.saathi.safety.SafetyTypes.Severity;
import dev.saathi.safety.SafetyTypes.Source;
import dev.saathi.safety.SafetyTypes.SourceType;
import dev.saathi.safety.SafetyTypes.Status;
import dev.saathi.safety.SafetyTypes.ThreatKind;
import dev.saathi.util.CancellationToken;

/**
 * The single analysis path shared by the notification listener, Safe Browser and manual Check:
 * normalise → Gemma (if READY) → schema validation → rules fallback when needed → deterministic guard → result.
 * Blocking; callers run it off the main thread. Never returns a "safe" verdict for failed analysis.
 */
public final class SafetyPipeline {

    public static final int MAX_INPUT_CHARS = 10_000;

    /** What happened with the model for this item (for the event record and tests). */
    public enum ModelOutcome { NOT_AVAILABLE, USED, REJECTED, TIMED_OUT, FAILED, INCONCLUSIVE, CANCELLED }

    public static final class Result {
        public final SafetyClassification classification;
        public final ModelOutcome modelOutcome;
        public final String modelNote;
        public final long durationMs;
        public final boolean truncated;

        Result(SafetyClassification c, ModelOutcome o, String note, long ms, boolean truncated) {
            classification = c;
            modelOutcome = o;
            modelNote = note == null ? "" : note;
            durationMs = ms;
            this.truncated = truncated;
        }

        /** True if a later model pass could improve this result (it was produced without the model). */
        public boolean eligibleForModelReanalysis() {
            return modelOutcome == ModelOutcome.NOT_AVAILABLE || modelOutcome == ModelOutcome.TIMED_OUT || modelOutcome == ModelOutcome.FAILED;
        }
    }

    private final LanguageModel model; // may be null
    private final RulesClassifier rules = new RulesClassifier();

    public SafetyPipeline(LanguageModel model) {
        this.model = model;
    }

    public Result analyze(SourceType type, String rawText, String contextNote, CancellationToken token) {
        long t0 = System.currentTimeMillis();
        if (rawText == null || rawText.trim().isEmpty()) {
            return new Result(SafetyClassification.unavailable(type, Status.CONTENT_UNAVAILABLE,
                    "No readable text was available to check."), ModelOutcome.NOT_AVAILABLE, "", 0, false);
        }
        String text = rawText.replaceAll("[\\p{Cntrl}&&[^\\n]]", " ").replaceAll("[ \\t]+", " ").trim();
        boolean truncated = false;
        if (text.length() > MAX_INPUT_CHARS) {
            text = text.substring(0, MAX_INPUT_CHARS);
            truncated = true;
        }

        SafetyClassification modelResult = null;
        ModelOutcome outcome = ModelOutcome.NOT_AVAILABLE;
        String note;
        if (model == null || model.getState() != ModelState.READY) {
            note = model == null ? "No on-device model in this build" : model.getState().getDescription();
        } else if (text.length() > ClassificationPrompt.MAX_CONTENT_CHARS) {
            note = "Text is longer than the model's input limit; rules were used";
        } else {
            note = "";
            try {
                String raw = model.generate(ClassificationPrompt.system(), ClassificationPrompt.user(type, text, contextNote), token);
                ClassificationParser.Result p = ClassificationParser.parse(raw, type, text, model.getModelId());
                if (p.value == null) {
                    outcome = ModelOutcome.REJECTED;
                    note = "Model answer failed validation (" + p.rejection + ")";
                } else if (isInconclusive(p.value)) {
                    outcome = ModelOutcome.INCONCLUSIVE;
                    note = "Model was unsure";
                    modelResult = p.value;
                } else {
                    outcome = ModelOutcome.USED;
                    modelResult = p.value;
                }
            } catch (LanguageModel.ModelException e) {
                outcome = e.cancelled ? ModelOutcome.CANCELLED : e.timedOut ? ModelOutcome.TIMED_OUT : ModelOutcome.FAILED;
                note = e.cancelled ? "Cancelled" : e.timedOut ? "Model took too long" : "Model error";
            } catch (RuntimeException e) {
                outcome = ModelOutcome.FAILED;
                note = "Model error";
            }
        }
        if (outcome == ModelOutcome.CANCELLED) {
            return new Result(SafetyClassification.unavailable(type, Status.PENDING, "Analysis was cancelled."), outcome, note,
                    System.currentTimeMillis() - t0, truncated);
        }

        SafetyClassification base;
        if (outcome == ModelOutcome.USED) {
            base = modelResult;
        } else {
            base = rules.classify(type, text);
            if (outcome == ModelOutcome.INCONCLUSIVE && modelResult != null && !base.hasAnyConcern()) {
                // Neither the model nor the rules could decide: keep uncertainty visible.
                SafetyClassification.Builder b = base.toBuilder();
                b.status = Status.NEEDS_REVIEW;
                b.explanation = "Saathi couldn't tell from this alone. If it worries you, ask a trusted adult.";
                base = b.build();
            }
        }
        if (type == SourceType.BROWSER_PAGE && base.selfHarm.isPersonalRisk()) {
            // Someone else's words on a web page are not the child's own statement.
            SafetyClassification.Builder b = base.toBuilder();
            b.selfHarm = SelfHarmKind.AMBIGUOUS;
            b.selfHarmSeverity = Severity.LOW;
            b.guardNotes.add("Page text is written by someone else, so it isn't treated as the child's own words.");
            base = b.build();
        }
        SafetyClassification guarded = SafetyGuard.apply(base, text);
        return new Result(guarded, outcome, note, System.currentTimeMillis() - t0, truncated);
    }

    /** A model result that labels nothing and is unsure, or calls self-harm ambiguous, is not a decision. */
    static boolean isInconclusive(SafetyClassification c) {
        boolean nothing = c.threat == ThreatKind.NONE && c.scam == ScamKind.NONE && !c.selfHarm.isPersonalRisk();
        return (nothing && c.confidence == Confidence.LOW) || c.selfHarm == SelfHarmKind.AMBIGUOUS && c.selfHarmSeverity == Severity.NONE;
    }

    /** Convenience for display: whether the final result came from the model. */
    public static boolean modelContributed(Result r) {
        Source s = r.classification.source;
        return s == Source.GEMMA || s == Source.GEMMA_WITH_GUARD || s == Source.COMBINED;
    }
}
