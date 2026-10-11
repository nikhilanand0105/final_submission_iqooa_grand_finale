package dev.saathi.ai.explain;

import dev.saathi.util.CancellationToken;

/**
 * Produces the explanation for a check result: tries the on-device model when it is READY, validates its output,
 * and otherwise returns the labelled rules-based explanation. Model output can never trigger notifications or
 * change the analyzer verdict; it only produces display text.
 */
public final class ExplanationService {

    public static final class Outcome {
        public final SafetyExplanation explanation;
        /** Plain-language note about why the model was or wasn't used. */
        public final String note;
        public final boolean cancelled;

        Outcome(SafetyExplanation e, String note, boolean cancelled) {
            this.explanation = e;
            this.note = note;
            this.cancelled = cancelled;
        }
    }

    private final LanguageModel model; // may be null

    public ExplanationService(LanguageModel model) {
        this.model = model;
    }

    public Outcome explain(FindingSet fs, String submittedContent, String question, String language,
                           boolean threatMatchEstablished, CancellationToken token) {
        String lang = "hi".equals(language) ? "hi" : "en";
        if (model == null) {
            return new Outcome(RulesBasedExplainer.explain(fs, lang), "No on-device AI model is included in this build.", false);
        }
        ModelState st = model.getState();
        if (st != ModelState.READY) {
            return new Outcome(RulesBasedExplainer.explain(fs, lang), st.getDescription() + ", so rules-based guidance is shown.", false);
        }
        String sys = ExplanationPromptBuilder.systemInstruction(lang);
        String user = ExplanationPromptBuilder.userMessage(fs, submittedContent, question);
        String lastReason = null;
        for (int attempt = 0; attempt < 2; attempt++) {
            if (token != null && token.isCancelled()) return new Outcome(RulesBasedExplainer.explain(fs, lang), "Cancelled.", true);
            String raw;
            try {
                raw = model.generate(sys, user, token);
            } catch (LanguageModel.ModelException e) {
                if (e.cancelled) return new Outcome(RulesBasedExplainer.explain(fs, lang), "Cancelled.", true);
                String why = e.timedOut ? "The on-device model took too long" : "The on-device model hit an error";
                return new Outcome(RulesBasedExplainer.explain(fs, lang), why + ", so rules-based guidance is shown.", false);
            } catch (RuntimeException e) {
                return new Outcome(RulesBasedExplainer.explain(fs, lang), "The on-device model hit an error, so rules-based guidance is shown.", false);
            }
            ModelOutputValidator.Result v = ModelOutputValidator.validate(raw, fs, model.getModelId(), lang, threatMatchEstablished);
            if (v.explanation != null) return new Outcome(v.explanation, "", false);
            lastReason = v.rejectionReason;
        }
        return new Outcome(RulesBasedExplainer.explain(fs, lang),
                "The AI's answer didn't pass Saathi's safety checks (" + lastReason + "), so rules-based guidance is shown.", false);
    }
}
