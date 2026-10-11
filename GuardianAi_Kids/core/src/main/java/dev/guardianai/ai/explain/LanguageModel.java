package dev.guardianai.ai.explain;

import dev.guardianai.util.CancellationToken;

/** Boundary to an on-device text model. The Android LiteRT-LM adapter implements this. */
public interface LanguageModel {

    class ModelException extends Exception {
        public final boolean timedOut;
        public final boolean cancelled;

        public ModelException(String msg, boolean timedOut, boolean cancelled) {
            super(msg);
            this.timedOut = timedOut;
            this.cancelled = cancelled;
        }
    }

    ModelState getState();

    /** Short identifier of the loaded model (file name), for labelling output. */
    String getModelId();

    /**
     * Runs one generation. Blocking; must be called off the main thread. Implementations must honour the token
     * and a time limit, and return to READY afterwards.
     */
    String generate(String systemInstruction, String userMessage, CancellationToken token) throws ModelException;
}
