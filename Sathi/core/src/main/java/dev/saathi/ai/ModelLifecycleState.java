package dev.saathi.ai;

/**
 * Explicit lifecycle states of the on-device language model runtime.
 */
public enum ModelLifecycleState {
    /**
     * Model weights file (.litertlm) was not found on local storage.
     */
    MISSING("Model weights file not found on device"),

    /**
     * Model file exists but failed magic header or integrity verification.
     */
    INTEGRITY_CHECK_FAILED("Corrupted model file or invalid magic header"),

    /**
     * Model is being mapped into memory and hardware delegates are initializing.
     */
    LOADING("Initializing LiteRT-LM engine on background thread"),

    /**
     * Model engine and conversation session are ready for on-device inference.
     */
    READY("Gemma 4-E2B-it active on hardware acceleration"),

    /**
     * System was unable to allocate contiguous RAM/VRAM for model context.
     */
    OUT_OF_MEMORY("Insufficient RAM to initialize on-device LLM context"),

    /**
     * Runtime or native delegate error occurred during execution.
     */
    ERROR("Model initialization or inference failed"),

    /**
     * Platform or CPU/GPU architecture does not support the model runtime.
     */
    UNAVAILABLE("Hardware or runtime environment unsupported");

    private final String description;

    ModelLifecycleState(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }
}
