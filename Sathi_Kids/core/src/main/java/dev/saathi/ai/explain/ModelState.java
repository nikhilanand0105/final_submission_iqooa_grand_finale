package dev.saathi.ai.explain;

/** Genuine lifecycle states of the on-device language model. */
public enum ModelState {
    UNAVAILABLE("No model file is installed on this phone"),
    INITIALIZING("Loading the on-device model"),
    READY("On-device model ready"),
    GENERATING("On-device model is writing"),
    FAILED("The on-device model failed to load or run"),
    RESOURCE_CONSTRAINED("Not enough free memory to run the on-device model"),
    CLOSED("On-device model released to save memory");

    private final String description;

    ModelState(String d) {
        description = d;
    }

    public String getDescription() { return description; }
}
