package dev.guardianai.shield.apk;

/** Technical outcome of reading/parsing the selected file. */
public enum AnalysisStatus {
    COMPLETE("Analysis completed"),
    PARTIAL("Some parts of the file could not be analysed"),
    EMPTY_FILE("The file is empty"),
    NOT_A_ZIP("The file is not an Android app package"),
    NOT_AN_APK("The archive has no Android manifest, so it is not an installable app"),
    CORRUPTED_ARCHIVE("The archive is damaged or incomplete"),
    OVERSIZED_FILE("The file is larger than the on-device limit"),
    PERMISSION_DENIED("The app was not allowed to read this file"),
    READ_ERROR("The file could not be read"),
    CANCELLED("The check was cancelled");

    private final String description;

    AnalysisStatus(String description) {
        this.description = description;
    }

    public String getDescription() { return description; }

    public boolean isFailure() {
        return this != COMPLETE && this != PARTIAL;
    }
}
