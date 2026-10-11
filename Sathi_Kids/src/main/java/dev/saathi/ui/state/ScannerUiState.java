package dev.saathi.ui.state;

import dev.saathi.model.ApkAnalysisReport;
import dev.saathi.model.ScanVerdict;

public class ScannerUiState {

    public enum LanguagePreference {
        ENGLISH,
        HINDI
    }

    private final boolean isLoading;
    private final String currentProgressStage;
    private final ApkAnalysisReport report;
    private final boolean isSeniorModeActive;
    private final LanguagePreference language;
    private final String errorMessage;

    public ScannerUiState(
            boolean isLoading,
            String currentProgressStage,
            ApkAnalysisReport report,
            boolean isSeniorModeActive,
            LanguagePreference language,
            String errorMessage) {
        this.isLoading = isLoading;
        this.currentProgressStage = currentProgressStage;
        this.report = report;
        this.isSeniorModeActive = isSeniorModeActive;
        this.language = language;
        this.errorMessage = errorMessage;
    }

    public static ScannerUiState initial() {
        return new ScannerUiState(false, "Ready", null, false, LanguagePreference.ENGLISH, null);
    }

    public boolean isLoading() {
        return isLoading;
    }

    public String getCurrentProgressStage() {
        return currentProgressStage;
    }

    public ApkAnalysisReport getReport() {
        return report;
    }

    public boolean isSeniorModeActive() {
        return isSeniorModeActive;
    }

    public LanguagePreference getLanguage() {
        return language;
    }

    public String getErrorMessage() {
        return errorMessage;
    }
}
