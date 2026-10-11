package dev.saathi.ui.viewmodel;

import dev.saathi.engine.ApkInstallHandoffHelper;
import dev.saathi.engine.SaathiApkIntelligence;
import dev.saathi.model.ApkAnalysisReport;
import dev.saathi.storage.LocalStorageRepository;
import dev.saathi.ui.state.ScannerUiState;

import java.io.File;
import java.io.InputStream;
import java.util.function.Consumer;

/**
 * Android Architecture Components ViewModel coordinating APK inspection, state presentation,
 * and safe installation handoff without violating Google Play policies.
 */
public class ApkScannerViewModel {

    private final SaathiApkIntelligence apkIntelligence;
    private final LocalStorageRepository storageRepository;
    private ScannerUiState currentState;
    private Consumer<ScannerUiState> stateObserver;

    public ApkScannerViewModel(SaathiApkIntelligence apkIntelligence, LocalStorageRepository storageRepository) {
        this.apkIntelligence = apkIntelligence != null ? apkIntelligence : new SaathiApkIntelligence();
        this.storageRepository = storageRepository != null ? storageRepository : new LocalStorageRepository();
        this.currentState = ScannerUiState.initial();
    }

    public void observeState(Consumer<ScannerUiState> observer) {
        this.stateObserver = observer;
        if (observer != null) {
            observer.accept(this.currentState);
        }
    }

    public void setSeniorMode(boolean enabled) {
        updateState(new ScannerUiState(
                currentState.isLoading(),
                currentState.getCurrentProgressStage(),
                currentState.getReport(),
                enabled,
                currentState.getLanguage(),
                currentState.getErrorMessage()
        ));
    }

    public void setLanguage(ScannerUiState.LanguagePreference language) {
        updateState(new ScannerUiState(
                currentState.isLoading(),
                currentState.getCurrentProgressStage(),
                currentState.getReport(),
                currentState.isSeniorModeActive(),
                language,
                currentState.getErrorMessage()
        ));
    }

    public void scanApkFile(File file) {
        updateState(new ScannerUiState(
                true,
                "Inspecting APK container & manifest...",
                null,
                currentState.isSeniorModeActive(),
                currentState.getLanguage(),
                null
        ));

        try {
            ApkAnalysisReport report = apkIntelligence.analyzeApk(file);

            // Record audit in local encrypted storage (metadata only, no raw file saved)
            storageRepository.recordScan(
                    report.getFileName(),
                    report.getSha256Checksum(),
                    report.getVerdict(),
                    report.getIndicators().size(),
                    "PENDING_USER_REVIEW"
            );

            updateState(new ScannerUiState(
                    false,
                    "Analysis Complete",
                    report,
                    currentState.isSeniorModeActive(),
                    currentState.getLanguage(),
                    null
            ));
        } catch (Exception e) {
            updateState(new ScannerUiState(
                    false,
                    "Error",
                    null,
                    currentState.isSeniorModeActive(),
                    currentState.getLanguage(),
                    "Failed to scan APK: " + e.getMessage()
            ));
        }
    }

    public void scanApkStream(String fileName, InputStream stream, long size) {
        updateState(new ScannerUiState(
                true,
                "Inspecting APK package...",
                null,
                currentState.isSeniorModeActive(),
                currentState.getLanguage(),
                null
        ));

        try {
            ApkAnalysisReport report = apkIntelligence.analyzeApk(fileName, stream, size);

            storageRepository.recordScan(
                    report.getFileName(),
                    report.getSha256Checksum(),
                    report.getVerdict(),
                    report.getIndicators().size(),
                    "PENDING_USER_REVIEW"
            );

            updateState(new ScannerUiState(
                    false,
                    "Analysis Complete",
                    report,
                    currentState.isSeniorModeActive(),
                    currentState.getLanguage(),
                    null
            ));
        } catch (Exception e) {
            updateState(new ScannerUiState(
                    false,
                    "Error",
                    null,
                    currentState.isSeniorModeActive(),
                    currentState.getLanguage(),
                    "Failed to scan stream: " + e.getMessage()
            ));
        }
    }

    public ApkInstallHandoffHelper.InstallIntentDescriptor prepareInstallHandoff(String contentUri) {
        if (currentState.getReport() != null && currentState.getReport().canSafelyProceedWithInstall()) {
            return ApkInstallHandoffHelper.createSystemInstallIntent(contentUri);
        }
        return null;
    }

    private void updateState(ScannerUiState newState) {
        this.currentState = newState;
        if (stateObserver != null) {
            stateObserver.accept(newState);
        }
    }

    public ScannerUiState getCurrentState() {
        return currentState;
    }
}
