package dev.guardianai.shield.apk;

import dev.guardianai.model.ThreatSeverity;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Structured evidence derived from the exact file the child selected. Any section that could not be extracted
 * is null, and the reason is listed in {@link #notExtracted}.
 */
public final class ApkAnalysisResult {

    public final AnalysisStatus status;
    public final ApkRiskVerdict verdict;
    public final String fileName;
    public final long sizeBytes;
    public final String sha256;                 // null if the file could not be read
    public final ManifestInfo manifest;         // null if not parsed
    public final String manifestError;
    public final SigningInfo signing;           // null if not inspected
    public final ZipInventory inventory;        // null if the archive could not be opened
    public final DexInspector.Summary dex;      // null if no DEX was inspected
    public final List<ApkIndicator> indicators;
    public final FileHashReputationProvider.Outcome hashLookup;
    public final String hashProviderName;
    public final String summary;
    public final String whyItMatters;
    public final List<String> nextSteps;
    public final String limitations;
    public final List<String> notExtracted;
    public final String analyzerVersion;
    public final long durationMs;

    ApkAnalysisResult(AnalysisStatus status, ApkRiskVerdict verdict, String fileName, long sizeBytes, String sha256,
                      ManifestInfo manifest, String manifestError, SigningInfo signing, ZipInventory inventory,
                      DexInspector.Summary dex, List<ApkIndicator> indicators,
                      FileHashReputationProvider.Outcome hashLookup, String hashProviderName, String summary,
                      String whyItMatters, List<String> nextSteps, String limitations, List<String> notExtracted,
                      String analyzerVersion, long durationMs) {
        this.status = status;
        this.verdict = verdict;
        this.fileName = fileName;
        this.sizeBytes = sizeBytes;
        this.sha256 = sha256;
        this.manifest = manifest;
        this.manifestError = manifestError;
        this.signing = signing;
        this.inventory = inventory;
        this.dex = dex;
        this.indicators = Collections.unmodifiableList(new ArrayList<>(indicators));
        this.hashLookup = hashLookup;
        this.hashProviderName = hashProviderName;
        this.summary = summary;
        this.whyItMatters = whyItMatters;
        this.nextSteps = Collections.unmodifiableList(new ArrayList<>(nextSteps));
        this.limitations = limitations;
        this.notExtracted = Collections.unmodifiableList(new ArrayList<>(notExtracted));
        this.analyzerVersion = analyzerVersion;
        this.durationMs = durationMs;
    }

    public ThreatSeverity highestSeverity() {
        ThreatSeverity max = ThreatSeverity.INFO;
        for (ApkIndicator i : indicators) if (i.severity.getWeight() > max.getWeight()) max = i.severity;
        return max;
    }

    public boolean hasIndicator(String id) {
        for (ApkIndicator i : indicators) if (i.id.equals(id)) return true;
        return false;
    }

    public List<String> requestedPermissions() {
        return manifest == null ? Collections.<String>emptyList() : manifest.permissions;
    }
}
