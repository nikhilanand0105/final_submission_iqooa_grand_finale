package dev.saathi.engine;

import dev.saathi.model.*;
import dev.saathi.parser.*;
import dev.saathi.rules.ThreatRuleEvaluator;

import dev.saathi.shield.network.hash.ApkHashReputationProvider;
import dev.saathi.shield.network.hash.HashReputationResult;
import dev.saathi.shield.network.url.ReputationState;

import java.io.File;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * Main entry point for Saathi APK Intelligence (under Saathi Shield).
 * Performs complete offline static reverse engineering without executing the APK,
 * coupled with privacy-safe cryptographic hash reputation verification.
 */
public class SaathiApkIntelligence {

    private final ThreatRuleEvaluator ruleEvaluator;
    private final ApkHashReputationProvider hashReputationProvider;

    public SaathiApkIntelligence() {
        this(new ThreatRuleEvaluator(), new ApkHashReputationProvider.NoOpHashReputationProvider());
    }

    public SaathiApkIntelligence(ThreatRuleEvaluator evaluator) {
        this(evaluator, new ApkHashReputationProvider.NoOpHashReputationProvider());
    }

    public SaathiApkIntelligence(ThreatRuleEvaluator evaluator, ApkHashReputationProvider hashProvider) {
        this.ruleEvaluator = evaluator != null ? evaluator : new ThreatRuleEvaluator();
        this.hashReputationProvider = hashProvider != null ? hashProvider : new ApkHashReputationProvider.NoOpHashReputationProvider();
    }

    public ThreatRuleEvaluator getRuleEvaluator() {
        return ruleEvaluator;
    }

    public ApkHashReputationProvider getHashReputationProvider() {
        return hashReputationProvider;
    }

    /**
     * Inspects a local APK file.
     */
    public ApkAnalysisReport analyzeApk(File apkFile) {
        return analyzeApk(apkFile != null ? apkFile.getName() : "unknown.apk", apkFile);
    }

    /**
     * Inspects a local APK file preserving its original external file name for rule evaluation.
     */
    public ApkAnalysisReport analyzeApk(String fileName, File apkFile) {
        if (apkFile == null || !apkFile.exists() || !apkFile.canRead()) {
            return buildFailureReport(fileName != null ? fileName : "null", "File does not exist or cannot be read.");
        }

        try {
            ApkPackageReader.ExtractedApkData data = ApkPackageReader.read(apkFile);
            return analyzeExtractedData(fileName, data, apkFile);
        } catch (Exception e) {
            return buildFailureReport(fileName, "Failed to read APK container: " + e.getMessage());
        }
    }

    /**
     * Inspects an APK stream directly (e.g. from Android ContentResolver or FileProvider).
     */
    public ApkAnalysisReport analyzeApk(String fileName, InputStream inputStream, long totalSizeBytes) {
        try {
            ApkPackageReader.ExtractedApkData data = ApkPackageReader.read(inputStream, totalSizeBytes);
            return analyzeExtractedData(fileName, data, null);
        } catch (Exception e) {
            return buildFailureReport(fileName, "Failed to read APK input stream: " + e.getMessage());
        }
    }

    private ApkAnalysisReport analyzeExtractedData(String fileName, ApkPackageReader.ExtractedApkData data, File apkFile) {
        boolean parseSuccess = true;
        ManifestMetadata manifest = null;
        DexInspectionResult dexResult = null;
        CertificateMetadata certificate = null;

        // 1. Decode Manifest
        if (data.manifestBytes != null && data.manifestBytes.length > 0) {
            manifest = BinaryXmlDecoder.decode(data.manifestBytes);
        } else {
            parseSuccess = false;
        }

        // 2. Scan DEX Bytecode
        if (!data.dexFilesBytes.isEmpty()) {
            dexResult = DexBytecodeScanner.scan(data.dexFilesBytes);
        }

        // 3. Inspect Digital Signatures
        certificate = SignatureInspector.inspect(data.metaInfEntries, apkFile);

        // 4. Evaluate Security Rules
        List<ThreatIndicator> indicators = new ArrayList<>(ruleEvaluator.evaluateAll(
                data.sha256Checksum,
                fileName,
                manifest,
                dexResult,
                certificate,
                data.embeddedHiddenPayloads
        ));

        // 4b. Add Structural Anomalies as direct factual indicators
        if (data.structuralAnomalies != null && !data.structuralAnomalies.isEmpty()) {
            for (String anomaly : data.structuralAnomalies) {
                indicators.add(new ThreatIndicator(
                        "STRUCTURAL_ANOMALY_" + Math.abs(anomaly.hashCode()),
                        "APK Archive Anomaly",
                        anomaly,
                        ThreatSeverity.HIGH,
                        "CONTAINER",
                        "ZIP Archive Structure",
                        "Structural archive anomalies, decompression bomb patterns, or path traversals are evasion tactics used to bypass standard scanner controls.",
                        true
                ));
            }
        }

        // 4c. Online Threat Intelligence Hash Reputation Check (Cryptographic hash only)
        HashReputationResult hashResult = null;
        if (hashReputationProvider != null && hashReputationProvider.isConfigured()) {
            hashResult = hashReputationProvider.checkHashReputation(data.sha256Checksum);
            if (hashResult != null && hashResult.getState() == ReputationState.THREAT_MATCH) {
                indicators.add(new ThreatIndicator(
                        "ONLINE_THREAT_INTEL_HASH_MATCH",
                        "Online Threat-Intelligence Malware Match",
                        "Cryptographic hash matches active malware verified by " + hashReputationProvider.getProviderName()
                                + " (" + hashResult.getMaliciousDetections() + "/" + hashResult.getTotalEngines() + " detections"
                                + (hashResult.getThreatDetails().isEmpty() ? "" : ": " + hashResult.getThreatDetails()) + ").",
                        ThreatSeverity.CRITICAL,
                        "THREAT_INTELLIGENCE",
                        hashReputationProvider.getProviderName(),
                        "The cryptographic SHA-256 fingerprint matches verified malware samples in external threat-intelligence feeds.",
                        true
                ));
            }
        } else {
            hashResult = HashReputationResult.notChecked("Live hash reputation provider unconfigured. Displaying local static analysis only.");
        }

        // 5. Determine Verdict
        ScanVerdict verdict = ruleEvaluator.determineVerdict(data.sha256Checksum, indicators, parseSuccess);
        if (hashResult != null && hashResult.getState() == ReputationState.THREAT_MATCH) {
            verdict = ScanVerdict.KNOWN_MALICIOUS;
        } else if (parseSuccess && (dexResult == null || dexResult.getDexFileCount() == 0) && verdict == ScanVerdict.NO_KNOWN_THREAT_DETECTED) {
            verdict = ScanVerdict.INCONCLUSIVE;
        }

        // 6. Generate Plain-Language and Technical Explanations
        VerdictExplainer.Explanations exp = VerdictExplainer.explain(verdict, indicators, manifest, certificate);

        boolean canInstall = (verdict == ScanVerdict.NO_KNOWN_THREAT_DETECTED || verdict == ScanVerdict.CAUTION);

        return new ApkAnalysisReport(
                fileName,
                data.sha256Checksum,
                data.totalSizeBytes,
                verdict,
                exp.technicalSummary,
                exp.plainLanguageSummary,
                indicators,
                manifest,
                certificate,
                dexResult,
                exp.recommendedActions,
                canInstall,
                data.totalZipEntries,
                data.totalUncompressedBytes,
                data.zipEntryInventory,
                data.nativeLibraries,
                data.structuralAnomalies,
                hashResult
        );
    }

    private ApkAnalysisReport buildFailureReport(String fileName, String reason) {
        VerdictExplainer.Explanations exp = VerdictExplainer.explain(
                ScanVerdict.UNABLE_TO_DETERMINE,
                null, null, null
        );

        return new ApkAnalysisReport(
                fileName,
                "0000000000000000000000000000000000000000000000000000000000000000",
                0,
                ScanVerdict.UNABLE_TO_DETERMINE,
                "Analysis failed: " + reason,
                exp.plainLanguageSummary,
                List.of(new ThreatIndicator("UNREADABLE_FILE", "Unreadable File", reason, ThreatSeverity.MEDIUM, "CONTAINER")),
                null,
                null,
                null,
                exp.recommendedActions,
                false
        );
    }
}
