package dev.guardianai.engine;

import dev.guardianai.model.*;
import dev.guardianai.parser.*;
import dev.guardianai.rules.ThreatRuleEvaluator;

import java.io.File;
import java.io.InputStream;
import java.util.List;

/**
 * Main entry point for GuardianAi APK Intelligence (under GuardianAi Shield).
 * Performs complete offline static reverse engineering without executing the APK.
 */
public class GuardianAiApkIntelligence {

    private final ThreatRuleEvaluator ruleEvaluator;

    public GuardianAiApkIntelligence() {
        this.ruleEvaluator = new ThreatRuleEvaluator();
    }

    public GuardianAiApkIntelligence(ThreatRuleEvaluator evaluator) {
        this.ruleEvaluator = evaluator != null ? evaluator : new ThreatRuleEvaluator();
    }

    public ThreatRuleEvaluator getRuleEvaluator() {
        return ruleEvaluator;
    }

    /**
     * Inspects a local APK file.
     */
    public ApkAnalysisReport analyzeApk(File apkFile) {
        if (apkFile == null || !apkFile.exists() || !apkFile.canRead()) {
            return buildFailureReport(apkFile != null ? apkFile.getName() : "null", "File does not exist or cannot be read.");
        }

        try {
            ApkPackageReader.ExtractedApkData data = ApkPackageReader.read(apkFile);
            return analyzeExtractedData(apkFile.getName(), data);
        } catch (Exception e) {
            return buildFailureReport(apkFile.getName(), "Failed to read APK container: " + e.getMessage());
        }
    }

    /**
     * Inspects an APK stream directly (e.g. from Android ContentResolver or FileProvider).
     */
    public ApkAnalysisReport analyzeApk(String fileName, InputStream inputStream, long totalSizeBytes) {
        try {
            ApkPackageReader.ExtractedApkData data = ApkPackageReader.read(inputStream, totalSizeBytes);
            return analyzeExtractedData(fileName, data);
        } catch (Exception e) {
            return buildFailureReport(fileName, "Failed to read APK input stream: " + e.getMessage());
        }
    }

    private ApkAnalysisReport analyzeExtractedData(String fileName, ApkPackageReader.ExtractedApkData data) {
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
        certificate = SignatureInspector.inspect(data.metaInfEntries);

        // 4. Evaluate Security Rules
        List<ThreatIndicator> indicators = ruleEvaluator.evaluateAll(
                data.sha256Checksum,
                manifest,
                dexResult,
                certificate,
                data.embeddedHiddenPayloads
        );

        // 5. Determine Verdict
        ScanVerdict verdict = ruleEvaluator.determineVerdict(data.sha256Checksum, indicators, parseSuccess);

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
                canInstall
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
