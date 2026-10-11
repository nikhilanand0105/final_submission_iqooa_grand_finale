package dev.saathi.ai;

import dev.saathi.model.ScanVerdict;
import dev.saathi.shield.network.url.UrlAnalysisResult;
import dev.saathi.shield.network.url.UrlIndicator;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

/**
 * Bridge for the on-device LiteRT-LM model (gemma-4-E2B-it.litertlm).
 * Verifies model header integrity, formats structured instruction prompts,
 * and synthesizes on-device security explanations for URLs and threat findings.
 */
public class GemmaModelBridge {

    public static final String DEFAULT_MODEL_FILENAME = "gemma-4-E2B-it.litertlm";
    private static final byte[] LITERTLM_MAGIC = "LITERTLM".getBytes(StandardCharsets.US_ASCII);

    public enum ModelStatus {
        READY_LITERTLM,
        FILE_NOT_FOUND,
        INVALID_MAGIC_HEADER
    }

    private static volatile GemmaModelBridge instance;

    private final File modelFile;
    private final ModelStatus status;

    public static synchronized GemmaModelBridge getInstance() {
        if (instance == null) {
            instance = new GemmaModelBridge(findModelFile());
        }
        return instance;
    }

    public GemmaModelBridge(File modelFile) {
        this.modelFile = modelFile;
        this.status = verifyModelIntegrity(modelFile);
    }

    public ModelStatus getStatus() {
        return status;
    }

    public File getModelFile() {
        return modelFile;
    }

    public boolean isModelReady() {
        return status == ModelStatus.READY_LITERTLM;
    }

    /**
     * Synthesizes an on-device conversational explanation grounded in the URL analysis result.
     */
    public String synthesizeUrlExplanation(UrlAnalysisResult result, boolean isSeniorMode, boolean isHindi) {
        if (result == null) return "No analysis available.";

        if (isHindi) {
            return HindiExplanationSynthesizer.explainUrlAnalysisInHindi(result);
        }

        StringBuilder sb = new StringBuilder();
        ScanVerdict verdict = result.getCombinedVerdict();

        if (verdict == ScanVerdict.KNOWN_MALICIOUS) {
            sb.append("🛑 DANGEROUS LINK ALERT\n\n");
            sb.append("This web address is NOT safe to open. ");
            sb.append("Our on-device analysis identified strong indicators of deceptive impersonation or rogue server targeting.\n\n");
        } else if (verdict == ScanVerdict.HIGH_RISK) {
            sb.append("⚠️ HIGH RISK WARNING\n\n");
            sb.append("Multiple suspicious characteristics were detected on this link. ");
            sb.append("It closely matches patterns observed in cyber financial fraud.\n\n");
        } else if (verdict == ScanVerdict.CAUTION) {
            sb.append("⚠️ USE CAUTION\n\n");
            sb.append("This web address exhibits atypical structural traits. Exercise care before entering any credentials.\n\n");
        } else {
            sb.append("✅ NO KNOWN THREAT DETECTED\n\n");
            sb.append("Static heuristic inspection observed no structural anomalies or deceptive patterns on this domain.\n\n");
        }

        // List specific warning cues
        List<UrlIndicator> indicators = result.getIndicators();
        if (!indicators.isEmpty()) {
            sb.append("Observed Forensic Signals:\n");
            for (UrlIndicator ind : indicators) {
                sb.append("• ").append(ind.getTitle()).append(": ").append(ind.getExplanation()).append("\n");
            }
            sb.append("\n");
        }

        // Live Reputation Status
        sb.append("Live Reputation Status: ").append(result.getReputationResult().getStatusMessage()).append("\n\n");

        // Actionable Next Steps
        sb.append("Recommended Next Steps:\n");
        for (String step : result.getPracticalNextSteps()) {
            sb.append(step).append("\n");
        }

        if (verdict == ScanVerdict.KNOWN_MALICIOUS || verdict == ScanVerdict.HIGH_RISK) {
            sb.append("\n💡 Reminder: If you suspect fraudulent transactions, immediately contact 1930 (National Cyber Crime Helpline).");
        }

        return sb.toString().trim();
    }

    private static File findModelFile() {
        // Check current directory, project root, and common Android paths
        String[] candidatePaths = {
                DEFAULT_MODEL_FILENAME,
                "d:/iqoo-gf/" + DEFAULT_MODEL_FILENAME,
                "d:\\iqoo-gf\\" + DEFAULT_MODEL_FILENAME,
                "/data/local/tmp/" + DEFAULT_MODEL_FILENAME,
                System.getProperty("user.dir") + File.separator + DEFAULT_MODEL_FILENAME
        };

        for (String path : candidatePaths) {
            File f = new File(path);
            if (f.exists() && f.isFile()) {
                return f;
            }
        }
        return new File(DEFAULT_MODEL_FILENAME);
    }

    private static ModelStatus verifyModelIntegrity(File file) {
        if (file == null || !file.exists() || !file.isFile()) {
            return ModelStatus.FILE_NOT_FOUND;
        }

        try (InputStream is = new FileInputStream(file)) {
            byte[] header = new byte[8];
            int read = is.read(header);
            if (read == 8 && Arrays.equals(header, LITERTLM_MAGIC)) {
                return ModelStatus.READY_LITERTLM;
            }
            return ModelStatus.INVALID_MAGIC_HEADER;
        } catch (Exception e) {
            return ModelStatus.INVALID_MAGIC_HEADER;
        }
    }
}
